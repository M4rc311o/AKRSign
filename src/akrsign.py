from enum import Flag
from msilib import sequence
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta, timezone
import warnings
import argparse
import sys
import os

class CertificateAuthorityError(Exception):
    pass

class CertificateAuthority:
    # create CertificateAuthority class instance as singleton
    __instance = None
    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(CertificateAuthority, cls).__new__(cls)
        return cls.__instance

    def __init__(self):
        self.x509_ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "BPC-AKR Certification Authority"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Czechia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BPC-AKR")
        ])
        self.year_validity = 5
        self.data_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), "AKRSign_data")
        self.ca_key_and_cert_path = os.path.join(self.data_directory, "ca_key_and_cert.p12")
        self.ca_public_cert_path = os.path.join(self.data_directory, "ca_root_cert.pem")
        self.issued_cert_dir = os.path.join(self.data_directory, "issued_certificates")
        
        try:
            os.makedirs(self.issued_cert_dir, exist_ok=True)
        except Exception as e:
            raise CertificateAuthorityError("Error with creating CA data directories:\n" + str(e))

        # load CA private key
        if os.path.isfile(self.ca_key_and_cert_path):
            try:
                with open(self.ca_key_and_cert_path, "rb") as key_cert_f:
                    self.private_key, certificate, inter_cert = pkcs12.load_key_and_certificates(
                        key_cert_f.read(),
                        password=None
                    )
            except Exception as e:
                raise CertificateAuthorityError("Error with reading CAs PKCS #12 file:\n" + str(e))
            if self.private_key is None:
                raise CertificateAuthorityError("CAs PKCS #12 file does not contain private key or was not loaded properly")
            if certificate is None:
                warnings.warn("CAs PKCS #12 file does not contain public key certificate")
        else:
            self.ca_gen_key_cert()

    # generate CA private key and self-signed certificate       
    def ca_gen_key_cert(self):
        # generate private key ECDSA 256b
        self.private_key = ec.generate_private_key(
            ec.SECP256R1()
        )

        cert_builder = x509.CertificateBuilder()    # create certificate builder for self-signed Root CA certificate
        cert_builder = cert_builder.subject_name(self.x509_ca_name) # subject information
        cert_builder = cert_builder.issuer_name(self.x509_ca_name)  # issure information
        cert_builder = cert_builder.not_valid_before(datetime.today())  # valid from today
        cert_builder = cert_builder.not_valid_after(datetime.today() + timedelta(days=(365 * 30)))  # valid for 30 years
        cert_builder = cert_builder.public_key(self.private_key.public_key())   # subject public key

        # misc
        cert_builder = cert_builder.serial_number(x509.random_serial_number())

        # constrains
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        # specify key usages (certificate can be used for signing other certificates and CRLs)
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                digital_signature=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )

        # self-sign the certificate with CAs private key
        root_cert = cert_builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())

        # save CA PKCS #12 file
        try:
            with open(self.ca_key_and_cert_path, "wb") as key_cert_f:
                key_cert_f.write(pkcs12.serialize_key_and_certificates(
                    name=root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.encode(),
                    key=self.private_key,
                    cert=root_cert,
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        except Exception as e:
            raise CertificateAuthorityError("Error with saving CAs PKCS #12 file:\n" + str(e))

        # save CA Root certificate
        try:
            with open(self.ca_public_cert_path, "wb") as cert_f:
                cert_f.write(root_cert.public_bytes(
                    encoding=serialization.Encoding.PEM                 # save in .pem file
                ))
        except Exception as e:
            raise CertificateAuthorityError("Error with saving CA public certificate file: " + str(e))

    def handle_csr(self, serialized_csr: bytes) -> bytes:
        csr = x509.load_pem_x509_csr(serialized_csr)                    # deserialize csr

        # check Certificate Signing Request Validity
        if not csr.is_signature_valid:
            raise CertificateAuthorityError("Certificate signing request is not valid")

        # HERE should CA also check if provided information are correct

        cert_builder = x509.CertificateBuilder()    # create certificate builder for end-entity certificate
        cert_builder = cert_builder.subject_name(csr.subject)   # subject information
        cert_builder = cert_builder.issuer_name(self.x509_ca_name)  # issuer information
        cert_builder = cert_builder.not_valid_before(datetime.today())  # valid from today
        cert_builder = cert_builder.not_valid_after(datetime.today() + timedelta(days=(365 * self.year_validity)))  # valid for 5 years
        cert_builder = cert_builder.public_key(csr.public_key())    # subject public key

        # misc
        cert_builder = cert_builder.serial_number(x509.random_serial_number())

        # constrains
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )

        # specify key usages (certificate can be used for verifying digital signatures)
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )

        # sign the certificate with CAs private key
        end_entity_cert = cert_builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())

        serialized_end_entity_cert = end_entity_cert.public_bytes(encoding=serialization.Encoding.PEM)

        # save issued end-entity certificate
        try:
            with open(os.path.join(self.issued_cert_dir, f"{end_entity_cert.serial_number}.pem"), "wb") as cert_f:
                cert_f.write(serialized_end_entity_cert)
        except Exception as e:
            raise CertificateAuthorityError("Error with saving issued end-entity certificate file: " + str(e))

        # return serialized end-entity certificate
        return serialized_end_entity_cert

def compute_file_hash(file_path: str) -> bytes:
    file_hash = hashes.Hash(hashes.SHA256())
    try:
        with open(file_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):   # read file in 4 KiB chunks
                file_hash.update(byte_block)
    except:
        print("Error with opening file for signing")
    file_hash = file_hash.finalize()
    return file_hash

def create_AlgorithmIdentifier() -> bytes:
    sha256WithRSAEncryption_oid_der = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"   # sha256WithRSAEncryption OID 1.2.840.113549.1.1.11
    AlgorithmIdentifier_sequence_length = len(sha256WithRSAEncryption_oid_der) + 2
    # SEQUENCE tag + sequence length + algorithm oid + parameters (should be null according to RFC 8017; \x05 represents NULL tag) + parameters length
    AlgorithmIdentifier_asn1_der = b"\x30" + AlgorithmIdentifier_sequence_length.to_bytes(1, "big", signed=False) + sha256WithRSAEncryption_oid_der + b"\x05" + b"\x00"
    return AlgorithmIdentifier_asn1_der

def create_DigestInfo(AlgorithmIdentifier_asn1_der: bytes, file_hash: bytes) -> bytes:
    hash_length = len(file_hash)
    DigestInfo_sequence_length = len(AlgorithmIdentifier_asn1_der) + hash_length + 2
    # SEQUENCE tag + sequence length + AlgorithmIdentifier + OCTET STRING tag + hash length + file hash
    DigestInfo_asn1_der = b"\x30" + DigestInfo_sequence_length.to_bytes(1, "big", signed=False) + AlgorithmIdentifier_asn1_der + b"\x04" + hash_length.to_bytes(1, "big", signed=False) + file_hash
    return DigestInfo_asn1_der

def encode_EMSA_PKCS1_v1_5(key_size: int, file_hash: bytes) -> bytes:
    # creation of ASN.1 AlgorithmIdentifier
    AlgorithmIdentifier_asn1_der = create_AlgorithmIdentifier()
    # creation of ASN.1 DigestInfo
    DigestInfo_asn1_der = create_DigestInfo(AlgorithmIdentifier_asn1_der, file_hash)
    # constructing encryption block
    padding_len = ((key_size + 7) // 8) - 3 - len(DigestInfo_asn1_der)
    padding = b"\xff" * padding_len
    encryption_block = b"\x00" + b"\x01" + padding + b"\x00" + DigestInfo_asn1_der
    return encryption_block

def create_signature(file_path: str, sig_out_path: str, private_key_path: str) -> bool:
    try:
        with open(private_key_path, "rb") as key_f:
            private_key = serialization.load_pem_private_key(
                key_f.read(),
                password=None
            )
    except Exception as e:
        print("Error with loading private key:\n" + str(e))
        return True
    
    if not isinstance(private_key, rsa.RSAPrivateKey):
        print("Unsupported key type")
        return True
    
    ############################################################
    # RSASSA-PKCS1-v1_5 signature generation based on RFC 8017 #
    ############################################################
    
    # EMSA-PKCS1-v1_5 encoding
    encryption_block = encode_EMSA_PKCS1_v1_5(private_key.key_size, compute_file_hash(file_path))

    # OS2IP (convert encryption_block to integer)
    encryption_block_as_int = int.from_bytes(encryption_block, byteorder="big", signed=False)

    # RSASP1 with Chinese remainder algorithm
    s1 = pow(encryption_block_as_int, private_key.private_numbers().dmp1, private_key.private_numbers().p)
    s2 = pow(encryption_block_as_int, private_key.private_numbers().dmq1, private_key.private_numbers().q)
    h = (private_key.private_numbers().iqmp * (s1 - s2)) % private_key.private_numbers().p
    file_signature_as_int = (s2 + h * private_key.private_numbers().q) % (private_key.public_key().public_numbers().n)

    # I2OSP (convert file_signature_as_int to bytes)
    file_signature = file_signature_as_int.to_bytes((private_key.key_size + 7) // 8, byteorder="big", signed=False)

    # save file containing signature
    try:
        with open(sig_out_path, "wb") as sig_f:
            sig_f.write(file_signature)
    except Exception as e:
        print("Error with saving file containing signature:\n" + str(e))
        return True
    return False

def verify_signature(file_path: str, signature_path: str, certificate_path: str) -> bool:
    try:
        with open(signature_path, "rb") as sig_f:
            file_signature = sig_f.read()
    except:
        print("Error with opening file containing signature")
        return True

    try:
        with open(certificate_path, "rb") as cert_f:
            public_key = x509.load_pem_x509_certificate(
                cert_f.read()
            ).public_key()
    except Exception as e:
        print("Error with loading public key certificate:\n" + str(e))
        return True
    
    if not isinstance(public_key, rsa.RSAPublicKey):
        print("Unsupported key type")
        return True

    ##############################################################
    # RSASSA-PKCS1-v1_5 signature verification based on RFC 8017 #
    ##############################################################

    # OS2IP (convert file_signature to integer)
    file_signature_as_int = int.from_bytes(file_signature, byteorder="big", signed=False)

    # RSAVP1
    decrypted_block_as_int = pow(file_signature_as_int, public_key.public_numbers().e, public_key.public_numbers().n)

    # I2OSP (convert decrypted_block_as_int to bytes)
    decrypted_block = decrypted_block_as_int.to_bytes((public_key.key_size + 7) // 8, byteorder="big", signed=False)

    # EMSA-PKCS1-v1_5 encoding (on original file)
    encryption_block = encode_EMSA_PKCS1_v1_5(public_key.key_size, compute_file_hash(file_path))

    if encryption_block != decrypted_block:
        return True
    
    if verify_certificate(certificate_path) != False:
        return True
    return False

def create_certificate(cert_out_path: str, private_key_out_path: str, pkcs12_out_path: str | None) -> bool:
    common_name = input("Common name: ")
    country_name = input("Country code (cz, ...): ")
    locality_name = input("Locality name: ")
    state_or_province_name = input("State/province name: ")
    organization_name = input("Organization name: ")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    try:
        akr_ca = CertificateAuthority()
    except Exception as e:
        print("Error with creating Certificate Authority:\n" + str(e))
        return True

    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name)
    ]))

    csr = csr_builder.sign(private_key, algorithm=hashes.SHA256())
    serial_cert = akr_ca.handle_csr(csr.public_bytes(encoding=serialization.Encoding.PEM))

    # save private key into PEM file in PKCS #8 format
    try:
        with open(private_key_out_path, "wb") as key_f:
            key_f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except Exception as e:
        print("Error with saving private key:\n" + str(e))
        return True        

    # save end-entity certificate into PEM file
    try:
        with open(cert_out_path, "wb") as cert_f:
            cert_f.write(serial_cert)
    except Exception as e:
        print("Error with saving certificate:\n" + str(e))
        return True
    
    # save certificate and private key into PKCS #12 file
    if pkcs12_out_path is not None:
        certificate = x509.load_pem_x509_certificate(serial_cert)
        try:
            with open(pkcs12_out_path, "wb") as pkcs12_f:
                pkcs12_f.write(pkcs12.serialize_key_and_certificates(
                    name=certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.encode(),
                    key=private_key,
                    cert=certificate,
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        except Exception as e:
            print("Error with saving PKCS #12 file:\n" + str(e))
    
    return False

def verify_certificate(certificate_path: str) -> bool:
    ca_cert_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "AKRSign_data/", "ca_root_cert.pem")

    # load end-entity certificate from PEM file
    try:
        with open(certificate_path, "rb") as cert_f:
            ee_certificate = x509.load_pem_x509_certificate(cert_f.read())
    except Exception as e:
        print("Error with loading end-entity certificate:\n" + str(e))
        return True
    
    try:
        akr_ca = CertificateAuthority()
    except Exception as e:
        print("Error with creating Certificate Authority:\n" + str(e))
        return True

    # load CA certificate from PEM file
    try:
        with open(ca_cert_path, "rb") as cert_f:
            ca_certificate = x509.load_pem_x509_certificate(cert_f.read())
    except Exception as e:
        print("Error with loading CA certificate:\n" + str(e))
        return True
    
    # verify that end-entity cert has same issuer as CA cert subject and that signature is correct
    try:
        ca_certificate.verify_directly_issued_by(ca_certificate)
    except ValueError:
        print("CA self-signed certificatte has different subject than issuer or the signature algorithm is unsupported.")
        return True
    except TypeError:
        print("Issuer does not have a supported public key type")
        return True
    except InvalidSignature:
        print("CA self-signed certificate signature is invalid.")
        return True

    # verify that end-entity cert has same issuer as CA cert subject and that signature is correct
    try:
        ee_certificate.verify_directly_issued_by(ca_certificate)
    except ValueError:
        print("Issuer name on the End-entity certificate does not match the subject name of the issuer or the signature algorithm is unsupported.")
        return True
    except TypeError:
        print("Issuer of End-entity certificate does not have a supported public key type")
        return True
    except InvalidSignature:
        print("End-entity certificate siganture is invalid")
        return True

    # verify that both certificates are valid (date)
    current_time = datetime.today()
    if current_time < ee_certificate.not_valid_before:
        print("End-entity certificate is not valid yet")
        return True
    elif current_time > ee_certificate.not_valid_after:
        print("End-entity certificate is expired")
        return True
    if current_time < ca_certificate.not_valid_before:
        print("CA certificate is not valid yet")
        return True
    elif current_time > ca_certificate.not_valid_after:
        print("CA certificate is expired")
        return True
    
    # verify that CA certificate is actually marked as CA
    try:
        basic_contrains = ca_certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if not basic_contrains.ca:
            print("CA certificate is not marked as CA certificate in basic constrains")
            return True
    except ExtensionNotFound:
        print("Basic constrain extension was not found in CA certificate. This extension is necessary for determining if CA certificate is actually CA certificate.")
        return True
    
    # verify that CA certificate has key usage to sign other certificates
    try:
        key_usage = ca_certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not key_usage.key_cert_sign:
            print("This CA certificate can not be used for signing other certificates")
            return True
    except ExtensionNotFound:
        print("Key usage extension was not found in CA certificate. This extension is necessary for determining if CA certificate can be used to sign other certificates")
        return True

    return False

def main(args):
    if args.subcommand == "create_signature":
        create_signature(args.file, args.sig_out, args.private_key)
    elif args.subcommand == "verify_signature":
        if verify_signature(args.file, args.signature, args.certificate) == False:
            print("Signature is valid")
        else:
            print("Signature is invalid")
    elif args.subcommand == "create_certificate":
        create_certificate(args.cert_out, args.private_key_out, args.pkcs12_out)
    elif args.subcommand == "verify_certificate":
        if verify_certificate(args.certificate) == False:
            print("Certificate is valid")
        else:
            print("Certificate is invalid")

    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool for digital signatures and certificates working with built-in CA",
        epilog="Created by 247568, 247603, 231271, 247589"
    )
    subparsers = parser.add_subparsers(
        description="Available functionalities",
        required=True,
    )

    # create signature parser
    parser_cs = subparsers.add_parser(
        "create_signature",
        aliases=["cs"],
        help="Create a digital signature of a file"
    )
    parser_cs.set_defaults(subcommand="create_signature")
    parser_cs.add_argument("--file", "-f", type=str, required=True, help="Path to file which is supposed to be sign")
    parser_cs.add_argument("--sig_out", "-s", type=str, required=True, help="Path for saving file containing signature")
    parser_cs.add_argument("--private_key", "-k", type=str, required=True, help="Path to private key to use for signing")

    # verify signature parser
    parser_vs = subparsers.add_parser(
        "verify_signature",
        aliases=["vs"],
        help="Verify digital signature of a file"
    )
    parser_vs.set_defaults(subcommand="verify_signature")
    parser_vs.add_argument("--file", "-f", type=str, required=True, help="Path to the file for which was the signature created")
    parser_vs.add_argument("--signature", "-s", type=str, required=True, help="Path to the file containing signature")
    parser_vs.add_argument("--certificate", "-c", type=str, required=True, help="Path to the public key certificate of an end-enitiy that signed the file")

    # create certificate parser
    parser_cc = subparsers.add_parser(
        "create_certificate",
        aliases=["cc"],
        help="Create and export public key certificate"
    )
    parser_cc.set_defaults(subcommand="create_certificate")
    parser_cc.add_argument("--cert_out", "-c", type=str, required=True, help="Path for saving public key certificate")
    parser_cc.add_argument("--private_key_out", "-k", type=str, required=True, help="Path for saving private key")
    parser_cc.add_argument("--pkcs12_out", "-p12", type=str, required=False, help="Path for saving private key and public key certificate in p12 (PKCS #12) file")

    # verify certificate parser
    parser_vc = subparsers.add_parser(
        "verify_certificate",
        aliases=["vc"],
        help="Verify public key certificate"
    )
    parser_vc.set_defaults(subcommand="verify_certificate")
    parser_vc.add_argument("--certificate", "-c", type=str, required=True, help="Path to the public key certificate")
    args = parser.parse_args()
    sys.exit(main(args))
