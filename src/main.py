from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime
import argparse
import sys
import os
import ca

def compute_file_hash(file_path):
    # compute file hash
    file_hash = hashes.Hash(hashes.SHA256())
    try:
        with open(file_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):   # read file in 4 KiB chunks
                file_hash.update(byte_block)
    except:
        print("Error with opening file for signing")
    file_hash = file_hash.finalize()
    return file_hash

def create_signature(file_path, sig_out_path, private_key_path):
    file_hash = compute_file_hash(file_path)

    try:
        with open(private_key_path, "rb") as key_f:
            private_key = serialization.load_pem_private_key(
                key_f.read(),
                password=None
            )
    except Exception as e:
        print("Error with loading private key:\n" + str(e))
        return 1 
    
    # PKCS #1 v1.5 padding
    padding_len = (private_key.key_size / 8) - 3 - len(file_hash)
    padding = os.urandom(padding_len) #missing filtering zero bytes!!!!
    encryption_block = b"\x00" + b"\x02" + padding + b"\x00" + file_hash

    # RSA encryption
    # convert encryption_block to integer
    encryption_block_as_int = int.from_bytes(encryption_block, "big", signed=False)

    # Chinese remainder algorithm
    s1 = pow(encryption_block_as_int, private_key.private_numbers().dmp1, private_key.private_numbers().p)
    s2 = pow(encryption_block_as_int, private_key.private_numbers().dmq1, private_key.private_numbers().q)
    h = (private_key.private_numbers().iqmp * (s1 - s2)) % private_key.private_numbers().p
    file_signature_as_int = (s2 + h * private_key.private_numbers().q) % (private_key.private_numbers().p * private_key.private_numbers().q)

    # convert file_signature_as_int to bytes
    file_signature = file_signature_as_int.to_bytes((file_signature_as_int.bit_length() + 7) // 8, byteorder='big', signed=False)

    # save file containing signature
    try:
        with open(sig_out_path, "wb") as sig_f:
            sig_f.write(file_signature)
    except Exception as e:
        print("Error with saving file containing signature")
        return 1
    return 0

def verify_signature(file_path, signature_path, certificate_path):
    pass

def create_certificate(cert_out_path, private_key_out_path, pkcs12_out_path):
    common_name = input("Common name: ")
    country_name = input("Country name: ")
    locality_name = input("Locality name: ")
    state_or_province_name = input("State/province name: ")
    organization_name = input("Organization name: ")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    try:
        akr_ca = ca.CertificateAuthority()
    except Exception as e:
        print("Error with creating Certificate Authority:\n" + str(e))
        return 1

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
        return 1        

    # save end-entity certificate into PEM file
    try:
        with open(cert_out_path, "wb") as cert_f:
            cert_f.write(serial_cert)
    except Exception as e:
        print("Error with saving certificate:\n" + str(e))
        return 1
    
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
    
    return 0

def verify_certificate(certificate_path):
    # load end-entity certificate from PEM file
    try:
        with open(certificate_path, "rb") as cert_f:
            ee_certificate = x509.load_pem_x509_certificate(cert_f.read())
    except Exception as e:
        print("Error with loading end-entity certificate:\n" + str(e))
        return 1
    
    # load CA certificate from PEM file
    try:
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "AKRSign_data/", "ca_root_cert.pem"), "rb") as cert_f:
            ca_certificate = x509.load_pem_x509_certificate(cert_f.read())
    except Exception as e:
        print("Error with loading CA certificate:\n" + str(e))
        return 1

    # verify that end-entity cert has same issuer as CA cert subject and that signature is correct
    try:
        ee_certificate.verify_directly_issued_by(ca_certificate)
    except ValueError:
        print("Issuer name on the certificate does not match the subject name of the issuer or the signature algorithm is unsupported.")
        return 1
    except TypeError:
        print("Issuer does not have a supported public key type")
        return 1
    except InvalidSignature:
        return 1

    # verify that both certificates are valid (date)
    current_time = datetime.utcnow()
    if current_time < ee_certificate.not_valid_before:
        print("End-entity certificate is not valid yet")
        return 1
    elif current_time > ee_certificate.not_valid_before:
        print("End-entity certificate is expired")
        return 1
    if current_time < ca_certificate.not_valid_before:
        print("CA certificate is not valid yet")
        return 1
    elif current_time > ca_certificate.not_valid_before:
        print("CA certificate is expired")
        return 1
    
    # verify that CA certificate is actually marked as CA
    try:
        basic_contrains = ca_certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value()
        if not basic_contrains.ca:
            print("CA certificate is not marked as CA certificate in basic constrains")
            return 1
    except ExtensionNotFound:
        print("Basic constrain extension was not found in CA certificate. This extension is necessary for determining if CA certificate is actually CA certificate.")
        return 1
    
    # verify that CA certificate has key usage to sign other certificates
    try:
        key_usage = ca_certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value()
        if not key_usage.key_cert_sign:
            print("This CA certificate can not be used for signing other certificates")
            return 1
    except ExtensionNotFound:
        print("Key usage extension was not found in CA certificate. This extension is necessary for determining if CA certificate can be used to sign other certificates")
        return 1

    return 0

def main(args):
    if args.subcommand == "create_signature":
        create_signature(args.file, args.sig_out, args.private_key)
    elif args.subcommand == "verify_signature":
        verify_signature(args.file, args.signature, args.certificate)
    elif args.subcommand == "create_certificate":
        create_certificate(args.cert_out, args.private_key_out, args.pkcs12_out)
    elif args.subcommand == "verify_certificate":
        if verify_certificate(args.certificate) == 0:
            print("Signature is valid")
        else:
            print("Signature is invalid")

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
