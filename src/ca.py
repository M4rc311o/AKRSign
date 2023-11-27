from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import warnings
import datetime
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
        self.issued_cert_dir = os.path.join(self.data_directory, "issued_certificates/")
        
        os.makedirs(self.data_directory, exist_ok=True)
        os.makedirs(os.path.join(self.data_directory, "issued_certificates"), exist_ok=True)

        # load CA private key
        if os.path.isfile(self.ca_key_and_cert_path):
            try:
                with open(self.ca_key_and_cert_path, "rb") as key_cert_f:
                    self.private_key, certificate, inter_cert = pkcs12.load_key_and_certificates(
                        key_cert_f.read(),
                        password=None
                    )
            except Exception as e:
                raise CertificateAuthorityError("Error with reading CAs PKCS #12 file: " + str(e))
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
        cert_builder = cert_builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))  # valid from yesterday
        cert_builder = cert_builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=(365 * 30)))  # valid for 30 years
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
            raise CertificateAuthorityError("Error with saving CAs PKCS #12 file: " + str(e))

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
        cert_builder = cert_builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))  # valid from yesterday
        cert_builder = cert_builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=(365 * self.year_validity)))  # valid for 5 years
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
