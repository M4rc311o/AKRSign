from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import os
import datetime

class CertificateAuthorityError(Exception):
    pass

# make class singleton
class CertificateAuthority:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(CertificateAuthority, cls).__new__(cls)
            return cls.instance

    def __init__(self):
        self.ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "BPC-AKR Certification Authority"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BPC-AKR")
        ])
        self.year_validity = 5
        self.ca_private_key_path = "CA_keystore/ca_private_key.pem"
        self.ca_public_cert_path = "CA_keystore/ca_root_cert.pem"

        # load private key
        if os.path.isfile(self.ca_private_key_path):
            try:
                with open(self.ca_private_key_path, "rb") as key_f:
                    self.private_key = serialization.load_pem_private_key(
                        key_f.read(),
                        password=None
                    )
            except OSError as e:
                raise CertificateAuthorityError("Error with loading CA private key file: " + str(e))
        else:
            self.ca_gen_key_cert()

    # generate CA private key and self-signed certificate       
    def ca_gen_key_cert(self):
        # generate private key ECDSA 256b
        self.private_key = ec.generate_private_key(
            ec.SECP256R1()
        )

        # create certificate builder for self-signed Root CA certificate
        builder = x509.CertificateBuilder()

        # subject information
        builder = builder.subject_name(self.ca_name)

        # issure information
        builder = builder.issuer_name(self.ca_name)

        # validity
        builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))  # valid from yesterday
        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=(365 * 30)))  # valid for 30 years

        # misc
        builder = builder.serial_number(x509.random_serial_number())

        # subject public key
        builder = builder.public_key(self.private_key.public_key())

        # constrains
        # CA certificate = True
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

        # specify key usages (certificate can be used for signing other certificates and CRLs)
        builder = builder.add_extension(
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
        root_cert = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())

        # save CA private key
        try:
            with open(self.ca_private_key_path, "wb") as key_f:
                key_f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,                # save in .pem file
                    format=serialization.PrivateFormat.PKCS8,           # save PKCS8 format
                    encryption_algorithm=serialization.NoEncryption()   # save without encryption
                ))
        except OSError as e:
            raise CertificateAuthorityError("Error with saving CA private key file: " + str(e))

        # save CA Root certificate
        try:
            with open(self.ca_public_cert_path, "wb") as cert_f:
                cert_f.write(root_cert.public_bytes(
                    encoding=serialization.Encoding.PEM                 # save in .pem file
                ))
        except OSError as e:
            raise CertificateAuthorityError("Error with saving CA public certificate file: " + str(e))

    def handle_CSR(self, serialized_csr):
        csr = x509.load_pem_x509_csr(serialized_csr)                    # deserialize csr

        # check Certificate Signing Request Validity
        if not csr.is_signature_valid:
            raise CertificateAuthorityError("Certificate signing request is not valid")

        # HERE should CA also check if provided information are correct

        # create certificate builder for end-entity certificate
        builder = x509.CertificateBuilder()

        # subject information
        builder = builder.subject_name(csr.subject)

        # issuer information
        builder = builder.issuer_name(self.ca_name)

        # validity
        builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))  # valid from yesterday
        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=(365 * self.year_validity)))  # valid for 5 years

        # misc
        builder = builder.serial_number(x509.random_serial_number())

        # subject public key
        builder = builder.public_key(csr.public_key())

        # constrains
        # CA certificate = False
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

        # specify key usages (certificate can be used for verifying digital signatures)
        builder = builder.add_extension(
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
        end_entity_cert = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())

        # return serialized end entity certificate
        return end_entity_cert.public_bytes(encoding=serialization.Encoding.PEM)
