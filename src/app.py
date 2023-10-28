from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import sys
import ca

def request_certificate(private_key, public_key, common_name, country_name, locality_name, state_or_province_name, organization_name):
    akr_ca = ca.CertificateAuthority()
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name)
    ]))

    csr = csr_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    serial_cert = akr_ca.handle_csr(csr.public_bytes(
        encoding=serialization.Encoding.PEM
    ))
    return x509.load_pem_x509_certificate(serial_cert)

def main():
    return 0

if __name__ == "__main__":
    sys.exit(main())
