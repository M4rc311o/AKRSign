from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime

# generate private key
private_key = ec.generate_private_key(
    ec.SECP256R1()
)

public_key = private_key.public_key()

# create certificate builder for self-signed Root CA certificate
builder = x509.CertificateBuilder()

# subject information
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "BPC-AKR Certification Authority"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BPC-AKR"),
]))

# issure information
builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "BPC-AKR Certification Authority"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BPC-AKR"),
]))

# validity
builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))  # valid from yesterday
builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=(365 * 30)))  # valid for 30 years

# misc
builder = builder.serial_number(x509.random_serial_number())

# public key
builder = builder.public_key(public_key)

# constrains
builder = builder.add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True
)

builder = builder.add_extension(
    x509.KeyUsage(key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, digital_signature=False, encipher_only=False, decipher_only=False), critical=True
)

root_cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

# save CA private key
with open("CA_private_key.pem", "wb") as key_f:
    key_f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,                # save in .pem file
        format=serialization.PrivateFormat.PKCS8,           # save PKCS8 format
        encryption_algorithm=serialization.NoEncryption()   # save without encryption
    ))

# save CA Root certificate
with open("CA_root_cert.pem", "wb") as cert_f:
    cert_f.write(root_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ))
