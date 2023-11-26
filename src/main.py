from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from Crypto.PublicKey import RSA
import os
import sys
import ca

app_cert_dir = "EE_store/"
file_to_sign = "test_file.txt"

def create_new_end_entity():
    common_name = input("Common name: ")
    country_name = input("Country name: ")
    locality_name = input("Locality name: ")
    state_or_province_name = input("State/province name: ")
    organization_name = input("Organization name: ")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    private_key.sign()

    akr_ca = ca.CertificateAuthority()
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
    certificate = x509.load_pem_x509_certificate(serial_cert)

    # save end-entity PKCS #12 file
    try:
        with open(os.path.join(app_cert_dir, f"{certificate.serial_number}.p12"), "wb") as key_cert_f:
            key_cert_f.write(pkcs12.serialize_key_and_certificates(
                name=certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.encode(),
                key=private_key,
                cert=certificate,
                cas=None,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except Exception as e:
        print("Error with saving new End-entity PKCS #12 file")

    return private_key

def create_signature(hash, private_key):

    pass

def main():
    # print end-entity signing options
    file_index = 0
    pkcs12_files = []
    for file_name in os.listdir(app_cert_dir):
        if file_name.endswith(".p12"):
            pkcs12_files.append(file_name)
            file_index += 1
            try:
                with open(os.path.join(app_cert_dir, file_name), "rb") as key_cert_f:
                    pkcs12_data = pkcs12.load_pkcs12(
                        key_cert_f.read(),
                        password=None
                    )
            except Exception as e:
                print("Error with loading already created end-entities :" + str(e))
            print(f"{file_index}.\t{pkcs12_data.cert.friendly_name.decode()}")
    print(f"\n{file_index + 1}\tCreate new End-entity")

    # read selected end-entity option
    while True:
        try:
            choice = int(input("\nChoose one of the options: "))
            if choice > 0 and choice <= (file_index + 1):
                break
            else:
                print("Invalid input. Please enter integer from range.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    if choice == (file_index + 1):
        create_new_end_entity()
    else:
        # HERE load private key
        pass

    # create file hash
    file_hash = hashes.Hash(hashes.SHA256())
    try:
        with open("test_file.txt", "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                file_hash.update(byte_block)
    except:
        print("Error with opening file for signing")
    file_hash = file_hash.finalize()



    return 0

if __name__ == "__main__":
    sys.exit(main())
