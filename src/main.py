from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
import argparse
import sys
import ca

def create_signature(file_path, sig_out_path, private_key_path):
    pass

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
    pass

def main(args):
    if args.subcommand == "create_signature":
        create_signature(args.file, args.sig_out, args.private_key)
    elif args.subcommand == "verify_signature":
        verify_signature(args.file, args.signature, args.certificate)
    elif args.subcommand == "create_certificate":
        create_certificate(args.cert_out, args.private_key_out, args.pkcs12_out)
    elif args.subcommand == "verify_certificate":
        verify_certificate(args.certificate)
    
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
