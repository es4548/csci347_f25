import argparse
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

#  make key files
def ensure_keys_exist():
    os.makedirs("keys", exist_ok=True)
    private_key_path = "keys/private_key.pem"
    public_key_path = "keys/public_key.pem"

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("🔑 Generating new RSA key pair...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(public_key_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("✅ Keys saved in 'keys/' folder.")

# make sure keys are there
ensure_keys_exist()


def load_private_key(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Private key not found at {filepath}")
    with open(filepath, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Public key not found at {filepath}")
    with open(filepath, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def hash_document(filepath):
    with open(filepath, "rb") as f:
        file_bytes = f.read()
        return hashlib.sha256(file_bytes).digest()

#  Sign doc
def sign_document(document_path, private_key_path="keys/private_key.pem"):
    private_key = load_private_key(private_key_path)
    document_hash = hash_document(document_path)
    signature = private_key.sign(
        document_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    signature_path = f"{document_path}.sig"
    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)
    print(f"✅ Document signed! Signature saved as '{signature_path}'.")

# verify signature
def verify_signature(document_path, signature_path, public_key_path="keys/public_key.pem"):
    public_key = load_public_key(public_key_path)
    document_hash = hash_document(document_path)
    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()
    try:
        public_key.verify(
            signature,
            document_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        print("✅ Signature is valid.")
    except InvalidSignature:
        print("❌ Signature is invalid!")

# hash display
def print_document_hash(document_path):
    hash_value = hash_document(document_path)
    print(f"SHA-256 hash of '{document_path}': {hash_value.hex()}")

# CLI
def main():
    parser = argparse.ArgumentParser(description="Secure Document Signing System")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Sign a document")
    sign_parser.add_argument("document", help="Path to document to sign")

    verify_parser = subparsers.add_parser("verify", help="Verify a document signature")
    verify_parser.add_argument("document", help="Path to original document")
    verify_parser.add_argument("signature", help="Path to signature file")

    hash_parser = subparsers.add_parser("hash", help="Display document hash")
    hash_parser.add_argument("document", help="Path to document")

    args = parser.parse_args()

    if args.command == "sign":
        sign_document(args.document)
    elif args.command == "verify":
        verify_signature(args.document, args.signature)
    elif args.command == "hash":
        print_document_hash(args.document)

if __name__ == "__main__":
    main()
