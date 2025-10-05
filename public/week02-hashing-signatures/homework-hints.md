# Week 2 Homework Hints: Document Signature Verification

## 🎯 Quick Start Guide (5 hours total)

### Time Breakdown
- **Setup & Key Understanding**: 1 hour
- **Core Implementation**: 3 hours
- **CLI & Testing**: 1 hour

## 📋 Step-by-Step Implementation

### Step 1: Environment Setup (15 minutes)
```bash
# Install required library
pip install cryptography

# Create project structure
mkdir week02-doc-signer
cd week02-doc-signer
mkdir keys signatures

# Create main file
touch doc_signer.py
```

### Step 2: Understand RSA Signatures (30 minutes)

**Key Concepts to Grasp:**
- **Private Key**: Signs documents (keep secret!)
- **Public Key**: Verifies signatures (can share)
- **Hash**: Creates fingerprint of document
- **Signature**: Encrypted hash using private key

**Think of it like a wax seal**: Only you can create it (private key), but anyone can verify it's really yours (public key).

### Step 3: Copy and Modify Starter Code (15 minutes)

Start with the provided functions and add these essential components:

```python
import argparse
import sys
import os
from pathlib import Path

# Copy all the provided starter functions here

PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
SIGNATURES_DIR = "signatures"
```

### Step 4: Generate Key Pair First (30 minutes)

**Critical First Step**: You need keys before you can sign anything!

```python
def generate_keys():
    """Generate RSA key pair"""
    # Create keys directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Get public key
    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ Keys generated successfully!")
```

### Step 5: Implement Document Signing (45 minutes)

```python
def sign_document(document_path):
    """Sign a document and save signature"""
    try:
        # 1. Check if document exists
        if not os.path.exists(document_path):
            print(f"❌ Document not found: {document_path}")
            return False

        # 2. Load private key
        private_key = load_private_key()

        # 3. Read document content
        with open(document_path, 'rb') as f:
            document_data = f.read()

        # 4. Create signature
        signature = private_key.sign(
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 5. Save signature to file
        signature_path = f"{SIGNATURES_DIR}/{Path(document_path).name}.sig"
        os.makedirs(SIGNATURES_DIR, exist_ok=True)

        with open(signature_path, "wb") as f:
            f.write(signature)

        print(f"✅ Document signed: {signature_path}")
        return True

    except Exception as e:
        print(f"❌ Signing failed: {e}")
        return False
```

### Step 6: Implement Signature Verification (45 minutes)

```python
def verify_signature(document_path, signature_path):
    """Verify document signature"""
    try:
        # 1. Check if files exist
        if not os.path.exists(document_path):
            print(f"❌ Document not found: {document_path}")
            return False

        if not os.path.exists(signature_path):
            print(f"❌ Signature not found: {signature_path}")
            return False

        # 2. Load public key
        public_key = load_public_key()

        # 3. Read document and signature
        with open(document_path, 'rb') as f:
            document_data = f.read()

        with open(signature_path, 'rb') as f:
            signature = f.read()

        # 4. Verify signature
        public_key.verify(
            signature,
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("✅ Signature valid!")
        return True

    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return False
```

### Step 7: Document Hash Checking (30 minutes)

```python
def check_document_hash(document_path, expected_hash=None):
    """Calculate and optionally compare document hash"""
    try:
        if not os.path.exists(document_path):
            print(f"❌ Document not found: {document_path}")
            return False

        # Calculate current hash
        current_hash = calculate_hash(document_path)
        print(f"📊 Document hash: {current_hash}")

        if expected_hash:
            if current_hash == expected_hash:
                print("✅ Document unchanged!")
                return True
            else:
                print("⚠️ Document has been modified!")
                return False

        return True

    except Exception as e:
        print(f"❌ Hash calculation failed: {e}")
        return False
```

### Step 8: Command Line Interface (45 minutes)

```python
def main():
    parser = argparse.ArgumentParser(description="Document Signature Tool")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Generate keys command
    gen_parser = subparsers.add_parser('generate-keys', help='Generate key pair')

    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign document')
    sign_parser.add_argument('document', help='Document to sign')

    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify signature')
    verify_parser.add_argument('document', help='Document to verify')
    verify_parser.add_argument('signature', help='Signature file')

    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Calculate document hash')
    hash_parser.add_argument('document', help='Document to hash')

    args = parser.parse_args()

    # Execute commands
    if args.command == 'generate-keys':
        generate_keys()
    elif args.command == 'sign':
        sign_document(args.document)
    elif args.command == 'verify':
        verify_signature(args.document, args.signature)
    elif args.command == 'hash':
        check_document_hash(args.document)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: "No such file or directory" for keys
**Solution**: Run `generate-keys` command first!
```bash
python doc_signer.py generate-keys
```

### Issue: "InvalidSignature" exception
**Causes**:
- Document was modified after signing
- Wrong signature file
- Corrupted signature
**Solution**: Re-sign the document or check file paths

### Issue: Permission denied errors
**Solution**: Make sure you have write permissions in current directory

### Issue: "No module named 'cryptography'"
**Solution**: Install with `pip install cryptography`

## ✅ Testing Workflow

### Basic Test Sequence:
```bash
# 1. Generate keys (do this FIRST!)
python doc_signer.py generate-keys

# 2. Create a test document
echo "This is a test document" > test.txt

# 3. Sign the document
python doc_signer.py sign test.txt

# 4. Verify the signature
python doc_signer.py verify test.txt signatures/test.txt.sig

# 5. Check document hash
python doc_signer.py hash test.txt

# 6. Test tampering detection
echo "Modified content" > test.txt
python doc_signer.py verify test.txt signatures/test.txt.sig
# Should fail!
```

### Advanced Testing:
```bash
# Test with different file types
echo "Secret data" > secret.txt
python doc_signer.py sign secret.txt

# Test with binary files
python doc_signer.py sign doc_signer.py
python doc_signer.py verify doc_signer.py signatures/doc_signer.py.sig
```

## 📁 Expected File Structure
```
week02-doc-signer/
├── doc_signer.py              # Your implementation
├── keys/
│   ├── private_key.pem        # Generated private key
│   └── public_key.pem         # Generated public key
├── signatures/
│   ├── test.txt.sig           # Generated signatures
│   └── secret.txt.sig
├── test.txt                   # Test documents
├── secret.txt
└── README.txt                 # Usage instructions
```

## 🎯 Grading Focus Areas

1. **Signature Creation (10 points)**: Documents can be properly signed
2. **Signature Verification (10 points)**: Valid signatures pass, invalid fail
3. **Tamper Detection (5 points)**: Modified documents are detected

## 💡 Pro Tips

1. **Always Generate Keys First**: Most problems come from missing keys
2. **Test with Simple Files**: Start with plain text before trying complex files
3. **Check File Paths**: Use absolute paths if having trouble
4. **Understand the Error Messages**: Python cryptography errors are informative
5. **Binary vs Text Mode**: Always use 'rb'/'wb' for reading/writing signatures

## 🔍 Key Concepts to Understand

### Digital Signatures Provide:
- **Authentication**: Proves who signed it
- **Integrity**: Detects if document was changed
- **Non-repudiation**: Signer can't deny they signed it

### The Signature Process:
1. Hash the document (creates unique fingerprint)
2. Encrypt hash with private key (creates signature)
3. Anyone can decrypt signature with public key and compare hashes

## 🚀 Extension Ideas (Optional)

- Add timestamp to signatures
- Support signing multiple files at once
- Create signature verification reports
- Add certificate-style information to signatures

## ⏱️ Time Management Tips

- **Don't skip key generation**: It's required for everything else
- **Test each function separately**: Don't wait until the end
- **Focus on core functionality**: Get basic signing/verification working first
- **Save complex CLI features for last**

## 🔧 Debugging Helpers

**Check if keys exist:**
```python
def check_keys():
    private_exists = os.path.exists(PRIVATE_KEY_PATH)
    public_exists = os.path.exists(PUBLIC_KEY_PATH)
    print(f"Private key: {'✅' if private_exists else '❌'}")
    print(f"Public key: {'✅' if public_exists else '❌'}")
```

**Verify key loading:**
```python
try:
    private_key = load_private_key()
    public_key = load_public_key()
    print("✅ Keys loaded successfully")
except Exception as e:
    print(f"❌ Key loading failed: {e}")
```

Remember: Digital signatures are a fundamental security technology. Understanding this assignment will help you grasp how software updates, SSL certificates, and document signing systems work in the real world!