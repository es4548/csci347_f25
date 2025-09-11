# Week 2 Assignment: Document Signature Verification (Simplified)

**Due**: End of Week 2 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Submit Pull Request URL to Canvas
**Estimated Time**: 5 hours

## 🎯 Assignment Overview

Build a command-line tool that can verify digital signatures on documents. We'll provide pre-generated RSA keys and focus on understanding how signatures ensure document authenticity.

## 📋 Requirements

### Core Functionality (70 points)

Your signature verification tool must implement:

#### 1. Load Provided Keys (20 points)
- **Load RSA keys** from provided PEM files
- **Handle public and private keys**
- **Basic error handling** for missing files

#### 2. Document Operations (25 points)
- **Sign documents**: `sign_document(filepath, private_key)`
- **Verify signatures**: `verify_document(filepath, signature, public_key)`
- **Display verification results** clearly

#### 3. Hash Verification (25 points)
- **Calculate SHA-256 hashes** of documents
- **Compare document hashes** to detect changes
- **Report if document was modified** after signing

### Command-Line Interface (20 points)

Implement a simple CLI with these commands:

```bash
# Sign a document
python doc_signer.py sign <document>

# Verify a signature
python doc_signer.py verify <document> <signature>

# Check document hash
python doc_signer.py hash <document>
```

### Security Features (10 points)

- **Proper signature verification**
- **Clear error messages** for invalid signatures
- **Basic input validation**

## 🔧 Technical Specifications

### Provided Starter Code and Keys
```python
# starter_code.py - Copy this into your doc_signer.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import hashlib
import json
import os

# Pre-generated RSA keys (provided in keys/ directory)
def load_private_key(filepath='keys/private_key.pem'):
    """Load private key from PEM file"""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(), password=None
        )

def load_public_key(filepath='keys/public_key.pem'):
    """Load public key from PEM file"""
    with open(filepath, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()
```

### File Structure
```
doc_signer.py              # Your implementation
keys/                      # Provided keys
  ├── private_key.pem      # Pre-generated private key
  └── public_key.pem       # Pre-generated public key
signatures/                # Directory for signature files
README.txt                 # Usage instructions
```

## 📝 Implementation Guide

### 1. Use the Provided Functions
The starter code provides key loading and hash calculation. Use these in your implementation.

### 2. Implement Core Functions
```python
def sign_document(document_path):
    """Sign a document using the private key"""
    # Load private key using provided function
    # Read document content
    # Create signature using RSA with padding.PSS
    # Save signature to file
    
def verify_signature(document_path, signature_path):
    """Verify a document's signature"""
    # Load public key using provided function
    # Read document and signature
    # Verify using RSA
    # Return True if valid, False otherwise
    
def check_hash(document_path, original_hash):
    """Check if document has been modified"""
    # Calculate current hash using provided function
    # Compare with original hash
    # Report if modified
```

### 3. Simple Implementation Example

```python
import argparse
from pathlib import Path
import json

class SecureDocumentSigner:
    def __init__(self):
        self.key_manager = KeyManager()
        self.signer = DocumentSigner()
        self.monitor = IntegrityMonitor()
    
    def run_cli(self):
        parser = argparse.ArgumentParser(description="Secure Document Signing System")
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Generate keys command
        gen_parser = subparsers.add_parser('generate-keys', help='Generate new key pair')
        gen_parser.add_argument('--name', required=True, help='Signer name')
        gen_parser.add_argument('--password', help='Password for private key')
        
        # Sign command
        sign_parser = subparsers.add_parser('sign', help='Sign a document')
        sign_parser.add_argument('document', help='Document to sign')
        sign_parser.add_argument('--key', required=True, help='Private key file')
        
        # Verify command
        verify_parser = subparsers.add_parser('verify', help='Verify signature')
        verify_parser.add_argument('document', help='Document to verify')
        verify_parser.add_argument('signature', help='Signature file')
        verify_parser.add_argument('--key', required=True, help='Public key file')
        
        # Parse and execute
        args = parser.parse_args()
        
        if args.command == 'generate-keys':
            self.generate_keys(args.name, args.password)
        elif args.command == 'sign':
            self.sign_document(args.document, args.key)
        elif args.command == 'verify':
            self.verify_document(args.document, args.signature, args.key)
        else:
            parser.print_help()
    
    def generate_keys(self, name, password=None):
        """Generate and save key pair"""
        print(f"🔑 Generating keys for {name}...")
        # Implementation here
    
    def sign_document(self, document_path, key_path):
        """Sign a document"""
        print(f"✍️ Signing {document_path}...")
        # Implementation here
    
    def verify_document(self, document_path, signature_path, key_path):
        """Verify document signature"""
        print(f"🔍 Verifying {document_path}...")
        # Implementation here

if __name__ == "__main__":
    signer = SecureDocumentSigner()
    signer.run_cli()
```

## 💻 Example Usage

```bash
$ python doc_signer.py generate-keys --name "Alice Johnson"
🔑 Generating keys for Alice Johnson...
✅ Keys generated and saved to keys/
   Private key: keys/private_key.pem
   Public key: keys/public_key.pem

$ python doc_signer.py sign contract.pdf --key keys/private_key.pem
✍️ Signing contract.pdf...
📄 Document hash: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
✅ Document signed successfully
   Signature saved to: signatures/contract.pdf.sig

$ python doc_signer.py verify contract.pdf signatures/contract.pdf.sig --key keys/public_key.pem
🔍 Verifying contract.pdf...
✅ Signature valid!
   Signer: Alice Johnson
   Signed at: 2024-01-15 14:30:22
   Document integrity: Intact

$ python doc_signer.py check contract.pdf
📊 Integrity Check for contract.pdf
   Status: ✅ Unmodified since signing
   Original hash: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
   Current hash:  3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
   Last verified: 2024-01-15 14:35:00
```

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Points | Focus Area |
|-----------|---------|---------|
| **Signature Creation** | 10 | Documents can be signed using private key |
| **Signature Verification** | 10 | Signatures can be verified with public key |
| **Tamper Detection** | 5 | Modified documents are detected |

### Grade Scale
- **23-25 points (A)**: All features work correctly
- **20-22 points (B)**: Most features work, minor issues
- **18-19 points (C)**: Basic functionality works
- **15-17 points (D)**: Some features work
- **Below 15 points (F)**: Major problems

## 🚀 Optional Challenge

If you finish early (no bonus points):
- Add timestamp to signatures
- Support multiple file formats
- Create a signature validation report

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **Key generation works correctly**
- [ ] **Documents can be signed and verified**
- [ ] **Tampered documents are detected**
- [ ] **Integrity monitoring tracks all operations**
- [ ] **CLI provides all required commands**
- [ ] **Error handling covers edge cases**
- [ ] **Code is well-commented and organized**
- [ ] **README.txt explains usage and design**

### Testing Your Submission
```bash
# Test key generation
python doc_signer.py generate-keys --name "Test User"

# Test signing
echo "Test document content" > test.txt
python doc_signer.py sign test.txt --key keys/private_key.pem

# Test verification
python doc_signer.py verify test.txt signatures/test.txt.sig --key keys/public_key.pem

# Test tampering detection
echo "Modified content" > test.txt
python doc_signer.py verify test.txt signatures/test.txt.sig --key keys/public_key.pem
# Should report verification failure

# Test integrity monitoring
python doc_signer.py check test.txt
python doc_signer.py list-signed
```

## 📚 Resources and References

### Documentation
- **Cryptography library**: https://cryptography.io/en/latest/
- **Digital signatures**: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- **Python argparse**: https://docs.python.org/3/library/argparse.html

### Security Guidelines
- **NIST Digital Signature Standard**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- **PKI Best Practices**: https://www.keyfactor.com/resources/pki-best-practices/

## ❓ Frequently Asked Questions

**Q: Should I use RSA or ECDSA for signatures?**  
A: Use RSA for this assignment (it's in the tutorial), but ECDSA is also acceptable if you prefer.

**Q: How should I format the signature file?**  
A: Use JSON to store the signature, hash, timestamp, and metadata. This makes it easy to parse and verify.

**Q: Do I need to implement certificate validation?**  
A: No, that's a bonus feature. Focus on basic signature creation and verification first.

**Q: Should signatures be attached to documents or separate?**  
A: Keep them separate for this assignment. Real systems might embed them (like PDF signatures).

**Q: How do I handle large files efficiently?**  
A: Read and hash files in chunks (see tutorial example) rather than loading entire file into memory.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Can my system detect if someone modifies a signed document?**
2. **Are private keys properly protected?**
3. **Does verification clearly report success or failure?**
4. **Is my audit log tamper-evident?**
5. **Would this system work for real document signing needs?**

---

**Need Help?**
- Review the tutorial materials
- Check Canvas discussions for common issues
- Attend office hours for debugging help

**Good luck!** This assignment will give you practical experience with digital signatures and document integrity.