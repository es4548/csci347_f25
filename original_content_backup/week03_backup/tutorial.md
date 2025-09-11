# Week 3 Tutorial: PKI and Certificate Management

**Estimated Time**: 3-4 hours (broken into 5 modules)  
**Prerequisites**: Week 2 completed, understanding of digital signatures and public key cryptography

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (45 min): Created and analyzed X.509 certificates
2. **Module 2** (60 min): Built a complete Certificate Authority infrastructure  
3. **Module 3** (45 min): Generated Certificate Signing Requests and issued certificates
4. **Module 4** (60 min): Implemented certificate validation and trust chains
5. **Module 5** (30 min): Managed certificate lifecycle and revocation

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: X.509 Certificate Structure ✅ Checkpoint 1
- [ ] Module 2: Certificate Authority Setup ✅ Checkpoint 2
- [ ] Module 3: Certificate Signing Requests ✅ Checkpoint 3
- [ ] Module 4: Certificate Validation & Trust ✅ Checkpoint 4
- [ ] Module 5: Certificate Lifecycle Management ✅ Checkpoint 5

## 🧠 Prerequisites Quick Review

**New to PKI concepts?** Complete this 5-minute refresher before starting:

### Essential PKI Review
```python
# Public Key Infrastructure Components
# 1. Certificate Authority (CA) - Issues and manages certificates
# 2. Registration Authority (RA) - Verifies certificate requests
# 3. Certificate Repository - Stores and distributes certificates
# 4. Certificate Revocation List (CRL) - Lists revoked certificates

# X.509 Certificate contains:
# - Public key of certificate holder
# - Identity information (Subject)
# - Digital signature of issuing CA
# - Validity period (not before/after dates)
# - Certificate extensions (usage, constraints)
```

### Command Line Essentials
```bash
# OpenSSL basics (we'll use Python cryptography library instead)
openssl version                    # Check OpenSSL version
openssl x509 -in cert.pem -text   # View certificate contents
openssl req -new -key key.pem     # Create certificate signing request

# Directory structure we'll create
pki/
├── ca/                    # Certificate Authority files
├── certs/                 # Issued certificates
├── csr/                   # Certificate signing requests
└── crl/                   # Certificate revocation lists
```

**💡 Need more help?** 
- Watch: [PKI Explained in 10 minutes](https://www.youtube.com/watch?v=i-rtxrEz_E4) 
- Read: [X.509 Certificate Overview](https://tools.ietf.org/html/rfc5280)
- **Don't spend more than 10 minutes** - ask for help in Canvas discussions!

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Check cryptography library
python -c "from cryptography import x509; print('✅ X.509 support ready')"
python -c "from cryptography.hazmat.primitives import serialization; print('✅ Key serialization ready')"

# Create working directory
mkdir week3-pki
cd week3-pki
mkdir {ca,certs,csr,crl}
```

**⚠️ Problems with setup?** 
- Check [troubleshooting guide](../resources/troubleshooting.md)
- Post in Canvas discussions with your error message
- **Don't spend more than 15 minutes stuck** - get help!

---

## 📘 Module 1: X.509 Certificate Structure (45 minutes)

**Learning Objective**: Understand certificate format and create basic certificates

**What you'll build**: Certificate generator and parser that creates real X.509 certificates

### Step 1: Understanding Certificate Structure

Create `certificate_basics.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
from pathlib import Path

class CertificateBasics:
    """Learn X.509 certificate structure and generation"""
    
    def __init__(self):
        self.ca_dir = Path("ca")
        self.certs_dir = Path("certs")
        
    def create_private_key(self, key_size=2048):
        """Generate an RSA private key"""
        print(f"🔑 Generating {key_size}-bit RSA key...")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard public exponent
            key_size=key_size,
        )
        
        print(f"✅ Private key generated")
        print(f"📊 Key size: {private_key.key_size} bits")
        print(f"📊 Public exponent: {private_key.public_key().public_numbers().e}")
        
        return private_key
    
    def create_self_signed_certificate(self, private_key, common_name, 
                                     organization="Test Organization",
                                     country="US", days_valid=365):
        """Create a self-signed certificate (like a root CA)"""
        print(f"📜 Creating self-signed certificate for {common_name}...")
        
        # Build the certificate subject (who the certificate is for)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # For self-signed certificates, subject = issuer
        issuer = subject
        
        # Calculate validity period
        not_before = datetime.datetime.utcnow()
        not_after = not_before + datetime.timedelta(days=days_valid)
        
        # Generate a unique serial number
        serial_number = x509.random_serial_number()
        
        # Build the certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            not_before
        ).not_valid_after(
            not_after
        ).add_extension(
            # Mark as a Certificate Authority
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            # Define how the key can be used
            x509.KeyUsage(
                key_cert_sign=True,     # Can sign certificates
                crl_sign=True,          # Can sign CRLs
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            # Subject Key Identifier (unique ID for this key)
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(
            # Sign with the same private key (self-signed)
            private_key, 
            hashes.SHA256()
        )
        
        print(f"✅ Certificate created")
        print(f"📊 Serial number: {cert.serial_number}")
        print(f"📊 Valid from: {cert.not_valid_before}")
        print(f"📊 Valid until: {cert.not_valid_after}")
        print(f"📊 Subject: {cert.subject}")
        print(f"📊 Issuer: {cert.issuer}")
        
        return cert
    
    def analyze_certificate(self, certificate):
        """Analyze the contents of an X.509 certificate"""
        print("\n🔍 CERTIFICATE ANALYSIS")
        print("="*50)
        
        # Basic information
        print(f"📋 Basic Information:")
        print(f"   Serial Number: {certificate.serial_number}")
        print(f"   Version: {certificate.version}")
        print(f"   Signature Algorithm: {certificate.signature_algorithm_oid._name}")
        
        # Subject and Issuer
        print(f"\n👤 Subject (Certificate holder):")
        for attribute in certificate.subject:
            print(f"   {attribute.oid._name}: {attribute.value}")
            
        print(f"\n🏛️ Issuer (Certificate signer):")
        for attribute in certificate.issuer:
            print(f"   {attribute.oid._name}: {attribute.value}")
        
        # Validity period
        print(f"\n⏰ Validity Period:")
        print(f"   Not Before: {certificate.not_valid_before}")
        print(f"   Not After: {certificate.not_valid_after}")
        
        # Check if currently valid
        now = datetime.datetime.utcnow()
        is_valid = certificate.not_valid_before <= now <= certificate.not_valid_after
        print(f"   Currently Valid: {is_valid}")
        
        # Extensions
        print(f"\n🔧 Extensions:")
        for extension in certificate.extensions:
            print(f"   {extension.oid._name}: {extension.critical} (Critical: {extension.critical})")
            
            # Show specific extension details
            if isinstance(extension.value, x509.BasicConstraints):
                print(f"      CA: {extension.value.ca}")
                print(f"      Path Length: {extension.value.path_length}")
            elif isinstance(extension.value, x509.KeyUsage):
                usages = []
                if extension.value.digital_signature: usages.append("Digital Signature")
                if extension.value.key_cert_sign: usages.append("Certificate Signing")
                if extension.value.crl_sign: usages.append("CRL Signing")
                print(f"      Usage: {', '.join(usages) if usages else 'None'}")
    
    def save_certificate_and_key(self, certificate, private_key, name):
        """Save certificate and private key to files"""
        # Save certificate in PEM format
        cert_path = self.ca_dir / f"{name}.crt"
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"💾 Certificate saved: {cert_path}")
        
        # Save private key in PEM format
        key_path = self.ca_dir / f"{name}.key"
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # Unencrypted for demo
            ))
        print(f"🔑 Private key saved: {key_path}")
        
        return cert_path, key_path
    
    def load_certificate(self, cert_path):
        """Load a certificate from file"""
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            
        certificate = x509.load_pem_x509_certificate(cert_data)
        print(f"📂 Certificate loaded from {cert_path}")
        return certificate
    
    def demo_certificate_creation(self):
        """Demonstrate certificate creation and analysis"""
        print("🏗️ CERTIFICATE CREATION DEMO")
        print("="*50)
        
        # Step 1: Generate private key
        private_key = self.create_private_key()
        
        # Step 2: Create self-signed certificate
        certificate = self.create_self_signed_certificate(
            private_key=private_key,
            common_name="Test Root CA",
            organization="CSCI 347 Demo",
            days_valid=365
        )
        
        # Step 3: Analyze the certificate
        self.analyze_certificate(certificate)
        
        # Step 4: Save to files
        cert_path, key_path = self.save_certificate_and_key(
            certificate, private_key, "root-ca"
        )
        
        # Step 5: Load and verify we can read it back
        loaded_cert = self.load_certificate(cert_path)
        print(f"\n✅ Certificate round-trip successful")
        print(f"   Original serial: {certificate.serial_number}")
        print(f"   Loaded serial: {loaded_cert.serial_number}")
        print(f"   Match: {certificate.serial_number == loaded_cert.serial_number}")
        
        return certificate, private_key

# Demo the certificate basics
if __name__ == "__main__":
    cert_demo = CertificateBasics()
    certificate, private_key = cert_demo.demo_certificate_creation()
    
    print(f"\n💡 KEY CONCEPTS LEARNED:")
    print(f"   • X.509 certificates contain public keys and identity information")
    print(f"   • Self-signed certificates are signed by their own private key")
    print(f"   • Extensions define how certificates can be used")
    print(f"   • PEM format is the standard for certificate storage")
```

**Run it:**
```bash
python certificate_basics.py
```

**Expected Output:**
```
🏗️ CERTIFICATE CREATION DEMO
==================================================
🔑 Generating 2048-bit RSA key...
✅ Private key generated
📊 Key size: 2048 bits
📊 Public exponent: 65537
📜 Creating self-signed certificate for Test Root CA...
✅ Certificate created
📊 Serial number: 123456789...
📊 Valid from: 2024-XX-XX XX:XX:XX
📊 Valid until: 2025-XX-XX XX:XX:XX
📊 Subject: <Name(C=US,O=CSCI 347 Demo,CN=Test Root CA)>
📊 Issuer: <Name(C=US,O=CSCI 347 Demo,CN=Test Root CA)>

🔍 CERTIFICATE ANALYSIS
==================================================
[detailed certificate analysis output]
```

### Step 2: Understanding Different Certificate Types

Add this to your `certificate_basics.py`:

```python
def create_server_certificate(self, ca_cert, ca_private_key, server_name, 
                              alt_names=None, days_valid=90):
    """Create a server certificate signed by CA"""
    print(f"🌐 Creating server certificate for {server_name}...")
    
    # Generate new private key for the server
    server_private_key = self.create_private_key()
    
    # Build subject for server
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Server Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, server_name),
    ])
    
    # CA is the issuer
    issuer = ca_cert.subject
    
    # Validity period
    not_before = datetime.datetime.utcnow()
    not_after = not_before + datetime.timedelta(days=days_valid)
    
    # Subject Alternative Names (SANs) for additional hostnames/IPs
    san_list = [x509.DNSName(server_name)]
    if alt_names:
        for alt_name in alt_names:
            if alt_name.replace('.', '').replace(':', '').isdigit() or ':' in alt_name:
                # Looks like an IP address
                try:
                    san_list.append(x509.IPAddress(ipaddress.ip_address(alt_name)))
                except:
                    san_list.append(x509.DNSName(alt_name))
            else:
                san_list.append(x509.DNSName(alt_name))
    
    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).add_extension(
        # This is NOT a CA certificate
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # Server authentication usage
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,     # For TLS handshake
            content_commitment=False,
            key_encipherment=True,      # For RSA key exchange
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        # Extended Key Usage for TLS servers
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,  # TLS Web Server Authentication
        ]),
        critical=True,
    ).add_extension(
        # Subject Alternative Names
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        # Authority Key Identifier (links to CA)
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False,
    ).add_extension(
        # Subject Key Identifier
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False,
    ).sign(
        # Sign with CA's private key
        ca_private_key, 
        hashes.SHA256()
    )
    
    print(f"✅ Server certificate created")
    print(f"📊 Server: {server_name}")
    print(f"📊 Alternative names: {alt_names or 'None'}")
    print(f"📊 Valid for {days_valid} days")
    
    return cert, server_private_key

def demo_certificate_types(self):
    """Demonstrate different certificate types"""
    print("\n🎭 CERTIFICATE TYPES DEMO")
    print("="*50)
    
    # Create root CA
    print("\n1. Creating Root Certificate Authority...")
    ca_private_key = self.create_private_key()
    ca_certificate = self.create_self_signed_certificate(
        ca_private_key, "Demo Root CA", "CSCI 347"
    )
    
    # Create server certificate
    print("\n2. Creating Server Certificate...")
    server_cert, server_key = self.create_server_certificate(
        ca_certificate, ca_private_key, 
        "www.example.com",
        alt_names=["example.com", "api.example.com", "127.0.0.1"]
    )
    
    # Save all certificates
    self.save_certificate_and_key(ca_certificate, ca_private_key, "demo-root-ca")
    self.save_certificate_and_key(server_cert, server_key, "demo-server")
    
    # Analyze both certificates
    print("\n📋 ROOT CA ANALYSIS:")
    self.analyze_certificate(ca_certificate)
    
    print("\n📋 SERVER CERTIFICATE ANALYSIS:")
    self.analyze_certificate(server_cert)
    
    return ca_certificate, ca_private_key, server_cert, server_key

# Add this to the main section
if __name__ == "__main__":
    cert_demo = CertificateBasics()
    
    # Basic demo
    cert_demo.demo_certificate_creation()
    
    # Advanced demo
    cert_demo.demo_certificate_types()
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **Certificate Structure**: X.509 certificates contain public key, identity, and signature
2. **Self-signed vs CA-signed**: Root CAs are self-signed, others are signed by CAs
3. **Extensions**: Define certificate usage (CA, server auth, client auth, etc.)
4. **Subject vs Issuer**: Subject is who owns the cert, Issuer is who signed it

### 🛤️ Choose Your Learning Path

**Struggling with the code above?** Try the **Guided Path**:

#### Guided Path: Build It Step by Step
Start with just key generation:

```python
# Step 1: Just generate a key
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
print("Key generated!", private_key.key_size)
```

Then add certificate creation:

```python
# Step 2: Create basic certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    12345
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=1)
).sign(private_key, hashes.SHA256())

print("Certificate created!", cert.subject)
```

**🎯 Once this works, try the full example again!**

#### Advanced Path: Professional Development Extensions

**Security Engineering Challenges:**
- **Implement certificate templates** - Create reusable certificate profiles
- **Add certificate policies** - Implement policy OIDs and constraints  
- **Hardware Security Module integration** - Simulate HSM key storage
- **Certificate transparency logs** - Implement CT log submission

**Industry Scenario Extensions:**
```python
# Challenge: Implement enterprise certificate management
class EnterpriseCertificateManager:
    def __init__(self):
        self.templates = {}
        self.policies = {}
    
    def create_certificate_template(self, template_name, extensions):
        # TODO: Implement certificate templates
        # Requirements:
        # - Reusable configuration for common cert types
        # - Policy constraints and validation
        # - Automatic extension application
        pass
    
    def validate_certificate_request(self, csr):
        # TODO: Implement CSR validation
        # Requirements:
        # - Policy compliance checking
        # - Identity verification
        # - Extension validation
        pass
```

### ✅ Checkpoint 1 Complete!

**Before continuing, you should be able to:**
- ✅ Generate RSA key pairs
- ✅ Create self-signed certificates
- ✅ Understand certificate extensions
- ✅ Save/load certificates in PEM format
- ✅ Analyze certificate contents

**Still stuck?** 
- Post your error message in Canvas discussions
- Schedule office hours 
- **Don't spend more than 60 minutes on Module 1**

---

## 📘 Module 2: Certificate Authority Infrastructure (60 minutes)

**Learning Objective**: Build a complete Certificate Authority that can issue and manage certificates

**What you'll build**: Multi-tier CA system with root and intermediate CAs

### Step 1: Certificate Authority Class

Create `certificate_authority.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import json
import os
from pathlib import Path

class CertificateAuthority:
    """A complete Certificate Authority implementation"""
    
    def __init__(self, ca_name, base_dir="pki"):
        self.ca_name = ca_name
        self.base_dir = Path(base_dir)
        self.ca_dir = self.base_dir / "ca"
        self.certs_dir = self.base_dir / "certs"
        self.csr_dir = self.base_dir / "csr"
        self.crl_dir = self.base_dir / "crl"
        
        # Create directories
        for directory in [self.ca_dir, self.certs_dir, self.csr_dir, self.crl_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Certificate serial number tracking
        self.serial_file = self.ca_dir / "serial.txt"
        self.issued_certs = self.ca_dir / "issued.json"
        
        # CA certificate and key paths
        self.ca_cert_path = self.ca_dir / "ca.crt"
        self.ca_key_path = self.ca_dir / "ca.key"
        
        # Load CA if exists
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self.load_ca()
        else:
            self.ca_certificate = None
            self.ca_private_key = None
    
    def initialize_ca(self, country="US", organization="Test Organization", 
                     key_size=2048, days_valid=3650):
        """Initialize a new Certificate Authority"""
        print(f"🏛️ Initializing Certificate Authority: {self.ca_name}")
        print(f"📁 CA Directory: {self.ca_dir}")
        
        # Generate CA private key
        print(f"🔑 Generating CA private key ({key_size} bits)...")
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Create CA certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        # For root CA, subject = issuer
        issuer = subject
        
        # Set validity period
        not_before = datetime.datetime.utcnow()
        not_after = not_before + datetime.timedelta(days=days_valid)
        
        print(f"📜 Creating CA certificate...")
        print(f"   Valid from: {not_before.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Valid until: {not_after.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Build CA certificate
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            1  # Root CA gets serial number 1
        ).not_valid_before(
            not_before
        ).not_valid_after(
            not_after
        ).add_extension(
            # This is a CA certificate
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            # CA key usage
            x509.KeyUsage(
                key_cert_sign=True,     # Can sign certificates
                crl_sign=True,          # Can sign CRLs
                digital_signature=True, # Can create digital signatures
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            # Subject Key Identifier
            x509.SubjectKeyIdentifier.from_public_key(self.ca_private_key.public_key()),
            critical=False,
        ).sign(
            self.ca_private_key, 
            hashes.SHA256()
        )
        
        # Save CA certificate and key
        self._save_ca_files()
        
        # Initialize serial number tracking
        self._initialize_serial()
        
        print(f"✅ Certificate Authority initialized successfully")
        print(f"📊 CA Certificate Serial: {self.ca_certificate.serial_number}")
        print(f"📊 CA Subject: {self.ca_certificate.subject}")
        
        return self.ca_certificate
    
    def load_ca(self):
        """Load existing CA certificate and key"""
        print(f"📂 Loading existing CA: {self.ca_name}")
        
        # Load certificate
        with open(self.ca_cert_path, "rb") as f:
            cert_data = f.read()
        self.ca_certificate = x509.load_pem_x509_certificate(cert_data)
        
        # Load private key
        with open(self.ca_key_path, "rb") as f:
            key_data = f.read()
        self.ca_private_key = serialization.load_pem_private_key(
            key_data, password=None
        )
        
        print(f"✅ CA loaded successfully")
        print(f"📊 CA Subject: {self.ca_certificate.subject}")
        print(f"📊 CA Valid Until: {self.ca_certificate.not_valid_after}")
    
    def _save_ca_files(self):
        """Save CA certificate and private key to files"""
        # Save certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        
        # Save private key (unencrypted for demo)
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"💾 CA files saved:")
        print(f"   Certificate: {self.ca_cert_path}")
        print(f"   Private Key: {self.ca_key_path}")
    
    def _initialize_serial(self):
        """Initialize serial number tracking"""
        # Start serial numbers at 2 (CA uses 1)
        with open(self.serial_file, "w") as f:
            f.write("2")
        
        # Initialize issued certificates tracking
        with open(self.issued_certs, "w") as f:
            json.dump({}, f)
        
        print(f"📋 Serial number tracking initialized")
    
    def _get_next_serial(self):
        """Get next available serial number"""
        if not self.serial_file.exists():
            self._initialize_serial()
        
        with open(self.serial_file, "r") as f:
            serial = int(f.read().strip())
        
        # Increment for next use
        with open(self.serial_file, "w") as f:
            f.write(str(serial + 1))
        
        return serial
    
    def issue_certificate(self, subject_name, public_key, 
                         cert_type="server", alt_names=None, days_valid=90):
        """Issue a new certificate signed by this CA"""
        if not self.ca_certificate or not self.ca_private_key:
            raise RuntimeError("CA not initialized. Call initialize_ca() first.")
        
        print(f"📜 Issuing {cert_type} certificate for: {subject_name}")
        
        # Get next serial number
        serial_number = self._get_next_serial()
        
        # Build certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        # CA is the issuer
        issuer = self.ca_certificate.subject
        
        # Set validity period
        not_before = datetime.datetime.utcnow()
        not_after = not_before + datetime.timedelta(days=days_valid)
        
        # Start building certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            serial_number
        ).not_valid_before(
            not_before
        ).not_valid_after(
            not_after
        )
        
        # Add extensions based on certificate type
        if cert_type == "server":
            cert_builder = self._add_server_extensions(cert_builder, subject_name, alt_names)
        elif cert_type == "client":
            cert_builder = self._add_client_extensions(cert_builder)
        elif cert_type == "intermediate_ca":
            cert_builder = self._add_intermediate_ca_extensions(cert_builder)
        
        # Add common extensions
        cert_builder = cert_builder.add_extension(
            # Authority Key Identifier (links to issuing CA)
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.ca_private_key.public_key()
            ),
            critical=False,
        ).add_extension(
            # Subject Key Identifier
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        
        # Sign the certificate
        certificate = cert_builder.sign(
            self.ca_private_key,
            hashes.SHA256()
        )
        
        # Record the issued certificate
        self._record_issued_certificate(certificate, cert_type)
        
        print(f"✅ Certificate issued")
        print(f"📊 Serial Number: {serial_number}")
        print(f"📊 Type: {cert_type}")
        print(f"📊 Valid for: {days_valid} days")
        
        return certificate
    
    def _add_server_extensions(self, cert_builder, server_name, alt_names):
        """Add extensions for server certificates"""
        # Basic constraints - not a CA
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        
        # Key usage for servers
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,     # For TLS handshake
                content_commitment=False,
                key_encipherment=True,      # For RSA key exchange
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        # Extended key usage
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
        
        # Subject Alternative Names
        san_list = [x509.DNSName(server_name)]
        if alt_names:
            for alt_name in alt_names:
                san_list.append(x509.DNSName(alt_name))
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        
        return cert_builder
    
    def _add_client_extensions(self, cert_builder):
        """Add extensions for client certificates"""
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
        
        return cert_builder
    
    def _add_intermediate_ca_extensions(self, cert_builder):
        """Add extensions for intermediate CA certificates"""
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),  # Can issue certs but not sub-CAs
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        return cert_builder
    
    def _record_issued_certificate(self, certificate, cert_type):
        """Record issued certificate in tracking database"""
        # Load existing records
        if self.issued_certs.exists():
            with open(self.issued_certs, "r") as f:
                records = json.load(f)
        else:
            records = {}
        
        # Add new record
        serial_str = str(certificate.serial_number)
        records[serial_str] = {
            "serial_number": certificate.serial_number,
            "subject": str(certificate.subject),
            "type": cert_type,
            "issued_date": certificate.not_valid_before.isoformat(),
            "expiry_date": certificate.not_valid_after.isoformat(),
            "status": "active"
        }
        
        # Save records
        with open(self.issued_certs, "w") as f:
            json.dump(records, f, indent=2)
    
    def list_issued_certificates(self):
        """List all certificates issued by this CA"""
        if not self.issued_certs.exists():
            print("📋 No certificates have been issued yet")
            return []
        
        with open(self.issued_certs, "r") as f:
            records = json.load(f)
        
        print(f"📋 Certificates issued by {self.ca_name}:")
        print(f"{'Serial':<12} {'Subject':<30} {'Type':<12} {'Status':<8} {'Expires':<12}")
        print("-" * 80)
        
        for serial, cert_info in records.items():
            expiry = datetime.datetime.fromisoformat(cert_info['expiry_date'])
            print(f"{serial:<12} {cert_info['subject'][:28]:<30} {cert_info['type']:<12} "
                  f"{cert_info['status']:<8} {expiry.strftime('%Y-%m-%d'):<12}")
        
        return records
    
    def get_ca_info(self):
        """Get information about this CA"""
        if not self.ca_certificate:
            return "CA not initialized"
        
        info = {
            "name": self.ca_name,
            "subject": str(self.ca_certificate.subject),
            "serial_number": self.ca_certificate.serial_number,
            "not_before": self.ca_certificate.not_valid_before,
            "not_after": self.ca_certificate.not_valid_after,
            "is_ca": True,
            "key_size": self.ca_private_key.key_size
        }
        
        return info

# Demo the Certificate Authority
if __name__ == "__main__":
    print("🏛️ CERTIFICATE AUTHORITY DEMO")
    print("="*50)
    
    # Initialize a new CA
    ca = CertificateAuthority("CSCI 347 Demo CA")
    ca_cert = ca.initialize_ca(
        country="US",
        organization="CSCI 347 Class",
        days_valid=365  # Valid for 1 year
    )
    
    # Generate some keys for demonstration
    print("\n🔑 Generating keys for demo certificates...")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Issue server certificate
    print("\n🌐 Issuing server certificate...")
    server_cert = ca.issue_certificate(
        subject_name="demo.example.com",
        public_key=server_key.public_key(),
        cert_type="server",
        alt_names=["www.demo.example.com", "api.demo.example.com"],
        days_valid=90
    )
    
    # Issue client certificate
    print("\n👤 Issuing client certificate...")
    client_cert = ca.issue_certificate(
        subject_name="john.doe@example.com",
        public_key=client_key.public_key(),
        cert_type="client",
        days_valid=30
    )
    
    # Show issued certificates
    print("\n📋 Certificate Inventory:")
    ca.list_issued_certificates()
    
    # Show CA information
    print("\n🏛️ CA Information:")
    ca_info = ca.get_ca_info()
    for key, value in ca_info.items():
        print(f"   {key}: {value}")
```

**Run it:**
```bash
python certificate_authority.py
```

### Step 2: Intermediate Certificate Authority

Add support for intermediate CAs (CAs signed by other CAs):

```python
def create_intermediate_ca(self, intermediate_name, days_valid=1095):
    """Create an intermediate CA certificate signed by this root CA"""
    print(f"🏛️ Creating intermediate CA: {intermediate_name}")
    
    # Generate key for intermediate CA
    intermediate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Issue intermediate CA certificate
    intermediate_cert = self.issue_certificate(
        subject_name=intermediate_name,
        public_key=intermediate_key.public_key(),
        cert_type="intermediate_ca",
        days_valid=days_valid
    )
    
    # Create new CA instance for the intermediate
    intermediate_ca = CertificateAuthority(
        ca_name=intermediate_name,
        base_dir=self.base_dir / "intermediate"
    )
    
    # Set up the intermediate CA
    intermediate_ca.ca_certificate = intermediate_cert
    intermediate_ca.ca_private_key = intermediate_key
    intermediate_ca._save_ca_files()
    intermediate_ca._initialize_serial()
    
    print(f"✅ Intermediate CA created: {intermediate_name}")
    
    return intermediate_ca

def demo_multi_tier_ca(self):
    """Demonstrate multi-tier CA hierarchy"""
    print("\n🏗️ MULTI-TIER CA HIERARCHY DEMO")
    print("="*50)
    
    # Create intermediate CA
    intermediate_ca = self.create_intermediate_ca("CSCI 347 Intermediate CA")
    
    # Issue a certificate from the intermediate CA
    end_user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    end_user_cert = intermediate_ca.issue_certificate(
        subject_name="secure.example.com",
        public_key=end_user_key.public_key(),
        cert_type="server",
        days_valid=30
    )
    
    print("\n📊 Certificate Chain Created:")
    print(f"   Root CA: {self.ca_certificate.subject}")
    print(f"   Intermediate CA: {intermediate_ca.ca_certificate.subject}")
    print(f"   End Entity: {end_user_cert.subject}")
    
    return intermediate_ca, end_user_cert

# Add to the main demo
if __name__ == "__main__":
    # ... existing demo code ...
    
    # Multi-tier CA demo
    intermediate_ca, end_cert = ca.demo_multi_tier_ca()
```

### ✅ Checkpoint 2 Complete!

**Before continuing, you should be able to:**
- ✅ Initialize a Certificate Authority
- ✅ Track serial numbers and issued certificates
- ✅ Issue different types of certificates (server, client, intermediate CA)
- ✅ Create multi-tier CA hierarchies
- ✅ Save and load CA state

---

## 📘 Module 3: Certificate Signing Requests (45 minutes)

**Learning Objective**: Generate and process Certificate Signing Requests (CSRs)

**What you'll build**: CSR generation and validation system

### Step 1: CSR Management System

Create `csr_manager.py`:

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
from pathlib import Path

class CSRManager:
    """Manage Certificate Signing Requests"""
    
    def __init__(self, csr_dir="pki/csr"):
        self.csr_dir = Path(csr_dir)
        self.csr_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_csr(self, common_name, organization="Test Organization", 
                    country="US", email=None, alt_names=None, key_size=2048):
        """Generate a Certificate Signing Request"""
        print(f"📝 Generating CSR for: {common_name}")
        
        # Generate private key for the requestor
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        print(f"🔑 Generated {key_size}-bit private key")
        
        # Build the subject name
        subject_components = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        
        if email:
            subject_components.append(
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
            )
        
        subject = x509.Name(subject_components)
        
        # Start building the CSR
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Add Subject Alternative Names if provided
        if alt_names:
            san_list = []
            for alt_name in alt_names:
                if self._is_ip_address(alt_name):
                    san_list.append(x509.IPAddress(ipaddress.ip_address(alt_name)))
                else:
                    san_list.append(x509.DNSName(alt_name))
            
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        # Add key usage extension (what the key will be used for)
        csr_builder = csr_builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Add extended key usage (specific purposes)
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,  # TLS server
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS client
            ]),
            critical=False
        )
        
        # Sign the CSR with the private key
        csr = csr_builder.sign(private_key, hashes.SHA256())
        
        print(f"✅ CSR generated")
        print(f"📊 Subject: {csr.subject}")
        print(f"📊 Extensions: {len(csr.extensions)}")
        
        return csr, private_key
    
    def _is_ip_address(self, value):
        """Check if a string is an IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def save_csr(self, csr, private_key, filename_base):
        """Save CSR and private key to files"""
        # Save CSR
        csr_path = self.csr_dir / f"{filename_base}.csr"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        
        # Save private key
        key_path = self.csr_dir / f"{filename_base}.key"
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print(f"💾 Files saved:")
        print(f"   CSR: {csr_path}")
        print(f"   Private Key: {key_path}")
        
        return csr_path, key_path
    
    def load_csr(self, csr_path):
        """Load a CSR from file"""
        with open(csr_path, "rb") as f:
            csr_data = f.read()
        
        csr = x509.load_pem_x509_csr(csr_data)
        print(f"📂 CSR loaded from {csr_path}")
        return csr
    
    def analyze_csr(self, csr):
        """Analyze a Certificate Signing Request"""
        print("\n🔍 CSR ANALYSIS")
        print("="*50)
        
        # Basic information
        print(f"📋 Subject: {csr.subject}")
        print(f"📋 Signature Algorithm: {csr.signature_algorithm_oid._name}")
        
        # Public key information
        public_key = csr.public_key()
        if hasattr(public_key, 'key_size'):  # RSA key
            print(f"🔑 Key Type: RSA")
            print(f"🔑 Key Size: {public_key.key_size} bits")
            print(f"🔑 Public Exponent: {public_key.public_numbers().e}")
        
        # Extensions
        print(f"\n🔧 Extensions ({len(csr.extensions)}):")
        for ext in csr.extensions:
            print(f"   {ext.oid._name}: Critical={ext.critical}")
            
            if isinstance(ext.value, x509.SubjectAlternativeName):
                print(f"      Alternative Names:")
                for name in ext.value:
                    print(f"        - {name}")
            
            elif isinstance(ext.value, x509.KeyUsage):
                usages = []
                if ext.value.digital_signature: usages.append("Digital Signature")
                if ext.value.key_encipherment: usages.append("Key Encipherment")
                if ext.value.key_cert_sign: usages.append("Certificate Signing")
                print(f"      Key Usage: {', '.join(usages)}")
            
            elif isinstance(ext.value, x509.ExtendedKeyUsage):
                purposes = []
                for usage in ext.value:
                    purposes.append(usage._name)
                print(f"      Extended Usage: {', '.join(purposes)}")
    
    def validate_csr(self, csr):
        """Validate a CSR for policy compliance"""
        print("\n🔍 CSR VALIDATION")
        print("="*40)
        
        issues = []
        
        # Check subject has required fields
        subject_dict = {attr.oid: attr.value for attr in csr.subject}
        
        if NameOID.COMMON_NAME not in subject_dict:
            issues.append("❌ Missing Common Name (CN)")
        else:
            print(f"✅ Common Name present: {subject_dict[NameOID.COMMON_NAME]}")
        
        if NameOID.ORGANIZATION_NAME not in subject_dict:
            issues.append("⚠️ Missing Organization (O)")
        else:
            print(f"✅ Organization present: {subject_dict[NameOID.ORGANIZATION_NAME]}")
        
        # Check key strength
        public_key = csr.public_key()
        if hasattr(public_key, 'key_size'):
            if public_key.key_size < 2048:
                issues.append(f"❌ Key size too small: {public_key.key_size} bits (minimum 2048)")
            else:
                print(f"✅ Key size adequate: {public_key.key_size} bits")
        
        # Check signature validity
        try:
            # Verify CSR self-signature
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                csr.signature_hash_algorithm
            )
            print("✅ CSR signature valid")
        except Exception as e:
            issues.append(f"❌ Invalid CSR signature: {e}")
        
        # Summary
        if issues:
            print(f"\n❌ CSR VALIDATION FAILED:")
            for issue in issues:
                print(f"   {issue}")
            return False
        else:
            print(f"\n✅ CSR VALIDATION PASSED")
            return True
    
    def demo_csr_workflow(self):
        """Demonstrate complete CSR workflow"""
        print("📝 CSR WORKFLOW DEMO")
        print("="*50)
        
        # 1. Generate CSR for a web server
        print("\n1. Generating server CSR...")
        server_csr, server_key = self.generate_csr(
            common_name="secure.example.com",
            organization="Example Corp",
            email="admin@example.com",
            alt_names=["www.secure.example.com", "api.secure.example.com", "127.0.0.1"]
        )
        
        # 2. Save CSR files
        print("\n2. Saving CSR files...")
        csr_path, key_path = self.save_csr(server_csr, server_key, "server-example")
        
        # 3. Load and analyze CSR
        print("\n3. Loading and analyzing CSR...")
        loaded_csr = self.load_csr(csr_path)
        self.analyze_csr(loaded_csr)
        
        # 4. Validate CSR
        print("\n4. Validating CSR...")
        is_valid = self.validate_csr(loaded_csr)
        
        return server_csr, server_key, is_valid

# Demo CSR management
if __name__ == "__main__":
    csr_manager = CSRManager()
    csr, key, valid = csr_manager.demo_csr_workflow()
    
    print(f"\n💡 KEY CONCEPTS LEARNED:")
    print(f"   • CSRs contain public key and identity information")
    print(f"   • CSRs are self-signed to prove possession of private key")
    print(f"   • Extensions in CSRs request specific certificate features")
    print(f"   • CSRs must be validated before certificate issuance")
```

**Run it:**
```bash
python csr_manager.py
```

### Step 2: Integrate CSR Processing with CA

Add CSR processing methods to your `CertificateAuthority` class:

```python
# Add these methods to the CertificateAuthority class

def process_csr(self, csr_path, cert_type="server", days_valid=90):
    """Process a CSR and issue a certificate"""
    print(f"📝 Processing CSR: {csr_path}")
    
    # Load CSR
    with open(csr_path, "rb") as f:
        csr_data = f.read()
    csr = x509.load_pem_x509_csr(csr_data)
    
    # Validate CSR first
    if not self._validate_csr_for_issuance(csr):
        raise ValueError("CSR validation failed")
    
    # Extract subject name for certificate
    common_name = None
    for attribute in csr.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            common_name = attribute.value
            break
    
    if not common_name:
        raise ValueError("CSR missing Common Name")
    
    # Extract SANs from CSR
    alt_names = []
    for extension in csr.extensions:
        if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            for name in extension.value:
                if isinstance(name, x509.DNSName):
                    alt_names.append(name.value)
    
    # Issue certificate using CSR's public key
    certificate = self.issue_certificate(
        subject_name=common_name,
        public_key=csr.public_key(),
        cert_type=cert_type,
        alt_names=alt_names if alt_names else None,
        days_valid=days_valid
    )
    
    # Save certificate
    cert_filename = common_name.replace(".", "_").replace("*", "wildcard")
    cert_path = self.certs_dir / f"{cert_filename}.crt"
    
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"💾 Certificate saved: {cert_path}")
    
    return certificate, cert_path

def _validate_csr_for_issuance(self, csr):
    """Validate CSR meets CA policy requirements"""
    print("🔍 Validating CSR for certificate issuance...")
    
    # Check signature
    try:
        public_key = csr.public_key()
        public_key.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            csr.signature_hash_algorithm
        )
        print("✅ CSR signature valid")
    except Exception:
        print("❌ CSR signature invalid")
        return False
    
    # Check key strength
    if hasattr(public_key, 'key_size'):
        if public_key.key_size < 2048:
            print(f"❌ Key size too small: {public_key.key_size} bits")
            return False
        print(f"✅ Key size adequate: {public_key.key_size} bits")
    
    # Check subject
    has_cn = any(attr.oid == NameOID.COMMON_NAME for attr in csr.subject)
    if not has_cn:
        print("❌ Missing Common Name in subject")
        return False
    print("✅ Subject validation passed")
    
    return True

def demo_csr_integration(self):
    """Demo CSR processing integration"""
    print("\n🔄 CSR INTEGRATION DEMO")
    print("="*50)
    
    # Generate a CSR
    from csr_manager import CSRManager
    csr_mgr = CSRManager()
    
    csr, private_key = csr_mgr.generate_csr(
        common_name="integration.example.com",
        organization="Test Integration",
        alt_names=["www.integration.example.com"]
    )
    
    # Save CSR
    csr_path, key_path = csr_mgr.save_csr(csr, private_key, "integration-test")
    
    # Process CSR with CA
    certificate, cert_path = self.process_csr(csr_path, "server", 60)
    
    print(f"\n✅ Complete CSR-to-Certificate workflow successful")
    print(f"   CSR: {csr_path}")
    print(f"   Certificate: {cert_path}")
    print(f"   Private Key: {key_path}")
    
    return certificate, cert_path, key_path
```

### ✅ Checkpoint 3 Complete!

**Before continuing, you should be able to:**
- ✅ Generate Certificate Signing Requests (CSRs)
- ✅ Add extensions to CSRs (SANs, key usage, etc.)
- ✅ Validate CSRs for policy compliance
- ✅ Process CSRs and issue certificates
- ✅ Complete CSR-to-certificate workflow

---

## 📘 Module 4: Certificate Validation and Trust Chains (60 minutes)

**Learning Objective**: Implement certificate validation and trust chain verification

**What you'll build**: Certificate validator that checks trust chains, expiration, and revocation

### Step 1: Certificate Validator

Create `certificate_validator.py`:

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from pathlib import Path
from typing import List, Tuple, Optional

class CertificateValidator:
    """Validate certificates and certificate chains"""
    
    def __init__(self, trusted_ca_dir="pki/ca"):
        self.trusted_ca_dir = Path(trusted_ca_dir)
        self.trusted_cas = self._load_trusted_cas()
    
    def _load_trusted_cas(self) -> List[x509.Certificate]:
        """Load all trusted CA certificates"""
        trusted_cas = []
        
        if not self.trusted_ca_dir.exists():
            return trusted_cas
        
        for cert_file in self.trusted_ca_dir.glob("*.crt"):
            try:
                with open(cert_file, "rb") as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
                trusted_cas.append(cert)
                print(f"📂 Loaded trusted CA: {cert.subject}")
            except Exception as e:
                print(f"⚠️ Failed to load {cert_file}: {e}")
        
        return trusted_cas
    
    def validate_certificate(self, certificate: x509.Certificate, 
                           intermediate_certs: List[x509.Certificate] = None,
                           check_revocation: bool = False) -> Tuple[bool, List[str]]:
        """Validate a certificate against trusted CAs"""
        print(f"🔍 Validating certificate: {certificate.subject}")
        
        errors = []
        
        # 1. Check certificate validity period
        now = datetime.datetime.utcnow()
        if certificate.not_valid_before > now:
            errors.append(f"Certificate not yet valid (starts {certificate.not_valid_before})")
        
        if certificate.not_valid_after < now:
            errors.append(f"Certificate expired (expired {certificate.not_valid_after})")
        
        if certificate.not_valid_before <= now <= certificate.not_valid_after:
            print("✅ Certificate is within validity period")
        
        # 2. Build and verify certificate chain
        chain_valid, chain_errors = self._verify_certificate_chain(
            certificate, intermediate_certs or []
        )
        errors.extend(chain_errors)
        
        # 3. Check certificate extensions and constraints
        ext_valid, ext_errors = self._validate_extensions(certificate)
        errors.extend(ext_errors)
        
        # 4. Check revocation status (if requested)
        if check_revocation:
            revoked, revocation_errors = self._check_revocation_status(certificate)
            if revoked:
                errors.append("Certificate is revoked")
            errors.extend(revocation_errors)
        
        # Summary
        is_valid = len(errors) == 0
        status = "✅ VALID" if is_valid else "❌ INVALID"
        print(f"\n{status} Certificate validation result")
        
        if errors:
            print("Issues found:")
            for error in errors:
                print(f"   • {error}")
        
        return is_valid, errors
    
    def _verify_certificate_chain(self, certificate: x509.Certificate, 
                                 intermediate_certs: List[x509.Certificate]) -> Tuple[bool, List[str]]:
        """Verify the certificate chain up to a trusted root"""
        print("🔗 Verifying certificate chain...")
        errors = []
        
        # Start with the certificate to validate
        current_cert = certificate
        chain = [current_cert]
        
        # Build the chain by following issuer links
        while True:
            # Check if current certificate is self-signed (root CA)
            if self._is_self_signed(current_cert):
                print(f"   Root CA found: {current_cert.subject}")
                break
            
            # Look for issuer in intermediate certificates
            issuer_cert = self._find_issuer(current_cert, intermediate_certs + self.trusted_cas)
            
            if not issuer_cert:
                errors.append(f"Cannot find issuer for: {current_cert.subject}")
                break
            
            # Verify signature
            try:
                self._verify_signature(current_cert, issuer_cert)
                print(f"   ✅ Signature verified: {current_cert.subject}")
            except Exception as e:
                errors.append(f"Signature verification failed for {current_cert.subject}: {e}")
                break
            
            chain.append(issuer_cert)
            current_cert = issuer_cert
            
            # Prevent infinite loops
            if len(chain) > 10:
                errors.append("Certificate chain too long (>10)")
                break
        
        # Check if we reached a trusted root
        if not errors:
            root_cert = chain[-1]
            if not any(self._certificates_match(root_cert, trusted) for trusted in self.trusted_cas):
                errors.append("Certificate chain does not end in trusted root")
            else:
                print(f"   ✅ Chain ends in trusted root: {root_cert.subject}")
        
        print(f"   Certificate chain length: {len(chain)}")
        for i, cert in enumerate(chain):
            print(f"   {i}: {cert.subject}")
        
        return len(errors) == 0, errors
    
    def _is_self_signed(self, certificate: x509.Certificate) -> bool:
        """Check if a certificate is self-signed"""
        return certificate.subject == certificate.issuer
    
    def _find_issuer(self, certificate: x509.Certificate, 
                    candidate_certs: List[x509.Certificate]) -> Optional[x509.Certificate]:
        """Find the issuer certificate for a given certificate"""
        for candidate in candidate_certs:
            if certificate.issuer == candidate.subject:
                return candidate
        return None
    
    def _verify_signature(self, certificate: x509.Certificate, issuer_cert: x509.Certificate):
        """Verify certificate signature using issuer's public key"""
        issuer_public_key = issuer_cert.public_key()
        
        # Verify signature
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_hash_algorithm
        )
    
    def _certificates_match(self, cert1: x509.Certificate, cert2: x509.Certificate) -> bool:
        """Check if two certificates are the same"""
        return (cert1.subject == cert2.subject and 
                cert1.serial_number == cert2.serial_number and
                cert1.not_valid_before == cert2.not_valid_before)
    
    def _validate_extensions(self, certificate: x509.Certificate) -> Tuple[bool, List[str]]:
        """Validate certificate extensions"""
        print("🔧 Validating certificate extensions...")
        errors = []
        
        # Check Basic Constraints
        try:
            basic_constraints = certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            
            if basic_constraints.ca:
                print("   ✅ Certificate is marked as CA")
            else:
                print("   ✅ Certificate is marked as end-entity")
                
        except x509.ExtensionNotFound:
            errors.append("Missing Basic Constraints extension")
        
        # Check Key Usage
        try:
            key_usage = certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.KEY_USAGE
            ).value
            
            usages = []
            if key_usage.digital_signature: usages.append("Digital Signature")
            if key_usage.key_encipherment: usages.append("Key Encipherment")
            if key_usage.key_cert_sign: usages.append("Certificate Signing")
            
            print(f"   ✅ Key Usage: {', '.join(usages)}")
            
        except x509.ExtensionNotFound:
            errors.append("Missing Key Usage extension")
        
        return len(errors) == 0, errors
    
    def _check_revocation_status(self, certificate: x509.Certificate) -> Tuple[bool, List[str]]:
        """Check if certificate is revoked (simplified implementation)"""
        print("🚫 Checking revocation status...")
        
        # In a real implementation, this would:
        # 1. Check Certificate Revocation Lists (CRLs)
        # 2. Query OCSP responders
        # 3. Check certificate transparency logs
        
        # For this demo, we'll simulate a check
        print("   ✅ Certificate not found in revocation lists (simulated)")
        
        return False, []  # Not revoked, no errors
    
    def validate_hostname(self, certificate: x509.Certificate, hostname: str) -> Tuple[bool, str]:
        """Validate that certificate is valid for a specific hostname"""
        print(f"🌐 Validating hostname: {hostname}")
        
        # Check Common Name
        cn = None
        for attribute in certificate.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                cn = attribute.value
                break
        
        if cn and self._hostname_matches(hostname, cn):
            print(f"   ✅ Hostname matches Common Name: {cn}")
            return True, f"Matches CN: {cn}"
        
        # Check Subject Alternative Names
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            
            for san in san_ext:
                if isinstance(san, x509.DNSName):
                    if self._hostname_matches(hostname, san.value):
                        print(f"   ✅ Hostname matches SAN: {san.value}")
                        return True, f"Matches SAN: {san.value}"
            
        except x509.ExtensionNotFound:
            pass
        
        print(f"   ❌ Hostname does not match certificate")
        return False, "Hostname mismatch"
    
    def _hostname_matches(self, hostname: str, cert_name: str) -> bool:
        """Check if hostname matches certificate name (supports wildcards)"""
        # Simple wildcard matching
        if cert_name.startswith("*."):
            # Wildcard certificate
            wildcard_domain = cert_name[2:]
            return hostname.endswith(wildcard_domain) and hostname.count('.') >= wildcard_domain.count('.') + 1
        else:
            # Exact match
            return hostname.lower() == cert_name.lower()
    
    def demo_validation(self):
        """Demonstrate certificate validation"""
        print("🔍 CERTIFICATE VALIDATION DEMO")
        print("="*50)
        
        # Load certificates for testing
        cert_files = list(self.trusted_ca_dir.parent.glob("**/*.crt"))
        
        if not cert_files:
            print("❌ No certificates found for validation demo")
            print("   Run certificate_authority.py first to create test certificates")
            return
        
        # Test each certificate
        for cert_file in cert_files[:3]:  # Limit to first 3 for demo
            print(f"\n📋 Testing certificate: {cert_file.name}")
            
            with open(cert_file, "rb") as f:
                cert_data = f.read()
            certificate = x509.load_pem_x509_certificate(cert_data)
            
            # Validate certificate
            is_valid, errors = self.validate_certificate(certificate)
            
            # Test hostname validation if it's a server certificate
            if "server" in cert_file.name.lower() or "demo" in cert_file.name.lower():
                # Extract hostname from certificate
                cn = None
                for attr in certificate.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        cn = attr.value
                        break
                
                if cn:
                    hostname_valid, reason = self.validate_hostname(certificate, cn)
                    print(f"   Hostname validation: {'✅' if hostname_valid else '❌'} {reason}")

# Demo certificate validation
if __name__ == "__main__":
    validator = CertificateValidator()
    validator.demo_validation()
    
    print(f"\n💡 KEY CONCEPTS LEARNED:")
    print(f"   • Certificate validation requires checking multiple factors")
    print(f"   • Trust chains must end in a trusted root CA")
    print(f"   • Signature verification proves certificate authenticity")
    print(f"   • Hostname validation ensures certificate matches intended use")
```

**Run it:**
```bash
# First create some certificates to validate
python certificate_authority.py

# Then run the validator
python certificate_validator.py
```

### Step 2: Certificate Chain Builder

Add a utility to help build certificate chains:

```python
class CertificateChainBuilder:
    """Build certificate chains for validation"""
    
    def __init__(self, cert_dir="pki"):
        self.cert_dir = Path(cert_dir)
        self.all_certificates = self._load_all_certificates()
    
    def _load_all_certificates(self) -> List[x509.Certificate]:
        """Load all certificates from the PKI directory"""
        certificates = []
        
        for cert_file in self.cert_dir.rglob("*.crt"):
            try:
                with open(cert_file, "rb") as f:
                    cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
                certificates.append(cert)
            except Exception as e:
                print(f"⚠️ Failed to load {cert_file}: {e}")
        
        return certificates
    
    def build_chain(self, end_certificate: x509.Certificate) -> List[x509.Certificate]:
        """Build certificate chain from end certificate to root"""
        print(f"🔗 Building chain for: {end_certificate.subject}")
        
        chain = [end_certificate]
        current = end_certificate
        
        while not self._is_self_signed(current):
            issuer = self._find_issuer_in_collection(current, self.all_certificates)
            if not issuer:
                print(f"   ⚠️ Cannot find issuer for: {current.subject}")
                break
            
            chain.append(issuer)
            current = issuer
            print(f"   Added to chain: {issuer.subject}")
            
            if len(chain) > 10:  # Prevent infinite loops
                print(f"   ⚠️ Chain too long, stopping")
                break
        
        print(f"   ✅ Chain built with {len(chain)} certificates")
        return chain
    
    def _is_self_signed(self, cert: x509.Certificate) -> bool:
        return cert.subject == cert.issuer
    
    def _find_issuer_in_collection(self, cert: x509.Certificate, 
                                  certificates: List[x509.Certificate]) -> Optional[x509.Certificate]:
        for candidate in certificates:
            if cert.issuer == candidate.subject:
                return candidate
        return None
    
    def demo_chain_building(self):
        """Demonstrate chain building"""
        print("🔗 CERTIFICATE CHAIN BUILDING DEMO")
        print("="*50)
        
        # Find end-entity certificates (non-CA certificates)
        end_certs = []
        for cert in self.all_certificates:
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                if not basic_constraints.ca:
                    end_certs.append(cert)
            except x509.ExtensionNotFound:
                # No basic constraints = likely end-entity
                end_certs.append(cert)
        
        print(f"Found {len(end_certs)} end-entity certificates")
        
        # Build chains for each
        for cert in end_certs[:2]:  # Limit for demo
            print(f"\n📋 Building chain for: {cert.subject}")
            chain = self.build_chain(cert)
            
            print(f"   Chain ({len(chain)} certificates):")
            for i, c in enumerate(chain):
                cert_type = "End Entity"
                try:
                    bc = c.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
                    if bc.ca:
                        cert_type = "CA"
                except:
                    pass
                
                print(f"   {i+1}. {c.subject} ({cert_type})")

# Add to main demo
if __name__ == "__main__":
    # Existing validation demo
    validator = CertificateValidator()
    validator.demo_validation()
    
    # Chain building demo
    print("\n" + "="*60)
    chain_builder = CertificateChainBuilder()
    chain_builder.demo_chain_building()
```

### ✅ Checkpoint 4 Complete!

**Before continuing, you should be able to:**
- ✅ Validate certificate expiration dates
- ✅ Verify certificate signatures and trust chains
- ✅ Check certificate extensions and constraints
- ✅ Validate hostnames against certificates
- ✅ Build certificate chains from end-entity to root

---

## 📘 Module 5: Certificate Lifecycle Management (30 minutes)

**Learning Objective**: Implement certificate revocation and lifecycle management

**What you'll build**: Certificate Revocation List (CRL) generation and certificate lifecycle tracking

### Step 1: Certificate Revocation Lists

Add CRL support to your `CertificateAuthority` class:

```python
# Add these imports and methods to certificate_authority.py
from cryptography import x509
import json
from enum import Enum

class RevocationReason(Enum):
    """Certificate revocation reasons"""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10

# Add to CertificateAuthority class
def revoke_certificate(self, serial_number, reason=RevocationReason.UNSPECIFIED):
    """Revoke a certificate"""
    print(f"🚫 Revoking certificate: {serial_number}")
    
    # Load current issued certificates
    if not self.issued_certs.exists():
        raise ValueError("No issued certificates found")
    
    with open(self.issued_certs, "r") as f:
        records = json.load(f)
    
    serial_str = str(serial_number)
    if serial_str not in records:
        raise ValueError(f"Certificate {serial_number} not found")
    
    # Update status
    records[serial_str]["status"] = "revoked"
    records[serial_str]["revocation_date"] = datetime.datetime.utcnow().isoformat()
    records[serial_str]["revocation_reason"] = reason.name
    
    # Save updated records
    with open(self.issued_certs, "w") as f:
        json.dump(records, f, indent=2)
    
    print(f"✅ Certificate {serial_number} revoked")
    print(f"   Reason: {reason.name}")
    
    # Generate new CRL
    self.generate_crl()

def generate_crl(self):
    """Generate Certificate Revocation List"""
    print("📋 Generating Certificate Revocation List...")
    
    if not self.ca_certificate or not self.ca_private_key:
        raise RuntimeError("CA not initialized")
    
    # Load revoked certificates
    revoked_certs = []
    if self.issued_certs.exists():
        with open(self.issued_certs, "r") as f:
            records = json.load(f)
        
        for serial_str, cert_info in records.items():
            if cert_info["status"] == "revoked":
                revocation_date = datetime.datetime.fromisoformat(cert_info["revocation_date"])
                
                revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                    int(serial_str)
                ).revocation_date(
                    revocation_date
                ).add_extension(
                    x509.CRLReason(getattr(x509.ReasonFlags, cert_info["revocation_reason"].lower())),
                    critical=False
                ).build()
                
                revoked_certs.append(revoked_cert)
    
    # Build CRL
    crl_builder = x509.CertificateRevocationListBuilder().issuer_name(
        self.ca_certificate.subject
    ).last_update(
        datetime.datetime.utcnow()
    ).next_update(
        datetime.datetime.utcnow() + datetime.timedelta(days=7)  # CRL valid for 1 week
    )
    
    # Add revoked certificates
    for revoked_cert in revoked_certs:
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
    
    # Sign CRL
    crl = crl_builder.sign(self.ca_private_key, hashes.SHA256())
    
    # Save CRL
    crl_path = self.crl_dir / "ca.crl"
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    
    print(f"✅ CRL generated: {crl_path}")
    print(f"   Revoked certificates: {len(revoked_certs)}")
    print(f"   Valid until: {crl.next_update}")
    
    return crl, crl_path

def check_certificate_status(self, serial_number):
    """Check the status of a certificate"""
    if not self.issued_certs.exists():
        return "unknown", "No certificate records found"
    
    with open(self.issued_certs, "r") as f:
        records = json.load(f)
    
    serial_str = str(serial_number)
    if serial_str not in records:
        return "unknown", "Certificate not found in records"
    
    cert_info = records[serial_str]
    status = cert_info["status"]
    
    if status == "active":
        # Check if expired
        expiry = datetime.datetime.fromisoformat(cert_info["expiry_date"])
        if expiry < datetime.datetime.utcnow():
            return "expired", f"Certificate expired on {expiry.strftime('%Y-%m-%d')}"
        else:
            return "active", "Certificate is valid and active"
    
    elif status == "revoked":
        revocation_date = cert_info["revocation_date"]
        reason = cert_info["revocation_reason"]
        return "revoked", f"Certificate revoked on {revocation_date} (Reason: {reason})"
    
    return status, "Unknown status"

def demo_lifecycle_management(self):
    """Demonstrate certificate lifecycle management"""
    print("\n🔄 CERTIFICATE LIFECYCLE DEMO")
    print("="*50)
    
    # Issue a test certificate
    test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    test_cert = self.issue_certificate(
        subject_name="lifecycle.test.com",
        public_key=test_key.public_key(),
        cert_type="server",
        days_valid=30
    )
    
    # Check initial status
    print("\n1. Initial certificate status:")
    status, message = self.check_certificate_status(test_cert.serial_number)
    print(f"   Status: {status} - {message}")
    
    # Revoke the certificate
    print("\n2. Revoking certificate...")
    self.revoke_certificate(test_cert.serial_number, RevocationReason.SUPERSEDED)
    
    # Check status after revocation
    print("\n3. Status after revocation:")
    status, message = self.check_certificate_status(test_cert.serial_number)
    print(f"   Status: {status} - {message}")
    
    # Show CRL contents
    print("\n4. CRL Information:")
    crl_path = self.crl_dir / "ca.crl"
    if crl_path.exists():
        with open(crl_path, "rb") as f:
            crl_data = f.read()
        crl = x509.load_pem_x509_crl(crl_data)
        
        print(f"   Issuer: {crl.issuer}")
        print(f"   Last Update: {crl.last_update}")
        print(f"   Next Update: {crl.next_update}")
        print(f"   Revoked Certificates: {len(list(crl))}")
        
        for revoked_cert in crl:
            print(f"     Serial: {revoked_cert.serial_number}, Date: {revoked_cert.revocation_date}")
    
    return test_cert
```

### Step 2: Certificate Renewal System

Add certificate renewal capabilities:

```python
# Add to CertificateAuthority class
def renew_certificate(self, old_certificate, new_public_key=None, days_valid=90):
    """Renew an existing certificate"""
    print(f"🔄 Renewing certificate: {old_certificate.subject}")
    
    # Use existing public key if no new one provided
    if new_public_key is None:
        new_public_key = old_certificate.public_key()
        print("   Using existing public key")
    else:
        print("   Using new public key")
    
    # Extract information from old certificate
    common_name = None
    for attr in old_certificate.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            common_name = attr.value
            break
    
    # Determine certificate type from extensions
    cert_type = "server"  # default
    try:
        basic_constraints = old_certificate.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        if basic_constraints.ca:
            cert_type = "intermediate_ca" if basic_constraints.path_length == 0 else "ca"
    except x509.ExtensionNotFound:
        pass
    
    # Extract SANs
    alt_names = []
    try:
        san_ext = old_certificate.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        for san in san_ext:
            if isinstance(san, x509.DNSName):
                alt_names.append(san.value)
    except x509.ExtensionNotFound:
        pass
    
    # Issue new certificate
    new_certificate = self.issue_certificate(
        subject_name=common_name,
        public_key=new_public_key,
        cert_type=cert_type,
        alt_names=alt_names if alt_names else None,
        days_valid=days_valid
    )
    
    # Optionally revoke old certificate
    old_status, _ = self.check_certificate_status(old_certificate.serial_number)
    if old_status == "active":
        print("   Revoking old certificate...")
        self.revoke_certificate(old_certificate.serial_number, RevocationReason.SUPERSEDED)
    
    print(f"✅ Certificate renewed")
    print(f"   Old Serial: {old_certificate.serial_number}")
    print(f"   New Serial: {new_certificate.serial_number}")
    
    return new_certificate

def get_expiring_certificates(self, days_ahead=30):
    """Get certificates expiring within specified days"""
    if not self.issued_certs.exists():
        return []
    
    with open(self.issued_certs, "r") as f:
        records = json.load(f)
    
    expiring = []
    threshold = datetime.datetime.utcnow() + datetime.timedelta(days=days_ahead)
    
    for serial_str, cert_info in records.items():
        if cert_info["status"] == "active":
            expiry = datetime.datetime.fromisoformat(cert_info["expiry_date"])
            if expiry <= threshold:
                cert_info["serial_number"] = int(serial_str)
                cert_info["days_until_expiry"] = (expiry - datetime.datetime.utcnow()).days
                expiring.append(cert_info)
    
    # Sort by expiration date
    expiring.sort(key=lambda x: x["expiry_date"])
    
    return expiring

def demo_renewal_system(self):
    """Demonstrate certificate renewal"""
    print("\n🔄 CERTIFICATE RENEWAL DEMO")
    print("="*50)
    
    # Create a certificate that will "expire soon"
    renewal_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_cert = self.issue_certificate(
        subject_name="renewal.test.com",
        public_key=renewal_key.public_key(),
        cert_type="server",
        days_valid=1  # Very short for demo
    )
    
    print(f"\n1. Created certificate expiring soon:")
    print(f"   Serial: {old_cert.serial_number}")
    print(f"   Expires: {old_cert.not_valid_after}")
    
    # Check expiring certificates
    print("\n2. Checking for expiring certificates...")
    expiring = self.get_expiring_certificates(days_ahead=7)
    
    print(f"   Found {len(expiring)} certificates expiring within 7 days:")
    for cert_info in expiring:
        print(f"     Serial {cert_info['serial_number']}: {cert_info['subject']} "
              f"({cert_info['days_until_expiry']} days)")
    
    # Renew certificate
    print("\n3. Renewing certificate...")
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_cert = self.renew_certificate(old_cert, new_key.public_key(), days_valid=90)
    
    print(f"\n4. Renewal complete:")
    print(f"   New certificate expires: {new_cert.not_valid_after}")
    
    return new_cert
```

### Step 3: Complete Demo Integration

Create a comprehensive demo that ties everything together:

```python
# Add to the main section of certificate_authority.py
if __name__ == "__main__":
    print("🏛️ COMPLETE PKI SYSTEM DEMO")
    print("="*60)
    
    # 1. Initialize CA
    ca = CertificateAuthority("CSCI 347 Complete Demo CA")
    if not ca.ca_certificate:
        ca.initialize_ca()
    
    # 2. Basic certificate operations
    print("\n" + "="*40)
    print("BASIC CERTIFICATE OPERATIONS")
    print("="*40)
    
    # Issue various certificate types
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    server_cert = ca.issue_certificate(
        "complete-demo.example.com", server_key.public_key(), "server", 
        alt_names=["www.complete-demo.example.com"], days_valid=90
    )
    
    client_cert = ca.issue_certificate(
        "alice@example.com", client_key.public_key(), "client", days_valid=365
    )
    
    # 3. CSR processing demo
    print("\n" + "="*40)
    print("CSR PROCESSING")
    print("="*40)
    
    from csr_manager import CSRManager
    csr_mgr = CSRManager()
    
    # Generate and process CSR
    test_csr, test_key = csr_mgr.generate_csr(
        "csr-test.example.com", alt_names=["api.csr-test.example.com"]
    )
    csr_path, key_path = csr_mgr.save_csr(test_csr, test_key, "csr-demo")
    
    # CA processes CSR
    csr_cert, cert_path = ca.process_csr(csr_path, "server", 60)
    
    # 4. Certificate validation
    print("\n" + "="*40)
    print("CERTIFICATE VALIDATION")
    print("="*40)
    
    from certificate_validator import CertificateValidator
    validator = CertificateValidator()
    
    # Validate server certificate
    is_valid, errors = validator.validate_certificate(server_cert)
    hostname_valid, reason = validator.validate_hostname(server_cert, "complete-demo.example.com")
    
    print(f"Server certificate validation: {'✅' if is_valid else '❌'}")
    print(f"Hostname validation: {'✅' if hostname_valid else '❌'} ({reason})")
    
    # 5. Lifecycle management
    print("\n" + "="*40)
    print("LIFECYCLE MANAGEMENT")
    print("="*40)
    
    ca.demo_lifecycle_management()
    ca.demo_renewal_system()
    
    # 6. Final summary
    print("\n" + "="*40)
    print("PKI SYSTEM SUMMARY")
    print("="*40)
    
    ca.list_issued_certificates()
    
    ca_info = ca.get_ca_info()
    print(f"\nCA Information:")
    for key, value in ca_info.items():
        print(f"   {key}: {value}")
    
    print(f"\n🎉 Complete PKI system demonstration finished!")
    print(f"📁 Check the 'pki' directory for all generated files")
```

### ✅ Checkpoint 5 Complete!

**Before continuing, you should be able to:**
- ✅ Generate Certificate Revocation Lists (CRLs)
- ✅ Revoke certificates with proper reasons
- ✅ Check certificate revocation status
- ✅ Renew certificates with new or existing keys
- ✅ Monitor certificates approaching expiration
- ✅ Manage complete certificate lifecycles

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can create X.509 certificates with proper extensions
- [ ] You understand the difference between root and intermediate CAs
- [ ] You can generate and process Certificate Signing Requests
- [ ] You can validate certificate chains and trust relationships
- [ ] You can implement certificate revocation and renewal
- [ ] You can build a complete PKI system from scratch

## 🚀 Ready for the Assignment?

Excellent! Now you have all the knowledge to build an enterprise-grade Certificate Authority system. The assignment will challenge you to create a multi-tier PKI with proper certificate lifecycle management.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Mastered

1. **X.509 Certificate Structure** - Public key, identity, and digital signature
2. **Certificate Authority Operations** - Root CA setup, intermediate CA creation
3. **Certificate Signing Requests** - CSR generation, validation, and processing
4. **Trust Chain Validation** - Signature verification, chain building, trust anchors
5. **Certificate Lifecycle Management** - Issuance, renewal, revocation, and monitoring
6. **PKI Security Models** - Hierarchical trust, certificate policies, and constraints
7. **Real-world Applications** - TLS/SSL, code signing, email security, identity management

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!