# Week 3 Homework Hints: Certificate Analysis and Validation

## 🎯 Quick Start Guide (4 hours total)

### Time Breakdown
- **Setup & Understanding**: 45 minutes
- **Certificate Analyzer**: 1.5 hours
- **Chain Validator**: 1.5 hours
- **CLI & Testing**: 15 minutes

## 📋 Step-by-Step Implementation

### Step 1: Understanding X.509 Certificates (30 minutes)

**Key Concepts:**
- **X.509 Certificate**: Digital identity containing public key + metadata
- **Certificate Chain**: Leaf → Intermediate → Root CA
- **Trust**: Browsers have pre-installed root CA certificates
- **Validation**: Check signatures, dates, and trust chain

**Think of it like ID verification**: You show a driver's license (certificate), the checker verifies it's issued by a trusted DMV (CA), and confirms it's not expired.

### Step 2: Environment Setup (15 minutes)

```bash
pip install cryptography

mkdir week03-cert-analysis
cd week03-cert-analysis
mkdir test_certs

touch cert_analyzer.py
```

### Step 3: Build on the Provided Starter Code (30 minutes)

Copy the provided starter code and add these essential components:

```python
# Add these imports to the provided starter
import argparse
import sys
import os
from pathlib import Path

# All the provided starter functions go here...
# download_certificate(), parse_certificate(), validate_certificate()

def display_certificate_info(cert_info):
    """Display certificate information in a readable format"""
    print("\n📋 Certificate Information:")
    print(f"   Subject: {cert_info['subject']}")
    print(f"   Issuer: {cert_info['issuer']}")
    print(f"   Serial Number: {cert_info['serial_number']}")
    print(f"   Valid From: {cert_info['not_before']}")
    print(f"   Valid Until: {cert_info['not_after']}")
    print(f"   Signature Algorithm: {cert_info['signature_algorithm']}")
    print(f"   Version: {cert_info['version']}")
```

### Step 4: Complete the Certificate Parser (1 hour)

Enhance the provided `parse_certificate()` function:

```python
def parse_certificate(cert_data):
    """Parse X.509 certificate and extract key information"""
    # Load certificate (from provided starter code)
    if isinstance(cert_data, bytes):
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Extract basic information (from provided starter code)
    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "version": cert.version.name
    }

    # Add extension parsing (complete the TODO)
    extensions = {}

    # Parse Subject Alternative Name (SAN)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = []
        for name in san_ext.value:
            san_names.append(str(name))
        extensions['SAN'] = san_names
    except x509.ExtensionNotFound:
        pass

    # Parse Key Usage
    try:
        key_usage_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        key_usage = []
        ku = key_usage_ext.value
        if ku.digital_signature:
            key_usage.append("Digital Signature")
        if ku.key_encipherment:
            key_usage.append("Key Encipherment")
        if ku.key_agreement:
            key_usage.append("Key Agreement")
        if ku.key_cert_sign:
            key_usage.append("Certificate Sign")
        if ku.crl_sign:
            key_usage.append("CRL Sign")
        extensions['Key Usage'] = key_usage
    except x509.ExtensionNotFound:
        pass

    # Parse Basic Constraints
    try:
        basic_constraints_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        bc = basic_constraints_ext.value
        extensions['Basic Constraints'] = {
            'CA': bc.ca,
            'Path Length': bc.path_length
        }
    except x509.ExtensionNotFound:
        pass

    info['extensions'] = extensions

    # Add public key information (complete the TODO)
    public_key = cert.public_key()
    if hasattr(public_key, 'key_size'):  # RSA
        info['public_key'] = {
            'type': 'RSA',
            'size': public_key.key_size
        }
    elif hasattr(public_key, 'curve'):  # ECDSA
        info['public_key'] = {
            'type': 'ECDSA',
            'curve': public_key.curve.name
        }
    else:
        info['public_key'] = {'type': 'Unknown'}

    return info
```

### Step 5: Complete the Certificate Validator (30 minutes)

Enhance the provided `validate_certificate()` function:

```python
def validate_certificate(cert_data, issuer_cert_data=None):
    """Validate certificate against issuer"""
    results = {
        "valid": True,
        "errors": [],
        "warnings": []
    }

    # Load certificate
    if isinstance(cert_data, bytes):
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Check expiration dates (complete the TODO)
    now = datetime.datetime.utcnow()

    if now < cert.not_valid_before:
        results["errors"].append(f"Certificate not yet valid (valid from {cert.not_valid_before})")
        results["valid"] = False

    if now > cert.not_valid_after:
        results["errors"].append(f"Certificate expired on {cert.not_valid_after}")
        results["valid"] = False

    # Warn if certificate expires soon (within 30 days)
    days_until_expiry = (cert.not_valid_after - now).days
    if 0 < days_until_expiry <= 30:
        results["warnings"].append(f"Certificate expires in {days_until_expiry} days")

    # Verify signature if issuer provided (complete the TODO)
    if issuer_cert_data:
        try:
            if isinstance(issuer_cert_data, bytes):
                issuer_cert = x509.load_der_x509_certificate(issuer_cert_data, default_backend())
            else:
                issuer_cert = x509.load_pem_x509_certificate(issuer_cert_data, default_backend())

            # Verify signature
            issuer_public_key = issuer_cert.public_key()
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm
            )

        except Exception as e:
            results["errors"].append(f"Signature verification failed: {str(e)}")
            results["valid"] = False

    # Check certificate constraints (complete the TODO)
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if basic_constraints.value.ca and basic_constraints.critical:
            # This is a CA certificate
            pass
        elif not basic_constraints.value.ca:
            # This is an end-entity certificate
            pass
    except x509.ExtensionNotFound:
        results["warnings"].append("No Basic Constraints extension found")

    return results
```

### Step 6: Build Certificate Chain Validation (30 minutes)

```python
def validate_certificate_chain(cert_files):
    """Validate a certificate chain from leaf to root"""
    if not cert_files:
        return {"valid": False, "errors": ["No certificates provided"]}

    results = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "chain_info": []
    }

    certificates = []

    # Load all certificates
    for cert_file in cert_files:
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            certificates.append((cert, cert_file))
        except Exception as e:
            results["errors"].append(f"Failed to load {cert_file}: {str(e)}")
            results["valid"] = False
            return results

    # Sort certificates: leaf first, root last
    # Simple heuristic: leaf cert won't have Basic Constraints CA=True
    leaf_cert = None
    ca_certs = []

    for cert, filename in certificates:
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if basic_constraints.value.ca:
                ca_certs.append((cert, filename))
            else:
                leaf_cert = (cert, filename)
        except x509.ExtensionNotFound:
            # No basic constraints, assume it's a leaf cert
            leaf_cert = (cert, filename)

    if not leaf_cert:
        results["errors"].append("No leaf certificate found in chain")
        results["valid"] = False
        return results

    # Build chain: leaf -> intermediate(s) -> root
    chain = [leaf_cert] + ca_certs

    # Validate each link in the chain
    for i in range(len(chain) - 1):
        current_cert, current_file = chain[i]
        issuer_cert, issuer_file = chain[i + 1]

        # Check if issuer field matches subject field
        if current_cert.issuer != issuer_cert.subject:
            results["errors"].append(f"Chain break: {current_file} issuer doesn't match {issuer_file} subject")
            results["valid"] = False

        # Validate individual certificate
        with open(current_file, 'rb') as f:
            cert_data = f.read()
        with open(issuer_file, 'rb') as f:
            issuer_data = f.read()

        validation = validate_certificate(cert_data, issuer_data)
        if not validation["valid"]:
            results["errors"].extend(validation["errors"])
            results["valid"] = False
        results["warnings"].extend(validation["warnings"])

        # Add chain info
        results["chain_info"].append({
            "certificate": current_file,
            "subject": current_cert.subject.rfc4514_string(),
            "issuer": current_cert.issuer.rfc4514_string(),
            "valid": validation["valid"]
        })

    return results
```

### Step 7: Command Line Interface (15 minutes)

```python
def main():
    parser = argparse.ArgumentParser(description="Certificate Analysis and Validation Tool")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Analyze a certificate file
    analyze_parser = subparsers.add_parser('analyze', help='Analyze certificate file')
    analyze_parser.add_argument('--file', required=True, help='Certificate file to analyze')

    # Download and analyze a website's certificate
    download_parser = subparsers.add_parser('download', help='Download and analyze website certificate')
    download_parser.add_argument('--host', required=True, help='Website hostname')

    # Validate a certificate chain
    validate_parser = subparsers.add_parser('validate', help='Validate certificate chain')
    validate_parser.add_argument('--cert', required=True, help='Certificate to validate')
    validate_parser.add_argument('--chain', help='Certificate chain file')
    validate_parser.add_argument('--root', help='Root CA certificate')

    # Compare two certificates
    compare_parser = subparsers.add_parser('compare', help='Compare two certificates')
    compare_parser.add_argument('--cert1', required=True, help='First certificate')
    compare_parser.add_argument('--cert2', required=True, help='Second certificate')

    args = parser.parse_args()

    if args.command == 'analyze':
        with open(args.file, 'rb') as f:
            cert_data = f.read()

        cert_info = parse_certificate(cert_data)
        display_certificate_info(cert_info)

        # Show extensions
        if cert_info.get('extensions'):
            print("\n🔧 Extensions:")
            for ext_name, ext_value in cert_info['extensions'].items():
                print(f"   {ext_name}: {ext_value}")

        # Show public key info
        if cert_info.get('public_key'):
            pk = cert_info['public_key']
            print(f"\n🔑 Public Key: {pk['type']}")
            if 'size' in pk:
                print(f"   Key Size: {pk['size']} bits")
            if 'curve' in pk:
                print(f"   Curve: {pk['curve']}")

    elif args.command == 'download':
        try:
            print(f"📡 Downloading certificate from {args.host}...")
            cert_data = download_certificate(args.host)
            cert_info = parse_certificate(cert_data)
            display_certificate_info(cert_info)

            # Save downloaded certificate
            filename = f"{args.host.replace('.', '_')}_cert.pem"
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            with open(filename, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            print(f"💾 Certificate saved to {filename}")

        except Exception as e:
            print(f"❌ Failed to download certificate: {e}")

    elif args.command == 'validate':
        cert_files = [args.cert]
        if args.chain:
            cert_files.append(args.chain)
        if args.root:
            cert_files.append(args.root)

        if len(cert_files) == 1:
            # Single certificate validation
            with open(args.cert, 'rb') as f:
                cert_data = f.read()
            validation = validate_certificate(cert_data)
        else:
            # Chain validation
            validation = validate_certificate_chain(cert_files)

        print("\n🔍 Validation Results:")
        if validation["valid"]:
            print("✅ Certificate/chain is valid!")
        else:
            print("❌ Certificate/chain validation failed!")

        if validation["errors"]:
            print("\n❌ Errors:")
            for error in validation["errors"]:
                print(f"   • {error}")

        if validation["warnings"]:
            print("\n⚠️ Warnings:")
            for warning in validation["warnings"]:
                print(f"   • {warning}")

    elif args.command == 'compare':
        with open(args.cert1, 'rb') as f:
            cert1_data = f.read()
        with open(args.cert2, 'rb') as f:
            cert2_data = f.read()

        cert1_info = parse_certificate(cert1_data)
        cert2_info = parse_certificate(cert2_data)

        print("\n📊 Certificate Comparison:")
        print(f"Certificate 1 ({args.cert1}):")
        print(f"   Subject: {cert1_info['subject']}")
        print(f"   Issuer: {cert1_info['issuer']}")
        print(f"   Valid Until: {cert1_info['not_after']}")

        print(f"\nCertificate 2 ({args.cert2}):")
        print(f"   Subject: {cert2_info['subject']}")
        print(f"   Issuer: {cert2_info['issuer']}")
        print(f"   Valid Until: {cert2_info['not_after']}")

        # Compare key aspects
        if cert1_info['subject'] == cert2_info['subject']:
            print("\n✅ Same subject")
        else:
            print("\n❌ Different subjects")

        if cert1_info['public_key'] == cert2_info['public_key']:
            print("✅ Same public key")
        else:
            print("❌ Different public keys")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: "ExtensionNotFound" errors
**Cause**: Not all certificates have all extensions
**Solution**: Always use try/except blocks when parsing extensions

### Issue: "InvalidSignature" exception
**Cause**: Wrong issuer certificate or corrupted signature
**Solution**: Ensure you're using the correct issuer certificate for validation

### Issue: "No module named 'cryptography'"
**Solution**: Install with `pip install cryptography`

### Issue: Certificate download fails
**Cause**: Network issues, invalid hostname, or non-HTTPS site
**Solution**: Test with known working sites like google.com

### Issue: Date parsing errors
**Cause**: Timezone issues or invalid date formats
**Solution**: Use `datetime.datetime.utcnow()` for consistent UTC comparison

## ✅ Testing Workflow

### Analysis Tasks (as per assignment):

```bash
# 1. Analyze google.com certificate (valid certificate)
python cert_analyzer.py download --host google.com
python cert_analyzer.py analyze --file google_com_cert.pem

# 2. Test with provided certificates
python cert_analyzer.py analyze --file test_certs/valid_cert.pem
python cert_analyzer.py analyze --file test_certs/expired_cert.pem
python cert_analyzer.py analyze --file test_certs/self_signed.pem

# 3. Validate certificate chains
python cert_analyzer.py validate --cert test_certs/valid_cert.pem --chain test_certs/intermediate.pem --root test_certs/root_ca.pem

# 4. Compare certificates
python cert_analyzer.py compare --cert1 test_certs/old_cert.pem --cert2 test_certs/new_cert.pem
```

### Test Various Scenarios:
```bash
# Download certificates from different sites
python cert_analyzer.py download --host github.com
python cert_analyzer.py download --host badssl.com

# Test chain validation with different configurations
python cert_analyzer.py validate --cert leaf.pem --chain intermediate.pem
python cert_analyzer.py validate --cert leaf.pem  # Single cert validation
```

## 📁 Expected File Structure
```
week03-cert-analysis/
├── cert_analyzer.py           # Your implementation (based on starter code)
├── test_certs/               # Provided test certificates
│   ├── valid_cert.pem
│   ├── expired_cert.pem
│   ├── self_signed.pem
│   └── bad_chain.pem
├── google_com_cert.pem       # Downloaded certificates
├── github_com_cert.pem
├── analysis_report.md        # Your analysis report
├── test_results.txt          # Output from testing
└── README.md                 # Usage instructions
```

## 🎯 Grading Focus Areas (from assignment)

1. **Certificate Analyzer (7 points)**: Correctly extracts and displays all certificate fields
2. **Chain Validator (8 points)**: Properly validates certificate chains and identifies issues
3. **Analysis Tasks (5 points)**: Thoughtful analysis of real-world certificates
4. **Documentation (5 points)**: Clear explanations and security insights

## 💡 Pro Tips

1. **Start with the Provided Code**: Build on the starter functions, don't rewrite them
2. **Test with Real Certificates**: Download from google.com, github.com for testing
3. **Handle Missing Extensions Gracefully**: Use try/except for all extension parsing
4. **Focus on Certificate Analysis**: You're analyzing existing certificates, not creating new ones
5. **Understand Chain Validation**: How browsers verify website certificates

## 🔍 Key Concepts to Understand (from assignment)

### Assignment Learning Objectives:
- How X.509 certificates establish trust
- The role of Certificate Authorities
- How certificate chains work
- Common certificate vulnerabilities
- Why certificate validation is critical for security

### Real-World Certificate Analysis:
1. **Valid Certificate Analysis**: Understand how browsers trust google.com
2. **Expired Certificate Issues**: Why expired certificates break HTTPS
3. **Self-Signed Certificates**: Why browsers warn about these
4. **Chain Validation**: How intermediate CAs extend trust

## 🚀 Extension Ideas (Optional - Extra Credit)

The assignment mentions these optional extensions:
- Implement OCSP checking for revocation status (+1 point)
- Add certificate transparency log checking (+1 point)
- Create visualization of certificate chain (+1 point)

## ⏱️ Time Management

- **Focus on parsing and validation**: Core assignment requirements
- **Don't build a CA system**: You're analyzing existing certificates
- **Use provided starter code**: Builds on the template functions
- **Test with real websites**: Download and analyze actual certificates

## 🔧 Debugging Helpers

**View certificate with OpenSSL:**
```bash
openssl x509 -in google_com_cert.pem -text -noout
openssl x509 -in google_com_cert.pem -dates -noout
```

**Test certificate chain with OpenSSL:**
```bash
openssl verify -CAfile root_ca.pem -untrusted intermediate.pem leaf_cert.pem
```

**Download certificate manually:**
```bash
echo | openssl s_client -servername google.com -connect google.com:443 2>/dev/null | openssl x509 > google_manual.pem
```

## 📝 Analysis Report Guidelines

Your `analysis_report.md` should include:
1. **Certificate chain diagram** for one website (draw the trust path)
2. **Explanation of trust establishment** (how does your browser trust google.com?)
3. **Common certificate problems** and security implications
4. **RSA vs ECDSA comparison** from real certificates you analyzed

Remember: This assignment is about understanding how certificate validation protects web browsing, not about building PKI infrastructure!