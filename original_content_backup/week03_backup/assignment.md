# Week 3 Assignment: Certificate Analysis and Validation

**Due**: End of Week 3 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 4 hours  
**Submission**: Submit Pull Request URL to Canvas

---
*Updated for Fall 2025 - Undergraduate Level*

## 🎯 Assignment Overview

Analyze and validate X.509 certificates to understand PKI trust chains and security. You'll work with real certificates from popular websites and learn how browsers verify secure connections.

## 📋 Requirements

### Core Functionality (15 points)

#### 1. Certificate Analyzer (7 points)
Build a tool that extracts and displays certificate information:
- **Parse certificate fields**: Subject, Issuer, Serial Number
- **Extract validity dates**: Not Before, Not After
- **Identify key usage**: Digital Signature, Key Encipherment, etc.
- **Display certificate extensions**: SAN, Basic Constraints
- **Show signature algorithm**: RSA-SHA256, ECDSA, etc.

#### 2. Chain Validator (8 points)
Implement certificate chain validation:
- **Verify certificate signatures** using issuer's public key
- **Check validity dates** (not expired, not future-dated)
- **Validate trust chain** up to known root CA
- **Identify chain issues**: Missing intermediate, untrusted root
- **Display validation results** clearly

### Analysis Tasks (5 points)

Analyze these real-world scenarios:
1. **Valid certificate**: Download and analyze google.com certificate
2. **Expired certificate**: Analyze provided expired certificate
3. **Self-signed certificate**: Analyze provided test certificate
4. **Chain with intermediate**: Analyze certificate with full chain

### Documentation (5 points)

Create a report (`analysis_report.md`) that includes:
- Certificate chain diagram for one website
- Explanation of how trust is established
- Common certificate problems and their security implications
- Comparison of RSA vs ECDSA certificates

## 🔧 Technical Specifications

### Starter Code Provided

```python
# certificate_analyzer.py - Starter template
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import ssl
import socket
import datetime
import sys

def download_certificate(hostname, port=443):
    """
    Download certificate from a website
    
    Args:
        hostname (str): Website hostname
        port (int): HTTPS port (default 443)
    
    Returns:
        bytes: DER-encoded certificate
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert_binary()
            return der_cert

def parse_certificate(cert_data):
    """
    Parse X.509 certificate and extract key information
    
    Args:
        cert_data (bytes): DER or PEM encoded certificate
    
    Returns:
        dict: Certificate information
    """
    # Load certificate
    if isinstance(cert_data, bytes):
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extract basic information
    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "version": cert.version.name
    }
    
    # TODO: Add extension parsing
    # TODO: Add public key information
    
    return info

def validate_certificate(cert_data, issuer_cert_data=None):
    """
    Validate certificate against issuer
    
    Args:
        cert_data (bytes): Certificate to validate
        issuer_cert_data (bytes): Issuer certificate (optional)
    
    Returns:
        dict: Validation results
    """
    results = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    # TODO: Check expiration dates
    # TODO: Verify signature if issuer provided
    # TODO: Check certificate constraints
    
    return results
```

### Required Functionality

Your tool should support these commands:

```bash
# Analyze a certificate file
python cert_analyzer.py analyze --file certificate.pem

# Download and analyze a website's certificate
python cert_analyzer.py download --host google.com

# Validate a certificate chain
python cert_analyzer.py validate --cert server.pem --chain intermediate.pem --root ca.pem

# Compare two certificates
python cert_analyzer.py compare --cert1 old.pem --cert2 new.pem
```

### Sample Certificates Provided

We provide test certificates in the `test_certs/` directory:
- `valid_cert.pem` - Valid certificate with full chain
- `expired_cert.pem` - Expired certificate for testing
- `self_signed.pem` - Self-signed certificate
- `bad_chain.pem` - Certificate with chain issues

## 📝 Implementation Guide

### Step 1: Certificate Parsing (1 hour)
1. Load certificate from file or download from website
2. Extract all standard fields (subject, issuer, dates, etc.)
3. Parse extensions (SAN, Key Usage, etc.)
4. Display in readable format

### Step 2: Validation Logic (1.5 hours)
1. Check certificate dates (not expired)
2. Verify signature using issuer's public key
3. Validate certificate constraints
4. Check for common issues (weak keys, deprecated algorithms)

### Step 3: Chain Analysis (1 hour)
1. Build certificate chain from leaf to root
2. Validate each link in the chain
3. Identify trust anchor (root CA)
4. Report any chain issues

### Step 4: Testing and Documentation (30 minutes)
1. Test with provided certificates
2. Test with real website certificates
3. Document findings in report

## 🎓 Learning Objectives

By completing this assignment, you will understand:
- How X.509 certificates establish trust
- The role of Certificate Authorities
- How certificate chains work
- Common certificate vulnerabilities
- Why certificate validation is critical for security

## 📊 Grading Rubric

| Component | Points | Criteria |
|-----------|--------|----------|
| **Certificate Parser** | 7 | Correctly extracts and displays all certificate fields |
| **Chain Validator** | 8 | Properly validates certificate chains and identifies issues |
| **Analysis Tasks** | 5 | Thoughtful analysis of real-world certificates |
| **Documentation** | 5 | Clear explanations and security insights |

### Extra Credit Opportunities (+3 points)
- Implement OCSP checking for revocation status
- Add certificate transparency log checking
- Create visualization of certificate chain

## 💡 Hints and Tips

1. **Use the cryptography library** - It handles the complex crypto math
2. **Start with parsing** - Get certificate reading working first
3. **Test with known certificates** - Use provided test certificates
4. **Handle errors gracefully** - Certificates can be malformed
5. **Think like an attacker** - What certificate issues could be exploited?

## 🔐 Security Considerations

- Never accept invalid certificates in production code
- Understand the difference between self-signed and CA-signed
- Be aware of certificate pinning as additional security
- Know common attacks (MITM, DNS hijacking, CA compromise)

## 📚 Resources

- [X.509 Certificate Format](https://datatracker.ietf.org/doc/html/rfc5280)
- [Python Cryptography Docs](https://cryptography.io/en/latest/x509/)
- [SSL/TLS Certificate Verification](https://docs.python.org/3/library/ssl.html)
- [Common Certificate Errors](https://badssl.com/)

## Submission Requirements

Submit via GitHub Pull Request:
1. `cert_analyzer.py` - Your implementation
2. `analysis_report.md` - Your analysis findings
3. `test_results.txt` - Output from testing various certificates
4. Update your `assignments/week03/README.md` with any design notes

Remember: Focus on understanding HOW certificates establish trust, not on building complex infrastructure!