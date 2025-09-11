# 🔐 Week 2 Overview: Hashing & Digital Signatures

**⏰ Due Date**: Sunday, September 14, 2025 at 11:59 PM  
**📊 Total Time**: 5-6 hours | **🎯 Points Available**: 25 points  
**🧠 Cognitive Level**: Knowledge → Comprehension → Application (Bloom's Taxonomy)

---

## 📋 **This Week's Checklist**

```
Progress: [░░░░░░░░░░] 0%

□ 📖 Complete readings (90 min) - Hash functions, HMAC, Digital signatures
□ 🎥 Finish tutorial (3 hours) - Document integrity system implementation
□ 💻 Submit assignment (3 hours) - Digital signature verification system
□ ✅ Complete quiz in Canvas by Sunday
```

---

## 🎯 **Learning Objectives (Application Level)**

By the end of this week, you will be able to:
1. **Implement cryptographic hash functions** using Python's hashlib library
2. **Create HMAC systems** for message authentication with secret keys
3. **Build digital signature verification** using public key cryptography
4. **Design secure password storage** with salting and proper hashing
5. **Analyze hash-based security vulnerabilities** including rainbow table attacks
6. **Apply hash functions** in real-world security scenarios

## Start Here (5 minutes)

1. **Complete readings** - [Required Reading](#-step-1-readings-90-minutes) (90 minutes)
2. **Follow tutorial** - [Tutorial](tutorial.md) (2 hours)
3. **Complete assignment** - [Assignment](assignment.md) (2 hours)
4. **Take quiz** - Quiz available in Canvas

## 📚 **Step 1: Readings (90 minutes)**

**Core Cryptographic Concepts** *(Required)*:
- **Crypto101 Chapter 5**: Hash Functions *(30 min)*
  - Focus: SHA family, collision resistance, one-way properties
- **Crypto101 Chapter 6**: Message Authentication Codes *(30 min)*  
  - Focus: HMAC implementation and security properties
- **Crypto101 Chapter 7**: Digital Signatures *(30 min)*
  - Focus: RSA signatures, verification process, non-repudiation

**📖 Reading Success Check**: Can you explain the difference between hash functions, HMACs, and digital signatures, and when to use each?

### Additional Required Reading (4 hours total)
📖 **Complete these readings before starting the tutorial:**

1. **"Crypto 101" by Laurens Van Houtven**
   - **Link**: https://www.crypto101.io/
   - **Chapters**: 5-7 (Hash Functions, MACs, Digital Signatures)
   - **Pages**: 66-120
   - **Focus**: SHA-256, HMAC construction, RSA signatures

2. **NIST SP 800-107r1: Hash Algorithm Recommendations**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
   - **Pages**: 1-12 (Sections 1-5)
   - **Focus**: Approved hash functions, security considerations

3. **RFC 2104: HMAC Specification**
   - **Link**: https://datatracker.ietf.org/doc/html/rfc2104
   - **Focus**: HMAC construction and security properties

4. **Anderson's Security Engineering**
   - **Chapter**: 5.3 (Hash Functions and Message Authentication)
   - **Link**: https://www.cl.cam.ac.uk/~rja14/Papers/SEv3-ch5-7sep.pdf
   - **Focus**: Practical applications and attacks

### Optional Supplementary Materials (1 hour)
🎥 **For deeper understanding:**

- **Video**: "How Secure is 256 Bit Security?" - 3Blue1Brown
  - **Link**: https://www.youtube.com/watch?v=S9JGmA5_unY
  - **Length**: 20 minutes
  - **Value**: Intuitive understanding of cryptographic strength

- **Blog**: "A Few Thoughts on Cryptographic Engineering" - Matthew Green
  - **Link**: https://blog.cryptographyengineering.com/
  - **Focus**: Real-world crypto attacks and defenses

## 🛠️ **Step 2: Tutorial (3 hours)**

**What You'll Build**: Complete document integrity system with hash verification and digital signatures

**Learning Path**:
1. **Hash Function Implementation** *(45 min)*: SHA-256 and collision detection
2. **HMAC Authentication** *(45 min)*: Message authentication with secret keys  
3. **Digital Signature System** *(45 min)*: RSA signature creation and verification
4. **Password Security** *(45 min)*: Secure password hashing with salt

**🎥 Tutorial Success Check**: Your system can verify document integrity, authenticate messages, and validate digital signatures using industry-standard algorithms.

### Tutorial Overview

This week's hands-on tutorial covers:

1. **Part 1**: Basic hashing with SHA-256 (30 min)
2. **Part 2**: Secure password hashing and storage (60 min)
3. **Part 3**: Message Authentication Codes (HMAC) (45 min)
4. **Part 4**: Digital signatures with RSA (90 min)
5. **Part 5**: File integrity monitoring system (60 min)

**Tutorial Location**: [tutorial.md](tutorial.md)

## 🔍 Conceptual Overview

### Hash Functions vs Encryption vs Digital Signatures

| Function | Purpose | Key Usage | Output |
|----------|---------|-----------|---------|
| **Hash** | Data integrity | No key | Fixed-size digest |
| **Encryption** | Confidentiality | Shared secret | Variable-size ciphertext |  
| **Digital Signature** | Authentication | Private/public key pair | Signature + original data |

### This Week's Cryptographic Primitives

1. **SHA-256**: Secure Hash Algorithm producing 256-bit digests
2. **HMAC**: Hash-based Message Authentication Code for integrity + authenticity
3. **RSA Signatures**: Public-key digital signatures for non-repudiation
4. **PBKDF2**: Password-Based Key Derivation Function for secure password storage

## 📋 Pre-Tutorial Checklist

Before starting the tutorial, ensure you have:

- [ ] Completed all required readings
- [ ] Week 1 assignment submitted and validated
- [ ] Python environment active with required packages
- [ ] Understanding of symmetric encryption from Week 1
- [ ] **Git configured with your name and course identifier** (if not done in Week 1)

**Install additional packages**:
```bash
pip install cryptography hashlib-compat
```

**Set up Week 2 feature branch**:
```bash
# Ensure you're in your course repository and up-to-date
cd CSCI347_f25
git checkout main
git pull upstream main

# Create feature branch for Week 2 assignment  
git checkout -b week02-hashing-assignment

# Navigate to your Week 2 assignment directory
cd assignments/CSCI347_f25_Jane_Smith/week02  # Use your actual name

# Verify git configuration
git config --get user.name    # Should show "Jane Smith - CSCI347_f25"
git config --get user.email   # Should show your university email
```

**Verify your setup**:
```bash
python -c "import hashlib; print('Hash algorithms:', hashlib.algorithms_available)"
```

## 💻 **Step 3: Assignment (3 hours)**

**Deliverable**: Digital signature verification system for document authentication

**Core Requirements**:
- Hash-based document integrity checking
- HMAC message authentication implementation
- Digital signature creation and verification
- Secure password storage system
- Protection against common hash attacks

**🏆 Grading**: 25 points based on implementation correctness, security measures, and code quality

### Weekly Assignment: Secure Document Signing System

**Due**: End of Week 2 (see Canvas for exact deadline)  
**Estimated Time**: 3-4 hours

Build a command-line document signing and verification system that:

1. **Generates RSA key pairs** for digital signatures
2. **Signs documents** with private keys
3. **Verifies signatures** using public keys
4. **Monitors document integrity** after signing
5. **Provides audit trails** for all signing operations

**Full requirements**: [assignment.md](assignment.md)

### Assignment Deliverables
- `doc_signer.py` - Main implementation
- `keys/` - Directory for key storage
- `signatures/` - Directory for signature files
- `README.txt` - Usage instructions and design decisions
- Sample signed documents and verification reports

## ✅ **Step 4: Quiz**

**Location**: Quiz available in Canvas  
**Due**: Sunday by 11:59 PM

The quiz reinforces this week's key concepts including hash functions, HMAC, and digital signatures. Complete the quiz in Canvas after finishing your tutorial and readings.

## 🎯 **Week 2 Success Metrics**

**Minimum Success** *(Pass)*:
- [ ] Basic hash function implementation working
- [ ] Simple HMAC system functional
- [ ] Elementary digital signature verification
- [ ] Quiz completed in Canvas

**Target Success** *(B Grade)*:
- [ ] Comprehensive hash system with error handling
- [ ] Secure HMAC implementation with proper key management
- [ ] Complete digital signature system with verification
- [ ] Quiz completed in Canvas

**Excellence** *(A Grade)*:
- [ ] Advanced hash system with attack protection
- [ ] Production-ready HMAC with security best practices
- [ ] Professional digital signature implementation
- [ ] Quiz completed in Canvas
- [ ] Creative security enhancements and optimizations

## 🗓️ **Recommended Schedule**

| **Day** | **Activity** | **Time** | **Goal** |
|---------|--------------|----------|----------|
| **Mon** | Hash function readings | 90 min | Understand cryptographic hash theory |
| **Tue** | Tutorial: Hash implementation | 90 min | Build working hash system |
| **Wed** | Tutorial: HMAC system | 90 min | Add message authentication |
| **Thu** | Tutorial: Digital signatures | 90 min | Complete signature verification |
| **Fri** | Assignment work | 90 min | Document integrity system |
| **Sat** | Assignment completion | 90 min | Testing and documentation |
| **Sun** | Quiz and final review | Final review | **DEADLINE: 11:59 PM** |

### Alternative Schedule (7-8 hours total)
```
Day 1-2: Readings + tutorial start (3-4 hours)
Day 3-4: Complete tutorial + quiz (2.5-3 hours)
Day 5-6: Document signing assignment (2-3 hours)  
Day 7: Review and submit
```

## ✅ Self-Assessment

### Check Your Understanding
Answer these questions after completing the tutorial:

1. **Why can't hash functions be reversed** to find the original input?
2. **How does HMAC provide both integrity and authenticity** while hashes alone only provide integrity?
3. **What's the difference between RSA encryption and RSA signatures**?
4. **Why do we use salt when hashing passwords**?
5. **How do digital signatures provide non-repudiation**?

### Validation Script
Run the automated checker to verify your tutorial work:

```bash
python check-week2.py
```

**Expected output**: All cryptographic operations should work correctly.

## 🤝 Getting Help

### Common Issues
- **Hash collisions**: Understand theoretical vs. practical collision resistance
- **Signature verification failures**: Check key pairs match and data integrity
- **HMAC mismatches**: Ensure same key and message are used
- **Performance issues**: Large files may take time to hash

### Where to Ask Questions
1. **GitHub Issues**: Technical problems with cryptographic implementations  
2. **Canvas Discussions**: Conceptual questions about hash functions and signatures
3. **Office Hours**: Complex debugging and advanced cryptographic topics

## 📈 **Connection to Course Goals**

**This Week Contributes To**:
- **Learning Objective #1**: "Implement cryptographic protocols" → Hash functions and digital signatures
- **Learning Objective #2**: "Design secure authentication systems" → HMAC and signature verification
- **Learning Objective #7**: "Automate security processes using Python" → Cryptographic implementations

**Builds Toward**:
- **Week 3**: PKI systems and certificate-based authentication
- **Week 4**: Multi-factor authentication with hash-based components
- **Future Weeks**: Hash-based integrity checking in forensics and monitoring

## 🔍 Going Deeper (Optional)

### Advanced Topics
1. **Hash-based signatures**: Merkle signatures and post-quantum security
2. **Zero-knowledge proofs**: Proving knowledge without revealing information
3. **Commitment schemes**: Using hashes for secure commitments
4. **Cryptocurrency**: How Bitcoin uses hashing and digital signatures

### Research Challenges
- **Implement a Merkle tree** for efficient batch verification
- **Create a simple blockchain** using hash chains
- **Build a timestamping service** using digital signatures
- **Analyze hash function attacks** (length extension, collision attacks)

## 🎓 Professional Context

### Industry Applications
- **Digital forensics**: File integrity and evidence authentication
- **Software distribution**: Code signing and package integrity
- **Certificate authorities**: Root certificate signing
- **Audit systems**: Tamper-evident logging

### Career Relevance
- **Digital forensics examiner**: Ensuring evidence integrity
- **Security architect**: Designing secure authentication systems
- **DevOps engineer**: Implementing secure CI/CD pipelines
- **Compliance auditor**: Verifying data integrity controls

## 💡 **Week 2 Key Insights**

**Security Principles**:
- **Hash functions are one-way**: Easy to compute forward, impossible to reverse
- **Collisions are theoretically possible**: But computationally infeasible with proper algorithms
- **Salt prevents rainbow tables**: Always use unique salt for password hashing
- **HMAC provides authenticity**: Proves message came from someone with the secret key
- **Digital signatures provide non-repudiation**: Only private key holder could create signature

**Common Mistakes to Avoid**:
- Using MD5 or SHA-1 for security purposes (both cryptographically broken)
- Storing passwords without salt (vulnerable to rainbow table attacks)
- Using simple hash instead of HMAC for authentication
- Not verifying digital signatures properly
- Assuming hash functions provide encryption (they don't!)

## 📊 Key Concepts Summary

| Concept | Week 1 (Encryption) | Week 2 (Hashing/Signatures) |
|---------|-------------------|----------------------------|
| **Purpose** | Confidentiality | Integrity & Authentication |
| **Reversible** | Yes (with key) | No (one-way function) |
| **Key Type** | Symmetric | None (hash) or Asymmetric (signatures) |
| **Output Size** | Variable | Fixed |
| **Performance** | Fast | Very fast (hash), Slow (signatures) |

## 🚀 Next Week Preview

**Week 3: PKI and Certificate Management** will cover:
- X.509 certificates and certificate authorities
- RSA and ECDSA key pair generation
- Certificate signing requests (CSRs)
- TLS/SSL handshake and certificate chains
- Building your own Certificate Authority

**Preparation**: Review public-key cryptography concepts and X.509 certificate format.

---

**Ready to start?** Complete the required readings, then proceed to [tutorial.md](tutorial.md).

**Questions?** Check the troubleshooting guide or post in Canvas discussions.

---

*💡 **Pro Tip**: Hash functions are the foundation of modern cryptography. Master them this week, and you'll understand how digital signatures, password security, blockchain, and forensic integrity checking all work!*