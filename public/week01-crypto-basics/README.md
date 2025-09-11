# 🔐 Week 1 Overview: Cryptography Foundations

**⏰ Due Date**: Sunday, September 7, 2025 at 11:59 PM  
**📊 Total Time**: 4-5 hours | **🎯 Points Available**: 25 points  
**🧠 Cognitive Level**: Knowledge → Application (Bloom's Taxonomy)

---

## 📋 **This Week's Checklist**

```
Progress: [░░░░░░░░░░] 0%

□ 📖 Complete readings (45 min)
□ 🎥 Finish tutorial (3 hours) 
□ 💻 Submit assignment (3 hours)
□ ✅ Complete quiz in Canvas by Sunday
```

---

## 🎯 **Learning Objectives**

By the end of this week, you will be able to:
1. **Implement** symmetric encryption using industry-standard AES
2. **Generate** and manage cryptographic keys securely  
3. **Build** a password vault with proper key derivation
4. **Apply** security best practices for file encryption
5. **Explain** why certain cryptographic choices matter

---

## 🚀 **Quick Start Guide**

### Start Here (5 minutes)

1. **Set up environment** - [Environment Setup](environment-setup.md) (15-20 min)
2. **Read first** - [Crypto 101 Ch 1-2](https://www.crypto101.io/) (45 min)
3. **Then practice** - [Tutorial](tutorial.md) (3 hours)
4. **Build project** - [Assignment](assignment.md) (3 hours)
5. **Test knowledge** - Quiz available in Canvas

**Need help?** - Check [troubleshooting guide](../resources/troubleshooting.md) or post in Canvas discussions

---

## 📚 **Required Reading (45 minutes)**

### Core Concepts - Complete These First

1. **"Crypto 101" by Laurens Van Houtven** ⭐ **CORE**
   - **Link**: https://www.crypto101.io/
   - **Chapters**: 1-2 only (pages 1-30)
   - **Focus**: Basic cryptography concepts, terminology

2. **Python Cryptography Documentation** ⭐ **CORE**
   - **Link**: https://cryptography.io/en/latest/
   - **Section**: "Fernet (Symmetric Encryption)" - Quick Start only
   - **Focus**: Practical implementation basics

### Optional Deep Dive (If Time Permits)
- **Crypto 101 Chapters 3-4** - Stream and Block Ciphers (pages 31-65)
- **NIST Key Management Guidelines** - [SP 800-175B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf) (Executive Summary only)

**📖 Reading Success Check**: Can you explain what "symmetric encryption" means in plain English?

---

## 🛠️ **Tutorial Overview (3 hours)**

**What You'll Build**: A secure password vault application

### Learning Path
1. **Part 1** (30 min): Basic string encryption/decryption
2. **Part 2** (90 min): File encryption and key management
3. **Part 3** (45 min): Understanding encryption modes
4. **Part 4** (60 min): Password-based key derivation

**Tutorial Location**: [tutorial.md](tutorial.md)

**🎥 Tutorial Success Check**: Your password vault encrypts/decrypts files correctly

**Stuck?** Don't spend more than 30 minutes on any one problem. Post in Canvas discussions!

---

## 💻 **Assignment: Secure File Encryptor (3 hours)**

**Due**: End of Week 1 (see Canvas for exact deadline)  
**Points**: 25 points

### What You'll Build
A command-line file encryption tool that:
1. **Encrypts and decrypts files** using password-derived keys
2. **Uses secure key derivation** (PBKDF2) from passwords
3. **Handles basic error cases** gracefully
4. **Provides clean CLI interface** for encrypt/decrypt operations

### Professional Features to Add
- Master password strength validation
- Backup key generation and recovery
- Professional error handling and logging
- Comprehensive documentation and testing

**Full requirements**: [assignment.md](assignment.md)

### Submission Instructions

#### Step 1: Create Pull Request
1. **Push your code** to your forked repository:
   ```bash
   git add .
   git commit -m "Complete Week 1 cryptography assignment"
   git push origin week01-assignment
   ```

2. **Create Pull Request** on GitHub with description including:
   - Summary of implementation approach
   - Security considerations addressed
   - Challenges encountered and solutions
   - Testing approach used

#### Step 2: Submit to Canvas
1. **Copy the Pull Request URL**
2. **Go to Canvas** → Week 1 Assignment  
3. **Paste the PR URL** in the submission box
4. **Submit**

### Required Files in Your PR
- `password_vault.py` - Main implementation
- `README.md` - Usage instructions and design decisions
- `tests/` - Test files demonstrating functionality
- `examples/` - Usage examples

**🏆 Grading**: Based on functionality (40%), code quality (30%), documentation (20%), testing (10%)

---

## ✅ **Quiz**

**Location**: Quiz available in Canvas  
**Due**: Sunday by 11:59 PM

The quiz reinforces this week's key concepts from the tutorial and readings. Take the quiz in Canvas after completing your tutorial and assignment work.

---

## 🎯 **Success Metrics**

### Minimum Success (Pass)
- [ ] Password vault works with basic encryption/decryption
- [ ] Quiz completed in Canvas
- [ ] Assignment submitted on time

### Target Success (B Grade)
- [ ] All tutorial modules completed correctly
- [ ] Quiz completed in Canvas
- [ ] Assignment includes most required features

### Excellence (A Grade)
- [ ] Enhanced password vault with all professional features
- [ ] Quiz completed in Canvas
- [ ] Code demonstrates security best practices and clear documentation

---

## 🗓️ **Recommended Schedule**

| Day | Activity | Time | Deliverable |
|-----|----------|------|-------------|
| Mon-Tue | Readings + Tutorial Start | 3-4 hours | Understanding + Basic Code |
| Wed-Thu | Tutorial Completion | 2 hours | Working Password Vault |
| Fri-Sat | Assignment | 2-3 hours | Enhanced Features |
| Sun | Review, Test & Submit | 30 min | Final Submission by 11:59 PM |

**Need more time?** See [Appendix B: Alternative Pacing Options](#appendix-b-alternative-pacing-options)

---

## ⚡ **Environment Setup**

**🚨 First time here?** → [Complete Environment Setup](environment-setup.md) (15-20 min)

**✅ Already set up?** Verify:
```bash
python week01-crypto-basics/verify-environment.py
```

Expected output: All tests should pass before starting the tutorial.

---

## ✅ **Self-Assessment Questions**

After completing the tutorial, you should be able to answer:
1. **Why is the same plaintext encrypted to different ciphertexts** each time with Fernet?
2. **What happens if you lose the encryption key** for your data?
3. **Why shouldn't you use ECB mode** for encrypting files?
4. **How does salt protect** against rainbow table attacks?

---

## 🤝 **Getting Help**

### Common Issues
- **Import errors**: Ensure virtual environment is activated
- **Permission errors**: Don't use `sudo` with pip in virtual environments
- **Decryption failures**: Check you're using the correct key

### Where to Ask Questions
1. **Canvas Discussions**: Conceptual questions and peer help
2. **Office Hours**: Complex debugging and advanced topics
3. **GitHub Issues**: Technical problems with course materials

### Time Management Tips
- Aim for 1-2 hours daily rather than cramming
- Use the 30-minute rule: get help if stuck longer
- Focus on understanding over perfection

---

## 📈 **Connection to Course**

**This Week Contributes To**:
- Learning Objective #1: "Implement cryptographic systems for secure communications"
- Learning Objective #7: "Automate security processes using Python scripting"

**Builds Toward**:
- Week 2: Digital signatures and document integrity
- Week 3: Public key infrastructure and certificates
- Project 1 (Weeks 4-5): Enterprise MFA system

**Career Relevance**: Password management and encryption are fundamental to every cybersecurity role.

---

## 🚀 **Next Week Preview**

**Week 2: Hashing and Digital Signatures** will cover:
- SHA-256 and secure hashing functions
- Hash-based Message Authentication Codes (HMAC)
- Digital signatures with RSA and ECDSA
- Password hashing with salt and iterations
- File integrity monitoring systems

**Preparation**: Review basic number theory and modular arithmetic concepts.

---

## 🎉 **Week 1 Completion**

**Once Everything is Done**:
- [ ] Update your progress tracker
- [ ] Reflect: What was most challenging? Most interesting?
- [ ] Preview Week 2 materials
- [ ] Celebrate completing your first cybersecurity implementation! 🎉

---

**Ready to start?** Complete the required readings, then proceed to [tutorial.md](tutorial.md).

**Questions?** Check the troubleshooting guide or post in Canvas discussions.

---

# Appendix A: Advanced Topics and Professional Context

## 🔍 Going Deeper (Optional)

### Professional Development Opportunities
*Available to all students - no bonus points, just learning enrichment*

#### Industry Certification Preparation
This week's content directly maps to:
- **CompTIA Security+ CE**: Cryptography (15% of exam)
- **CISSP**: Domain 3 - Security Architecture and Engineering
- **CEH**: Module 20 - Cryptography

**Study Enhancement:**
- Practice with **CyberAces** cryptography challenges
- Complete **Cryptopals** crypto challenges (cryptopals.com)
- Take practice tests focusing on symmetric encryption

#### Advanced Research Challenges
1. **Post-quantum cryptography**: Implement lattice-based encryption
2. **Hardware security modules**: Research cloud HSM services (AWS KMS, Azure Key Vault)
3. **Side-channel attacks**: Analyze timing attacks on your implementation
4. **Formal verification**: Use cryptographic proofs to verify your algorithms

#### Industry Connections
- **Join professional organizations**: (ISC)² membership, ISACA student chapters
- **Attend virtual conferences**: RSA Conference, Black Hat, DEF CON (student rates)
- **Follow industry experts**: Dan Boneh (Stanford), Matthew Green (Johns Hopkins)
- **Contribute to open source**: Submit PRs to cryptography libraries

#### Real-World Applications
- **Enterprise scenarios**: How would Netflix encrypt streaming content?
- **Compliance requirements**: HIPAA encryption standards for healthcare data
- **Mobile security**: How does Signal implement end-to-end encryption?
- **Cloud security**: AWS S3 server-side encryption implementation

## 🎓 Professional Context

### Industry Applications
- **Data-at-rest encryption**: Database and file system encryption
- **Backup encryption**: Secure offsite storage
- **Application security**: Protecting sensitive user data
- **Compliance**: GDPR, HIPAA encryption requirements

### Career Relevance
- **Security Engineering**: Implementing encryption in products
- **SOC Analysis**: Understanding encrypted malware communication
- **Digital Forensics**: Dealing with encrypted evidence
- **Penetration Testing**: Bypassing weak encryption implementations

---

# Appendix B: Alternative Pacing Options

## For Well-Prepared Students
```
Day 1-2: Complete readings + start tutorial (3-4 hours)
Day 3-4: Finish tutorial + take quiz (2.5-3 hours)  
Day 5-6: Complete assignment (2-3 hours)
Day 7: Review and submit
```

## For Students Needing Extra Support
```
Day 1: Prerequisites review + setup (1-2 hours)
Day 2-3: Tutorial Module 1-2 only (3-4 hours) 
Day 4: Tutorial Module 3-4 + get help if stuck (3-4 hours)
Day 5: Start assignment with template (2-3 hours)
Day 6: Finish assignment + ask for help (2-3 hours)
Day 7: Review, test, and submit

Total: 12-15 hours (it's okay to take longer while learning)
```

**🚨 Time Management Rules:**
- **Don't spend more than 30 minutes stuck** without asking for help
- **Use office hours** - they're specifically for you
- **Focus on running code** before understanding theory
- **It's okay to submit working code** even if you don't understand every detail

*The tutorial includes comprehensive explanations and examples to support your learning whether you engage deeply with readings or use them as reference material.*

---

*💡 Remember: This course is designed for your success. Every week builds on the previous, and help is always available when you need it.*