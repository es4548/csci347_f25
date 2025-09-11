# 🔐 Week 3 Overview: PKI & Certificate Analysis

**⏰ Due Date**: Sunday, September 21, 2025 at 11:59 PM  
**📊 Total Time**: 4-5 hours | **🎯 Points Available**: 25 points  
**🧠 Cognitive Level**: Knowledge → Application → Analysis (Bloom's Taxonomy)

---
*Updated for Fall 2025*

## 📋 **This Week's Checklist**

```
Progress: [░░░░░░░░░░] 0%

□ 📖 Complete readings (60 min) - X.509 certificates, trust chains, validation
□ 🎥 Finish tutorial (2.5 hours) - Certificate analysis and validation techniques  
□ 💻 Submit assignment (1.5 hours) - Certificate analyzer tool
□ ✅ Complete quiz in Canvas by Sunday
```

---

## 🎯 **Learning Objectives (What You'll Master)**

By the end of this week, you will be able to:
1. **Analyze** X.509 certificate structure and extract key information
2. **Validate** certificate chains and understand trust relationships  
3. **Identify** common certificate security issues and vulnerabilities
4. **Use** professional tools to inspect and verify certificates
5. **Evaluate** certificate security properties and potential weaknesses
6. **Apply** certificate validation in real-world security scenarios

## Start Here (5 minutes)

1. **Complete readings** - [Required Reading](#-step-1-readings-60-minutes) 
2. **Follow tutorial** - [Tutorial](tutorial.md) (2.5 hours)
3. **Complete assignment** - [Assignment](assignment.md) (1.5 hours)
4. **Take quiz** - Quiz available in Canvas

## 📚 **Step 1: Readings (60 minutes)**

**Core Reading** *(Required)*:
- **Bulletproof SSL and TLS** - Chapter 1 *(30 min)*
  - Focus: Certificate validation process and trust chains
  - Why: Understanding how browsers verify certificates

**Technical Standards**:
- **X.509 Certificate Overview** - RFC 5280 sections 1-3 *(20 min)*  
  - Focus: Certificate structure and standard fields
  - Why: Technical foundation for certificate analysis

**Real-World Context**:
- **Certificate Transparency** - Overview *(10 min)*
  - Focus: How CT logs detect rogue certificates
  - Why: Modern certificate security monitoring

**📖 Reading Success Check**: Can you explain how a browser validates a certificate chain?

## 🛠️ **Step 2: Tutorial (2.5 hours)** 

**What You'll Learn**: How to analyze and validate X.509 certificates

**Learning Path**:
1. **Module 1** *(45 min)*: Certificate structure and parsing with Python
2. **Module 2** *(60 min)*: Certificate chain validation techniques
3. **Module 3** *(45 min)*: Real-world certificate analysis and security issues

**🎥 Tutorial Success Check**: You can download, parse, and validate any website's certificate

**Key Skills Developed**:
- Using Python's cryptography library for certificate analysis
- Understanding certificate extensions and their security implications  
- Identifying certificate validation errors and their causes
- Analyzing certificate chains from leaf to root

## 💻 **Step 3: Assignment (1.5 hours)**

**What You'll Build**: Certificate analyzer and validator tool

**Core Requirements**:
- Parse and display certificate information from files or websites
- Validate certificate chains and identify trust issues
- Analyze real-world certificates and document findings
- Create professional analysis report

**Skills Applied**:
- Certificate parsing and field extraction
- Chain validation and trust verification
- Security analysis and vulnerability identification
- Professional security documentation

## ✅ **Step 4: Quiz**

**Location**: Quiz available in Canvas  
**Time**: 15 minutes  
**Focus**: Certificate analysis concepts, validation process, security implications

The quiz tests your understanding of certificate structure, trust chains, and validation techniques covered in the readings and tutorial.

**Quiz Success Check**: You can identify certificate security issues and explain validation failures

## 📅 **Suggested Schedule**

| Day | Task | Time | Focus |
|-----|------|------|-------|
| **Mon** | Complete readings | 1 hour | Certificate fundamentals |
| **Tue** | Tutorial Module 1 | 45 min | Certificate parsing |
| **Wed** | Tutorial Module 2 | 1 hour | Chain validation |
| **Thu** | Tutorial Module 3 | 45 min | Security analysis |
| **Fri** | Start assignment | 1 hour | Build analyzer tool |
| **Sat** | Finish assignment | 30 min | Analysis report |
| **Sun** | Take quiz | 15 min | **DEADLINE: 11:59 PM** |

## 🔧 **Technical Setup**

This week requires:
- Python 3.11+ with cryptography library
- OpenSSL command line tools (for reference)
- Access to download certificates from websites
- Text editor for analysis reports

**Setup Verification**:
```python
from cryptography import x509
import ssl
print("✅ Ready for certificate analysis!")
```

## 💡 **Pro Tips for Success**

1. **Start with familiar websites**: Analyze certificates from sites you know (Google, GitHub)
2. **Use multiple validation tools**: Compare Python results with OpenSSL output
3. **Focus on security implications**: Why do validation failures matter?
4. **Document everything**: Good analysis reports help with quiz preparation
5. **Ask "what if" questions**: What happens if this certificate expires?

## 📊 **Assessment Breakdown**

- **Tutorial Completion** (Formative): Certificate parsing and validation techniques
- **Assignment** (25 points): Certificate analyzer tool and analysis report  
- **Quiz** (Canvas): Certificate analysis concepts and security principles

## 🚨 **Common Pitfalls to Avoid**

1. **Don't confuse parsing with building**: Focus on analyzing existing certificates
2. **Don't ignore certificate extensions**: They contain critical security information
3. **Don't skip error handling**: Certificate parsing can fail in many ways
4. **Don't forget the security angle**: Always ask "what are the security implications?"

## 🔗 **Connection to Course**

**Previous Weeks**: 
- Week 1: Encryption concepts used in certificate signatures
- Week 2: Hash functions used for certificate fingerprints

**Next Weeks**:
- Week 4: Certificates used for authentication systems
- Week 6: TLS certificates in network security
- Week 10+: Certificate analysis in digital forensics

## 📚 **Additional Resources**

**Tools**:
- OpenSSL command line for certificate inspection
- Browser developer tools for certificate viewing
- Online certificate analyzers for comparison

**Reference Materials**:
- X.509 Certificate Profile (RFC 5280)
- Certificate Transparency documentation  
- Common certificate validation errors guide

---

**Need Help?**
- Post specific questions in Canvas discussions
- Use tutorial validation checkpoints to verify progress
- Attend office hours for debugging assistance
- Check troubleshooting guide for common issues

**Success Indicator**: You can confidently analyze any website's certificate and explain its security properties!