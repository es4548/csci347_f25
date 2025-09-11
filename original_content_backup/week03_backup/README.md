# 🔐 Week 3 Overview: PKI & Certificate Management

**⏰ Due Date**: Sunday, September 21, 2025 at 11:59 PM  
**📊 Total Time**: 8-9 hours | **🎯 Points Available**: 35 points  
**🧠 Cognitive Level**: Application → Analysis (Bloom's Taxonomy)

---

## 📋 **This Week's Checklist**

```
Progress: [░░░░░░░░░░] 0%

□ 📖 Complete readings (90 min)
□ 🎥 Finish tutorial (4 hours) 
□ 💻 Submit assignment (3 hours)
□ ✅ Complete quiz in Canvas by Sunday
```

---

## 🎯 **Learning Objectives (What You'll Master)**

By the end of this week, you will be able to:
1. **Generate** and manage X.509 certificates using Python cryptography
2. **Build** a complete Certificate Authority (CA) infrastructure  
3. **Validate** certificate chains and trust relationships
4. **Implement** certificate lifecycle management with CSRs and revocation
5. **Deploy** PKI systems for secure enterprise communications

## Start Here (5 minutes)

1. **Complete readings** - [Required Reading](#-step-1-readings-90-minutes) 
2. **Follow tutorial** - [Tutorial](tutorial.md)
3. **Complete assignment** - [Assignment](assignment.md) 
4. **Take quiz** - Quiz available in Canvas

## 📚 **Step 1: Readings (90 minutes)**

**Core Reading** *(Required)*:
- **Bulletproof SSL and TLS** - Chapter 1 *(Free online)*
  - Focus: TLS handshake and certificate validation process
  - Why: Foundation for understanding PKI in practice

**Technical Standards**:
- **NIST SP 800-32** - Chapters 1-3 *(PKI fundamentals)*
  - Focus: Certificate authorities and trust models
  - Why: Industry-standard PKI architecture principles

**Real-World Context**:
- **Let's Encrypt "How It Works"** *(15 min read)*
  - Focus: Automated certificate management (ACME protocol)
  - Why: Modern PKI deployment practices

**Optional Deep Dive** *(If time permits)*:
- Mozilla CA Certificate Policy *(Advanced requirements)*

**📖 Reading Success Check**: Can you explain the difference between a root CA and intermediate CA?

### Required Reading (5 hours total)

1. **"Bulletproof SSL and TLS" Free Chapters**
   - **Link**: https://www.feistyduck.com/library/bulletproof-tls-guide/online/
   - **Chapter**: 1 (SSL, TLS, and Cryptography)
   - **Focus**: TLS handshake, certificate validation

2. **NIST SP 800-32: Public Key Technology Introduction**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-32.pdf
   - **Chapters**: 1-3 (PKI fundamentals)
   - **Focus**: Certificate authorities, trust models

3. **Let's Encrypt: "How It Works"**
   - **Link**: https://letsencrypt.org/how-it-works/
   - **Focus**: Automated certificate management (ACME protocol)

4. **Mozilla CA Certificate Policy**
   - **Link**: https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
   - **Focus**: Real-world certificate requirements and validation

## 🛠️ **Step 2: Tutorial (4 hours)** 

**What You'll Build**: A complete PKI system with certificate authority

**Learning Path**:
1. **Module 1** *(45 min)*: X.509 certificate structure and generation
2. **Module 2** *(60 min)*: Certificate Authority infrastructure setup
3. **Module 3** *(45 min)*: Certificate Signing Requests (CSRs) and issuance
4. **Module 4** *(60 min)*: Certificate validation and trust chain verification
5. **Module 5** *(30 min)*: Certificate lifecycle management and revocation

**🎥 Tutorial Success Check**: Your CA can issue, validate, and revoke certificates correctly

**Stuck?** Don't spend more than 30 minutes on any one problem. Post in Canvas discussions or check troubleshooting guide.

### Tutorial Overview

This week's tutorial covers:

1. **Part 1**: X.509 certificate structure and generation (45 min)
2. **Part 2**: Building a Certificate Authority (60 min)
3. **Part 3**: Certificate Signing Requests and issuance (45 min)
4. **Part 4**: TLS/SSL implementation and validation (90 min)
5. **Part 5**: Certificate lifecycle management (45 min)

## 💻 **Step 3: Assignment (3 hours)**

**Deliverable**: Enterprise Certificate Authority system with CLI interface

**What You'll Build**:
- Self-signed root CA with proper extensions
- CSR processing and certificate issuance workflow
- Certificate validation against CA trust chain  
- Certificate revocation list (CRL) management
- Professional command-line interface

**Submission**: 
- Complete ca_system.py with all required features
- Certificate database tracking issued certificates
- README.txt with usage instructions and security notes
- Working demonstration of full certificate lifecycle

**🏆 Grading**: 25 points based on PKI functionality, security practices, and CLI design

### Weekly Assignment: Mini Certificate Authority

Build a complete PKI system that:
1. **Creates root and intermediate CAs** with proper certificate chains
2. **Issues server and client certificates** for testing
3. **Implements certificate revocation** checking
4. **Provides TLS server/client** demonstration
5. **Manages certificate lifecycle** including renewal

## ✅ **Step 4: Quiz**

**Location**: Quiz available in Canvas  
**Due**: Sunday by 11:59 PM

The quiz reinforces this week's key PKI concepts and certificate management practices. Complete the quiz in Canvas after finishing your tutorial and assignment work.

## ✅ Self-Assessment Questions

1. **What's the difference between a root CA and intermediate CA?**
2. **How does certificate chain validation work?**
3. **Why are certificate extensions important?**
4. **What happens during a TLS handshake?**
5. **How do browsers validate SSL certificates?**

## 🎯 **Week 3 Success Metrics**

**Minimum Success** *(Pass)*:
- [ ] CA can generate root certificate and issue client certificates
- [ ] Quiz completed in Canvas
- [ ] Assignment submitted on time with basic functionality

**Target Success** *(B Grade)*:
- [ ] All tutorial modules completed with working PKI system
- [ ] Quiz completed in Canvas
- [ ] Assignment includes certificate validation and CLI interface

**Excellence** *(A Grade)*:
- [ ] Complete CA system with revocation and security features
- [ ] Quiz completed in Canvas
- [ ] Code demonstrates PKI best practices and professional documentation

## 🗓️ **Recommended Schedule**

**🗓️ Flexible Pacing Within the Week**:

| **Day** | **Activity** | **Time** | **Goal** |
|---------|--------------|----------|----------|
| **Mon** | Start readings | 90 min | Understand PKI fundamentals |
| **Tue** | Tutorial Modules 1-2 | 2 hours | Certificate generation working |
| **Wed** | Tutorial Modules 3-4 | 2 hours | CA infrastructure and CSR processing |
| **Thu** | Tutorial Module 5 + Begin assignment | 2 hours | Certificate lifecycle + CA system start |
| **Fri** | Continue assignment | 2 hours | CLI interface and validation |
| **Sat** | Finish assignment + Review | 1 hour | Documentation and quiz prep |
| **Sun** | Take quiz | Final review | **DEADLINE: 11:59 PM** |

## 📈 **Connection to Course Goals**

**This Week Contributes To**:
- **Learning Objective #2**: "Design secure authentication and authorization systems"
- **Learning Objective #4**: "Evaluate and implement cryptographic protocols"
- **Learning Objective #6**: "Analyze digital certificate management and PKI systems"

**Builds On**:
- **Week 1**: Symmetric encryption foundations for certificate protection
- **Week 2**: Digital signatures for certificate validation and trust

**Builds Toward**:
- **Week 4**: Authentication systems using certificate-based authentication
- **Project 2** *(Week 6-7)*: Secure web services with TLS/SSL
- **Week 8**: Network security protocols that rely on PKI infrastructure

**Career Relevance**: PKI and certificate management are critical for enterprise security, cloud infrastructure, and DevSecOps practices.

## 🆘 **Getting Help This Week**

**Technical Issues**:
1. Check `troubleshooting-pki.md` for certificate generation problems
2. Post in Canvas discussions with error messages and code snippets
3. Submit GitHub issue for assignment-specific CA system problems

**Conceptual Questions**:
1. Attend office hours (T/Th or by appointment) for PKI architecture questions
2. Email instructor for certificate validation clarifications
3. Form study groups to work through certificate chain problems

**Time Management**:
- PKI concepts can be complex - break tutorial into daily segments
- Use the 30-minute rule: get help if stuck on certificate errors
- Focus on understanding trust relationships over memorizing syntax

## 🔒 **Security Considerations This Week**

**Important Notes**:
- **Never use tutorial CAs in production** - these are for learning only
- **Protect private keys** - treat CA keys as highly sensitive
- **Understand trust implications** - adding CAs to trust stores has security impact
- **Certificate validation matters** - improper validation creates vulnerabilities

**Best Practices You'll Learn**:
- Proper certificate extensions for different use cases
- Secure serial number generation to prevent conflicts
- File permissions for protecting CA private keys
- Certificate revocation and CRL management

## 🎉 **Week 3 Completion**

**Once Everything is Done**:
- [ ] Update your progress tracker
- [ ] Reflect: How does PKI enable trust in distributed systems?
- [ ] Preview Week 4 authentication systems materials
- [ ] Test your CA system with different certificate types
- [ ] Celebrate building enterprise-grade security infrastructure! 🎉

**Ready for Week 4?** You'll use your PKI knowledge to implement robust authentication systems with certificate-based authentication.

## 🏆 **Professional Development Bonus**

**Industry Connections**:
- Your CA system demonstrates skills directly applicable to:
  - DevOps/DevSecOps certificate automation
  - Cloud infrastructure security (AWS ACM, GCP Certificate Manager)
  - Enterprise security architecture roles
  - Cybersecurity engineering positions

**Portfolio Value**: This assignment shows employers you can implement production-level PKI systems, not just understand concepts.

---

**Tutorial Location**: [tutorial.md](tutorial.md)  
**Assignment Details**: [assignment.md](assignment.md)

---

*💡 Remember: PKI is the foundation of internet security. Mastering certificate management opens doors to advanced cybersecurity roles and gives you skills used by every major organization.*