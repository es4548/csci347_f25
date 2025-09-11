# CSCI 347: Complete Reading List

**Course**: Network Security and Digital Forensics  
**Semester**: Fall 2025  
**Total Estimated Reading Time**: ~50 hours across 14 weeks

This document consolidates all required and supplementary readings from the course. Use this for:
- Link testing and validation
- Study planning and time management
- Quick reference for all course materials
- Comprehensive review preparation

---

## Week 1: Cryptography Basics

### Required Reading (2.5 hours)

1. **"Crypto 101" by Laurens Van Houtven** ⭐ **CORE**
   - **Link**: https://www.crypto101.io/
   - **Chapters**: 1-2 only (pages 1-30)
   - **Focus**: Basic cryptography concepts, terminology

2. **Python Cryptography Documentation** ⭐ **CORE**
   - **Link**: https://cryptography.io/en/latest/
   - **Section**: "Fernet (Symmetric Encryption)" - Quick Start only
   - **Focus**: Practical implementation basics

### Supplementary Reading (1.5 hours)

3. **"Crypto 101" Extended**
   - **Chapters**: 3-4 (Stream and Block Ciphers)
   - **Pages**: 31-65
   - **When to read**: After completing tutorial

4. **NIST Key Management Guidelines**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf
   - **Pages**: 1-10 (Executive Summary only)
   - **Purpose**: Professional context

### Optional Materials (1 hour)

- **Video**: "AES Explained" - Computerphile
  - **Link**: https://www.youtube.com/watch?v=O4xNJsjtN6E
  - **Length**: 13 minutes

- **Interactive**: CrypTool Online AES Demo
  - **Link**: https://www.cryptool.org/en/cto/aes

---

## Week 2: Hashing and Digital Signatures

### Required Reading (4 hours)

1. **NIST FIPS 180-4: Secure Hash Standard (SHS)**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
   - **Focus**: SHA-256 algorithm and implementation

2. **"Cryptography Engineering" by Ferguson, Schneier, Kohno**
   - **Chapter**: 5 (Hash Functions)
   - **Available**: University library or online access
   - **Focus**: Hash function security properties

3. **RFC 2104: HMAC**
   - **Link**: https://tools.ietf.org/rfc/rfc2104.txt
   - **Focus**: Keyed-hash message authentication

4. **Digital Signature Standard (DSS)**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
   - **Focus**: DSA, RSA, and ECDSA algorithms

---

## Week 3: PKI and Certificates

### Required Reading (5 hours)

1. **"Bulletproof SSL and TLS" Free Chapters**
   - **Link**: https://www.feistyduck.com/library/bulletproof-tls-guide/online/
   - **Chapter**: 1 (SSL, TLS, and Cryptography)
   - **Focus**: TLS handshake, certificate validation

2. **NIST SP 800-32: Public Key Technology Introduction**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-32.pdf
   - **Focus**: PKI fundamentals and trust models

3. **RFC 5280: Internet X.509 PKI Certificate Profile**
   - **Link**: https://tools.ietf.org/rfc/rfc5280.txt
   - **Sections**: 1-4 (Certificate structure and validation)

4. **OpenSSL Cookbook**
   - **Link**: https://www.feistyduck.com/library/openssl-cookbook/online/
   - **Chapters**: 1-2 (Certificate generation and management)

---

## Week 4: Multi-Factor Authentication Systems

### Required Reading (4 hours)

1. **NIST SP 800-63-3: Digital Identity Guidelines**
   - **Link**: https://pages.nist.gov/800-63-3/
   - **Focus**: SP 800-63B (Authentication and Lifecycle Management)

2. **OWASP Authentication Cheat Sheet**
   - **Link**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

3. **Anderson's Security Engineering - Chapter 2**
   - **Link**: https://www.cl.cam.ac.uk/~rja14/book.html
   - **Focus**: Usability and Psychology in Authentication

---

## Week 5: Access Control and Authorization

### Required Reading (4 hours)

1. **NIST RBAC Paper: "Role-Based Access Controls"**
   - **Link**: https://csrc.nist.gov/CSRC/media/Publications/conference-paper/1992/10/13/role-based-access-controls/final/documents/ferraiolo-kuhn-92.pdf

2. **Anderson's Security Engineering - Chapter 4**
   - **Link**: https://www.cl.cam.ac.uk/~rja14/book.html
   - **Focus**: Access Control principles and models

3. **Google BeyondCorp Papers** (Zero Trust Architecture)
   - **Link**: https://cloud.google.com/beyondcorp#researchPapers

---

## Week 6: Network Security

### Required Reading (4 hours)

1. **NIST SP 800-41: Guidelines for Firewall and Firewall Policy**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41.pdf

2. **"Network Security Essentials" by Stallings**
   - **Chapters**: 9-10 (Firewalls and IDS/IPS)
   - **Available**: University library

3. **Wireshark Network Analysis Official Guide**
   - **Link**: https://www.wiresharkbook.com/
   - **Chapters**: 1-3 (Protocol analysis basics)

---

## Week 7: Security Monitoring

### Required Reading (4 hours)

1. **NIST SP 800-92: Guide to Computer Security Log Management**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf

2. **"Applied Network Security Monitoring" by Sanders & Smith**
   - **Chapters**: 1-4 (NSM methodology)
   - **Focus**: Detection and analysis techniques

3. **SANS Reading Room: Security Monitoring Papers**
   - **Link**: https://www.sans.org/reading-room/whitepapers/monitoring/
   - **Select**: 3-4 papers on SIEM and log analysis

---

## Week 8: Vulnerability Assessment

### Required Reading (4 hours)

1. **NIST SP 800-115: Technical Guide to Information Security Testing**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf

2. **OWASP Testing Guide v4**
   - **Link**: https://owasp.org/www-project-web-security-testing-guide/
   - **Sections**: Introduction and Testing Framework

3. **CVE and CVSS Documentation**
   - **Link**: https://www.first.org/cvss/v3.1/specification-document
   - **Focus**: Vulnerability scoring methodology

---

## Week 9: Security Architecture

### Required Reading (4 hours)

1. **NIST Cybersecurity Framework v1.1**
   - **Link**: https://www.nist.gov/cyberframework/framework
   - **Complete document**

2. **TOGAF Security Architecture**
   - **Link**: https://pubs.opengroup.org/architecture/togaf9-doc/arch/
   - **Focus**: Security architecture principles

3. **"Security Architecture: Design, Deployment, and Operations"**
   - **Authors**: Ramachandran & Pearson
   - **Chapters**: 1-3 (Architecture fundamentals)

---

## Week 10: Digital Forensics Foundations

### Required Reading (4 hours)

1. **NIST SP 800-86: Guide to Integrating Forensic Techniques**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
   - **Complete document** (Primary forensics reference)

2. **Autopsy Digital Forensics Platform**
   - **Link**: https://sleuthkit.org/autopsy/docs/user-docs/4.19.3/
   - **Sections**: Getting Started, Basic Features, File Analysis

3. **"A Practitioner's Guide to Linux as a Forensic Platform"**
   - **Link**: https://linuxleo.com/
   - **Version**: 4.94 (Free download)
   - **Chapters**: 1-5

---

## Week 11: Advanced Forensics

### Required Reading (4 hours)

1. **"File System Forensic Analysis" by Brian Carrier**
   - **Chapters**: 1-5 (File system fundamentals)
   - **Focus**: NTFS, ext4, and HFS+ analysis

2. **NIST SP 800-101: Guidelines for Mobile Device Forensics**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf

3. **The Sleuth Kit Documentation**
   - **Link**: https://sleuthkit.org/sleuthkit/docs.php
   - **Focus**: Command-line forensic tools

---

## Week 12: Memory Analysis

### Required Reading (4 hours)

1. **"The Art of Memory Forensics" by Ligh, Case, Levy & Walters**
   - **Chapters**: 1-4 (Memory acquisition and analysis)
   - **Available**: University library

2. **Volatility Framework Documentation**
   - **Link**: https://volatilityfoundation.org/releases
   - **Focus**: Memory analysis techniques

3. **SANS Memory Forensics Papers**
   - **Link**: https://www.sans.org/reading-room/whitepapers/forensics/
   - **Select**: 2-3 papers on memory analysis

---

## Week 13: Mobile Forensics

### Required Reading (4 hours)

1. **NIST SP 800-101: Mobile Device Forensics Guidelines**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf
   - **Complete document**

2. **"Practical Mobile Forensics" by Bommisetty, Tamma & Mahalik**
   - **Chapters**: 1-6 (Mobile forensics fundamentals)
   - **Available**: University library

3. **iOS and Android Security Architecture**
   - **iOS**: Apple Platform Security Guide
   - **Android**: Android Security documentation
   - **Focus**: Security models and forensic implications

---

## Week 14: Integration and Capstone

### Required Reading (4 hours)

1. **Selected Papers from Previous Weeks** (Review)
   - **NIST Cybersecurity Framework** (Week 9)
   - **NIST Forensics Guidelines** (Week 10)
   - **Key cryptography papers** (Weeks 1-3)

2. **Industry Case Studies**
   - **Selected from**: SANS Reading Room
   - **Topics**: Incident response and forensics cases
   - **Count**: 3-4 detailed case studies

3. **Professional Standards and Ethics**
   - **ISFCE Code of Ethics**
   - **ACM Code of Ethics**
   - **Legal considerations in forensics**

---

## Additional Resources

### Books (Recommended for Purchase/Library Access)
- "Security Engineering" by Ross Anderson
- "Cryptography Engineering" by Ferguson, Schneier, Kohno
- "The Art of Memory Forensics" by Ligh, Case, Levy & Walters
- "Practical Mobile Forensics" by Bommisetty, Tamma & Mahalik

### Professional Organizations
- **(ISC)²**: https://www.isc2.org/
- **SANS Institute**: https://www.sans.org/
- **International Society of Forensic Computer Examiners (ISFCE)**: https://www.isfce.com/

### Online Resources
- **NIST Cybersecurity Publications**: https://csrc.nist.gov/publications
- **OWASP**: https://owasp.org/
- **CVE Database**: https://cve.mitre.org/

---

## Enhanced Optional References by Governing Sources

### **Federal Standards and Guidelines**

#### **National Institute of Standards and Technology (NIST)**
**Core Security Framework Documents:**
- **SP 800-53 Rev 5**: Security and Privacy Controls for Information Systems
  - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **Application**: Enterprise security controls relevant to Weeks 5-9

- **SP 800-61 Rev 2**: Computer Security Incident Handling Guide
  - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
  - **Application**: Incident response procedures for Weeks 7-8

- **SP 800-94**: Guide to Intrusion Detection and Prevention Systems
  - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf
  - **Application**: Network security monitoring for Week 6-7

#### **Department of Homeland Security (DHS)**
**Cybersecurity and Infrastructure Security Agency (CISA):**
- **Cybersecurity Performance Goals (CPGs)**
  - **Link**: https://www.cisa.gov/cross-sector-cybersecurity-performance-goals
  - **Application**: Enterprise security architecture (Week 9)

- **National Cybersecurity Review (NCR)**
  - **Link**: https://www.cisa.gov/sites/default/files/publications/National_Cybersecurity_Review_Final.pdf
  - **Application**: Current threat landscape context (All weeks)

#### **Federal Bureau of Investigation (FBI)**
**Digital Forensics Standards:**
- **Scientific Working Group on Digital Evidence (SWGDE)**
  - **Link**: https://www.swgde.org/documents
  - **Application**: Professional forensics standards (Weeks 10-14)

- **FBI Laboratory Services Handbook of Forensic Services**
  - **Available through**: FBI.gov forensics section
  - **Application**: Chain of custody and evidence handling (Weeks 10-14)

#### **Department of Justice (DOJ)**
**Legal Framework for Digital Evidence:**
- **Searching and Seizing Computers and Obtaining Electronic Evidence**
  - **Link**: https://www.justice.gov/criminal-ccips/ccips-documents-and-reports
  - **Application**: Legal considerations in forensics (Weeks 11-14)

- **Best Practices for Search of Electronic Storage Media in Criminal Cases**
  - **Available through**: DOJ Criminal Division
  - **Application**: Professional forensics procedures (Weeks 10-12)

### **International Standards Organizations**

#### **International Organization for Standardization (ISO)**
**Information Security Management:**
- **ISO/IEC 27001:2022**: Information Security Management Systems
  - **Reference**: International standard for ISMS
  - **Application**: Security architecture and governance (Week 9)

- **ISO/IEC 27035-1:2016**: Information Security Incident Management
  - **Reference**: International incident response framework
  - **Application**: Incident handling procedures (Weeks 7-8)

- **ISO/IEC 27037:2012**: Digital Evidence Identification, Collection, Acquisition
  - **Reference**: International forensics standard
  - **Application**: Digital forensics methodology (Weeks 10-11)

#### **International Electrotechnical Commission (IEC)**
**Cybersecurity Standards:**
- **IEC 62443 Series**: Industrial Communication Networks - Network and System Security
  - **Reference**: Industrial control systems security
  - **Application**: Network security in critical systems (Week 6)

### **Industry Consortiums and Standards Bodies**

#### **Internet Engineering Task Force (IETF)**
**Cryptographic and Security Protocols:**
- **RFC 8446**: Transport Layer Security (TLS) Version 1.3
  - **Link**: https://tools.ietf.org/rfc/rfc8446.txt
  - **Application**: Modern cryptographic protocols (Week 3)

- **RFC 7748**: Elliptic Curves for Security
  - **Link**: https://tools.ietf.org/rfc/rfc7748.txt
  - **Application**: Advanced cryptography (Week 1-2)

#### **SANS Critical Security Controls**
**Current Version 8.0:**
- **Implementation Groups and Security Functions**
  - **Link**: https://www.sans.org/white-papers/critical-security-controls/
  - **Application**: Practical security implementation (Weeks 5-9)

#### **OWASP Foundation**
**Web Application Security Standards:**
- **OWASP Top 10 - 2021**: Most Critical Security Risks
  - **Link**: https://owasp.org/Top10/
  - **Application**: Vulnerability assessment (Week 8)

- **OWASP Application Security Verification Standard (ASVS)**
  - **Link**: https://owasp.org/www-project-application-security-verification-standard/
  - **Application**: Secure development practices (Week 5)

### **Academic and Research Organizations**

#### **Association for Computing Machinery (ACM)**
**Digital Library Security Research:**
- **ACM Computing Surveys - Security Section**
  - **Link**: https://dl.acm.org/journal/csur
  - **Application**: Current security research trends (Advanced topics)

#### **IEEE Computer Society**
**Security and Privacy Standards:**
- **IEEE Security & Privacy Magazine**
  - **Link**: https://www.computer.org/csdl/magazine/sp
  - **Application**: Current security trends and research

#### **Association for Machine Learning (AML)**
**Security Applications of Machine Learning:**
*Note: Instructor has access to AML PDFs - to be added*

**Anticipated Topics:**
- **Machine Learning for Anomaly Detection** (Week 7 - SIEM enhancement)
- **AI-Powered Forensics Analysis** (Weeks 11-12 - Pattern recognition)
- **Automated Threat Classification** (Week 8 - Assessment tools)
- **Behavioral Analysis in Digital Forensics** (Week 13 - Mobile forensics)

### **Certification Body References**

#### **Certified Information Systems Security Professional (CISSP)**
**(ISC)² Official Study Materials:**
- **CISSP Official Study Guide** - Domain mappings
- **Application**: Professional certification preparation

#### **Certified Ethical Hacker (CEH)**
**EC-Council Official Materials:**
- **CEH v12 Handbook** - Penetration testing methodologies
- **Application**: Ethical hacking techniques (Week 8)

#### **Global Information Assurance Certification (GIAC)**
**SANS GIAC Certifications:**
- **GCFA**: GIAC Certified Forensic Analyst
- **GCFE**: GIAC Certified Forensic Examiner
- **Application**: Professional forensics certification paths (Weeks 10-14)

### **Legal and Regulatory Framework**

#### **Federal Rules of Evidence**
**Rule 702 - Expert Witness Testimony:**
- **Application**: Digital forensics expert testimony standards (Week 14)

#### **Daubert Standard**
**Scientific Evidence Admissibility:**
- **Application**: Forensics evidence reliability and validation (Weeks 11-14)

#### **Privacy Regulations**
**General Data Protection Regulation (GDPR):**
- **Application**: Privacy considerations in forensics (All weeks)

**California Consumer Privacy Act (CCPA):**
- **Application**: State-level privacy requirements (All weeks)

---

## Reference Integration by Week

### **Weeks 1-5: Foundation Security**
- **Primary**: NIST cryptographic standards, IETF RFCs
- **Secondary**: ISO 27001 series, OWASP guidelines
- **Legal**: Federal evidence rules, privacy regulations

### **Weeks 6-9: Enterprise Security**
- **Primary**: NIST SP 800 series, SANS Critical Controls
- **Secondary**: DHS/CISA guidance, ISO security management
- **Industry**: IEEE standards, professional certification materials

### **Weeks 10-14: Digital Forensics**
- **Primary**: FBI/DOJ forensics guidance, SWGDE standards
- **Secondary**: ISO forensics standards, GIAC certification materials
- **Legal**: Federal Rules of Evidence, Daubert standard applications
- **Advanced**: AML applications to forensics (with instructor PDFs)

---

**Total Reading Time**: Approximately 50 hours across 14 weeks  
**Average per Week**: 3.5 hours of reading plus hands-on practice

**Link Testing Status**: ❓ *Links require validation - see testing section below*

---

## Link Testing Checklist

**Status Legend**: ✅ Working | ❌ Broken | ⚠️ Requires Authentication | 🔍 Needs Review

### Week 1 Links
- [ ] https://www.crypto101.io/
- [ ] https://cryptography.io/en/latest/
- [ ] https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf
- [ ] https://www.youtube.com/watch?v=O4xNJsjtN6E
- [ ] https://www.cryptool.org/en/cto/aes

### Week 2 Links
- [ ] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- [ ] https://tools.ietf.org/rfc/rfc2104.txt
- [ ] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

### Week 3 Links
- [ ] https://www.feistyduck.com/library/bulletproof-tls-guide/online/
- [ ] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-32.pdf
- [ ] https://tools.ietf.org/rfc/rfc5280.txt
- [ ] https://www.feistyduck.com/library/openssl-cookbook/online/

### Week 4 Links
- [ ] https://pages.nist.gov/800-63-3/
- [ ] https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- [ ] https://www.cl.cam.ac.uk/~rja14/book.html

### Week 5 Links
- [ ] https://csrc.nist.gov/CSRC/media/Publications/conference-paper/1992/10/13/role-based-access-controls/final/documents/ferraiolo-kuhn-92.pdf
- [ ] https://www.cl.cam.ac.uk/~rja14/book.html
- [ ] https://cloud.google.com/beyondcorp#researchPapers

### Week 10 Links
- [ ] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
- [ ] https://sleuthkit.org/autopsy/docs/user-docs/4.19.3/
- [ ] https://linuxleo.com/

**Testing Instructions**: 
1. Check each link for accessibility
2. Verify content matches described focus areas
3. Note any authentication requirements
4. Update status symbols accordingly
5. Report broken links for immediate fixing