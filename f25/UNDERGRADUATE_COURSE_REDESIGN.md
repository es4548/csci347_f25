# CSCI 347: Undergraduate Course Redesign for Forensics Excellence

**Target Audience**: 3 undergraduate students, networking/Python background  
**Course Type**: Asynchronous, standalone delivery  
**Key Strength**: Strong forensics emphasis (preserve and enhance!)  
**Problem**: Graduate-level assignments inappropriate for undergraduate learning

---

## 🎯 Course Vision: Build Toward Forensics Excellence

### **Your Forensics Focus is Perfect for Undergraduates!**
- **Career relevant**: Digital forensics has strong job market
- **Hands-on learning**: Appeals to undergraduate learning style  
- **Practical skills**: Immediate application possibilities
- **Investigative nature**: Engaging problem-solving approach

### **Strategy**: Use Weeks 1-9 to Build Skills for Forensics Success

**New Course Arc:**
- **Weeks 1-5**: Foundation building with *simple* implementations
- **Weeks 6-9**: Security concepts through *analysis* rather than building
- **Weeks 10-14**: **ENHANCED** forensics focus (keep strong!)

---

## 🚨 Critical Undergraduate Adjustments

### **The Graduate vs. Undergraduate Reality:**

| Graduate Expectation | Undergraduate Reality | Solution |
|---------------------|----------------------|----------|
| Build production CA system | Learn PKI concepts | Certificate analysis exercises |
| Deploy ELK Stack SIEM | Understand log analysis | Use existing Splunk/ELK for analysis |
| Create penetration testing platform | Learn vulnerability assessment | Use existing tools (Nmap, OpenVAS) |
| Expert forensic testimony | Digital evidence analysis | Focus on investigation techniques |

---

## 📚 Preserve & Enhance: Weeks 10-14 (Forensics)

### **Week 10: Digital Forensics Foundations** ✅ **KEEP STRONG**
**Why it works for undergraduates:**
- Clear methodology (scientific approach)
- Hands-on evidence acquisition
- Immediate visual results
- Professional tool usage (Autopsy, Sleuth Kit)

**Minor adjustments:**
- Add more guided exercises with sample evidence
- Include common forensics scenarios (social media investigations)
- Provide pre-acquired evidence images to reduce technical barriers

### **Week 11: Advanced Forensics** ✅ **KEEP BUT SIMPLIFY INTEGRATION**
**Current strength:** Multi-source analysis is excellent learning
**Adjustment needed:** Reduce "advanced statistical analysis" requirement
**Keep:** File system analysis, timeline creation, cross-correlation
**Simplify:** Remove "expert testimony" and "legal admissibility" requirements

### **Week 12: Memory Forensics** ✅ **PERFECT FOR UNDERGRADUATES**
**Why this works:** 
- Volatility framework is professional but accessible
- Memory dumps provide rich investigative material
- Clear artifacts to discover and analyze
**Keep as-is** with better tutorial support

### **Week 13: Mobile Forensics** ✅ **HIGHLY ENGAGING FOR UNDERGRADUATES**
**Why students will love this:**
- Relevant to their daily technology use
- Immediate practical applications
- Modern forensics techniques
**Enhancement:** Add social media and app data analysis

### **Week 14: Integration** ✅ **EXCELLENT CAPSTONE**
**Perfect undergraduate project:** Comprehensive forensics investigation
**Keep the multi-week integration** - but focus on forensics tools integration

---

## 🔧 Major Simplifications Needed (Weeks 1-9)

### **Week 3: PKI Certificates** 
**Current**: Build complete Certificate Authority with CRL, OCSP, lifecycle management
**Undergraduate Version**: Certificate validation and trust chain analysis
```python
# Instead of building CA infrastructure:
# Focus on understanding and using certificates
def validate_certificate_chain(cert_file):
    """Learn how certificates work through analysis"""
    # Parse and validate existing certificates
    # Understand trust relationships
    # Check expiration and revocation
```

### **Week 6: Network Security**
**Current**: Deploy pfSense + GNS3 + Suricata + multi-zone network (20+ hours)
**Undergraduate Version**: Network security analysis and rule creation
```python
# Instead of network infrastructure:
# Focus on understanding network security through analysis
def analyze_firewall_logs(log_file):
    """Learn network security through log analysis"""
    # Parse firewall logs
    # Identify security events
    # Create basic detection rules
```

### **Week 7: SIEM and Monitoring**
**Current**: Build complete SIEM with ELK Stack, correlation rules, ML detection
**Undergraduate Version**: Security event analysis using existing SIEM tools
```python
# Instead of building SIEM:
# Use Splunk Free or pre-configured ELK to learn concepts
def analyze_security_events(events):
    """Learn SIEM concepts through analysis"""
    # Correlate related events
    # Create basic dashboards
    # Identify incident patterns
```

### **Week 8: Assessment Integration**
**Current**: Integrate weeks 3-7 into comprehensive penetration testing platform  
**Undergraduate Version**: Security assessment using standard tools
```python
# Instead of building assessment platform:
# Learn to use professional tools effectively
def security_assessment_report(target):
    """Learn assessment methodology"""
    # Use Nmap for scanning
    # Use OpenVAS for vulnerability detection
    # Generate professional reports
```

---

## 🎓 Undergraduate Learning Progression

### **Skills Building Arc (Perfect for Your Forensics Focus!):**

**Weeks 1-2**: **Crypto Foundations** 
- Simple encryption/decryption (builds confidence)
- Password management (practical application)
- *Foundation for understanding encrypted evidence in forensics*

**Weeks 3-4**: **Trust and Authentication**
- Certificate analysis (not building CA systems)
- Authentication mechanisms 
- *Essential for understanding digital identity in forensics*

**Weeks 5-6**: **Security Analysis**
- Access control models
- Network security through log analysis
- *Skills directly applicable to forensic investigations*

**Weeks 7-8**: **Incident Response Prep**
- Security monitoring concepts
- Vulnerability assessment methodology
- *Perfect preparation for forensics work*

**Week 9**: **Security Architecture**
- Understanding enterprise security
- *Context for where forensics fits in organizations*

**Weeks 10-14**: **FORENSICS EXCELLENCE** ⭐
- *Your strongest content - keep the emphasis!*
- Digital evidence acquisition and analysis
- Memory forensics and malware analysis  
- Mobile device investigations
- Comprehensive forensic investigations

---

## 🛠️ Tutorial Enhancement Strategy

### **Focus Tutorial Development Where It Matters Most:**

**Priority 1: Enhance Forensics Tutorials (Weeks 10-14)**
- Add more step-by-step guided exercises
- Include additional forensics scenarios
- Provide sample evidence from various case types
- Add professional forensics workflow tutorials

**Priority 2: Simplify Foundation Tutorials (Weeks 1-9)**
- Convert from "build systems" to "analyze systems"
- Add practical exercises with immediate feedback
- Focus on concepts over implementation complexity
- Provide working examples to modify rather than build from scratch

**Priority 3: Bridge to Forensics**
- Show how each early week connects to forensics work
- Add forensics context to security concepts
- Include mini-forensics exercises throughout early weeks

---

## 📊 Undergraduate-Appropriate Time Expectations

### **Revised Weekly Time Budget:**

| Weeks | Topic | Current Hours | Undergraduate Hours | Focus |
|-------|-------|---------------|-------------------|--------|
| 1-2 | Crypto Basics | 8-10 | 8-10 | ✅ Keep as-is |
| 3 | PKI Analysis | 15-20 | 8-10 | 🔧 Simplify significantly |
| 4-5 | Auth & Access | 10-12 | 10-12 | ✅ Appropriate level |
| 6 | Network Security | 20-25 | 8-10 | 🔧 Analysis vs. building |
| 7 | SIEM Analysis | 20-25 | 8-10 | 🔧 Use existing tools |
| 8 | Security Assessment | 25-30 | 10-12 | 🔧 Tool usage vs. building |
| 9 | Architecture | 10-12 | 10-12 | ✅ Keep conceptual focus |
| **10-14** | **FORENSICS** | **60-70** | **80-90** | ⭐ **ENHANCE!** |

**Total Course**: 280 hours → 240 hours (appropriate for undergraduate 3-credit)

---

## 🎯 Learning Outcomes: Undergraduate Career Focus

### **After This Course, Students Will:**

**Technical Skills:**
- Implement basic cryptographic systems
- Analyze network security configurations  
- Perform comprehensive digital forensics investigations ⭐
- Conduct memory and mobile device forensics ⭐
- Generate professional forensics reports ⭐

**Career Preparation:**
- **Digital Forensics Analyst** (primary career path)
- **Incident Response Specialist**
- **Cybersecurity Analyst**
- **Security Auditor**

**Professional Development:**
- Experience with industry-standard forensics tools
- Understanding of legal and ethical considerations
- Professional documentation and reporting skills
- Preparation for forensics certifications (EnCE, GCFA)

---

## 📋 Implementation Priority

### **Phase 1: Critical Simplifications (Immediate)**
1. **Week 6**: Replace infrastructure lab with network log analysis
2. **Week 7**: Modify to use existing SIEM tools for analysis  
3. **Week 8**: Convert to security assessment methodology vs. platform building
4. **Week 3**: Simplify PKI to certificate analysis vs. CA building

### **Phase 2: Forensics Enhancement (Next 2 weeks)**
1. **Week 10**: Add guided forensics scenarios with sample evidence
2. **Week 11**: Simplify integration requirements but keep multi-source analysis
3. **Week 12**: Enhance Volatility tutorials with more examples
4. **Week 13**: Add social media and app forensics modules

### **Phase 3: Foundation Tutorials (Ongoing)**
1. Convert "building" tutorials to "analysis" tutorials for Weeks 3, 6-8
2. Add forensics context to early week materials
3. Create bridge modules connecting security concepts to forensics applications

---

## 🎉 Why This Redesign Will Work

### **Preserves Your Vision:**
- **Strong forensics emphasis maintained and enhanced**
- **Career-relevant skills** for undergraduate job market
- **Hands-on learning** that engages undergraduate students
- **Professional tool experience** that employers value

### **Addresses Undergraduate Reality:**
- **Appropriate complexity** for undergraduate skill level
- **Achievable time commitments** for independent study
- **Strong tutorial support** for self-guided learning
- **Clear progression** building toward forensics excellence

### **Perfect for Your 3 Students:**
- **Asynchronous-friendly** with clear milestones
- **Networking/Python background leveraged** for forensics programming
- **Individual attention possible** with small cohort
- **High probability of success** leading to strong course evaluations

---

## 🚀 Expected Student Outcomes

**With This Redesign:**
- Students develop **strong forensics capabilities** (your goal!)
- **High engagement** due to relevant, investigative content
- **Career preparation** in growing digital forensics field
- **Portfolio projects** demonstrating real forensics skills
- **Foundation for advanced study** or immediate employment

**Forensics Focus Benefits:**
- **Immediate practical application** (analyze their own devices)
- **Clear career pathways** (digital forensics is hiring!)
- **Engaging problem-solving** (every case is a mystery)
- **Professional skill development** (industry-standard tools)

Your forensics emphasis is the perfect hook for undergraduate engagement - let's build the entire course to support that strength!