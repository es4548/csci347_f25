# CSCI 347 Modifications for Undergraduate Asynchronous Delivery

**Date**: August 2025  
**Issue**: Current course designed for graduate-level cybersecurity program with extensive lab support  
**Context**: 3 undergraduate students, networking/Python background, asynchronous standalone delivery  
**Key Requirement**: Preserve strong forensics emphasis while making content undergraduate-appropriate

## Executive Summary

This document outlines essential modifications to make CSCI 347 appropriate for **undergraduate** asynchronous delivery to 3 students. The current course is designed at graduate/professional level with requirements that exceed undergraduate capabilities. 

**Critical Finding**: Assignments require **graduate-level implementation skills** while targeting **undergraduate learners**.

**Key Insight**: Your emphasis on forensics (Weeks 10-14) is excellent for undergraduates - these are the most engaging and career-relevant topics. However, early weeks (3, 6-8) require dramatic simplification to build toward forensics success.

---

## 🚨 Critical Modifications Required

### **Week 3: PKI and Certificates**
**Current Assignment**: Full Certificate Authority implementation (production-level)
**Revised Assignment**: Certificate validation and basic PKI operations
```
REDUCE SCOPE BY: 60%
- Remove: Complete CA system with CRL, OCSP, certificate lifecycle management
- Keep: Certificate generation, validation, chain verification
- Add Tutorial: 2-hour CLI development module with argparse
```

### **Week 6: Network Security Infrastructure**  
**Current Assignment**: Multi-zone firewall + VPN + IDS/IPS + network segmentation
**Revised Assignment**: Firewall rule programming and analysis
```
REDUCE SCOPE BY: 75%
- Remove: Full network infrastructure deployment (1,380 lines of requirements)
- Keep: Firewall rule development and security policy implementation
- Replace: Network setup with packet analysis using provided captures
```

### **Week 7: SIEM and SOC Operations**
**Current Assignment**: Build complete SIEM system with ELK Stack
**Revised Assignment**: Security log analysis using existing tools
```
REDUCE SCOPE BY: 80%
- Remove: ELK Stack deployment, custom correlation rules, ML detection
- Keep: Log analysis, basic correlation, dashboard interpretation
- Replace: Infrastructure setup with Splunk Free or pre-configured ELK
```

### **Week 8: Comprehensive Assessment Platform**
**Current Assignment**: Integration of all previous weeks into penetration testing framework
**Revised Assignment**: Security assessment methodology and basic vulnerability scanning
```
REDUCE SCOPE BY: 70%
- Remove: Custom platform development integrating 7 previous weeks
- Keep: Vulnerability assessment methodology, basic scanning, reporting
- Replace: Complex integration with structured assessment checklist
```

### **Week 11: Advanced Multi-Source Forensic Investigation**
**Current Assignment**: Cross-platform correlation with legal admissibility standards
**Revised Assignment**: Single-source forensic analysis with basic reporting
```
REDUCE SCOPE BY: 65%
- Remove: Multi-source correlation, advanced statistical analysis, expert testimony
- Keep: File system analysis, artifact extraction, basic timeline creation
- Replace: Complex correlation with guided forensic scenario analysis
```

### **Week 12: Memory Forensics and Malware Analysis**
**Current Assignment**: Build memory analysis platform with custom YARA rules
**Revised Assignment**: Memory analysis using Volatility with guided exercises
```
REDUCE SCOPE BY: 50%
- Remove: Custom platform development, advanced malware analysis
- Keep: Volatility framework usage, memory dump analysis, basic artifact identification
- Replace: Platform development with structured analysis exercises
```

---

## 📚 Tutorial Enhancement Requirements

### **Week 3 Tutorial Additions (Critical)**
```
Add 3-hour prerequisite module:
1. Database design for certificate tracking (45 min)
2. Command-line interface development with argparse (90 min)  
3. File system security and permissions (45 min)
```

### **Week 6 Tutorial Restructure (Critical)**
```
Reduce configuration content by 40%, add:
1. Python network programming fundamentals (2 hours)
2. Security tool API integration (1.5 hours)
3. Practical firewall rule development (1 hour)
```

### **Week 8 Tutorial Major Revision (Critical)**
```
Break into prerequisite modules:
1. Security tool API integration (2 hours)
2. Vulnerability correlation basics (2 hours)
3. Professional reporting frameworks (1 hour)
4. Integration patterns for multi-week projects (1 hour)
```

### **Week 11 Tutorial Enhancements (Important)**  
```
Add practical implementation modules:
1. Database forensics with SQLite (1.5 hours)
2. Timeline analysis programming (1.5 hours)
3. Report generation with templates (1 hour)
```

---

## 🛠️ Infrastructure Simplification

### **Replace Complex Setups With:**
1. **Pre-configured VMs** instead of requiring students to build environments
2. **Packet Tracer simulations** instead of actual network infrastructure
3. **Cloud-based tools** (Splunk Free, AWS educate) instead of local installations
4. **Provided datasets** instead of live data collection requirements

### **Validation and Support Enhancements:**
1. **Automated validation scripts** for each assignment milestone
2. **Common troubleshooting guides** for each week's technical requirements
3. **Video walkthroughs** for complex setup procedures
4. **Alternative approaches** for students facing technical barriers

---

## 📊 Time Adjustment Analysis

### **Current vs. Revised Time Requirements**

| Week | Current Hours | Revised Hours | Reduction |
|------|---------------|---------------|-----------|
| 1-2  | 8-10         | 8-10          | 0%        |
| 3    | 15-20        | 10-12         | 40%       |
| 4-5  | 10-12        | 10-12         | 0%        |
| 6    | 20-25        | 10-12         | 50%       |
| 7    | 20-25        | 8-10          | 60%       |
| 8    | 25-30        | 12-15         | 50%       |
| 9-10 | 10-12        | 10-12         | 0%        |
| 11   | 20-25        | 12-15         | 40%       |
| 12   | 15-20        | 10-12         | 30%       |
| 13-14| 10-12        | 10-12         | 0%        |

**Total Reduction**: From 300+ hours to 200-220 hours (appropriate for 3-credit course)

---

## 🎯 Learning Objective Preservation

### **Maintained Core Objectives:**
- Cryptographic implementation and analysis
- Network security principles and application
- Digital forensics methodology and practice
- Security assessment and vulnerability analysis
- Professional documentation and reporting

### **Adjusted Complexity Level:**
- From **production/enterprise implementation** to **educational demonstration**
- From **multi-system integration** to **focused skill development**
- From **advanced research projects** to **structured learning exercises**
- From **independent discovery** to **guided skill building**

---

## 📋 Implementation Checklist

### **Phase 1: Critical Assignments (Immediate)**
- [ ] Week 3: Simplify PKI assignment and enhance tutorial
- [ ] Week 6: Replace infrastructure lab with programming focus
- [ ] Week 7: Modify SIEM assignment to use existing tools
- [ ] Week 8: Convert to assessment methodology vs. platform development

### **Phase 2: Tutorial Enhancements (Within 2 weeks)**  
- [ ] Week 3: Add CLI development and database modules
- [ ] Week 6: Restructure with Python networking fundamentals
- [ ] Week 8: Create prerequisite integration modules
- [ ] Week 11: Add practical implementation tutorials

### **Phase 3: Infrastructure Support (Ongoing)**
- [ ] Create pre-configured VMs for complex assignments
- [ ] Develop troubleshooting guides for each week
- [ ] Add validation scripts for assignment milestones
- [ ] Create video walkthroughs for technical procedures

---

## 🎓 Expected Outcomes

### **With Modifications:**
- **Achievable workload** for 3 students working independently
- **Strong tutorial support** matching assignment complexity
- **Practical skill development** in security and forensics
- **Professional-quality deliverables** at appropriate complexity level
- **High probability of student success** and course completion

### **Without Modifications:**
- **Excessive time requirements** leading to incomplete assignments
- **Technical barriers** preventing assignment completion
- **Tutorial-assignment gaps** causing student confusion
- **Infrastructure setup issues** consuming learning time
- **High probability of student failure** and course dissatisfaction

---

## 📞 Support Resources

### **For Students:**
- Enhanced troubleshooting documentation
- Alternative assignment approaches for technical difficulties  
- Clear prerequisite skill assessments
- Direct instructor support channels

### **For Instructor:**
- Simplified grading rubrics matching revised complexity
- Common issue identification guides
- Student progress monitoring checkpoints
- Technical setup verification procedures

---

**Priority**: Implement Phase 1 modifications immediately to prevent student difficulties in the most complex assignments.