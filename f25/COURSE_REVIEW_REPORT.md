# 📊 CSCI 347 Course Review Report

**Review Date**: September 2025  
**Reviewer**: Course Analysis System  
**Focus Areas**: 1) Instructor materials exposure, 2) Weekly workload, 3) Pedagogical effectiveness

---

## 🔍 Executive Summary

### Overall Assessment: **NEEDS ADJUSTMENT**

The course has strong pedagogical foundations and excellent forensics content, but requires workload reduction and better alignment with undergraduate expectations. Key findings:

- ✅ **No instructor-only materials exposed** in public folder
- ⚠️ **Workload exceeds 6 hours/week** in many modules  
- ⚠️ **Pedagogical approach too advanced** for undergraduate level in weeks 3-9
- ✅ **Excellent forensics content** in weeks 10-14

---

## 1️⃣ Instructor Materials Review

### ✅ **PASS - No Sensitive Materials Exposed**

**Materials Checked:**
- Grading rubrics: Show criteria only, no answer keys
- Assignment files: Template code and requirements only
- Project specifications: Public-appropriate evaluation criteria
- Documentation: No instructor notes or private content found

**Rubric Files Present:**
- `/projects/project1-mfa-system/rubric.md` - Criteria only
- `/projects/project2-forensics-platform/rubric.md` - Criteria only  
- `/projects/project3-advanced-analysis/rubric.md` - Criteria only
- `/projects/capstone/rubric.md` - Criteria only

**Recommendation**: No action needed. Security practices are appropriate.

---

## 2️⃣ Weekly Workload Analysis

### ⚠️ **FAIL - Exceeds 6 Hour Target**

### Current Workload Breakdown:

| Week | Tutorial | Assignment | Total | Status |
|------|----------|------------|-------|--------|
| Week 1 | ~2 hours | 5 hours | **7 hours** | ❌ Over |
| Week 2 | 4-5 hours | 5 hours | **9-10 hours** | ❌ Way over |
| Week 3 | ~3 hours | 6 hours | **9 hours** | ❌ Way over |
| Week 4 | ~3 hours | ~4 hours | **7 hours** | ❌ Over |
| Week 5 | ~3 hours | 4 hours | **7 hours** | ❌ Over |
| Week 6 | 4.5-5 hours | 6 hours | **10.5-11 hours** | ❌ Way over |
| Week 7 | 4.5-5 hours | ~5 hours | **9.5-10 hours** | ❌ Way over |
| Week 8 | ~4 hours | ~5 hours | **9 hours** | ❌ Way over |
| Week 9 | ~4 hours | 6 hours | **10 hours** | ❌ Way over |
| Week 10 | ~3 hours | 3-4 hours | **6-7 hours** | ⚠️ At limit |
| Week 11 | ~3 hours | ~4 hours | **7 hours** | ❌ Over |
| Week 12 | ~3 hours | 6 hours | **9 hours** | ❌ Way over |
| Week 13 | ~3 hours | 6 hours | **9 hours** | ❌ Way over |
| Week 14 | ~4 hours | 8 hours | **12 hours** | ❌ Way over |

### Major Workload Issues:

1. **Tutorials too comprehensive**: 4-5 hour tutorials are graduate-level
2. **Assignment complexity**: Building production systems (CA, SIEM, etc.)
3. **Integration weeks**: Weeks 8 & 14 require extensive prior knowledge
4. **No scaffolding**: Jump from basics to production systems

---

## 3️⃣ Pedagogical Effectiveness Analysis

### ⚠️ **PARTIALLY EFFECTIVE - Needs Undergraduate Alignment**

### Strengths:
✅ **Excellent forensics content** (weeks 10-14)
- Clear progression from basics to advanced
- Hands-on with professional tools
- Industry-relevant skills

✅ **Good foundational topics** (weeks 1-2)
- Cryptography basics well-structured
- Password security is practical

✅ **Strong practical focus**
- Real-world applications throughout
- Professional tool usage

### Critical Weaknesses:

#### 🔴 **Graduate-Level Complexity in Weeks 3-9**

| Week | Current Requirement | Undergraduate Appropriate |
|------|---------------------|---------------------------|
| 3 | Build complete CA with OCSP/CRL | Analyze certificates, validate chains |
| 6 | Deploy pfSense + Suricata + VLANs | Use Wireshark, analyze firewall logs |
| 7 | Build ELK Stack SIEM | Use Splunk Free, analyze events |
| 8 | Integrate penetration testing platform | Use existing tools (Nmap, OpenVAS) |
| 9 | Design zero-trust architecture | Analyze architecture case studies |

#### 🔴 **Insufficient Scaffolding**
- No progressive difficulty within topics
- Jumps from "hello world" to production systems
- Missing intermediate exercises

#### 🔴 **Unrealistic Time Expectations**
- "Build enterprise MFA in 5 hours"
- "Deploy complete SIEM in 6 hours"
- "Create forensics platform in 8 hours"

---

## 📋 Recommendations

### Priority 1: Reduce Workload to 6 Hours/Week

#### Tutorial Adjustments:
- **Split long tutorials**: Break 4-5 hour tutorials into 2-hour segments
- **Make sections optional**: Core (2 hrs) + Advanced (optional)
- **Provide more starter code**: Reduce implementation time

#### Assignment Simplifications:
- **Week 3**: Analyze certificates instead of building CA
- **Week 6**: Network analysis instead of infrastructure deployment
- **Week 7**: Use existing SIEM instead of building one
- **Week 8-9**: Security assessment using tools vs. building platform

### Priority 2: Improve Pedagogical Progression

#### Add Scaffolding:
```
Level 1: Understand concept (read/analyze)
Level 2: Use existing tools (apply)
Level 3: Modify/extend code (adapt)
Level 4: Build simple version (create)
```

#### Realistic Undergraduate Goals:

**Instead of**: "Build production CA system"
**Do**: "Validate certificate chains and understand trust"

**Instead of**: "Deploy enterprise SIEM"
**Do**: "Analyze security events in Splunk"

**Instead of**: "Create pentesting platform"  
**Do**: "Conduct basic security assessment with tools"

### Priority 3: Preserve Forensics Excellence

The forensics weeks (10-14) are appropriately scoped but need minor adjustments:

1. **Provide more evidence samples** to reduce acquisition time
2. **Create guided investigation scenarios** with clear objectives
3. **Add checkpoint validations** to ensure students are on track
4. **Include common real-world scenarios** (social media, cloud forensics)

---

## 🎯 Specific Week-by-Week Adjustments

### Weeks 1-2: Cryptography ✅ Minor Adjustments
- Reduce implementation complexity
- Provide more starter code
- **Target: 5 hours total**

### Weeks 3-5: PKI/Auth 🔧 Major Simplification
- Focus on analysis over implementation
- Use existing systems for learning
- **Target: 5 hours total**

### Weeks 6-9: Security 🔧 Major Restructuring  
- Replace building with analyzing
- Use professional tools instead of creating them
- **Target: 6 hours total**

### Weeks 10-14: Forensics ✅ Keep Strong, Minor Tweaks
- Maintain current excellence
- Add more guided exercises
- **Target: 6 hours total**

---

## 💡 Implementation Strategy

### Phase 1: Immediate Changes (Before Next Semester)
1. Add time estimates to all materials
2. Mark advanced sections as optional
3. Provide additional starter code
4. Create "quick start" versions of complex assignments

### Phase 2: Summer Redesign
1. Rewrite weeks 3-9 for undergraduate level
2. Create progressive difficulty paths
3. Develop more guided exercises
4. Build assessment rubrics aligned with 6-hour workload

### Phase 3: Continuous Improvement
1. Collect student time logs
2. Adjust based on actual completion times
3. Create optional advanced tracks for strong students
4. Develop peer learning opportunities

---

## 📊 Success Metrics

Track these to validate improvements:

1. **Average time to complete assignments** (target: <4 hours)
2. **Tutorial completion rates** (target: >80%)
3. **Student stress levels** (surveys)
4. **Concept mastery** (assessment scores)
5. **Forensics preparation** (weeks 10-14 success rate)

---

## 🏁 Conclusion

The course has excellent content and strong forensics focus, but needs significant workload reduction and undergraduate-appropriate restructuring in weeks 3-9. The forensics weeks (10-14) are a particular strength that should be preserved and enhanced.

**Key Actions**:
1. Reduce workload to 6 hours/week immediately
2. Simplify weeks 3-9 from "build" to "analyze"
3. Maintain forensics excellence with minor enhancements
4. Add progressive scaffolding throughout

With these adjustments, CSCI 347 can become an exemplary undergraduate security and forensics course that prepares students for industry while maintaining reasonable workload expectations.