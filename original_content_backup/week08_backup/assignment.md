# Week 8 Assignment: Security Assessment & Risk Analysis

**Due**: End of Week 8 (see Canvas for exact deadline)  
**Points**: 25 points  
**Time Commitment**: 8-10 hours (focused on analysis vs. platform building)  
**Submission**: Submit Pull Request URL to Canvas  

## 🏆 Part I Network Security Capstone

This assignment represents the **capstone of Part I (Network Security)** by conducting a comprehensive security assessment using industry-standard tools and methodologies.

## 🎯 Assignment Overview

Conduct a thorough security assessment using existing security tools and frameworks. Your implementation should demonstrate mastery of vulnerability assessment, risk analysis, and security reporting learned throughout Weeks 1-7.

**Key Focus**: Using professional tools effectively rather than building assessment platforms from scratch.

## 📋 Requirements

### Core Assessment Activities (70 points)

#### 1. Automated Vulnerability Assessment (25 points)
Using provided tools and test environments:

- **Nmap network discovery** on provided target networks
- **OpenVAS vulnerability scanning** with configuration analysis
- **Web application testing** using OWASP ZAP on sample applications  
- **SSL/TLS assessment** using SSLyze on test certificates
- **Results correlation** identifying patterns across different scanners

**Deliverable**: `vulnerability_assessment_report.md` with findings, risk ratings, and remediation recommendations

#### 2. Security Configuration Review (25 points)
Analyze provided configuration files:

- **Firewall rule analysis** identifying policy gaps and conflicts
- **Authentication system review** checking MFA implementation security
- **PKI configuration audit** validating certificate policies
- **Access control matrix** review for privilege escalation risks
- **SIEM rule effectiveness** evaluation for detection coverage

**Deliverable**: `security_configuration_audit.md` with detailed findings and improvement recommendations

#### 3. Risk Assessment & Prioritization (20 points)
Create comprehensive risk analysis:

- **CVSS scoring** for identified vulnerabilities
- **Business impact assessment** considering asset criticality
- **Risk matrix development** plotting probability vs. impact
- **Remediation roadmap** with timeline and priority recommendations
- **Executive summary** suitable for management presentation

**Deliverable**: `risk_assessment_report.md` with executive summary and technical details

### Documentation & Analysis (20 points)

Create professional security assessment documentation:

```
executive_summary.md           # High-level findings for management
technical_findings.md          # Detailed technical analysis
remediation_plan.md           # Step-by-step improvement plan
assessment_methodology.md     # Tools and processes used
appendix/                     # Supporting evidence and screenshots
```

### Professional Presentation (10 points)

Develop a presentation suitable for:
- **Technical team briefing** (15 minutes)
- **Executive dashboard** (summary slides)
- **Remediation planning session** (actionable items)

## 🧪 Testing Environment

Your assessment will use:
- **Intentionally vulnerable VMs** (provided)
- **Sample web applications** with known vulnerabilities
- **Test network configurations** with security gaps
- **Practice SSL certificates** with various issues
- **Realistic enterprise scenarios** for context

## 📊 Assessment Tools (Provided)

You'll use these industry-standard tools:
- **Nmap** - Network discovery and port scanning
- **OpenVAS** - Comprehensive vulnerability scanner
- **OWASP ZAP** - Web application security testing
- **SSLyze** - SSL/TLS configuration analysis
- **Nikto** - Web server vulnerability scanner
- **Custom Python scripts** - For report automation

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Risk Assessment** | 60% | 15 points |
| **Professional Documentation** | 20% | 5 points |
| **Risk Communication** | 20% | 5 points |

### 5-Point Scale Criteria

**Risk Assessment (15 points)**
- **Excellent (15)**: Accurate CVSS scoring, thorough business impact analysis, realistic prioritization, professional remediation roadmap
- **Proficient (12)**: Good risk analysis, adequate business context, reasonable prioritization, solid recommendations
- **Developing (9)**: Basic risk assessment, limited business context, simple prioritization, basic recommendations
- **Needs Improvement (6)**: Poor risk analysis, weak business understanding, unrealistic prioritization, inadequate recommendations
- **Inadequate (3)**: Major assessment flaws, no business context, poor recommendations, unprofessional quality
- **No Submission (0)**: Missing or no attempt

**Professional Documentation (5 points)**
- **Excellent (5)**: Comprehensive report, clear structure, executive summary, detailed technical findings, professional presentation
- **Proficient (4)**: Good report structure, adequate summaries, decent technical detail
- **Developing (3)**: Basic report, limited structure, simple findings
- **Needs Improvement (2)**: Poor documentation, confusing structure, inadequate detail
- **Inadequate (1)**: Unprofessional documentation, major structural problems, minimal content
- **No Submission (0)**: Missing or no attempt

**Risk Communication (5 points)**
- **Excellent (5)**: Clear executive communication, actionable technical guidance, effective risk visualization, appropriate audience targeting
- **Proficient (4)**: Good communication, adequate guidance, reasonable visualization
- **Developing (3)**: Basic communication, limited guidance, simple visualization
- **Needs Improvement (2)**: Poor communication, weak guidance, inadequate visualization
- **Inadequate (1)**: Ineffective communication, no clear guidance, unusable visualization
- **No Submission (0)**: Missing or no attempt

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would my assessment help an organization improve security?**
2. **Are my risk ratings justified and business-relevant?**
3. **Can a security team implement my recommendations?**
4. **Is my executive summary clear to non-technical leadership?**
5. **Did I follow ethical assessment practices?**

## 📤 Submission Instructions

### Step 1: Create Pull Request
1. **Push your assessment** to your forked repository:
   ```bash
   git add .
   git commit -m "Complete Week 8 security assessment capstone"
   git push origin week08-assessment
   ```

2. **Create Pull Request** on GitHub with description including:
   - Summary of assessment scope and methodology
   - Key findings and risk ratings
   - Most critical recommendations
   - Tools and techniques used

### Step 2: Submit to Canvas
1. **Copy the Pull Request URL**
2. **Go to Canvas** → Week 8 Assignment  
3. **Paste the PR URL** in the submission box
4. **Submit**

### Required Files in Your PR
- `vulnerability_assessment_report.md` - Comprehensive findings
- `security_configuration_audit.md` - Configuration review
- `risk_assessment_report.md` - Risk analysis and prioritization
- `executive_summary.md` - Management-level summary
- `remediation_plan.md` - Implementation roadmap
- `assessment_presentation.pdf` - Professional briefing slides
- `tools_and_commands.md` - Documentation of tools used
- `evidence/` - Screenshots and supporting materials

**Assessment Targets Provided**:
- Vulnerable VMs and applications for safe testing
- Sample configurations with intentional security gaps
- Test certificates and network scenarios
- Assessment report templates and examples

## 🎓 Learning Outcomes Demonstrated

Upon completion, you will have demonstrated:
- **Professional vulnerability assessment** using industry tools
- **Risk analysis and prioritization** with business context
- **Security configuration review** identifying policy gaps
- **Professional security reporting** for multiple audiences
- **Ethical assessment practices** and responsible disclosure

---

**Need Help?**
- Check [troubleshooting guide](../resources/troubleshooting.md)
- Post questions in Canvas discussions  
- Attend office hours for methodology guidance
- Review NIST SP 800-115 for assessment framework