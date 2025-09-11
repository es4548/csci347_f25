# Week 6 Assignment: Network Security Analysis & Policy Design

**Due**: End of Week 6 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 6 hours  
**Submission**: Submit Pull Request URL to Canvas

## 🎯 Assignment Overview

Analyze network security configurations using provided firewall rules and network captures. This assignment focuses on security analysis and policy review using pre-configured tools and sample data.

## 📋 Requirements

### Core Functionality (15 points)

**Focus Area: Firewall Analysis Engine**

#### 1. Firewall Rule Analysis (15 points)
Analyze provided firewall configurations:

- **Rule parser** for iptables format rules (provided samples)
- **Policy conflict detection** identifying overlapping or contradictory rules
- **Security gap identification** finding missing protections
- **Risk scoring** based on rule permissiveness
- **Report generation** with actionable recommendations

*Note: Network capture files and analysis tools provided as sample data*

### Documentation and Analysis (5 points)

Create focused security analysis documentation:

```
firewall_analysis_report.md    # Analysis of provided firewall rules
security_recommendations.md    # Policy improvement recommendations
```

### Security Analysis (5 points)

Provide professional security assessment:
- **Risk prioritization** of identified security gaps
- **Remediation timeline** with implementation difficulty
- **Cost-benefit analysis** of security improvements

## 🧪 Testing and Validation

Your tools will be tested with:
- **Sample firewall configurations** (provided in resources/)
- **Network traffic captures** (pcap files provided)
- **Synthetic attack scenarios** for anomaly detection
- **Real-world policy frameworks** for compliance checking

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Firewall Analysis** | 60% | 15 points |
| **Documentation** | 20% | 5 points |
| **Security Assessment** | 20% | 5 points |

### 5-Point Scale Criteria

**Firewall Analysis (15 points)**
- **Excellent (15)**: Comprehensive rule parsing, accurate conflict detection, professional risk scoring, actionable recommendations
- **Proficient (12)**: Good rule analysis, basic conflict detection, reasonable recommendations
- **Developing (9)**: Simple rule parsing, limited conflict detection, basic recommendations
- **Needs Improvement (6)**: Poor analysis quality, weak conflict detection, minimal recommendations
- **Inadequate (3)**: Major analysis gaps, incorrect findings, unusable recommendations
- **No Submission (0)**: Missing or no attempt

**Documentation (5 points)**
- **Excellent (5)**: Professional reports, clear findings, executive summary suitable for management
- **Proficient (4)**: Good documentation, adequate explanations, decent presentation
- **Developing (3)**: Basic documentation, limited explanations, simple presentation
- **Needs Improvement (2)**: Poor documentation, unclear explanations, unprofessional
- **Inadequate (1)**: Minimal documentation, major gaps, illegible
- **No Submission (0)**: Missing or no attempt

**Security Assessment (5 points)**
- **Excellent (5)**: Thorough risk prioritization, realistic timelines, cost-benefit analysis, professional insights
- **Proficient (4)**: Good risk assessment, adequate prioritization, reasonable recommendations
- **Developing (3)**: Basic risk analysis, limited prioritization, simple recommendations
- **Needs Improvement (2)**: Poor risk assessment, weak prioritization, unrealistic recommendations
- **Inadequate (1)**: Minimal assessment, no prioritization, unusable recommendations
- **No Submission (0)**: Missing or no attempt

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Can my tools actually help a security analyst?**
2. **Do my analyses provide actionable insights?**
3. **Would I trust my recommendations in a real environment?**
4. **Is my code robust enough for production use?**
5. **Do my reports communicate clearly to both technical and management audiences?**

## 📤 Submission Instructions

### Step 1: Create Pull Request
1. **Push your code** to your forked repository:
   ```bash
   git add .
   git commit -m "Complete Week 6 network security analysis tools"
   git push origin week06-assignment
   ```

2. **Create Pull Request** on GitHub with description including:
   - Summary of tools developed
   - Key analysis findings from sample data
   - Challenges encountered and solutions
   - Testing approach used

### Step 2: Submit to Canvas
1. **Copy the Pull Request URL**
2. **Go to Canvas** → Week 6 Assignment  
3. **Paste the PR URL** in the submission box
4. **Submit**

### Required Files in Your PR
- `firewall_analyzer.py` - Firewall rule analysis tool
- `requirements.txt` - Python dependencies
- `README.md` - Tool usage and methodology
- `firewall_analysis_report.md` - Analysis of provided firewall rules
- `security_recommendations.md` - Policy improvement recommendations

**Resources Provided**:
- Sample firewall configurations in multiple formats
- Network traffic captures (pcap files)
- Security policy templates and frameworks
- Analysis report examples

---

**Need Help?**
- Check [troubleshooting guide](../resources/troubleshooting.md)
- Post questions in Canvas discussions  
- Attend office hours for architecture guidance