# Week 9 Assignment: Enterprise Security Architecture Design

**Due**: End of Week 9 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 6 hours  
**Submission**: Submit Pull Request URL to Canvas

## 🎯 Assignment Overview

Design focused security architecture using threat modeling and provided security framework templates. This assignment emphasizes threat analysis and risk-based decision making using pre-built framework mappings and templates.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Threat Modeling & Risk Assessment** (15 points)
2. **Architecture Documentation** (5 points)
3. **Risk Communication** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build focused threat modeling system:

```python
# Core modules to implement
threat_modeling.py      # STRIDE analysis & risk calculator
architecture_report.py  # Documentation generator
```

### Required Libraries
```python
import pandas as pd
import matplotlib.pyplot as plt
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
import json
```

## 📝 Detailed Requirements

### 1. Threat Modeling & Risk Assessment (15 points)

**Focus Area: STRIDE Threat Analysis**

Implement comprehensive threat modeling system:

**Required Features:**
- **Asset identification** with business criticality classification
- **STRIDE threat analysis** for each asset type with detailed scenarios
- **Quantitative risk calculation** using ALE methodology (SLE × ARO)
- **Risk prioritization** with business impact and likelihood scoring
- **Threat model visualization** showing attack vectors and relationships
- **Risk treatment recommendations** with cost-benefit analysis

**Deliverable:** `threat_modeling.py` with Asset, Threat, and RiskCalculator classes

*Note: Framework mappings and dashboard templates provided as starter code*

### 2. Architecture Documentation (5 points)

Create professional security architecture documentation:

**Required Features:**
- **Threat model diagrams** showing attack vectors and defenses
- **Risk register** with treatment decisions and timelines
- **Executive summary** with business risk justification
- **Implementation roadmap** with prioritized security investments

**Deliverable:** `architecture_report.py` generating professional documentation

### 3. Risk Communication (5 points)

Develop clear risk communication materials:

**Required Features:**
- **Executive briefing** materials with business impact focus
- **Technical implementation** guidance for security teams
- **Risk visualization** showing threat landscape and priorities
- **ROI analysis** for proposed security investments

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── threat_modeling.py
│   └── architecture_report.py
├── data/
│   ├── assets.json
│   └── threats.json
├── templates/
│   ├── framework_mappings.json  # Pre-built NIST/ISO mappings
│   └── dashboard_templates/     # Visualization templates
├── reports/
│   ├── threat_model_report.html
│   ├── executive_summary.pdf
│   └── risk_register.xlsx
└── README.md
```

### Sample Asset Definition
```python
@dataclass
class Asset:
    asset_id: str
    name: str
    asset_type: str  # data, system, facility, personnel
    business_value: int  # 1-5 scale
    confidentiality: int  # 1-5 scale
    integrity: int  # 1-5 scale
    availability: int  # 1-5 scale
    owner: str
    custodian: str
```

### Sample Threat Analysis
```python
def analyze_stride_threats(asset: Asset) -> List[Threat]:
    """
    Analyze asset for STRIDE threats
    Returns prioritized threat list with risk scores
    """
    threats = []
    
    # Analyze each STRIDE category
    for category in StrideCategory:
        threat_scenarios = identify_threat_scenarios(asset, category)
        for scenario in threat_scenarios:
            risk_score = calculate_risk(scenario.likelihood, scenario.impact)
            threats.append(Threat(asset.asset_id, category, scenario, risk_score))
    
    return sorted(threats, key=lambda t: t.risk_score, reverse=True)
```

## 🧪 Testing Requirements

Your implementation must include:

### Unit Tests
- **Threat calculation** accuracy verification
- **Risk scoring** algorithm validation
- **Control mapping** completeness checks
- **Dashboard data** integrity testing
- **Report generation** functionality testing

### Integration Tests
- **End-to-end workflow** from assets to reports
- **Framework integration** across NIST/ISO/CIS
- **Dashboard updates** reflecting control changes
- **Multi-scenario** risk analysis validation

### Sample Test Data
Provide realistic test data including:
- 20+ enterprise assets across different types
- 50+ mapped security controls
- 100+ threat scenarios with risk scores
- 30+ security metrics with historical data

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all Python files)
2. **Documentation** (README.md with usage instructions)
3. **Test Suite** (test files with sample data)
4. **Sample Reports** (generated architecture documentation)
5. **Demo Video** (5-minute walkthrough of key features)

### README.md Must Include:
- **Installation instructions** with dependencies
- **Usage examples** for each major component
- **Architecture decisions** and design rationale
- **Framework mapping** explanation
- **Known limitations** and future improvements

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Threat Modeling & Risk Assessment** | 60% | 15 points |
| **Architecture Documentation** | 20% | 5 points |
| **Risk Communication** | 20% | 5 points |

### 5-Point Scale Criteria

**Threat Modeling & Risk Assessment (15 points)**
- **Excellent (15)**: Complete STRIDE implementation, accurate quantitative risk calculations, sophisticated threat scenarios, comprehensive business impact analysis, professional risk prioritization
- **Proficient (12)**: Good threat modeling, mostly accurate calculations, adequate scenarios, reasonable business context
- **Developing (9)**: Basic threat identification, simple risk scoring, limited scenarios, minimal business analysis
- **Needs Improvement (6)**: Incomplete threat analysis, calculation errors, unrealistic scenarios, poor business understanding
- **Inadequate (3)**: Major gaps in threat modeling, significant errors, minimal scenarios, no business context
- **No Submission (0)**: Missing or no attempt

**Architecture Documentation (5 points)**
- **Excellent (5)**: Comprehensive documentation, professional diagrams, clear executive summaries, detailed implementation guides, excellent presentation
- **Proficient (4)**: Good documentation, adequate diagrams, clear explanations, decent presentation
- **Developing (3)**: Basic documentation, simple diagrams, limited detail, adequate structure
- **Needs Improvement (2)**: Poor documentation, inadequate diagrams, unclear explanations, weak structure
- **Inadequate (1)**: Minimal documentation, missing key components, unprofessional presentation
- **No Submission (0)**: Missing or no attempt

**Risk Communication (5 points)**
- **Excellent (5)**: Clear executive communication, actionable technical guidance, effective visualizations, appropriate audience targeting, compelling ROI analysis
- **Proficient (4)**: Good communication, adequate guidance, reasonable visualizations, decent ROI analysis
- **Developing (3)**: Basic communication, limited guidance, simple visualizations, basic ROI
- **Needs Improvement (2)**: Poor communication, weak guidance, inadequate visualizations, unrealistic ROI
- **Inadequate (1)**: Ineffective communication, no clear guidance, unusable materials
- **No Submission (0)**: Missing or no attempt

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Optional Challenge

**Advanced Threat Modeling**: Implement attack tree analysis in addition to STRIDE, with probability calculations for multi-step attack scenarios. Include threat actor profiling and capability assessment.

## 💡 Tips for Success

1. **Start with Assets**: Define your enterprise asset inventory first
2. **Use Real Examples**: Base threats on actual security incidents
3. **Framework Research**: Study real NIST/ISO implementations
4. **Visual Design**: Create professional-looking dashboards
5. **Test Thoroughly**: Validate calculations with manual checks
6. **Document Well**: Clear explanation increases points significantly

## 📚 Resources

- NIST Cybersecurity Framework v1.1
- ISO 27001:2013 Control Set
- CIS Controls Version 8
- FAIR Risk Assessment Methodology
- STRIDE Threat Modeling Guide

---

**Good luck building your enterprise security architecture!** 🏗️🔒