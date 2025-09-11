# Week 10 Assignment: Digital Forensics Laboratory

**Due**: End of Week 10 (see Canvas for exact deadline)  
**Total Points**: 25  
**Estimated Time**: 3-4 hours  
**Submission**: Pull Request with forensics lab implementation

## 🎯 Assignment Overview

Build a comprehensive digital forensics laboratory that demonstrates proper evidence handling, analysis, and reporting. You'll create a forensics toolkit that can acquire evidence, maintain chain of custody, perform timeline analysis, and generate professional reports.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Evidence Acquisition & Preservation** (5 points)
2. **File System Analysis** (5 points)
3. **Timeline & Artifact Recovery** (5 points)
4. **Forensic Reporting** (5 points)
5. **Chain of Custody Management** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based forensics platform with these components:

```python
# Core modules to implement
evidence_manager.py     # Evidence acquisition and preservation
filesystem_analyzer.py  # File system parsing and analysis
timeline_builder.py     # Event timeline reconstruction
artifact_extractor.py   # Deleted file and metadata recovery
forensic_reporter.py    # Professional report generation
```

### Required Libraries
```python
import hashlib
import sqlite3
from datetime import datetime
import os
import struct
from typing import Dict, List, Optional, Tuple
import json
import pandas as pd
from dataclasses import dataclass
```

## 📝 Detailed Requirements

### 1. Evidence Acquisition & Preservation (5 points)

Implement forensically sound evidence handling:

**Required Features:**
- **Disk imaging** with verification (simulate with file copying)
- **Hash verification** using multiple algorithms (MD5, SHA-256, SHA-512)
- **Write blocking** simulation to prevent evidence contamination
- **Evidence integrity** monitoring throughout analysis
- **Acquisition logging** with timestamps and operator information

**Deliverable:** `evidence_manager.py` with imaging and verification capabilities

### 2. File System Analysis (5 points)

Create comprehensive file system examination tools:

**Required Features:**
- **File system parsing** (simulate NTFS/ext4 structures)
- **Directory tree reconstruction** with deleted entries
- **File metadata extraction** (timestamps, permissions, size)
- **Slack space analysis** for hidden data
- **Master file table** simulation and analysis

**Deliverable:** `filesystem_analyzer.py` with parsing and analysis functions

### 3. Timeline & Artifact Recovery (5 points)

Build timeline reconstruction and artifact recovery:

**Required Features:**
- **Timeline generation** from file system timestamps
- **Deleted file recovery** using file signatures
- **File carving** for fragmented files
- **Registry artifact** simulation (Windows-style)
- **Browser history** reconstruction from databases

**Deliverable:** `timeline_builder.py` and `artifact_extractor.py`

### 4. Forensic Reporting (5 points)

Generate professional forensic investigation reports:

**Required Features:**
- **Executive summary** with key findings
- **Technical analysis** with detailed evidence
- **Timeline reports** in multiple formats
- **Evidence catalog** with hash verification
- **Chain of custody** documentation

**Deliverable:** `forensic_reporter.py` with multiple report formats

### 5. Chain of Custody Management (5 points)

Implement complete chain of custody tracking:

**Required Features:**
- **Evidence tracking** from acquisition to analysis
- **Operator logging** with authentication
- **Action auditing** with timestamps
- **Transfer documentation** between analysts
- **Integrity verification** at each step

**Deliverable:** Chain of custody system integrated across all modules







## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria


### Professional Development Outcomes

**Upon successful completion, you will have demonstrated**:
- Industry-standard digital forensics methodology suitable for professional practice
- Legal compliance meeting court admissibility and expert testimony standards
- Advanced timeline analysis and event correlation capabilities
- Comprehensive security architecture investigation skills
- Professional communication suitable for executive and technical audiences
- Foundation preparation for advanced forensic platform development (Project 2)
- Integration of preventive security knowledge with reactive investigation techniques

**Career Preparation**: This investigation aligns with professional forensic examiner roles, incident response analyst positions, and cybersecurity consulting opportunities requiring both technical expertise and business communication skills.

## 🚀 Bonus Opportunities (+2 points max)

- **Advanced File Carving**: Reconstruct fragmented files across multiple clusters
- **Network Artifacts**: Analyze network connection logs and packet traces
- **Encryption Handling**: Detect and document encrypted files and volumes
- **Mobile Simulation**: Add smartphone-style artifact analysis
- **Advanced Visualization**: Interactive timeline and file system browsers

## 💡 Tips for Success

1. **Study Real Tools**: Understand how Autopsy, FTK, and EnCase work
2. **Focus on Accuracy**: Forensic tools must be precise and reliable
3. **Document Everything**: Chain of custody is critical for legal validity
4. **Test Thoroughly**: Validate your tools with known test data
5. **Professional Reports**: Format matters for court presentation
6. **Follow Standards**: Adhere to NIST and ISO forensic guidelines

## 📚 Resources

- NIST SP 800-86: Computer Forensics Guidelines
- ISO/IEC 27037: Digital Evidence Guidelines
- Autopsy Digital Forensics Platform Documentation
- File System Forensics Analysis (Brian Carrier)
- Digital Forensics with Open Source Tools

---

**Build your forensic investigation platform with precision and integrity!** 🔍⚖️