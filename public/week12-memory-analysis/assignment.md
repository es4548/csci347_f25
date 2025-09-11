# Week 12 Assignment: Memory Forensics and Malware Analysis Platform

**Due**: End of Week 12 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 6 hours  
**Submission**: Submit Pull Request URL to Canvas

## 🎯 Assignment Overview

Build focused memory analysis tools using provided memory dumps and pre-built analysis frameworks. This assignment emphasizes practical memory forensics skills using existing tools and provided memory dump files.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Memory Dump Analysis Using Volatility** (15 points)
2. **Analysis Reporting** (5 points)
3. **Threat Identification** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build memory analysis tools using provided frameworks:

```python
# Core modules to implement
memory_analyzer.py      # Volatility-based memory analysis
analysis_reporter.py    # Professional analysis reporting
threat_detector.py      # Basic malware and anomaly detection
```

### Required Libraries
```python
import struct
import hashlib
from datetime import datetime
import re
import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
```

## 📝 Detailed Requirements

### 1. Memory Dump Analysis Using Volatility (15 points)

**Focus Area: Practical Memory Forensics with Professional Tools**

**Required Features:**
- **Process analysis** using Volatility framework with provided memory dumps
- **Network artifacts** extraction and analysis from memory
- **Registry analysis** from memory-resident registry data
- **File extraction** and analysis from memory dumps
- **Timeline analysis** of system activities from memory artifacts
- **Malware detection** using memory-based indicators

**Deliverable:** `memory_analyzer.py` leveraging Volatility framework

*Note: Volatility framework pre-installed, memory dumps provided*

### 2. Analysis Reporting (5 points)

**Required Features:**
- **Executive summary** with key findings from memory analysis
- **Technical findings** with detailed artifact analysis
- **IOC documentation** with extracted indicators of compromise
- **Methodology documentation** explaining analysis procedures used

**Deliverable:** `analysis_reporter.py` with professional reporting

### 3. Threat Identification (5 points)

**Required Features:**
- **Anomaly detection** in process behavior and system artifacts
- **Malware identification** using memory-based signatures
- **Suspicious activity** flagging and prioritization
- **Attack pattern** recognition from memory artifacts

**Deliverable:** `threat_detector.py` with basic threat hunting

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── memory_analyzer.py
│   ├── analysis_reporter.py
│   └── threat_detector.py
├── samples/
│   ├── memory_dumps/          # Provided memory dump files
│   │   ├── infected_system.dmp
│   │   ├── clean_system.dmp
│   │   └── suspicious_activity.dmp
│   └── volatility_profiles/    # Pre-configured profiles
├── reports/
│   ├── memory_analysis_report.html
│   ├── ioc_summary.json
│   └── findings_summary.md
└── README.md
```

### Sample Process Analysis
```python
@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    path: str
    command_line: str
    create_time: datetime
    exit_time: Optional[datetime]
    handles: int
    threads: int
    vad_regions: List[Dict]
    dlls_loaded: List[str]
    
    def is_suspicious(self) -> bool:
        """Detect suspicious process characteristics"""
        suspicious_indicators = []
        
        # Check for process hollowing
        if self.has_hollow_indicators():
            suspicious_indicators.append("Process hollowing detected")
        
        # Check for unusual parent-child relationships
        if self.has_suspicious_parent():
            suspicious_indicators.append("Suspicious parent process")
        
        # Check for code injection indicators
        if self.has_injection_indicators():
            suspicious_indicators.append("Code injection detected")
        
        return len(suspicious_indicators) > 0
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from process memory"""
        # Simulate string extraction from process memory regions
        strings = []
        for vad_region in self.vad_regions:
            if vad_region['protection'] & 0x04:  # Readable
                region_strings = self.extract_region_strings(vad_region)
                strings.extend(region_strings)
        return strings
```

### Sample Malware Detection
```python
class MalwareDetector:
    def __init__(self):
        self.yara_rules = self.load_yara_rules()
        self.behavioral_patterns = self.load_behavioral_patterns()
        self.family_signatures = self.load_family_signatures()
    
    def scan_process(self, process: Process) -> Dict:
        """Comprehensive malware scan of process"""
        results = {
            'pid': process.pid,
            'name': process.name,
            'signature_matches': [],
            'behavioral_indicators': [],
            'family_classification': None,
            'threat_score': 0
        }
        
        # YARA rule scanning
        for rule in self.yara_rules:
            if self.match_yara_rule(process, rule):
                results['signature_matches'].append(rule['name'])
        
        # Behavioral analysis
        behaviors = self.analyze_behavior(process)
        results['behavioral_indicators'] = behaviors
        
        # Family classification
        family = self.classify_family(process, results['signature_matches'], behaviors)
        results['family_classification'] = family
        
        # Calculate threat score
        results['threat_score'] = self.calculate_threat_score(results)
        
        return results
    
    def detect_packer(self, process: Process) -> Optional[str]:
        """Detect if process is packed/encrypted"""
        # Check entropy of executable sections
        entropy = self.calculate_entropy(process.memory_regions)
        
        # Check for packer signatures
        packer_sigs = ['UPX', 'ASPack', 'PECompact', 'Themida']
        for sig in packer_sigs:
            if self.find_signature(process, sig):
                return sig
        
        # High entropy might indicate packing
        if entropy > 7.5:
            return "Unknown Packer (High Entropy)"
        
        return None
```

### Sample Rootkit Detection
```python
class RootkitDetector:
    def detect_hidden_processes(self, process_list: List[Process]) -> List[Dict]:
        """Detect hidden processes using cross-view analysis"""
        hidden_processes = []
        
        # Get process lists from different enumeration methods
        pslist_pids = set(p.pid for p in process_list)
        psscan_pids = self.enumerate_psscan()
        thrdproc_pids = self.enumerate_thrdproc()
        
        # Find discrepancies
        for pid in psscan_pids.union(thrdproc_pids):
            if pid not in pslist_pids:
                hidden_process = self.get_process_details(pid)
                hidden_processes.append({
                    'pid': pid,
                    'detection_method': 'Cross-view analysis',
                    'process_info': hidden_process,
                    'confidence': 0.8
                })
        
        return hidden_processes
    
    def detect_ssdt_hooks(self) -> List[Dict]:
        """Detect System Service Descriptor Table hooks"""
        hooks = []
        
        # Simulate SSDT analysis
        ssdt_entries = self.get_ssdt_table()
        
        for entry in ssdt_entries:
            if self.is_ssdt_entry_hooked(entry):
                hooks.append({
                    'service_id': entry['id'],
                    'service_name': entry['name'],
                    'original_address': entry['original'],
                    'hooked_address': entry['current'],
                    'hooking_module': self.resolve_module(entry['current'])
                })
        
        return hooks
    
    def analyze_vad_anomalies(self, process: Process) -> List[Dict]:
        """Analyze VAD tree for anomalies indicating injection"""
        anomalies = []
        
        for vad in process.vad_regions:
            # Look for unusual memory permissions
            if vad['protection'] == 0x40:  # PAGE_EXECUTE_READWRITE
                anomalies.append({
                    'type': 'Suspicious Memory Permissions',
                    'address': vad['start_address'],
                    'size': vad['size'],
                    'protection': vad['protection'],
                    'description': 'RWX memory region indicates possible code injection'
                })
            
            # Check for private memory with no backing file
            if vad['type'] == 'Private' and not vad['mapped_file']:
                if self.contains_executable_code(vad):
                    anomalies.append({
                        'type': 'Injected Code',
                        'address': vad['start_address'],
                        'size': vad['size'],
                        'description': 'Private executable memory without backing file'
                    })
        
        return anomalies
```

## 🧪 Testing Requirements

Your implementation must include:

### Malware Detection Tests
- **Known malware** detection accuracy
- **Packer detection** validation with samples
- **False positive** rate measurement
- **Behavioral pattern** recognition testing
- **Family classification** accuracy assessment

### Rootkit Detection Tests
- **Hidden process** detection validation
- **Hook detection** accuracy testing
- **Injection technique** identification
- **Cross-view consistency** verification
- **Anti-evasion** technique effectiveness

### Performance and Accuracy Tests
Create comprehensive test suites including:
- Memory dumps with known malware infections
- Clean system baselines for false positive testing
- Rootkit-infected samples with known hiding techniques
- APT simulation scenarios with multi-stage attacks
- Performance benchmarks for large memory dumps

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all memory analysis modules)
2. **Test Memory Dumps** (simulated samples with known characteristics)
3. **Analysis Reports** (generated from test samples)
4. **Rule Sets** (YARA-style rules and behavioral patterns)
5. **Technical Documentation** (README.md with analysis methodologies)

### README.md Must Include:
- **Analysis techniques** used for each detection method
- **Rule development** process and validation
- **Accuracy metrics** and false positive rates
- **Performance benchmarks** and optimization notes
- **Known limitations** and future improvement areas

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Memory Analysis Using Volatility** | 60% | 15 points |
| **Analysis Reporting** | 20% | 5 points |
| **Threat Identification** | 20% | 5 points |

### 5-Point Scale Criteria

**Memory Analysis Using Volatility (15 points)**
- **Excellent (15)**: Comprehensive Volatility usage, accurate process analysis, thorough network artifacts extraction, complete registry analysis, successful file extraction, detailed timeline analysis, effective malware detection
- **Proficient (12)**: Good Volatility usage, adequate analysis capabilities, reasonable artifact extraction, basic timeline construction
- **Developing (9)**: Simple Volatility usage, limited analysis depth, minimal artifact extraction, basic timeline
- **Needs Improvement (6)**: Poor Volatility usage, weak analysis capabilities, inadequate artifact extraction, incomplete timeline
- **Inadequate (3)**: Minimal Volatility usage, major analysis gaps, broken artifact extraction, unusable timeline
- **No Submission (0)**: Missing or no attempt

**Analysis Reporting (5 points)**
- **Excellent (5)**: Professional reports, comprehensive executive summary, detailed technical findings, complete IOC documentation, excellent methodology explanation
- **Proficient (4)**: Good reports, adequate summaries, decent technical detail, basic IOC documentation
- **Developing (3)**: Basic reporting, limited structure, simple findings, minimal documentation
- **Needs Improvement (2)**: Poor report quality, inadequate structure, weak findings, unprofessional presentation
- **Inadequate (1)**: Minimal reporting capabilities, major gaps, unusable documentation
- **No Submission (0)**: Missing or no attempt

**Threat Identification (5 points)**
- **Excellent (5)**: Accurate anomaly detection, effective malware identification, proper suspicious activity flagging, clear attack pattern recognition
- **Proficient (4)**: Good threat detection, adequate malware identification, reasonable activity flagging
- **Developing (3)**: Basic threat detection, limited malware identification, simple activity flagging
- **Needs Improvement (2)**: Poor threat detection, weak malware identification, inadequate activity analysis
- **Inadequate (1)**: Minimal threat detection capabilities, major identification gaps
- **No Submission (0)**: Missing or no attempt

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Optional Challenge

**Advanced Memory Forensics**: Implement custom Volatility plugins for specialized artifact extraction, with focus on encrypted memory regions or advanced persistence mechanisms.

## 💡 Tips for Success

1. **Study Volatility**: Understand how professional tools work
2. **Test with Real Samples**: Use actual malware samples when possible (safely)
3. **Focus on Accuracy**: False positives are as bad as false negatives
4. **Document Techniques**: Explain your detection methodologies
5. **Optimize Performance**: Memory analysis can be resource-intensive
6. **Validate Results**: Cross-check findings with known analysis tools

## 📚 Resources & Required Tools

### Open Source Tools (All Free)
- **Volatility 3** - https://github.com/volatilityfoundation/volatility3
- **YARA** - https://github.com/VirusTotal/yara (BSD 3-Clause License)
- **MITRE ATT&CK** - https://attack.mitre.org/ (Apache 2.0 License)
- **Python Libraries** - pandas, matplotlib, numpy (all free)

### Reference Materials
- The Art of Memory Forensics (Michael Hale Ligh)
- Volatility Framework Documentation
- YARA Rule Writing Guide
- MITRE ATT&CK Framework
- Practical Malware Analysis (Michael Sikorski)
- Rootkits and Bootkits (Alex Matrosov)

### 🚨 IMPORTANT: Tool Access

**Volatility Framework**: Pre-installed and configured with necessary plugins. Memory dump samples provided for analysis. If you encounter installation issues, contact the instructor immediately for support.

---

**Uncover the secrets hidden in volatile memory!** 🧠🔍