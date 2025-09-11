# Week 6 Assignment: Network Security Analysis

**Due**: End of Week 6  
**Points**: 25 points  
**Estimated Time**: 5 hours  
**Submission**: Submit Pull Request URL to Canvas

---
*Updated for Fall 2025*

## 🎯 Assignment Overview

Analyze network traffic and create security rules to detect and prevent attacks. Use Wireshark and Python to understand network security principles.

## 📋 Requirements

### Part 1: Traffic Analysis (10 points)

Using provided packet captures:
1. **Identify normal traffic patterns**
2. **Detect anomalous behavior**
3. **Find security violations**
4. **Document attack signatures**

### Part 2: Firewall Rules (8 points)

Create firewall rules (iptables format) to:
- Block common attack patterns
- Allow legitimate traffic
- Implement defense in depth
- Log suspicious activity

### Part 3: IDS Signatures (7 points)

Write Snort-compatible rules to detect:
- Port scans
- SQL injection attempts
- Brute force attacks
- Data exfiltration

## 🔧 Tools and Resources

- Wireshark for packet analysis
- Python scapy for packet manipulation
- Sample PCAP files provided
- Firewall rule tester script

## 📝 Deliverables

1. `network_analysis.py` - Traffic analysis script
2. `firewall_rules.txt` - Your firewall configuration
3. `ids_rules.txt` - IDS detection rules
4. `analysis_report.md` - Findings and recommendations
5. `screenshots/` - Evidence of detected attacks

## Learning Objectives

- Understand TCP/IP security
- Recognize attack patterns
- Create effective security rules
- Analyze real network threats
