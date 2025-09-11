# Week 7 Assignment: Security Monitoring with SIEM

**Due**: End of Week 7  
**Points**: 25 points  
**Estimated Time**: 5 hours  
**Submission**: Submit Pull Request URL to Canvas

---
*Updated for Fall 2025*

## 🎯 Assignment Overview

Use Splunk (free version) to analyze security logs and create detection rules for common attacks. Learn how Security Operations Centers (SOCs) monitor for threats.

## 📋 Requirements

### Part 1: Log Analysis (10 points)

Using provided log files:
1. **Import logs into Splunk**
2. **Create search queries for security events**
3. **Identify attack patterns**
4. **Build correlation rules**

### Part 2: Dashboard Creation (8 points)

Build security dashboards showing:
- Failed login attempts
- Suspicious network connections
- File integrity violations
- User behavior anomalies

### Part 3: Alert Rules (7 points)

Create alerts for:
- Brute force attacks
- Privilege escalation
- Data exfiltration
- Malware indicators

## 🔧 Setup Instructions

1. Download Splunk Free (500MB/day limit)
2. Import provided sample logs
3. Follow tutorial for basic SPL queries
4. Use provided detection rule templates

## 📝 Deliverables

1. `splunk_queries.txt` - Your search queries
2. `dashboard_config.xml` - Dashboard configuration
3. `alert_rules.txt` - Alert configurations
4. `incident_report.md` - Analysis of detected incidents
5. `screenshots/` - Dashboard and alert evidence

## Sample Data Provided

- Web server logs with attacks
- Authentication logs with brute force
- Network logs with scanning activity
- System logs with privilege escalation
