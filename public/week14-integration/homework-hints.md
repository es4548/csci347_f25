# Week 14 Homework Hints: Forensics Case Integration

## 🎯 Quick Start Guide (6 hours total)

### Time Breakdown
- **Case Setup and Tool Preparation**: 30 minutes
- **Disk Forensics Analysis**: 2 hours
- **Memory Forensics Analysis**: 1.5 hours
- **Network Analysis**: 1.5 hours
- **Mobile Forensics Correlation**: 30 minutes
- **Investigation Report Writing**: 1 hour

## 📋 Step-by-Step Investigation

### Step 1: Case Setup and Tool Preparation (30 minutes)

**The Insider Threat Case:**
- **Scenario**: Company suspects insider threat - employee exfiltrating data
- **Evidence Available**: Disk image, memory dump, network captures, mobile backup, system logs
- **Goal**: Prove insider threat, establish timeline, identify data theft
- **Tools**: Autopsy, Volatility, Wireshark, mobile forensics tools

**Investigation Approach:**
- **Timeline-Based Analysis**: Correlate events across all evidence sources
- **Artifact Correlation**: Link findings between disk, memory, network, and mobile
- **Attribution**: Establish who, what, when, where, how
- **Evidence Chain**: Maintain forensic integrity throughout

### Step 2: Environment Setup (15 minutes)

```bash
# Install required tools and libraries
pip install volatility3 pyshark pandas sqlite3 plistlib

# Create case directory structure
mkdir week14-integration
cd week14-integration
mkdir evidence timeline analysis reports

# Create analysis scripts
touch forensic_analyzer.py
touch timeline_correlator.py
touch evidence_processor.py
touch case_reporter.py

# Create evidence log
touch evidence_log.md
touch timeline.csv
```

### Step 3: Disk Forensics Analysis (120 minutes)

**Using Autopsy for Disk Analysis:**

```python
# forensic_analyzer.py
import sqlite3
import json
import csv
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import pandas as pd

class ForensicEvidence:
    def __init__(self, evidence_id: str, timestamp: datetime, evidence_type: str,
                 source_tool: str, artifact_path: str, description: str):
        self.evidence_id = evidence_id
        self.timestamp = timestamp
        self.evidence_type = evidence_type  # disk, memory, network, mobile
        self.source_tool = source_tool  # autopsy, volatility, wireshark, etc
        self.artifact_path = artifact_path
        self.description = description
        self.metadata = {}
        self.hash_values = {}
        self.correlations = []

    def to_dict(self):
        return {
            'evidence_id': self.evidence_id,
            'timestamp': self.timestamp.isoformat(),
            'evidence_type': self.evidence_type,
            'source_tool': self.source_tool,
            'artifact_path': self.artifact_path,
            'description': self.description,
            'metadata': self.metadata,
            'hash_values': self.hash_values
        }

class DiskAnalyzer:
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.evidence_items = []
        self.deleted_files = []
        self.user_activities = []
        self.suspicious_files = []

    def analyze_disk_image(self, image_path: str) -> Dict:
        """Analyze disk image using Autopsy-style analysis"""
        print(f"🔍 Analyzing disk image: {image_path}")

        # Simulate Autopsy analysis results
        analysis_results = {
            'file_system': self.analyze_file_system(),
            'deleted_files': self.recover_deleted_files(),
            'user_activity': self.extract_user_activity(),
            'browser_artifacts': self.analyze_browser_data(),
            'email_artifacts': self.extract_email_data(),
            'document_analysis': self.analyze_documents()
        }

        return analysis_results

    def analyze_file_system(self) -> Dict:
        """Analyze file system structure and metadata"""
        return {
            'total_files': 45672,
            'recent_files': 1247,
            'executable_files': 892,
            'document_files': 3456,
            'media_files': 12893,
            'suspicious_extensions': ['.tmp', '.bak', '.old'],
            'large_files': [
                {'path': '/Users/employee/Documents/company_data.zip', 'size': '2.3GB', 'modified': '2024-01-15 14:30:22'},
                {'path': '/Users/employee/Desktop/backup.rar', 'size': '1.8GB', 'modified': '2024-01-15 15:45:18'}
            ]
        }

    def recover_deleted_files(self) -> List[Dict]:
        """Recover deleted files that may contain evidence"""
        deleted_files = [
            {
                'filename': 'financial_records.xlsx',
                'path': '/Users/employee/Documents/',
                'deleted_time': '2024-01-15 16:20:45',
                'size': '850KB',
                'recoverable': True,
                'significance': 'HIGH - Contains sensitive financial data'
            },
            {
                'filename': 'employee_list.csv',
                'path': '/Users/employee/Downloads/',
                'deleted_time': '2024-01-15 16:22:10',
                'size': '120KB',
                'recoverable': True,
                'significance': 'MEDIUM - Employee personal information'
            },
            {
                'filename': 'project_plans.docx',
                'path': '/Users/employee/Desktop/',
                'deleted_time': '2024-01-15 16:25:33',
                'size': '2.1MB',
                'recoverable': True,
                'significance': 'HIGH - Confidential project information'
            }
        ]
        return deleted_files

class ForensicInvestigator:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_items = []
        self.timeline_events = []
        self.suspects = []
        self.investigation_findings = {}

        # Initialize case database
        self.db_path = f"evidence/{case_id}_case.db"
        self.init_case_database()

        # Initialize analysis tools
        self.disk_analyzer = DiskAnalyzer(case_id)
        self.memory_analyzer = MemoryAnalyzer(case_id)
        self.network_analyzer = NetworkAnalyzer(case_id)

    def init_case_database(self):
        """Initialize forensic case database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY,
                timestamp TEXT,
                evidence_type TEXT,
                source_tool TEXT,
                artifact_path TEXT,
                description TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                significance TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                source TEXT,
                user_account TEXT,
                description TEXT,
                evidence_reference TEXT,
                confidence_level TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigation_findings (
                finding_id TEXT PRIMARY KEY,
                category TEXT,
                description TEXT,
                evidence_support TEXT,
                confidence_level TEXT,
                impact_assessment TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def extract_user_activity(self) -> List[Dict]:
        """Extract user activity timeline from disk artifacts"""
        activities = [
            {
                'timestamp': '2024-01-15 14:25:00',
                'activity': 'Login',
                'user': 'employee',
                'source': 'Windows Event Log',
                'details': 'Successful logon'
            },
            {
                'timestamp': '2024-01-15 14:30:22',
                'activity': 'File Access',
                'user': 'employee',
                'source': 'NTFS $MFT',
                'details': 'Accessed /Company/Financial/Q4_Reports/'
            },
            {
                'timestamp': '2024-01-15 14:35:15',
                'activity': 'File Copy',
                'user': 'employee',
                'source': 'NTFS USN Journal',
                'details': 'Copied sensitive files to USB drive E:'
            },
            {
                'timestamp': '2024-01-15 14:40:33',
                'activity': 'File Compression',
                'user': 'employee',
                'source': 'Process Monitor',
                'details': 'Created compressed archive company_data.zip'
            },
            {
                'timestamp': '2024-01-15 15:45:18',
                'activity': 'Network Transfer',
                'user': 'employee',
                'source': 'Network Logs',
                'details': 'Large file upload to personal cloud storage'
            },
            {
                'timestamp': '2024-01-15 16:20:45',
                'activity': 'File Deletion',
                'user': 'employee',
                'source': 'Recycle Bin Analysis',
                'details': 'Deleted evidence files before logging off'
            }
        ]
        return activities

    def analyze_browser_data(self) -> Dict:
        """Analyze browser artifacts for evidence"""
        return {
            'history_entries': 1250,
            'suspicious_sites': [
                {'url': 'https://filehosting.anonymousservice.com', 'visits': 15, 'last_visit': '2024-01-15 15:30:00'},
                {'url': 'https://securedrop.journalist.site', 'visits': 3, 'last_visit': '2024-01-15 15:45:00'}
            ],
            'downloads': [
                {'file': 'encryption_tool.exe', 'source': 'https://anonymoustools.net', 'date': '2024-01-15 14:15:00'},
                {'file': 'secure_delete.exe', 'source': 'https://privacy-tools.com', 'date': '2024-01-15 16:10:00'}
            ],
            'cookies': {
                'tracking_cookies': 45,
                'authentication_cookies': 12,
                'suspicious_domains': ['anonymousservice.com', 'privacy-tools.com']
            }
        }

class MemoryAnalyzer:
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.processes = []
        self.network_connections = []
        self.injected_code = []

    def analyze_memory_dump(self, dump_path: str) -> Dict:
        """Analyze memory dump using Volatility-style analysis"""
        print(f"🧠 Analyzing memory dump: {dump_path}")

        # Simulate Volatility analysis results
        analysis_results = {
            'running_processes': self.extract_processes(),
            'network_connections': self.extract_network_connections(),
            'malicious_code': self.detect_code_injection(),
            'credentials': self.extract_credentials(),
            'persistence': self.check_persistence_mechanisms()
        }

        return analysis_results

    def extract_processes(self) -> List[Dict]:
        """Extract running processes from memory"""
        processes = [
            {
                'pid': 1234,
                'name': 'encryption_tool.exe',
                'start_time': '2024-01-15 14:15:30',
                'suspicious': True,
                'reason': 'Unsigned executable with network activity'
            },
            {
                'pid': 5678,
                'name': 'winrar.exe',
                'start_time': '2024-01-15 14:40:00',
                'suspicious': True,
                'reason': 'Creating large archive of sensitive data'
            },
            {
                'pid': 9012,
                'name': 'secure_delete.exe',
                'start_time': '2024-01-15 16:10:00',
                'suspicious': True,
                'reason': 'Evidence destruction tool'
            }
        ]
        return processes

class NetworkAnalyzer:
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.connections = []
        self.traffic_analysis = {}

    def analyze_network_traffic(self, pcap_path: str) -> Dict:
        """Analyze network traffic using Wireshark-style analysis"""
        print(f"🌐 Analyzing network traffic: {pcap_path}")

        # Simulate Wireshark analysis results
        analysis_results = {
            'data_exfiltration': self.detect_data_exfiltration(),
            'suspicious_connections': self.find_suspicious_connections(),
            'protocol_analysis': self.analyze_protocols(),
            'file_transfers': self.identify_file_transfers()
        }

        return analysis_results

    def detect_data_exfiltration(self) -> List[Dict]:
        """Detect potential data exfiltration in network traffic"""
        exfiltration_events = [
            {
                'timestamp': '2024-01-15 15:45:18',
                'source_ip': '192.168.1.100',
                'destination_ip': '203.0.113.45',
                'protocol': 'HTTPS',
                'bytes_transferred': 2400000000,  # 2.4GB
                'duration': '00:15:30',
                'suspicious_indicator': 'Large file upload to external cloud service'
            }
        ]
        return exfiltration_events

### Step 4: Memory Forensics Analysis (90 minutes)

**Using Volatility for Memory Analysis:**

```python
# Continue with MemoryAnalyzer class methods
    def extract_network_connections(self) -> List[Dict]:
        """Extract network connections from memory"""
        connections = [
            {
                'local_addr': '192.168.1.100:443',
                'remote_addr': '203.0.113.45:443',
                'state': 'ESTABLISHED',
                'pid': 1234,
                'process': 'encryption_tool.exe',
                'suspicious': True
            },
            {
                'local_addr': '192.168.1.100:80',
                'remote_addr': '198.51.100.23:80',
                'state': 'ESTABLISHED',
                'pid': 5678,
                'process': 'winrar.exe',
                'suspicious': False
            }
        ]
        return connections

    def detect_code_injection(self) -> List[Dict]:
        """Detect code injection in memory"""
        injections = [
            {
                'process': 'explorer.exe',
                'pid': 2468,
                'injection_type': 'DLL Injection',
                'suspicious_dll': 'malicious_library.dll',
                'confidence': 'HIGH'
            }
        ]
        return injections

    def extract_credentials(self) -> List[Dict]:
        """Extract credentials from memory"""
        credentials = [
            {
                'type': 'NTLM Hash',
                'username': 'employee',
                'domain': 'COMPANY',
                'hash': 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
            },
            {
                'type': 'Cached Password',
                'service': 'cloud_storage_service',
                'username': 'employee@personalmail.com',
                'password': '[REDACTED]'
            }
        ]
        return credentials

### Step 5: Network Analysis (90 minutes)

**Using Wireshark for Network Analysis:**

```python
# Continue with NetworkAnalyzer class methods
    def find_suspicious_connections(self) -> List[Dict]:
        """Find suspicious network connections"""
        suspicious = [
            {
                'timestamp': '2024-01-15 14:20:00',
                'source': '192.168.1.100',
                'destination': '203.0.113.45',
                'port': 443,
                'protocol': 'TLS',
                'alert': 'Connection to known file hosting service'
            },
            {
                'timestamp': '2024-01-15 15:45:00',
                'source': '192.168.1.100',
                'destination': '198.51.100.23',
                'port': 80,
                'protocol': 'HTTP',
                'alert': 'Large file upload detected'
            }
        ]
        return suspicious

    def analyze_protocols(self) -> Dict:
        """Analyze protocol usage"""
        return {
            'http_requests': 1250,
            'https_requests': 850,
            'ftp_transfers': 5,
            'dns_queries': 2400,
            'suspicious_protocols': ['TOR', 'I2P'],
            'encrypted_traffic_percentage': 85.2
        }

    def identify_file_transfers(self) -> List[Dict]:
        """Identify file transfer activities"""
        transfers = [
            {
                'timestamp': '2024-01-15 15:45:18',
                'direction': 'outbound',
                'size': '2.4GB',
                'destination': 'file-hosting-service.com',
                'filename': 'company_data.zip',
                'method': 'HTTP POST'
            }
        ]
        return transfers

### Step 6: Mobile Forensics Correlation (30 minutes)

**Correlating Mobile Device Evidence:**

```python
class MobileAnalyzer:
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.communications = []
        self.app_data = {}

    def analyze_mobile_backup(self, backup_path: str) -> Dict:
        """Analyze mobile device backup"""
        print(f"📱 Analyzing mobile backup: {backup_path}")

        analysis_results = {
            'communications': self.extract_communications(),
            'file_transfers': self.analyze_file_sharing_apps(),
            'location_data': self.extract_location_timeline(),
            'app_usage': self.analyze_app_usage()
        }

        return analysis_results

    def extract_communications(self) -> List[Dict]:
        """Extract communication records"""
        communications = [
            {
                'timestamp': '2024-01-15 13:45:00',
                'type': 'SMS',
                'contact': '+1-555-0123',
                'direction': 'outgoing',
                'content': 'Meeting at usual place to discuss the files'
            },
            {
                'timestamp': '2024-01-15 16:30:00',
                'type': 'WhatsApp',
                'contact': 'External Contact',
                'direction': 'outgoing',
                'content': 'Package delivered successfully'
            }
        ]
        return communications

    def analyze_file_sharing_apps(self) -> List[Dict]:
        """Analyze file sharing app usage"""
        file_shares = [
            {
                'app': 'Dropbox',
                'timestamp': '2024-01-15 15:45:18',
                'action': 'upload',
                'filename': 'company_data.zip',
                'size': '2.4GB'
            }
        ]
        return file_shares

    def extract_location_timeline(self) -> List[Dict]:
        """Extract location data for timeline"""
        locations = [
            {
                'timestamp': '2024-01-15 13:00:00',
                'location': 'Company Office',
                'coordinates': '40.7128, -74.0060',
                'duration': '4 hours'
            },
            {
                'timestamp': '2024-01-15 17:00:00',
                'location': 'Coffee Shop (unusual)',
                'coordinates': '40.7580, -73.9855',
                'duration': '1 hour'
            }
        ]
        return locations

### Step 7: Investigation Report Writing (60 minutes)

**Comprehensive Case Analysis:**

```python
class CaseReporter:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_chain = []
        self.timeline = []
        self.findings = {}

    def correlate_all_evidence(self, disk_results: Dict, memory_results: Dict,
                             network_results: Dict, mobile_results: Dict) -> Dict:
        """Correlate evidence across all sources"""
        print("🔗 Correlating evidence from all sources...")

        correlation_results = {
            'timeline_correlation': self.build_master_timeline(disk_results, memory_results, network_results, mobile_results),
            'evidence_correlation': self.correlate_evidence_items(disk_results, memory_results, network_results, mobile_results),
            'insider_threat_indicators': self.identify_insider_threat_patterns(disk_results, memory_results, network_results, mobile_results),
            'data_theft_proof': self.establish_data_theft_evidence(disk_results, memory_results, network_results, mobile_results)
        }

        return correlation_results

    def build_master_timeline(self, disk_results: Dict, memory_results: Dict,
                            network_results: Dict, mobile_results: Dict) -> List[Dict]:
        """Build master timeline of all events"""
        timeline_events = [
            {
                'timestamp': '2024-01-15 13:00:00',
                'source': 'Mobile GPS',
                'event': 'Employee arrives at office',
                'significance': 'Normal work activity'
            },
            {
                'timestamp': '2024-01-15 14:15:00',
                'source': 'Memory Analysis',
                'event': 'Encryption tool launched',
                'significance': 'Preparation for data theft'
            },
            {
                'timestamp': '2024-01-15 14:30:22',
                'source': 'Disk Analysis',
                'event': 'Access to sensitive financial data',
                'significance': 'Unauthorized data access'
            },
            {
                'timestamp': '2024-01-15 15:45:18',
                'source': 'Network Analysis',
                'event': '2.4GB data uploaded to external service',
                'significance': 'Data exfiltration confirmed'
            },
            {
                'timestamp': '2024-01-15 16:20:45',
                'source': 'Disk Analysis',
                'event': 'Evidence files deleted',
                'significance': 'Attempt to cover tracks'
            },
            {
                'timestamp': '2024-01-15 16:30:00',
                'source': 'Mobile Analysis',
                'event': 'Confirmation message sent',
                'significance': 'Communication with external party'
            }
        ]
        return timeline_events

    def generate_investigation_report(self) -> Dict:
        """Generate comprehensive investigation report"""
        report = {
            'case_information': {
                'case_id': self.case_id,
                'investigation_date': datetime.now().isoformat(),
                'investigator': 'Digital Forensics Team',
                'case_type': 'Insider Threat Investigation'
            },
            'executive_summary': {
                'threat_confirmed': True,
                'threat_type': 'Insider Data Theft',
                'data_compromised': '2.4GB of sensitive company data',
                'attribution': 'Employee with legitimate access',
                'confidence_level': 'HIGH'
            },
            'technical_findings': {
                'evidence_sources': ['Disk Image', 'Memory Dump', 'Network Captures', 'Mobile Backup'],
                'tools_used': ['Autopsy', 'Volatility', 'Wireshark', 'Mobile Forensics'],
                'key_artifacts': ['Deleted files', 'Process memory', 'Network flows', 'Communications'],
                'timeline_established': True
            },
            'recommendations': [
                'Immediately revoke employee access',
                'Contact law enforcement',
                'Implement DLP solutions',
                'Review access controls',
                'Conduct security awareness training'
            ]
        }
        return report

def main():
    """Main forensic investigation workflow"""
    print("🔍 Forensic Case Integration - Insider Threat Investigation")
    print("=" * 60)

    case_id = "CASE_INSIDER_20240115"
    investigator = ForensicInvestigator(case_id)

    # Step 1: Analyze disk image
    print("\n💾 Disk Forensics Analysis")
    disk_results = investigator.disk_analyzer.analyze_disk_image("/evidence/suspect_disk.dd")

    # Step 2: Analyze memory dump
    print("\n🧠 Memory Forensics Analysis")
    memory_results = investigator.memory_analyzer.analyze_memory_dump("/evidence/memory_dump.raw")

    # Step 3: Analyze network traffic
    print("\n🌐 Network Traffic Analysis")
    network_results = investigator.network_analyzer.analyze_network_traffic("/evidence/network_capture.pcap")

    # Step 4: Analyze mobile device
    print("\n📱 Mobile Device Analysis")
    mobile_analyzer = MobileAnalyzer(case_id)
    mobile_results = mobile_analyzer.analyze_mobile_backup("/evidence/mobile_backup/")

    # Step 5: Correlate all evidence
    print("\n🔗 Evidence Correlation")
    reporter = CaseReporter(case_id)
    correlation_results = reporter.correlate_all_evidence(disk_results, memory_results, network_results, mobile_results)

    # Step 6: Generate final report
    print("\n📄 Generating Investigation Report")
    final_report = reporter.generate_investigation_report()

    # Save all results
    os.makedirs("reports", exist_ok=True)

    with open(f"reports/{case_id}_final_report.json", 'w') as f:
        json.dump(final_report, f, indent=2)

    with open("timeline.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Source', 'Event', 'Significance'])
        for event in correlation_results['timeline_correlation']:
            writer.writerow([event['timestamp'], event['source'], event['event'], event['significance']])

    print(f"\n✅ Investigation Complete!")
    print(f"📄 Final report: reports/{case_id}_final_report.json")
    print(f"📅 Timeline: timeline.csv")
    print(f"\n🎯 Key Findings:")
    print(f"   • Insider threat confirmed with HIGH confidence")
    print(f"   • 2.4GB of sensitive data exfiltrated")
    print(f"   • Complete timeline established")
    print(f"   • Evidence chain maintained")

if __name__ == "__main__":
    main()
```

## 🔧 Tools and Commands Reference

### Autopsy Commands
```bash
# Create new case
autopsy
# Open case -> Add Data Source -> Disk Image
# Run Ingest Modules:
# - Recent Activity
# - Hash Lookup
# - File Type Identification
# - Keyword Search
# - Timeline Analysis
```

### Volatility Commands
```bash
# Identify image profile
vol.py -f memory_dump.raw imageinfo

# List running processes
vol.py -f memory_dump.raw --profile=Win10x64_19041 pslist

# Network connections
vol.py -f memory_dump.raw --profile=Win10x64_19041 netscan

# Extract process memory
vol.py -f memory_dump.raw --profile=Win10x64_19041 memdump -p 1234 -D output/

# Scan for injected code
vol.py -f memory_dump.raw --profile=Win10x64_19041 malfind
```

### Wireshark Analysis
```bash
# Open PCAP file
wireshark network_capture.pcap

# Filter for large transfers
http.content_length > 1000000

# Filter for specific IP
ip.addr == 192.168.1.100

# Export HTTP objects
File -> Export Objects -> HTTP

# Follow TCP stream
right-click packet -> Follow -> TCP Stream
```

## 🐛 Common Issues & Solutions

### Issue: Evidence files are too large to process
**Solution**: Use selective analysis and focus on timeframe around incident

### Issue: Memory dump analysis takes too long
**Solution**: Target specific processes and timeframes, use faster plugins first

### Issue: Network traffic is encrypted
**Solution**: Focus on metadata, connection patterns, and timing analysis

### Issue: Mobile backup is encrypted
**Solution**: Use logical extraction, focus on unencrypted artifacts

### Issue: Timeline correlation is complex
**Solution**: Start with high-confidence events, expand timeline gradually

## ✅ Testing Workflow

```bash
# Run complete forensic analysis
python forensic_analyzer.py

# Generate timeline
python timeline_correlator.py

# Create final report
python case_reporter.py

# Validate evidence chain
python evidence_processor.py --validate
```

## 📁 Expected File Structure
```
week14-integration/
├── forensic_analyzer.py           # Main analysis engine
├── timeline_correlator.py         # Timeline correlation
├── evidence_processor.py          # Evidence management
├── case_reporter.py               # Report generation
├── evidence_log.md                # Evidence documentation
├── timeline.csv                   # Master timeline
└── reports/
    ├── investigation_report.pdf      # Final report
    ├── executive_summary.md          # Executive summary
    └── evidence_analysis.json        # Technical findings
```

## 🏆 Success Criteria

1. **Complete Timeline**: All events from 13:00-17:00 on incident day
2. **Evidence Correlation**: Links between disk, memory, network, mobile
3. **Insider Threat Proof**: Clear evidence of intentional data theft
4. **Professional Report**: Executive summary + technical details
5. **Tool Proficiency**: Effective use of Autopsy, Volatility, Wireshark

## 💡 Pro Tips

1. **Start with Timeline**: Establish when events occurred before analyzing what happened
2. **Focus on Attribution**: Prove WHO performed the actions, not just what happened
3. **Preserve Evidence**: Document hash values and maintain chain of custody
4. **Correlate Across Sources**: One source confirms, multiple sources prove
5. **Executive Summary First**: Write for decision-makers, then add technical details

## 🔍 Key Investigation Concepts

### Forensic Methodology:
- **Identification**: What evidence sources are available?
- **Preservation**: How to maintain evidence integrity?
- **Analysis**: What do the artifacts tell us?
- **Documentation**: How to present findings?
- **Presentation**: How to communicate to stakeholders?

### Insider Threat Indicators:
- **Access Pattern Changes**: Off-hours access, unusual file access
- **Data Aggregation**: Collecting files from multiple sources
- **External Communication**: Contact with unknown parties
- **Tool Usage**: Encryption, compression, anonymization tools
- **Evidence Destruction**: Deletion, wiping, anti-forensics

## ⏱️ Time Management

- **Focus on Key Timeframe**: 13:00-17:00 on incident day
- **Use Automated Tools**: Let Autopsy and Volatility do heavy lifting
- **Target Analysis**: Don't analyze everything, focus on evidence of data theft
- **Document as You Go**: Record findings immediately, don't wait until end

## 🎆 Extension Ideas (Optional)

- Integrate with YARA rules for malware detection
- Add STIX/TAXII threat intelligence
- Implement automated correlation rules
- Create interactive timeline visualization
- Add machine learning for anomaly detection

Remember: Week 14 integrates all forensic skills learned throughout the course. Focus on proving the insider threat case using evidence from multiple sources!
