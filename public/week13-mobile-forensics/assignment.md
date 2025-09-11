# Week 13 Assignment: Mobile Device and Cloud Forensics Platform

**Due**: End of Week 13 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 6 hours  
**Submission**: Submit Pull Request URL to Canvas

## 🎯 Assignment Overview

Build focused mobile forensics analysis tools using provided mobile data extracts and pre-built parsing frameworks. This assignment emphasizes practical mobile forensics skills using existing tools and provided mobile device data samples.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Mobile Data Analysis** (15 points) - Choose Android OR iOS
2. **Application Artifact Analysis** (5 points)
3. **Mobile Forensics Reporting** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build focused mobile analysis tools (choose Android OR iOS):

```python
# Core modules to implement
mobile_analyzer.py      # Android OR iOS data analysis
app_artifact_parser.py  # Application artifact extraction
forensics_reporter.py   # Mobile forensics reporting
```

### Required Libraries
```python
import sqlite3
import json
import plistlib
from datetime import datetime, timezone
import hashlib
import base64
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import pandas as pd
import xml.etree.ElementTree as ET
from pathlib import Path
```

## 📝 Detailed Requirements

### 1. Mobile Data Analysis - Choose Android OR iOS (15 points)

**Focus Area: Single Platform Deep Analysis Using Provided Data**

#### Option A: Android Analysis
**Required Features:**
- **SQLite database** parsing for system and app data using provided extracts
- **Shared preferences** analysis from Android applications
- **Communication analysis** (SMS, call logs, contacts) using provided databases
- **Application data** extraction from provided app data directories
- **Timeline construction** from Android system artifacts

#### Option B: iOS Analysis  
**Required Features:**
- **Plist file analysis** using provided iOS backup data
- **SQLite database** parsing for iOS system and app data
- **Communication analysis** from iOS message and call databases
- **Application artifact** extraction from iOS backup structures
- **Timeline construction** from iOS system artifacts

**Deliverable:** `mobile_analyzer.py` with chosen platform analysis

*Note: Mobile device data extracts provided for both Android and iOS platforms*

### 2. Application Artifact Analysis (5 points)

**Required Features:**
- **Popular app analysis** (WhatsApp, browser data, social media) from provided extracts
- **Database parsing** for application-specific data structures
- **Media file** analysis and metadata extraction
- **User activity** reconstruction from application artifacts

**Deliverable:** `app_artifact_parser.py` with application-specific parsing

### 3. Mobile Forensics Reporting (5 points)

**Required Features:**
- **Executive summary** with key mobile forensics findings
- **Technical analysis** with detailed artifact analysis
- **Timeline presentation** showing user activities and communications
- **Privacy impact** assessment from extracted personal data

**Deliverable:** `forensics_reporter.py` with mobile-specific reporting

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── mobile_analyzer.py        # Android OR iOS analysis
│   ├── app_artifact_parser.py    # Application-specific parsing
│   └── forensics_reporter.py     # Mobile forensics reporting
├── data/
│   ├── android_samples/          # Provided Android extracts
│   │   ├── contacts.db
│   │   ├── sms.db
│   │   ├── whatsapp_msgstore.db
│   │   └── browser_history.db
│   └── ios_samples/              # Provided iOS backup extracts
│       ├── manifest.plist
│       ├── sms.db
│       ├── contacts.sqlitedb
│       └── safari_history.db
├── reports/
│   ├── mobile_forensics_report.html
│   ├── timeline_analysis.json
│   └── privacy_assessment.md
└── README.md
```

### Sample Android Analysis
```python
@dataclass
class AndroidApp:
    package_name: str
    app_name: str
    version: str
    install_date: datetime
    permissions: List[str]
    data_directory: str
    databases: List[str]
    shared_prefs: Dict[str, Any]
    
    def analyze_database(self, db_path: str) -> List[Dict]:
        """Analyze SQLite database for app artifacts"""
        artifacts = []
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Get all table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                # Skip system tables
                if table_name.startswith('sqlite_'):
                    continue
                
                # Analyze table content
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Convert to structured data
                for row in rows:
                    artifact = dict(zip(columns, row))
                    artifact['_table'] = table_name
                    artifact['_timestamp'] = datetime.now().isoformat()
                    artifacts.append(artifact)
        
        return artifacts
    
    def extract_communications(self) -> Dict[str, List]:
        """Extract communication artifacts from app"""
        communications = {
            'messages': [],
            'calls': [],
            'contacts': []
        }
        
        # Look for common communication patterns
        for db in self.databases:
            if 'message' in db.lower() or 'sms' in db.lower():
                communications['messages'].extend(self.extract_messages(db))
            elif 'call' in db.lower():
                communications['calls'].extend(self.extract_calls(db))
            elif 'contact' in db.lower():
                communications['contacts'].extend(self.extract_contacts(db))
        
        return communications
```

### Sample iOS Analysis
```python
class iOSAnalyzer:
    def __init__(self, backup_path: str):
        self.backup_path = Path(backup_path)
        self.manifest = self.parse_manifest()
        self.info_plist = self.parse_info_plist()
    
    def parse_manifest(self) -> Dict:
        """Parse iOS backup manifest"""
        manifest_path = self.backup_path / 'Manifest.plist'
        
        if manifest_path.exists():
            with open(manifest_path, 'rb') as f:
                return plistlib.load(f)
        return {}
    
    def analyze_keychain(self) -> List[Dict]:
        """Analyze keychain items from backup"""
        keychain_items = []
        
        # Look for keychain database
        keychain_path = self.find_file_by_domain('KeychainDomain')
        
        if keychain_path:
            # Simulate keychain analysis
            with sqlite3.connect(keychain_path) as conn:
                cursor = conn.cursor()
                
                # Extract stored credentials
                query = """
                SELECT service, account, created_date, modified_date
                FROM keychain_items
                WHERE accessible = 1
                """
                
                for row in cursor.execute(query):
                    keychain_items.append({
                        'service': row[0],
                        'account': row[1],
                        'created': row[2],
                        'modified': row[3],
                        'type': 'credential'
                    })
        
        return keychain_items
    
    def extract_location_data(self) -> List[Dict]:
        """Extract location data from iOS backup"""
        locations = []
        
        # Look for location databases
        location_files = [
            'consolidated.db',
            'cache_encryptedA.db',
            'locationd_cache_encryptedA.db'
        ]
        
        for filename in location_files:
            db_path = self.find_file_by_name(filename)
            if db_path:
                locations.extend(self.parse_location_db(db_path))
        
        return locations
    
    def analyze_app_data(self, bundle_id: str) -> Dict:
        """Analyze specific iOS app data"""
        app_data = {
            'bundle_id': bundle_id,
            'documents': [],
            'preferences': {},
            'databases': [],
            'caches': []
        }
        
        # Find app container
        app_path = self.find_app_container(bundle_id)
        
        if app_path:
            # Analyze app documents
            docs_path = app_path / 'Documents'
            if docs_path.exists():
                app_data['documents'] = self.enumerate_files(docs_path)
            
            # Analyze app preferences
            prefs_path = app_path / 'Library' / 'Preferences'
            if prefs_path.exists():
                app_data['preferences'] = self.parse_preferences(prefs_path)
            
            # Find SQLite databases
            for db_file in app_path.rglob('*.sqlite*'):
                app_data['databases'].append(str(db_file))
        
        return app_data
```

### Sample Cloud Investigation
```python
class CloudInvestigator:
    def __init__(self):
        self.sync_logs = []
        self.file_versions = {}
        self.sharing_activities = []
    
    def analyze_sync_patterns(self, sync_data: List[Dict]) -> Dict:
        """Analyze cloud synchronization patterns"""
        patterns = {
            'sync_frequency': {},
            'device_activity': {},
            'conflict_resolution': [],
            'large_transfers': [],
            'suspicious_activity': []
        }
        
        for event in sync_data:
            # Analyze sync frequency per device
            device_id = event.get('device_id')
            if device_id not in patterns['sync_frequency']:
                patterns['sync_frequency'][device_id] = 0
            patterns['sync_frequency'][device_id] += 1
            
            # Check for large file transfers
            file_size = event.get('file_size', 0)
            if file_size > 100_000_000:  # 100MB
                patterns['large_transfers'].append(event)
            
            # Detect unusual activity patterns
            if self.is_suspicious_activity(event):
                patterns['suspicious_activity'].append(event)
        
        return patterns
    
    def reconstruct_file_history(self, file_path: str) -> List[Dict]:
        """Reconstruct file modification history across devices"""
        history = []
        
        # Simulate file version tracking
        versions = self.file_versions.get(file_path, [])
        
        for version in versions:
            history.append({
                'timestamp': version['modified_date'],
                'device': version['device_id'],
                'action': version['action'],
                'file_size': version['size'],
                'hash': version['content_hash'],
                'conflict': version.get('conflict_resolution', False)
            })
        
        # Sort by timestamp
        return sorted(history, key=lambda x: x['timestamp'])
    
    def analyze_sharing_patterns(self) -> Dict:
        """Analyze file sharing and collaboration patterns"""
        sharing_analysis = {
            'public_shares': [],
            'private_shares': [],
            'collaboration_networks': {},
            'access_patterns': {}
        }
        
        for activity in self.sharing_activities:
            # Classify sharing type
            if activity.get('public_access'):
                sharing_analysis['public_shares'].append(activity)
            else:
                sharing_analysis['private_shares'].append(activity)
            
            # Build collaboration networks
            owner = activity.get('owner')
            collaborators = activity.get('shared_with', [])
            
            if owner not in sharing_analysis['collaboration_networks']:
                sharing_analysis['collaboration_networks'][owner] = set()
            
            sharing_analysis['collaboration_networks'][owner].update(collaborators)
        
        return sharing_analysis
```

## 🧪 Testing Requirements

Your implementation must include:

### Mobile Platform Tests
- **Android database** parsing accuracy
- **iOS backup** extraction validation
- **App data** recovery completeness
- **Communication** artifact extraction
- **Location data** accuracy verification

### Cloud Analysis Tests
- **Sync pattern** detection validation
- **File history** reconstruction accuracy
- **Sharing analysis** completeness
- **Cross-platform** consistency verification
- **Timeline correlation** accuracy

### Integration Testing
Create comprehensive test scenarios including:
- Multi-device user scenarios with Android and iOS
- Cloud synchronization across multiple services
- Communication across different platforms and apps
- Privacy exposure analysis across platforms
- Timeline correlation validation with known events

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all mobile forensics modules)
2. **Test Data Sets** (simulated mobile and cloud data)
3. **Analysis Reports** (generated from test scenarios)
4. **App Analyzer Plugins** (for major mobile applications)
5. **Documentation** (README.md with analysis methodologies)

### README.md Must Include:
- **Mobile forensics** methodologies and approaches
- **App data extraction** techniques and limitations
- **Cloud investigation** procedures and challenges
- **Cross-platform correlation** algorithms
- **Privacy considerations** and legal compliance notes

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Mobile Data Analysis** | 60% | 15 points |
| **Application Artifact Analysis** | 20% | 5 points |
| **Mobile Forensics Reporting** | 20% | 5 points |

### 5-Point Scale Criteria

**Mobile Data Analysis (15 points)**
- **Excellent (15)**: Comprehensive platform analysis (Android OR iOS), accurate database parsing, complete communication extraction, thorough application data analysis, professional timeline construction
- **Proficient (12)**: Good platform analysis, adequate database handling, reasonable communication extraction, basic timeline
- **Developing (9)**: Simple platform analysis, limited database parsing, minimal communication extraction, basic timeline
- **Needs Improvement (6)**: Poor platform analysis, weak database handling, inadequate extraction, incomplete timeline
- **Inadequate (3)**: Minimal platform capabilities, major functionality gaps, broken analysis
- **No Submission (0)**: Missing or no attempt

**Application Artifact Analysis (5 points)**
- **Excellent (5)**: Sophisticated application analysis, comprehensive artifact extraction, multiple app support, accurate parsing, meaningful insights
- **Proficient (4)**: Good application analysis, adequate extraction, reasonable app coverage, decent parsing
- **Developing (3)**: Basic application analysis, limited extraction, few apps supported, simple parsing
- **Needs Improvement (2)**: Poor application analysis, weak extraction, significant parsing limitations
- **Inadequate (1)**: Minimal application support, major extraction failures, broken parsing
- **No Submission (0)**: Missing or no attempt

**Mobile Forensics Reporting (5 points)**
- **Excellent (5)**: Professional reports, comprehensive executive summary, detailed technical analysis, excellent timeline presentation, thorough privacy assessment
- **Proficient (4)**: Good reports, adequate summaries, decent technical detail, basic timeline, reasonable privacy notes
- **Developing (3)**: Basic reports, limited structure, simple findings, minimal timeline, basic privacy assessment
- **Needs Improvement (2)**: Poor report quality, inadequate structure, weak findings, incomplete timeline, minimal privacy analysis
- **Inadequate (1)**: Unprofessional reports, major gaps, unusable analysis, no privacy consideration
- **No Submission (0)**: Missing or no attempt

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Optional Challenge

**Advanced Mobile Forensics**: Implement parsing for encrypted databases or develop timeline correlation between multiple mobile applications with conflict resolution for timestamp discrepancies.

## 💡 Tips for Success

1. **Study Real Apps**: Understand how popular apps store data
2. **Focus on Privacy**: Mobile devices contain highly sensitive information
3. **Test Cross-Platform**: Ensure correlation works across different platforms
4. **Document Limitations**: Mobile forensics has many technical and legal constraints
5. **Validate Timelines**: Timezone handling is critical for accurate correlation
6. **Consider Encryption**: Modern mobile devices use extensive encryption

## 📚 Resources & Required Tools

### Open Source Tools (All Free)
- **SQLite3** - Python standard library (public domain)
- **plistlib** - Python standard library (free)
- **biplist** - https://github.com/wooster/biplist (MIT License)
- **Pandas** - https://pandas.pydata.org/ (BSD 3-Clause License)
- **Python Libraries** - json, datetime, hashlib (all free standard library)

### Reference Materials
- NIST SP 800-101r1: Guidelines for Mobile Device Forensics
- iOS Security Guide (Apple)
- Android Security Documentation (Google)
- Mobile Forensics Investigating Digital Evidence
- Practical Mobile Forensics (Satish Bommisetty)
- Cloud Security and Privacy (Tim Mather)

### 🚨 IMPORTANT: Platform Choice and Data Access

**Platform Selection**: Choose either Android OR iOS analysis based on your interest and career goals. Both platforms provide equivalent learning outcomes.

**Mobile Data Samples**: Pre-extracted mobile device data provided for both platforms. Contact the instructor immediately if you encounter issues accessing the sample data files.

---

**Unlock the secrets of mobile devices and cloud storage!** 📱☁️