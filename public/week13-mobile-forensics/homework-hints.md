# Week 13 Homework Hints: Mobile Device and Cloud Forensics Platform

## 🎯 Quick Start Guide (6 hours total)

### Time Breakdown
- **Mobile Forensics Concepts**: 45 minutes
- **Mobile Data Analysis (Android OR iOS)**: 2.5 hours
- **Application Artifact Analysis**: 1.5 hours
- **Cloud Forensics Integration**: 1 hour
- **Mobile Forensics Reporting**: 30 minutes

## 📋 Step-by-Step Implementation

### Step 1: Mobile Forensics Fundamentals (30 minutes)

**Key Mobile Forensics Concepts:**
- **Logical Acquisition**: Accessing data through normal interfaces
- **Physical Acquisition**: Bit-by-bit copy of device storage
- **File System Extraction**: Direct access to file system
- **Application Data**: App-specific databases and files
- **Cloud Synchronization**: Data stored in cloud services

**Mobile-Specific Challenges:**
- **Device Encryption**: Full device and app-level encryption
- **Anti-Forensics**: Apps designed to hide or delete data
- **Fragmentation**: Different OS versions and manufacturers
- **Cloud Dependencies**: Critical data stored remotely

### Step 2: Environment Setup (15 minutes)

```bash
pip install sqlite3 plistlib xml.etree.ElementTree

mkdir week13-mobile-forensics
cd week13-mobile-forensics
mkdir android_analysis ios_analysis app_artifacts cloud_data reports

touch mobile_analyzer.py
touch app_artifact_parser.py
touch cloud_forensics.py
touch mobile_reporter.py
```

### Step 3: Mobile Device Analysis - Choose Android OR iOS (150 minutes)

#### Option A: Android Analysis

```python
# mobile_analyzer.py (Android Focus)
import sqlite3
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
import hashlib
import base64

class AndroidContact:
    def __init__(self, contact_id: int, display_name: str, phone_number: str = "", email: str = ""):
        self.contact_id = contact_id
        self.display_name = display_name
        self.phone_number = phone_number
        self.email = email
        self.last_contacted = None
        self.times_contacted = 0

    def to_dict(self):
        return {
            'contact_id': self.contact_id,
            'display_name': self.display_name,
            'phone_number': self.phone_number,
            'email': self.email,
            'last_contacted': self.last_contacted.isoformat() if self.last_contacted else None,
            'times_contacted': self.times_contacted
        }

class AndroidMessage:
    def __init__(self, message_id: int, thread_id: int, address: str, body: str, timestamp: datetime):
        self.message_id = message_id
        self.thread_id = thread_id
        self.address = address  # Phone number
        self.body = body
        self.timestamp = timestamp
        self.message_type = "SMS"  # SMS, MMS
        self.read_status = False

    def to_dict(self):
        return {
            'message_id': self.message_id,
            'thread_id': self.thread_id,
            'address': self.address,
            'body': self.body,
            'timestamp': self.timestamp.isoformat(),
            'type': self.message_type,
            'read': self.read_status
        }

class AndroidCallLog:
    def __init__(self, call_id: int, number: str, call_type: str, timestamp: datetime, duration: int):
        self.call_id = call_id
        self.number = number
        self.call_type = call_type  # INCOMING, OUTGOING, MISSED
        self.timestamp = timestamp
        self.duration = duration  # seconds

    def to_dict(self):
        return {
            'call_id': self.call_id,
            'number': self.number,
            'type': self.call_type,
            'timestamp': self.timestamp.isoformat(),
            'duration': self.duration
        }

class AndroidAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.device_info = {}
        self.contacts = []
        self.messages = []
        self.call_logs = []
        self.installed_apps = []
        self.browser_history = []
        self.wifi_networks = []
        self.location_data = []
        self.media_files = []

        # Initialize analysis database
        self.db_path = f"android_analysis/{case_id}_android_analysis.db"
        self.init_database()

    def init_database(self):
        """Initialize Android analysis database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_info (
                property TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                contact_id INTEGER PRIMARY KEY,
                display_name TEXT,
                phone_number TEXT,
                email TEXT,
                last_contacted TEXT,
                times_contacted INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY,
                thread_id INTEGER,
                address TEXT,
                body TEXT,
                timestamp TEXT,
                type TEXT,
                read_status BOOLEAN
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS call_logs (
                call_id INTEGER PRIMARY KEY,
                number TEXT,
                type TEXT,
                timestamp TEXT,
                duration INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS installed_apps (
                package_name TEXT PRIMARY KEY,
                app_name TEXT,
                version TEXT,
                install_time TEXT,
                permissions TEXT,
                data_usage INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS browser_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def create_sample_android_data(self):
        """Create sample Android data for analysis"""
        print("📱 Creating sample Android device data...")

        # Create sample contacts database
        contacts_db_path = "android_analysis/contacts2.db"
        os.makedirs(os.path.dirname(contacts_db_path), exist_ok=True)

        conn = sqlite3.connect(contacts_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                _id INTEGER PRIMARY KEY,
                display_name TEXT,
                data1 TEXT,
                data2 TEXT,
                mimetype TEXT
            )
        ''')

        sample_contacts = [
            (1, "John Doe", "+1234567890", "john@example.com", "vnd.android.cursor.item/phone_v2"),
            (2, "Jane Smith", "+1987654321", "jane@company.com", "vnd.android.cursor.item/phone_v2"),
            (3, "Suspicious Contact", "+1666666666", "hacker@evil.com", "vnd.android.cursor.item/phone_v2"),
            (4, "Emergency Services", "911", "", "vnd.android.cursor.item/phone_v2")
        ]

        for contact in sample_contacts:
            cursor.execute('INSERT INTO contacts VALUES (?, ?, ?, ?, ?)', contact)

        conn.commit()
        conn.close()

        # Create sample SMS database
        sms_db_path = "android_analysis/mmssms.db"
        conn = sqlite3.connect(sms_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms (
                _id INTEGER PRIMARY KEY,
                thread_id INTEGER,
                address TEXT,
                body TEXT,
                date INTEGER,
                type INTEGER,
                read INTEGER
            )
        ''')

        sample_messages = [
            (1, 1, "+1234567890", "Hey, are you free tonight?", 1640995200000, 1, 1),
            (2, 1, "+1234567890", "Yes, what did you have in mind?", 1640995260000, 2, 1),
            (3, 2, "+1666666666", "The package has been delivered to the usual location", 1640995320000, 1, 0),
            (4, 2, "+1666666666", "Payment will be transferred as discussed", 1640995380000, 1, 0),
            (5, 3, "+1987654321", "Don't forget about tomorrow's meeting", 1640995440000, 1, 1)
        ]

        for message in sample_messages:
            cursor.execute('INSERT INTO sms VALUES (?, ?, ?, ?, ?, ?, ?)', message)

        conn.commit()
        conn.close()

        # Create sample call log database
        calls_db_path = "android_analysis/contacts2.db"
        conn = sqlite3.connect(calls_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS calls (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                type INTEGER,
                date INTEGER,
                duration INTEGER
            )
        ''')

        sample_calls = [
            (1, "+1234567890", 2, 1640995200000, 180),  # Outgoing, 3 minutes
            (2, "+1666666666", 1, 1640995500000, 0),    # Incoming, missed
            (3, "+1987654321", 1, 1640995800000, 45),   # Incoming, 45 seconds
            (4, "+1666666666", 2, 1640996100000, 30)    # Outgoing, 30 seconds
        ]

        for call in sample_calls:
            cursor.execute('INSERT INTO calls VALUES (?, ?, ?, ?, ?)', call)

        conn.commit()
        conn.close()

        print("✅ Sample Android data created")

    def analyze_contacts(self) -> List[AndroidContact]:
        """Analyze Android contacts database"""
        print("👥 Analyzing contacts...")

        contacts = []
        contacts_db_path = "android_analysis/contacts2.db"

        if not os.path.exists(contacts_db_path):
            return contacts

        try:
            conn = sqlite3.connect(contacts_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT _id, display_name, data1, data2
                FROM contacts
                WHERE mimetype = 'vnd.android.cursor.item/phone_v2'
            ''')

            for row in cursor.fetchall():
                contact = AndroidContact(
                    contact_id=row[0],
                    display_name=row[1] or "Unknown",
                    phone_number=row[2] or "",
                    email=row[3] or ""
                )
                contacts.append(contact)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing contacts: {e}")

        self.contacts = contacts
        print(f"✅ Found {len(contacts)} contacts")
        return contacts

    def analyze_messages(self) -> List[AndroidMessage]:
        """Analyze SMS/MMS messages"""
        print("💬 Analyzing messages...")

        messages = []
        sms_db_path = "android_analysis/mmssms.db"

        if not os.path.exists(sms_db_path):
            return messages

        try:
            conn = sqlite3.connect(sms_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT _id, thread_id, address, body, date, type, read
                FROM sms
                ORDER BY date DESC
            ''')

            for row in cursor.fetchall():
                # Convert Android timestamp (milliseconds) to datetime
                timestamp = datetime.fromtimestamp(row[4] / 1000)

                message = AndroidMessage(
                    message_id=row[0],
                    thread_id=row[1],
                    address=row[2],
                    body=row[3],
                    timestamp=timestamp
                )

                # Type: 1=Received, 2=Sent
                message.message_type = "Received" if row[5] == 1 else "Sent"
                message.read_status = bool(row[6])

                messages.append(message)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing messages: {e}")

        self.messages = messages
        print(f"✅ Found {len(messages)} messages")

        # Check for suspicious content
        self.check_suspicious_messages()
        return messages

    def analyze_call_logs(self) -> List[AndroidCallLog]:
        """Analyze call logs"""
        print("📞 Analyzing call logs...")

        call_logs = []
        calls_db_path = "android_analysis/contacts2.db"

        if not os.path.exists(calls_db_path):
            return call_logs

        try:
            conn = sqlite3.connect(calls_db_path)
            cursor = conn.cursor()

            # Check if calls table exists
            cursor.execute('''
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='calls'
            ''')

            if cursor.fetchone():
                cursor.execute('''
                    SELECT _id, number, type, date, duration
                    FROM calls
                    ORDER BY date DESC
                ''')

                for row in cursor.fetchall():
                    timestamp = datetime.fromtimestamp(row[3] / 1000)

                    # Call types: 1=Incoming, 2=Outgoing, 3=Missed
                    call_type_map = {1: "Incoming", 2: "Outgoing", 3: "Missed"}
                    call_type = call_type_map.get(row[2], "Unknown")

                    call_log = AndroidCallLog(
                        call_id=row[0],
                        number=row[1],
                        call_type=call_type,
                        timestamp=timestamp,
                        duration=row[4]
                    )

                    call_logs.append(call_log)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing call logs: {e}")

        self.call_logs = call_logs
        print(f"✅ Found {len(call_logs)} call records")
        return call_logs

    def check_suspicious_messages(self):
        """Check messages for suspicious content"""
        suspicious_keywords = [
            'password', 'secret', 'confidential', 'hack', 'exploit',
            'malware', 'virus', 'backdoor', 'rootkit', 'payload',
            'bomb', 'attack', 'threat', 'kill', 'destroy'
        ]

        for message in self.messages:
            body_lower = message.body.lower()
            for keyword in suspicious_keywords:
                if keyword in body_lower:
                    print(f"⚠️ Suspicious message content detected: {keyword}")
                    print(f"   From: {message.address}")
                    print(f"   Content: {message.body[:50]}...")

    def analyze_shared_preferences(self, app_package: str) -> Dict:
        """Analyze Android shared preferences for an app"""
        print(f"⚙️ Analyzing shared preferences for {app_package}...")

        preferences = {}
        prefs_path = f"android_analysis/shared_prefs/{app_package}_preferences.xml"

        # Create sample preferences file
        os.makedirs(os.path.dirname(prefs_path), exist_ok=True)

        sample_prefs = f'''<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">user123</string>
    <string name="last_login">2024-01-15T10:30:00</string>
    <boolean name="remember_password" value="true" />
    <string name="api_endpoint">https://api.{app_package}.com</string>
    <int name="session_timeout" value="1800" />
    <string name="device_id">ANDROID_DEVICE_12345</string>
</map>'''

        with open(prefs_path, 'w') as f:
            f.write(sample_prefs)

        try:
            tree = ET.parse(prefs_path)
            root = tree.getroot()

            for child in root:
                if child.tag == 'string':
                    preferences[child.get('name')] = child.text
                elif child.tag == 'boolean':
                    preferences[child.get('name')] = child.get('value') == 'true'
                elif child.tag == 'int':
                    preferences[child.get('name')] = int(child.get('value'))

        except Exception as e:
            print(f"Error parsing preferences: {e}")

        return preferences

    def analyze_installed_apps(self) -> List[Dict]:
        """Analyze installed applications"""
        print("📱 Analyzing installed applications...")

        # Simulate installed apps data
        installed_apps = [
            {
                'package_name': 'com.whatsapp',
                'app_name': 'WhatsApp',
                'version': '2.23.24.14',
                'install_time': '2024-01-01T00:00:00',
                'permissions': ['CAMERA', 'MICROPHONE', 'CONTACTS', 'STORAGE'],
                'data_usage': 524288000  # 500MB
            },
            {
                'package_name': 'com.suspicious.app',
                'app_name': 'System Update',
                'version': '1.0.0',
                'install_time': '2024-01-14T15:30:00',
                'permissions': ['ADMIN', 'DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW'],
                'data_usage': 10485760  # 10MB
            },
            {
                'package_name': 'com.android.chrome',
                'app_name': 'Google Chrome',
                'version': '120.0.6099.144',
                'install_time': '2023-12-01T10:00:00',
                'permissions': ['INTERNET', 'CAMERA', 'MICROPHONE', 'LOCATION'],
                'data_usage': 1073741824  # 1GB
            }
        ]

        # Check for suspicious apps
        for app in installed_apps:
            suspicious_permissions = ['DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW', 'ADMIN']
            app_permissions = app.get('permissions', [])

            if any(perm in app_permissions for perm in suspicious_permissions):
                print(f"⚠️ Suspicious app detected: {app['app_name']}")
                print(f"   Package: {app['package_name']}")
                print(f"   Suspicious permissions: {[p for p in app_permissions if p in suspicious_permissions]}")

        self.installed_apps = installed_apps
        return installed_apps

    def save_analysis_results(self):
        """Save Android analysis results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save contacts
        for contact in self.contacts:
            cursor.execute('''
                INSERT OR REPLACE INTO contacts
                (contact_id, display_name, phone_number, email, last_contacted, times_contacted)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                contact.contact_id,
                contact.display_name,
                contact.phone_number,
                contact.email,
                contact.last_contacted.isoformat() if contact.last_contacted else None,
                contact.times_contacted
            ))

        # Save messages
        for message in self.messages:
            cursor.execute('''
                INSERT OR REPLACE INTO messages
                (message_id, thread_id, address, body, timestamp, type, read_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                message.message_id,
                message.thread_id,
                message.address,
                message.body,
                message.timestamp.isoformat(),
                message.message_type,
                message.read_status
            ))

        # Save call logs
        for call in self.call_logs:
            cursor.execute('''
                INSERT OR REPLACE INTO call_logs
                (call_id, number, type, timestamp, duration)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                call.call_id,
                call.number,
                call.call_type,
                call.timestamp.isoformat(),
                call.duration
            ))

        # Save installed apps
        for app in self.installed_apps:
            cursor.execute('''
                INSERT OR REPLACE INTO installed_apps
                (package_name, app_name, version, install_time, permissions, data_usage)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                app['package_name'],
                app['app_name'],
                app['version'],
                app['install_time'],
                json.dumps(app['permissions']),
                app['data_usage']
            ))

        conn.commit()
        conn.close()

    def generate_android_report(self) -> Dict:
        """Generate comprehensive Android analysis report"""
        report = {
            'case_id': self.case_id,
            'device_type': 'Android',
            'analysis_date': datetime.now().isoformat(),
            'summary': {
                'contacts_found': len(self.contacts),
                'messages_analyzed': len(self.messages),
                'calls_analyzed': len(self.call_logs),
                'apps_installed': len(self.installed_apps)
            },
            'communication_analysis': {
                'frequent_contacts': self.get_frequent_contacts(),
                'recent_messages': [msg.to_dict() for msg in self.messages[:10]],
                'call_patterns': self.analyze_call_patterns()
            },
            'app_analysis': {
                'suspicious_apps': self.get_suspicious_apps(),
                'high_permission_apps': self.get_high_permission_apps()
            },
            'timeline': self.build_activity_timeline(),
            'privacy_concerns': self.identify_privacy_concerns(),
            'recommendations': self.generate_android_recommendations()
        }

        return report

    def get_frequent_contacts(self) -> List[Dict]:
        """Get most frequently contacted numbers"""
        contact_frequency = {}

        # Count messages
        for message in self.messages:
            contact_frequency[message.address] = contact_frequency.get(message.address, 0) + 1

        # Count calls
        for call in self.call_logs:
            contact_frequency[call.number] = contact_frequency.get(call.number, 0) + 1

        # Sort by frequency
        frequent = sorted(contact_frequency.items(), key=lambda x: x[1], reverse=True)

        return [{'number': num, 'contact_count': count} for num, count in frequent[:5]]

    def analyze_call_patterns(self) -> Dict:
        """Analyze calling patterns"""
        patterns = {
            'total_calls': len(self.call_logs),
            'incoming_calls': len([c for c in self.call_logs if c.call_type == "Incoming"]),
            'outgoing_calls': len([c for c in self.call_logs if c.call_type == "Outgoing"]),
            'missed_calls': len([c for c in self.call_logs if c.call_type == "Missed"]),
            'average_duration': 0,
            'longest_call': 0
        }

        if self.call_logs:
            total_duration = sum(call.duration for call in self.call_logs)
            patterns['average_duration'] = total_duration / len(self.call_logs)
            patterns['longest_call'] = max(call.duration for call in self.call_logs)

        return patterns

    def get_suspicious_apps(self) -> List[Dict]:
        """Identify potentially suspicious applications"""
        suspicious_apps = []
        suspicious_permissions = ['DEVICE_ADMIN', 'SYSTEM_ALERT_WINDOW', 'ADMIN']

        for app in self.installed_apps:
            app_permissions = app.get('permissions', [])
            suspicious_perms = [p for p in app_permissions if p in suspicious_permissions]

            if suspicious_perms:
                suspicious_apps.append({
                    'package_name': app['package_name'],
                    'app_name': app['app_name'],
                    'suspicious_permissions': suspicious_perms,
                    'install_time': app['install_time']
                })

        return suspicious_apps

    def get_high_permission_apps(self) -> List[Dict]:
        """Get apps with many permissions"""
        return [
            {
                'package_name': app['package_name'],
                'app_name': app['app_name'],
                'permission_count': len(app.get('permissions', [])),
                'permissions': app.get('permissions', [])
            }
            for app in self.installed_apps
            if len(app.get('permissions', [])) > 5
        ]

    def build_activity_timeline(self) -> List[Dict]:
        """Build timeline of device activities"""
        timeline = []

        # Add messages to timeline
        for message in self.messages:
            timeline.append({
                'timestamp': message.timestamp.isoformat(),
                'type': 'Message',
                'description': f"{message.message_type} message from {message.address}",
                'content': message.body[:50] + "..." if len(message.body) > 50 else message.body
            })

        # Add calls to timeline
        for call in self.call_logs:
            timeline.append({
                'timestamp': call.timestamp.isoformat(),
                'type': 'Call',
                'description': f"{call.call_type} call with {call.number}",
                'duration': call.duration
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        return timeline[:20]  # Last 20 activities

    def identify_privacy_concerns(self) -> List[str]:
        """Identify privacy and security concerns"""
        concerns = []

        # Check for suspicious contacts
        suspicious_numbers = ['+1666666666']  # Known suspicious numbers
        for contact in self.contacts:
            if contact.phone_number in suspicious_numbers:
                concerns.append(f"Contact with suspicious number: {contact.phone_number}")

        # Check for unread suspicious messages
        for message in self.messages:
            if not message.read_status and 'password' in message.body.lower():
                concerns.append("Unread message containing password-related content")

        # Check for high-permission apps
        high_perm_apps = self.get_high_permission_apps()
        if high_perm_apps:
            concerns.append(f"{len(high_perm_apps)} apps with excessive permissions")

        return concerns

    def generate_android_recommendations(self) -> List[str]:
        """Generate Android-specific recommendations"""
        recommendations = []

        if self.get_suspicious_apps():
            recommendations.append("Remove or quarantine suspicious applications")

        if any('password' in msg.body.lower() for msg in self.messages):
            recommendations.append("Review messages for exposed credentials")

        recommendations.extend([
            "Enable device encryption if not already active",
            "Review app permissions and revoke unnecessary access",
            "Implement mobile device management (MDM) solution",
            "Regular security audits of installed applications",
            "Enable remote wipe capability for lost devices"
        ])

        return recommendations

def main():
    """Main Android analyzer demo"""
    print("📱 Android Mobile Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_ANDROID_20240115"
    analyzer = AndroidAnalyzer(case_id)

    # Create sample data
    analyzer.create_sample_android_data()

    # Perform analysis
    analyzer.analyze_contacts()
    analyzer.analyze_messages()
    analyzer.analyze_call_logs()
    analyzer.analyze_installed_apps()

    # Analyze shared preferences for suspicious app
    prefs = analyzer.analyze_shared_preferences("com.suspicious.app")
    print(f"📄 Found {len(prefs)} preference settings")

    # Save results
    analyzer.save_analysis_results()

    # Generate report
    report = analyzer.generate_android_report()

    # Save report
    report_file = f"reports/{case_id}_android_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Android analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Android Analysis Summary:")
    print(f"   Contacts: {report['summary']['contacts_found']}")
    print(f"   Messages: {report['summary']['messages_analyzed']}")
    print(f"   Calls: {report['summary']['calls_analyzed']}")
    print(f"   Apps: {report['summary']['apps_installed']}")

    if report['app_analysis']['suspicious_apps']:
        print(f"\n⚠️ Suspicious Apps:")
        for app in report['app_analysis']['suspicious_apps']:
            print(f"   • {app['app_name']} ({app['package_name']})")

if __name__ == "__main__":
    main()
```

#### Option B: iOS Analysis

```python
# mobile_analyzer.py (iOS Focus)
import plistlib
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
import base64

class iOSContact:
    def __init__(self, record_id: int, first_name: str = "", last_name: str = ""):
        self.record_id = record_id
        self.first_name = first_name
        self.last_name = last_name
        self.phone_numbers = []
        self.email_addresses = []
        self.creation_date = None
        self.modification_date = None

    @property
    def display_name(self):
        return f"{self.first_name} {self.last_name}".strip() or "Unknown"

    def to_dict(self):
        return {
            'record_id': self.record_id,
            'display_name': self.display_name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone_numbers': self.phone_numbers,
            'email_addresses': self.email_addresses,
            'creation_date': self.creation_date.isoformat() if self.creation_date else None,
            'modification_date': self.modification_date.isoformat() if self.modification_date else None
        }

class iOSMessage:
    def __init__(self, rowid: int, guid: str, text: str, handle_id: int, timestamp: datetime):
        self.rowid = rowid
        self.guid = guid
        self.text = text
        self.handle_id = handle_id
        self.timestamp = timestamp
        self.is_from_me = False
        self.is_read = False
        self.service = "iMessage"

    def to_dict(self):
        return {
            'rowid': self.rowid,
            'guid': self.guid,
            'text': self.text,
            'handle_id': self.handle_id,
            'timestamp': self.timestamp.isoformat(),
            'is_from_me': self.is_from_me,
            'is_read': self.is_read,
            'service': self.service
        }

class iOSAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.backup_info = {}
        self.contacts = []
        self.messages = []
        self.call_history = []
        self.safari_history = []
        self.installed_apps = []
        self.keychain_items = []
        self.location_data = []
        self.photos_metadata = []

        # Initialize analysis database
        self.db_path = f"ios_analysis/{case_id}_ios_analysis.db"
        self.init_database()

    def init_database(self):
        """Initialize iOS analysis database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_info (
                property TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                record_id INTEGER PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,
                phone_numbers TEXT,
                email_addresses TEXT,
                creation_date TEXT,
                modification_date TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                rowid INTEGER PRIMARY KEY,
                guid TEXT,
                text TEXT,
                handle_id INTEGER,
                timestamp TEXT,
                is_from_me BOOLEAN,
                is_read BOOLEAN,
                service TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS safari_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def create_sample_ios_data(self):
        """Create sample iOS backup data for analysis"""
        print("📱 Creating sample iOS backup data...")

        # Create Info.plist
        info_plist_path = "ios_analysis/Info.plist"
        os.makedirs(os.path.dirname(info_plist_path), exist_ok=True)

        info_data = {
            'Device Name': 'iPhone 13',
            'Product Type': 'iPhone14,5',
            'Product Version': '17.2.1',
            'Serial Number': 'ABC123DEF456',
            'iTunes Version': '12.12.0.1',
            'Last Backup Date': datetime.now(),
            'Target Identifier': '12345678-ABCD-EFGH-1234-567890ABCDEF',
            'Applications': {
                'com.apple.mobilemail': {'Container': 'Mail'},
                'com.apple.MobileSMS': {'Container': 'Messages'},
                'com.apple.mobilesafari': {'Container': 'Safari'},
                'com.whatsapp.WhatsApp': {'Container': 'WhatsApp'}
            }
        }

        with open(info_plist_path, 'wb') as f:
            plistlib.dump(info_data, f)

        # Create AddressBook database
        contacts_db_path = "ios_analysis/AddressBook.sqlitedb"
        conn = sqlite3.connect(contacts_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ABPerson (
                ROWID INTEGER PRIMARY KEY,
                First TEXT,
                Last TEXT,
                CreationDate REAL,
                ModificationDate REAL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ABMultiValue (
                UID INTEGER PRIMARY KEY,
                record_id INTEGER,
                property INTEGER,
                identifier INTEGER,
                value TEXT,
                label TEXT
            )
        ''')

        sample_contacts = [
            (1, "John", "Doe", 694224000.0, 694224000.0),  # iOS timestamp format
            (2, "Jane", "Smith", 694224000.0, 694224000.0),
            (3, "Suspicious", "Contact", 694224000.0, 694224000.0),
            (4, "Emergency", "Services", 694224000.0, 694224000.0)
        ]

        for contact in sample_contacts:
            cursor.execute('INSERT INTO ABPerson VALUES (?, ?, ?, ?, ?)', contact)

        # Add phone numbers
        phone_data = [
            (1, 1, 3, 1, "+1234567890", "_$!<Mobile>!$_"),
            (2, 2, 3, 2, "+1987654321", "_$!<Mobile>!$_"),
            (3, 3, 3, 3, "+1666666666", "_$!<Mobile>!$_"),
            (4, 4, 3, 4, "911", "_$!<Mobile>!$_")
        ]

        for phone in phone_data:
            cursor.execute('INSERT INTO ABMultiValue VALUES (?, ?, ?, ?, ?, ?)', phone)

        conn.commit()
        conn.close()

        # Create Messages database
        sms_db_path = "ios_analysis/sms.db"
        conn = sqlite3.connect(sms_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message (
                ROWID INTEGER PRIMARY KEY,
                guid TEXT,
                text TEXT,
                handle_id INTEGER,
                date INTEGER,
                is_from_me INTEGER,
                is_read INTEGER,
                service TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS handle (
                ROWID INTEGER PRIMARY KEY,
                id TEXT,
                service TEXT
            )
        ''')

        # Add handles (phone numbers/emails)
        handles = [
            (1, "+1234567890", "SMS"),
            (2, "+1666666666", "SMS"),
            (3, "suspicious@evil.com", "iMessage")
        ]

        for handle in handles:
            cursor.execute('INSERT INTO handle VALUES (?, ?, ?)', handle)

        # Add messages (iOS uses nanoseconds since 2001-01-01)
        messages = [
            (1, "MSG-001", "Hey, how are you?", 1, 694224000000000000, 0, 1, "SMS"),
            (2, "MSG-002", "The package is ready for pickup", 2, 694224060000000000, 0, 0, "SMS"),
            (3, "MSG-003", "Meeting confirmed for tomorrow", 1, 694224120000000000, 1, 1, "SMS"),
            (4, "MSG-004", "Confidential data has been extracted", 3, 694224180000000000, 0, 0, "iMessage")
        ]

        for message in messages:
            cursor.execute('INSERT INTO message VALUES (?, ?, ?, ?, ?, ?, ?, ?)', message)

        conn.commit()
        conn.close()

        # Create Safari History
        safari_db_path = "ios_analysis/History.db"
        conn = sqlite3.connect(safari_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history_items (
                id INTEGER PRIMARY KEY,
                url TEXT,
                domain_expansion TEXT,
                visit_count INTEGER,
                daily_visit_counts BLOB,
                weekly_visit_counts BLOB,
                autocomplete_triggers BLOB,
                should_recompute_derived_visit_counts INTEGER,
                visit_count_score REAL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history_visits (
                id INTEGER PRIMARY KEY,
                history_item INTEGER,
                visit_time REAL,
                title TEXT,
                load_successful BOOLEAN,
                http_non_get BOOLEAN,
                synthesized BOOLEAN,
                redirect_source INTEGER,
                redirect_destination INTEGER
            )
        ''')

        sample_urls = [
            (1, "https://www.google.com", "", 15, b'', b'', b'', 0, 15.0),
            (2, "https://malware.evil.com/payload", "", 1, b'', b'', b'', 0, 1.0),
            (3, "https://github.com", "", 8, b'', b'', b'', 0, 8.0),
            (4, "https://darkweb.onion/secrets", "", 2, b'', b'', b'', 0, 2.0)
        ]

        for url in sample_urls:
            cursor.execute('INSERT INTO history_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', url)

        sample_visits = [
            (1, 1, 694224000.0, "Google", 1, 0, 0, -1, -1),
            (2, 2, 694224300.0, "Malware Download", 1, 0, 0, -1, -1),
            (3, 3, 694224600.0, "GitHub", 1, 0, 0, -1, -1),
            (4, 4, 694224900.0, "Secret Files", 1, 0, 0, -1, -1)
        ]

        for visit in sample_visits:
            cursor.execute('INSERT INTO history_visits VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', visit)

        conn.commit()
        conn.close()

        print("✅ Sample iOS data created")

    def parse_info_plist(self) -> Dict:
        """Parse iOS backup Info.plist"""
        print("📋 Parsing backup Info.plist...")

        info_plist_path = "ios_analysis/Info.plist"
        if not os.path.exists(info_plist_path):
            return {}

        try:
            with open(info_plist_path, 'rb') as f:
                info_data = plistlib.load(f)

            self.backup_info = {
                'device_name': info_data.get('Device Name', 'Unknown'),
                'product_type': info_data.get('Product Type', 'Unknown'),
                'ios_version': info_data.get('Product Version', 'Unknown'),
                'serial_number': info_data.get('Serial Number', 'Unknown'),
                'backup_date': info_data.get('Last Backup Date', datetime.now()),
                'applications': list(info_data.get('Applications', {}).keys())
            }

            print(f"✅ Device: {self.backup_info['device_name']} (iOS {self.backup_info['ios_version']})")
            print(f"   Serial: {self.backup_info['serial_number']}")
            print(f"   Apps: {len(self.backup_info['applications'])}")

        except Exception as e:
            print(f"Error parsing Info.plist: {e}")

        return self.backup_info

    def analyze_contacts(self) -> List[iOSContact]:
        """Analyze iOS AddressBook database"""
        print("👥 Analyzing contacts...")

        contacts = []
        contacts_db_path = "ios_analysis/AddressBook.sqlitedb"

        if not os.path.exists(contacts_db_path):
            return contacts

        try:
            conn = sqlite3.connect(contacts_db_path)
            cursor = conn.cursor()

            # Get contacts
            cursor.execute('''
                SELECT ROWID, First, Last, CreationDate, ModificationDate
                FROM ABPerson
            ''')

            for row in cursor.fetchall():
                contact = iOSContact(
                    record_id=row[0],
                    first_name=row[1] or "",
                    last_name=row[2] or ""
                )

                # Convert iOS timestamp (seconds since 2001-01-01)
                if row[3]:
                    contact.creation_date = datetime(2001, 1, 1) + \
                                          datetime.timedelta(seconds=row[3])
                if row[4]:
                    contact.modification_date = datetime(2001, 1, 1) + \
                                              datetime.timedelta(seconds=row[4])

                # Get phone numbers and emails
                cursor.execute('''
                    SELECT value, label, property
                    FROM ABMultiValue
                    WHERE record_id = ?
                ''', (contact.record_id,))

                for value_row in cursor.fetchall():
                    value, label, prop = value_row
                    if prop == 3:  # Phone number
                        contact.phone_numbers.append(value)
                    elif prop == 4:  # Email
                        contact.email_addresses.append(value)

                contacts.append(contact)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing contacts: {e}")

        self.contacts = contacts
        print(f"✅ Found {len(contacts)} contacts")
        return contacts

    def analyze_messages(self) -> List[iOSMessage]:
        """Analyze iOS Messages database"""
        print("💬 Analyzing messages...")

        messages = []
        sms_db_path = "ios_analysis/sms.db"

        if not os.path.exists(sms_db_path):
            return messages

        try:
            conn = sqlite3.connect(sms_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT m.ROWID, m.guid, m.text, m.handle_id, m.date,
                       m.is_from_me, m.is_read, m.service, h.id
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                ORDER BY m.date DESC
            ''')

            for row in cursor.fetchall():
                # Convert iOS timestamp (nanoseconds since 2001-01-01)
                timestamp = datetime(2001, 1, 1) + \
                           datetime.timedelta(seconds=row[4] / 1000000000)

                message = iOSMessage(
                    rowid=row[0],
                    guid=row[1],
                    text=row[2] or "",
                    handle_id=row[3],
                    timestamp=timestamp
                )

                message.is_from_me = bool(row[5])
                message.is_read = bool(row[6])
                message.service = row[7] or "Unknown"

                messages.append(message)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing messages: {e}")

        self.messages = messages
        print(f"✅ Found {len(messages)} messages")

        # Check for suspicious content
        self.check_suspicious_messages()
        return messages

    def analyze_safari_history(self) -> List[Dict]:
        """Analyze Safari browsing history"""
        print("🌐 Analyzing Safari history...")

        history = []
        safari_db_path = "ios_analysis/History.db"

        if not os.path.exists(safari_db_path):
            return history

        try:
            conn = sqlite3.connect(safari_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT hi.url, hv.title, hi.visit_count, hv.visit_time
                FROM history_items hi
                JOIN history_visits hv ON hi.id = hv.history_item
                ORDER BY hv.visit_time DESC
            ''')

            for row in cursor.fetchall():
                # Convert Safari timestamp (seconds since 2001-01-01)
                visit_time = datetime(2001, 1, 1) + \
                           datetime.timedelta(seconds=row[3])

                history_item = {
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2],
                    'last_visit': visit_time
                }

                history.append(history_item)

                # Check for suspicious URLs
                suspicious_domains = ['malware', 'evil', 'darkweb', 'onion']
                if any(domain in row[0].lower() for domain in suspicious_domains):
                    print(f"⚠️ Suspicious URL found: {row[0]}")

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing Safari history: {e}")

        self.safari_history = history
        print(f"✅ Found {len(history)} history entries")
        return history

    def check_suspicious_messages(self):
        """Check messages for suspicious content"""
        suspicious_keywords = [
            'password', 'confidential', 'secret', 'hack', 'malware',
            'virus', 'exploit', 'payload', 'backdoor'
        ]

        for message in self.messages:
            if message.text:
                text_lower = message.text.lower()
                for keyword in suspicious_keywords:
                    if keyword in text_lower:
                        print(f"⚠️ Suspicious message content: {keyword}")
                        print(f"   Content: {message.text[:50]}...")

    def save_analysis_results(self):
        """Save iOS analysis results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save backup info
        for key, value in self.backup_info.items():
            cursor.execute('''
                INSERT OR REPLACE INTO backup_info (property, value)
                VALUES (?, ?)
            ''', (key, str(value)))

        # Save contacts
        for contact in self.contacts:
            cursor.execute('''
                INSERT OR REPLACE INTO contacts
                (record_id, first_name, last_name, phone_numbers, email_addresses,
                 creation_date, modification_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                contact.record_id,
                contact.first_name,
                contact.last_name,
                json.dumps(contact.phone_numbers),
                json.dumps(contact.email_addresses),
                contact.creation_date.isoformat() if contact.creation_date else None,
                contact.modification_date.isoformat() if contact.modification_date else None
            ))

        # Save messages
        for message in self.messages:
            cursor.execute('''
                INSERT OR REPLACE INTO messages
                (rowid, guid, text, handle_id, timestamp, is_from_me, is_read, service)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                message.rowid,
                message.guid,
                message.text,
                message.handle_id,
                message.timestamp.isoformat(),
                message.is_from_me,
                message.is_read,
                message.service
            ))

        # Save Safari history
        for item in self.safari_history:
            cursor.execute('''
                INSERT OR REPLACE INTO safari_history
                (url, title, visit_count, last_visit_time)
                VALUES (?, ?, ?, ?)
            ''', (
                item['url'],
                item['title'],
                item['visit_count'],
                item['last_visit'].isoformat()
            ))

        conn.commit()
        conn.close()

    def generate_ios_report(self) -> Dict:
        """Generate comprehensive iOS analysis report"""
        report = {
            'case_id': self.case_id,
            'device_type': 'iOS',
            'analysis_date': datetime.now().isoformat(),
            'device_info': self.backup_info,
            'summary': {
                'contacts_found': len(self.contacts),
                'messages_analyzed': len(self.messages),
                'safari_history_entries': len(self.safari_history)
            },
            'communication_analysis': {
                'message_summary': self.analyze_message_patterns(),
                'frequent_contacts': self.get_frequent_contacts()
            },
            'web_activity': {
                'top_sites': self.get_top_websites(),
                'suspicious_urls': self.get_suspicious_urls()
            },
            'timeline': self.build_ios_timeline(),
            'privacy_concerns': self.identify_ios_privacy_concerns(),
            'recommendations': self.generate_ios_recommendations()
        }

        return report

    def analyze_message_patterns(self) -> Dict:
        """Analyze messaging patterns"""
        patterns = {
            'total_messages': len(self.messages),
            'sent_messages': len([m for m in self.messages if m.is_from_me]),
            'received_messages': len([m for m in self.messages if not m.is_from_me]),
            'unread_messages': len([m for m in self.messages if not m.is_read]),
            'services_used': list(set(m.service for m in self.messages))
        }

        return patterns

    def get_frequent_contacts(self) -> List[Dict]:
        """Get most frequently contacted numbers from messages"""
        contact_frequency = {}

        for message in self.messages:
            if not message.is_from_me:  # Received messages
                contact_frequency[message.handle_id] = contact_frequency.get(message.handle_id, 0) + 1

        frequent = sorted(contact_frequency.items(), key=lambda x: x[1], reverse=True)
        return [{'handle_id': handle, 'message_count': count} for handle, count in frequent[:5]]

    def get_top_websites(self) -> List[Dict]:
        """Get most visited websites"""
        return sorted(self.safari_history, key=lambda x: x['visit_count'], reverse=True)[:10]

    def get_suspicious_urls(self) -> List[str]:
        """Identify suspicious URLs"""
        suspicious_domains = ['malware', 'evil', 'darkweb', 'onion', 'hack']
        suspicious_urls = []

        for item in self.safari_history:
            if any(domain in item['url'].lower() for domain in suspicious_domains):
                suspicious_urls.append(item['url'])

        return suspicious_urls

    def build_ios_timeline(self) -> List[Dict]:
        """Build timeline of iOS activities"""
        timeline = []

        # Add messages
        for message in self.messages:
            timeline.append({
                'timestamp': message.timestamp.isoformat(),
                'type': 'Message',
                'description': f"{'Sent' if message.is_from_me else 'Received'} {message.service} message",
                'content': message.text[:50] + "..." if len(message.text) > 50 else message.text
            })

        # Add Safari visits
        for item in self.safari_history:
            timeline.append({
                'timestamp': item['last_visit'].isoformat(),
                'type': 'Web Visit',
                'description': f"Visited {item['title']}",
                'url': item['url']
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)
        return timeline[:20]

    def identify_ios_privacy_concerns(self) -> List[str]:
        """Identify iOS-specific privacy concerns"""
        concerns = []

        # Check for suspicious messages
        if any('password' in msg.text.lower() for msg in self.messages if msg.text):
            concerns.append("Messages contain password-related content")

        # Check for suspicious web activity
        if self.get_suspicious_urls():
            concerns.append("Suspicious web browsing activity detected")

        # Check for unread messages
        unread_count = len([m for m in self.messages if not m.is_read])
        if unread_count > 10:
            concerns.append(f"{unread_count} unread messages may contain important evidence")

        return concerns

    def generate_ios_recommendations(self) -> List[str]:
        """Generate iOS-specific recommendations"""
        recommendations = []

        if self.get_suspicious_urls():
            recommendations.append("Investigate suspicious web browsing activity")

        if any('confidential' in msg.text.lower() for msg in self.messages if msg.text):
            recommendations.append("Review messages for data exposure")

        recommendations.extend([
            "Enable iOS device encryption and secure boot",
            "Review app permissions and data access",
            "Implement iOS enterprise mobility management",
            "Regular backup and security assessment",
            "Enable Find My iPhone for device tracking"
        ])

        return recommendations

def main():
    """Main iOS analyzer demo"""
    print("📱 iOS Mobile Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_IOS_20240115"
    analyzer = iOSAnalyzer(case_id)

    # Create sample data
    analyzer.create_sample_ios_data()

    # Perform analysis
    analyzer.parse_info_plist()
    analyzer.analyze_contacts()
    analyzer.analyze_messages()
    analyzer.analyze_safari_history()

    # Save results
    analyzer.save_analysis_results()

    # Generate report
    report = analyzer.generate_ios_report()

    # Save report
    report_file = f"reports/{case_id}_ios_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 iOS analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 iOS Analysis Summary:")
    print(f"   Device: {report['device_info']['device_name']}")
    print(f"   iOS Version: {report['device_info']['ios_version']}")
    print(f"   Contacts: {report['summary']['contacts_found']}")
    print(f"   Messages: {report['summary']['messages_analyzed']}")
    print(f"   Safari History: {report['summary']['safari_history_entries']}")

    if report['web_activity']['suspicious_urls']:
        print(f"\n⚠️ Suspicious URLs:")
        for url in report['web_activity']['suspicious_urls']:
            print(f"   • {url}")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: SQLite database locked or corrupted
**Solution**: Use WAL mode and proper connection handling: `PRAGMA journal_mode=WAL`

### Issue: iOS timestamp conversion errors
**Solution**: Remember iOS uses seconds since 2001-01-01, not Unix epoch

### Issue: Missing sample data files
**Solution**: Run the sample data creation functions first

### Issue: Permission denied accessing real device data
**Solution**: Use logical acquisition tools or work with pre-extracted data

## ✅ Testing Workflow

```bash
# Run Android analysis
python mobile_analyzer.py  # with Android implementation

# Run iOS analysis
python mobile_analyzer.py  # with iOS implementation

# Test app artifact parsing
python app_artifact_parser.py

# Generate comprehensive report
python -c "
from mobile_analyzer import AndroidAnalyzer  # or iOSAnalyzer
analyzer = AndroidAnalyzer('TEST_CASE')
analyzer.create_sample_android_data()
analyzer.analyze_contacts()
analyzer.analyze_messages()
report = analyzer.generate_android_report()
print(f'Analysis complete: {report[\"summary\"]}')
"
```

## 📁 Expected File Structure
```
week13-mobile-forensics/
├── mobile_analyzer.py             # Android OR iOS analysis
├── app_artifact_parser.py         # Application-specific parsing
├── cloud_forensics.py             # Cloud data analysis
├── mobile_reporter.py             # Mobile forensics reporting
├── android_analysis/              # Android-specific data
│   ├── contacts2.db               # Contacts database
│   ├── mmssms.db                  # SMS/MMS database
│   ├── *_android_analysis.db      # Analysis results
│   └── shared_prefs/              # App preferences
├── ios_analysis/                  # iOS-specific data
│   ├── Info.plist                # Backup information
│   ├── AddressBook.sqlitedb       # Contacts database
│   ├── sms.db                     # Messages database
│   ├── History.db                 # Safari history
│   └── *_ios_analysis.db          # Analysis results
├── app_artifacts/                 # App-specific data
│   ├── whatsapp_msgstore.db       # WhatsApp messages
│   ├── chrome_history.db          # Browser data
│   └── social_media_*.json        # Social media exports
└── reports/
    ├── *_android_report.json      # Android analysis reports
    ├── *_ios_report.json          # iOS analysis reports
    └── *_mobile_final_report.pdf  # Comprehensive reports
```

## 🎯 Grading Focus Areas

1. **Mobile Data Analysis (15 points)**: Comprehensive platform analysis (Android OR iOS)
2. **Application Artifact Analysis (5 points)**: App-specific data extraction
3. **Mobile Forensics Reporting (5 points)**: Professional mobile forensics documentation

## 💡 Pro Tips

1. **Choose Your Platform**: Focus on either Android OR iOS for deep analysis
2. **Understand Database Schemas**: Each platform has different data structures
3. **Handle Timestamps Carefully**: Android and iOS use different timestamp formats
4. **Focus on High-Value Artifacts**: Messages, contacts, and call logs are most important
5. **Consider Privacy**: Mobile devices contain highly personal information

## 🔍 Key Mobile Forensics Concepts

### Android Forensics:
- **SQLite Databases**: Most data stored in SQLite format
- **Shared Preferences**: App configuration and user data
- **APK Analysis**: Understanding app structure and permissions
- **ADB Access**: Android Debug Bridge for data extraction

### iOS Forensics:
- **Property Lists**: Configuration stored in plist format
- **Backup Structure**: iTunes/Finder backup organization
- **Keychain Analysis**: Encrypted credential storage
- **App Sandboxing**: Isolated app data containers

## 🚀 Extension Ideas (Optional)

- Add support for app-specific databases (WhatsApp, Telegram, etc.)
- Implement timeline correlation across multiple mobile devices
- Add cloud synchronization data analysis
- Create mobile malware detection capabilities
- Implement automated mobile evidence extraction

## ⏱️ Time Management

- **Choose your platform early**: Don't try to do both Android and iOS
- **Focus on sample data**: Create realistic test scenarios
- **Prioritize high-value artifacts**: Messages and contacts first
- **Test with real apps**: Use actual app database schemas

Remember: Mobile forensics is highly specialized and constantly evolving. Focus on understanding the fundamentals and building practical analysis skills that can be adapted to new platforms and apps!