# Week 10 Homework Hints: Digital Forensics Laboratory

## 🎯 Quick Start Guide (3-4 hours total)

### Time Breakdown
- **Forensics Concepts & Setup**: 45 minutes
- **Evidence Manager**: 1 hour
- **File System Analyzer**: 1 hour
- **Timeline Builder & Artifact Extractor**: 1 hour
- **Forensic Reporter**: 30 minutes

## 📋 Step-by-Step Implementation

### Step 1: Understanding Digital Forensics (30 minutes)

**Key Forensics Principles:**
- **Chain of Custody**: Documented possession of evidence
- **Write Protection**: Prevent evidence contamination
- **Integrity Verification**: Ensure evidence hasn't changed
- **Documentation**: Detailed records of all actions
- **Admissibility**: Evidence must be legally acceptable

**Common Forensics Process:**
1. **Acquisition**: Create forensic images
2. **Preservation**: Maintain evidence integrity
3. **Analysis**: Examine evidence for relevant data
4. **Documentation**: Record findings and methodology
5. **Presentation**: Report results clearly

### Step 2: Environment Setup (15 minutes)

```bash
pip install hashlib sqlite3 pandas

mkdir week10-digital-forensics
cd week10-digital-forensics
mkdir evidence analysis reports test_data

touch evidence_manager.py
touch filesystem_analyzer.py
touch timeline_builder.py
touch artifact_extractor.py
touch forensic_reporter.py
```

### Step 3: Evidence Acquisition and Preservation (60 minutes)

```python
# evidence_manager.py
import hashlib
import os
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import shutil

class ChainOfCustody:
    def __init__(self):
        self.entries = []

    def add_entry(self, action: str, person: str, notes: str = ""):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'person': person,
            'notes': notes
        }
        self.entries.append(entry)

    def to_dict(self):
        return {'chain_of_custody': self.entries}

class EvidenceItem:
    def __init__(self, item_id: str, description: str, source_path: str):
        self.item_id = item_id
        self.description = description
        self.source_path = source_path
        self.acquisition_time = datetime.now()
        self.hashes = {}
        self.size = 0
        self.chain_of_custody = ChainOfCustody()
        self.metadata = {}

    def calculate_hashes(self, algorithms: List[str] = ['md5', 'sha256', 'sha512']):
        """Calculate multiple hash values for integrity verification"""
        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Source file not found: {self.source_path}")

        self.size = os.path.getsize(self.source_path)

        # Initialize hash objects
        hash_objects = {}
        for algorithm in algorithms:
            if algorithm == 'md5':
                hash_objects[algorithm] = hashlib.md5()
            elif algorithm == 'sha256':
                hash_objects[algorithm] = hashlib.sha256()
            elif algorithm == 'sha512':
                hash_objects[algorithm] = hashlib.sha512()

        # Read file in chunks and update hashes
        with open(self.source_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

        # Store final hash values
        for algorithm, hash_obj in hash_objects.items():
            self.hashes[algorithm] = hash_obj.hexdigest()

        self.chain_of_custody.add_entry(
            "Hash calculation",
            "Forensic Investigator",
            f"Calculated {', '.join(algorithms)} hashes"
        )

    def verify_integrity(self, algorithm: str = 'sha256') -> bool:
        """Verify evidence integrity by recalculating hash"""
        if algorithm not in self.hashes:
            return False

        # Recalculate hash
        if algorithm == 'md5':
            hash_obj = hashlib.md5()
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512()
        else:
            return False

        with open(self.source_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        current_hash = hash_obj.hexdigest()
        original_hash = self.hashes[algorithm]

        verification_result = current_hash == original_hash
        self.chain_of_custody.add_entry(
            "Integrity verification",
            "Forensic Investigator",
            f"Verification {'PASSED' if verification_result else 'FAILED'}: {algorithm}"
        )

        return verification_result

    def to_dict(self):
        return {
            'item_id': self.item_id,
            'description': self.description,
            'source_path': self.source_path,
            'acquisition_time': self.acquisition_time.isoformat(),
            'size': self.size,
            'hashes': self.hashes,
            'metadata': self.metadata,
            'chain_of_custody': self.chain_of_custody.to_dict()
        }

class EvidenceManager:
    def __init__(self, case_name: str, investigator: str):
        self.case_name = case_name
        self.investigator = investigator
        self.case_id = f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.evidence_items = {}
        self.case_notes = []

        # Initialize case database
        self.db_path = f"evidence/{self.case_id}_evidence.db"
        self.init_database()

    def init_database(self):
        """Initialize evidence database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_info (
                case_id TEXT PRIMARY KEY,
                case_name TEXT,
                investigator TEXT,
                created_at TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                item_id TEXT PRIMARY KEY,
                description TEXT,
                source_path TEXT,
                acquisition_time TEXT,
                size INTEGER,
                hashes TEXT,
                metadata TEXT,
                chain_of_custody TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                note TEXT,
                investigator TEXT
            )
        ''')

        # Insert case information
        cursor.execute('''
            INSERT OR REPLACE INTO case_info (case_id, case_name, investigator, created_at)
            VALUES (?, ?, ?, ?)
        ''', (self.case_id, self.case_name, self.investigator, datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def acquire_evidence(self, item_id: str, description: str, source_path: str,
                        create_image: bool = True) -> EvidenceItem:
        """Acquire evidence with proper forensic procedures"""

        # Create evidence item
        evidence = EvidenceItem(item_id, description, source_path)

        # Record acquisition
        evidence.chain_of_custody.add_entry(
            "Evidence acquisition",
            self.investigator,
            f"Acquired from {source_path}"
        )

        # Calculate integrity hashes
        try:
            evidence.calculate_hashes()
            print(f"✅ Evidence {item_id} acquired successfully")
            print(f"   Size: {evidence.size:,} bytes")
            print(f"   SHA256: {evidence.hashes.get('sha256', 'N/A')}")

        except Exception as e:
            print(f"❌ Error calculating hashes: {e}")
            return None

        # Create forensic image if requested
        if create_image:
            image_path = self.create_forensic_image(evidence)
            evidence.metadata['forensic_image'] = image_path

        # Store evidence
        self.evidence_items[item_id] = evidence
        self.save_evidence_to_db(evidence)

        return evidence

    def create_forensic_image(self, evidence: EvidenceItem) -> str:
        """Create bit-by-bit forensic image"""
        image_filename = f"{evidence.item_id}_forensic_image.dd"
        image_path = f"evidence/{image_filename}"

        try:
            # Simulate forensic imaging (in real forensics, use dd or specialized tools)
            shutil.copy2(evidence.source_path, image_path)

            # Calculate hash of image
            image_evidence = EvidenceItem(f"{evidence.item_id}_image", "Forensic image", image_path)
            image_evidence.calculate_hashes()

            evidence.chain_of_custody.add_entry(
                "Forensic imaging",
                self.investigator,
                f"Created forensic image: {image_filename}"
            )

            print(f"📸 Forensic image created: {image_path}")
            return image_path

        except Exception as e:
            print(f"❌ Error creating forensic image: {e}")
            return ""

    def verify_evidence_integrity(self, item_id: str) -> bool:
        """Verify evidence integrity"""
        if item_id not in self.evidence_items:
            print(f"❌ Evidence {item_id} not found")
            return False

        evidence = self.evidence_items[item_id]
        integrity_ok = evidence.verify_integrity()

        if integrity_ok:
            print(f"✅ Evidence {item_id} integrity verified")
        else:
            print(f"❌ Evidence {item_id} integrity check FAILED")

        return integrity_ok

    def add_case_note(self, note: str):
        """Add note to case file"""
        self.case_notes.append({
            'timestamp': datetime.now().isoformat(),
            'note': note,
            'investigator': self.investigator
        })

        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO case_notes (timestamp, note, investigator)
            VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), note, self.investigator))
        conn.commit()
        conn.close()

    def save_evidence_to_db(self, evidence: EvidenceItem):
        """Save evidence item to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO evidence_items
            (item_id, description, source_path, acquisition_time, size, hashes, metadata, chain_of_custody)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            evidence.item_id,
            evidence.description,
            evidence.source_path,
            evidence.acquisition_time.isoformat(),
            evidence.size,
            json.dumps(evidence.hashes),
            json.dumps(evidence.metadata),
            json.dumps(evidence.chain_of_custody.to_dict())
        ))

        conn.commit()
        conn.close()

    def generate_evidence_report(self) -> Dict:
        """Generate comprehensive evidence report"""
        report = {
            'case_info': {
                'case_id': self.case_id,
                'case_name': self.case_name,
                'investigator': self.investigator,
                'created_at': datetime.now().isoformat()
            },
            'evidence_summary': {
                'total_items': len(self.evidence_items),
                'total_size': sum(item.size for item in self.evidence_items.values()),
                'integrity_status': {}
            },
            'evidence_items': [],
            'case_notes': self.case_notes
        }

        # Add evidence details
        for item_id, evidence in self.evidence_items.items():
            integrity_ok = evidence.verify_integrity()
            report['evidence_summary']['integrity_status'][item_id] = integrity_ok

            evidence_report = evidence.to_dict()
            evidence_report['integrity_verified'] = integrity_ok
            report['evidence_items'].append(evidence_report)

        return report

    def create_test_evidence(self):
        """Create sample evidence files for testing"""
        os.makedirs("test_data", exist_ok=True)

        # Create sample files
        test_files = {
            'suspicious_document.txt': "This is a suspicious document with secret information.\nPassword: admin123\nServer: 192.168.1.100",
            'deleted_email.eml': "From: hacker@evil.com\nTo: insider@company.com\nSubject: Data Transfer\n\nThe files are ready for pickup.",
            'malware_sample.exe': b'\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00',  # PE header
            'network_log.txt': "2024-01-15 10:30:45 - Connection from 10.0.0.100 to 192.168.1.200:445\n2024-01-15 10:31:00 - Large data transfer detected\n2024-01-15 10:31:15 - Connection terminated"
        }

        for filename, content in test_files.items():
            file_path = f"test_data/{filename}"
            mode = 'wb' if isinstance(content, bytes) else 'w'
            with open(file_path, mode) as f:
                f.write(content)

        print("✅ Test evidence files created in test_data/")

def main():
    """Main evidence manager demo"""
    print("🔬 Digital Forensics Evidence Manager")
    print("=" * 40)

    # Create evidence manager
    manager = EvidenceManager("Insider Threat Investigation", "Forensic Analyst")

    # Create test evidence
    manager.create_test_evidence()

    print(f"\n📁 Case: {manager.case_name}")
    print(f"Case ID: {manager.case_id}")
    print(f"Investigator: {manager.investigator}")

    # Acquire evidence
    test_files = [
        ("EVIDENCE_001", "Suspicious document", "test_data/suspicious_document.txt"),
        ("EVIDENCE_002", "Deleted email", "test_data/deleted_email.eml"),
        ("EVIDENCE_003", "Malware sample", "test_data/malware_sample.exe"),
        ("EVIDENCE_004", "Network logs", "test_data/network_log.txt")
    ]

    for item_id, description, source_path in test_files:
        evidence = manager.acquire_evidence(item_id, description, source_path)
        if evidence:
            manager.add_case_note(f"Acquired evidence: {description} from {source_path}")

    # Verify integrity
    print(f"\n🔍 Verifying Evidence Integrity:")
    for item_id in manager.evidence_items.keys():
        manager.verify_evidence_integrity(item_id)

    # Generate report
    report = manager.generate_evidence_report()

    # Save report
    report_file = f"reports/{manager.case_id}_evidence_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Evidence report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Evidence Summary:")
    print(f"   Total items: {report['evidence_summary']['total_items']}")
    print(f"   Total size: {report['evidence_summary']['total_size']:,} bytes")

    integrity_passed = sum(1 for status in report['evidence_summary']['integrity_status'].values() if status)
    print(f"   Integrity verified: {integrity_passed}/{len(report['evidence_summary']['integrity_status'])}")

if __name__ == "__main__":
    main()
```

### Step 4: File System Analysis (60 minutes)

```python
# filesystem_analyzer.py
import os
import stat
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import sqlite3

class FileSystemEntry:
    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.is_deleted = False
        self.metadata = {}
        self.timestamps = {}
        self.permissions = {}
        self.file_type = ""
        self.size = 0
        self.signatures = []

        if os.path.exists(path):
            self.analyze_file()

    def analyze_file(self):
        """Analyze file metadata and properties"""
        try:
            stat_info = os.stat(self.path)

            # Basic file information
            self.size = stat_info.st_size
            self.file_type = self.identify_file_type()

            # Timestamps
            self.timestamps = {
                'created': datetime.fromtimestamp(stat_info.st_ctime),
                'modified': datetime.fromtimestamp(stat_info.st_mtime),
                'accessed': datetime.fromtimestamp(stat_info.st_atime)
            }

            # Permissions
            self.permissions = {
                'mode': stat.filemode(stat_info.st_mode),
                'owner_read': bool(stat_info.st_mode & stat.S_IRUSR),
                'owner_write': bool(stat_info.st_mode & stat.S_IWUSR),
                'owner_execute': bool(stat_info.st_mode & stat.S_IXUSR),
                'group_read': bool(stat_info.st_mode & stat.S_IRGRP),
                'group_write': bool(stat_info.st_mode & stat.S_IWGRP),
                'group_execute': bool(stat_info.st_mode & stat.S_IXGRP),
                'other_read': bool(stat_info.st_mode & stat.S_IROTH),
                'other_write': bool(stat_info.st_mode & stat.S_IWOTH),
                'other_execute': bool(stat_info.st_mode & stat.S_IXOTH)
            }

            # File signatures
            self.signatures = self.analyze_file_signatures()

        except Exception as e:
            self.metadata['error'] = str(e)

    def identify_file_type(self) -> str:
        """Identify file type based on extension and content"""
        _, ext = os.path.splitext(self.path.lower())

        if os.path.isdir(self.path):
            return "directory"

        extension_map = {
            '.txt': 'text',
            '.doc': 'document',
            '.docx': 'document',
            '.pdf': 'document',
            '.jpg': 'image',
            '.jpeg': 'image',
            '.png': 'image',
            '.gif': 'image',
            '.exe': 'executable',
            '.dll': 'library',
            '.zip': 'archive',
            '.rar': 'archive',
            '.log': 'log',
            '.db': 'database',
            '.sqlite': 'database'
        }

        return extension_map.get(ext, 'unknown')

    def analyze_file_signatures(self) -> List[str]:
        """Analyze file signatures (magic numbers)"""
        signatures = []

        if os.path.isfile(self.path) and self.size > 0:
            try:
                with open(self.path, 'rb') as f:
                    header = f.read(16)  # Read first 16 bytes

                # Common file signatures
                signature_map = {
                    b'\x50\x4b': 'ZIP/Office document',
                    b'\x4d\x5a': 'PE executable',
                    b'\x89\x50\x4e\x47': 'PNG image',
                    b'\xff\xd8\xff': 'JPEG image',
                    b'\x25\x50\x44\x46': 'PDF document',
                    b'\xd0\xcf\x11\xe0': 'Microsoft Office document',
                    b'SQLite format 3': 'SQLite database'
                }

                for sig, description in signature_map.items():
                    if header.startswith(sig):
                        signatures.append(description)

            except Exception:
                pass

        return signatures

    def to_dict(self):
        return {
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'file_type': self.file_type,
            'is_deleted': self.is_deleted,
            'timestamps': {k: v.isoformat() if isinstance(v, datetime) else v
                          for k, v in self.timestamps.items()},
            'permissions': self.permissions,
            'signatures': self.signatures,
            'metadata': self.metadata
        }

class FileSystemAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.analyzed_files = {}
        self.directory_tree = {}
        self.deleted_files = []
        self.suspicious_files = []

        # Initialize analysis database
        self.db_path = f"analysis/{case_id}_filesystem_analysis.db"
        self.init_database()

    def init_database(self):
        """Initialize filesystem analysis database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filesystem_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                name TEXT,
                size INTEGER,
                file_type TEXT,
                is_deleted BOOLEAN,
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                permissions TEXT,
                signatures TEXT,
                metadata TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deleted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT,
                recovery_method TEXT,
                recovery_confidence TEXT,
                discovered_at TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def analyze_directory(self, root_path: str, max_depth: int = 10) -> Dict:
        """Recursively analyze directory structure"""
        print(f"🔍 Analyzing directory: {root_path}")

        analysis_results = {
            'root_path': root_path,
            'total_files': 0,
            'total_directories': 0,
            'total_size': 0,
            'file_types': {},
            'suspicious_patterns': [],
            'timeline_entries': []
        }

        def analyze_recursive(current_path: str, depth: int = 0):
            if depth > max_depth:
                return

            try:
                for item in os.listdir(current_path):
                    item_path = os.path.join(current_path, item)

                    # Analyze file/directory
                    fs_entry = FileSystemEntry(item_path)
                    self.analyzed_files[item_path] = fs_entry

                    if os.path.isfile(item_path):
                        analysis_results['total_files'] += 1
                        analysis_results['total_size'] += fs_entry.size

                        # Count file types
                        file_type = fs_entry.file_type
                        analysis_results['file_types'][file_type] = analysis_results['file_types'].get(file_type, 0) + 1

                        # Check for suspicious patterns
                        self.check_suspicious_patterns(fs_entry, analysis_results)

                        # Add to timeline
                        for timestamp_type, timestamp in fs_entry.timestamps.items():
                            analysis_results['timeline_entries'].append({
                                'timestamp': timestamp,
                                'type': timestamp_type,
                                'path': item_path,
                                'action': f'File {timestamp_type}'
                            })

                    elif os.path.isdir(item_path):
                        analysis_results['total_directories'] += 1
                        analyze_recursive(item_path, depth + 1)

                    # Save to database
                    self.save_filesystem_entry(fs_entry)

            except PermissionError:
                analysis_results['suspicious_patterns'].append({
                    'type': 'Access Denied',
                    'path': current_path,
                    'description': 'Permission denied accessing directory'
                })
            except Exception as e:
                analysis_results['suspicious_patterns'].append({
                    'type': 'Analysis Error',
                    'path': current_path,
                    'description': str(e)
                })

        analyze_recursive(root_path)

        # Sort timeline entries
        analysis_results['timeline_entries'].sort(key=lambda x: x['timestamp'])

        print(f"✅ Analysis complete:")
        print(f"   Files: {analysis_results['total_files']}")
        print(f"   Directories: {analysis_results['total_directories']}")
        print(f"   Total size: {analysis_results['total_size']:,} bytes")
        print(f"   Suspicious patterns: {len(analysis_results['suspicious_patterns'])}")

        return analysis_results

    def check_suspicious_patterns(self, fs_entry: FileSystemEntry, analysis_results: Dict):
        """Check for suspicious file patterns"""

        # Suspicious file names
        suspicious_names = [
            'password', 'secret', 'confidential', 'private',
            'admin', 'root', 'backup', 'config', 'temp'
        ]

        if any(pattern in fs_entry.name.lower() for pattern in suspicious_names):
            analysis_results['suspicious_patterns'].append({
                'type': 'Suspicious Filename',
                'path': fs_entry.path,
                'description': f'File name contains suspicious keywords: {fs_entry.name}'
            })
            self.suspicious_files.append(fs_entry)

        # Hidden files (starting with .)
        if fs_entry.name.startswith('.') and fs_entry.name not in ['.', '..']:
            analysis_results['suspicious_patterns'].append({
                'type': 'Hidden File',
                'path': fs_entry.path,
                'description': f'Hidden file detected: {fs_entry.name}'
            })

        # Executable files in unusual locations
        if fs_entry.file_type == 'executable' and '/tmp/' in fs_entry.path:
            analysis_results['suspicious_patterns'].append({
                'type': 'Suspicious Executable Location',
                'path': fs_entry.path,
                'description': 'Executable file in temporary directory'
            })

        # Large files (potential data exfiltration)
        if fs_entry.size > 100 * 1024 * 1024:  # 100MB
            analysis_results['suspicious_patterns'].append({
                'type': 'Large File',
                'path': fs_entry.path,
                'description': f'Large file detected: {fs_entry.size:,} bytes'
            })

        # Recently modified files
        if fs_entry.timestamps.get('modified'):
            time_diff = datetime.now() - fs_entry.timestamps['modified']
            if time_diff.days < 7:  # Modified within last week
                analysis_results['suspicious_patterns'].append({
                    'type': 'Recently Modified',
                    'path': fs_entry.path,
                    'description': f'File modified {time_diff.days} days ago'
                })

    def simulate_deleted_file_recovery(self) -> List[Dict]:
        """Simulate recovery of deleted files"""
        print("🔄 Simulating deleted file recovery...")

        # Simulate finding deleted files
        deleted_files = [
            {
                'original_path': '/home/user/Documents/confidential_data.xlsx',
                'recovery_method': 'File carving',
                'recovery_confidence': 'High',
                'file_type': 'spreadsheet',
                'estimated_size': 2048576,
                'deletion_timestamp': '2024-01-10T14:30:00'
            },
            {
                'original_path': '/tmp/malware_download.exe',
                'recovery_method': 'Slack space analysis',
                'recovery_confidence': 'Medium',
                'file_type': 'executable',
                'estimated_size': 1024000,
                'deletion_timestamp': '2024-01-12T09:15:00'
            },
            {
                'original_path': '/var/log/auth.log.deleted',
                'recovery_method': 'Journal analysis',
                'recovery_confidence': 'Low',
                'file_type': 'log',
                'estimated_size': 512000,
                'deletion_timestamp': '2024-01-13T16:45:00'
            }
        ]

        # Save deleted files to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for deleted_file in deleted_files:
            cursor.execute('''
                INSERT INTO deleted_files
                (original_path, recovery_method, recovery_confidence, discovered_at)
                VALUES (?, ?, ?, ?)
            ''', (
                deleted_file['original_path'],
                deleted_file['recovery_method'],
                deleted_file['recovery_confidence'],
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

        self.deleted_files = deleted_files

        print(f"✅ Found {len(deleted_files)} deleted files")
        for file_info in deleted_files:
            print(f"   • {file_info['original_path']} ({file_info['recovery_confidence']} confidence)")

        return deleted_files

    def save_filesystem_entry(self, fs_entry: FileSystemEntry):
        """Save filesystem entry to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO filesystem_entries
            (path, name, size, file_type, is_deleted, created_time, modified_time,
             accessed_time, permissions, signatures, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fs_entry.path,
            fs_entry.name,
            fs_entry.size,
            fs_entry.file_type,
            fs_entry.is_deleted,
            fs_entry.timestamps.get('created', '').isoformat() if fs_entry.timestamps.get('created') else '',
            fs_entry.timestamps.get('modified', '').isoformat() if fs_entry.timestamps.get('modified') else '',
            fs_entry.timestamps.get('accessed', '').isoformat() if fs_entry.timestamps.get('accessed') else '',
            json.dumps(fs_entry.permissions),
            json.dumps(fs_entry.signatures),
            json.dumps(fs_entry.metadata)
        ))

        conn.commit()
        conn.close()

    def generate_filesystem_report(self) -> Dict:
        """Generate comprehensive filesystem analysis report"""
        report = {
            'analysis_info': {
                'case_id': self.case_id,
                'analyst': 'Forensic Investigator',
                'analysis_date': datetime.now().isoformat()
            },
            'summary': {
                'total_files_analyzed': len(self.analyzed_files),
                'suspicious_files_found': len(self.suspicious_files),
                'deleted_files_recovered': len(self.deleted_files)
            },
            'file_type_distribution': {},
            'suspicious_findings': [
                {
                    'path': sf.path,
                    'type': sf.file_type,
                    'size': sf.size,
                    'modified': sf.timestamps.get('modified', '').isoformat() if sf.timestamps.get('modified') else ''
                }
                for sf in self.suspicious_files
            ],
            'deleted_files': self.deleted_files,
            'recommendations': []
        }

        # Calculate file type distribution
        for fs_entry in self.analyzed_files.values():
            file_type = fs_entry.file_type
            report['file_type_distribution'][file_type] = report['file_type_distribution'].get(file_type, 0) + 1

        # Generate recommendations
        if self.suspicious_files:
            report['recommendations'].append(f"Investigate {len(self.suspicious_files)} suspicious files")

        if self.deleted_files:
            report['recommendations'].append(f"Analyze {len(self.deleted_files)} recovered deleted files")

        report['recommendations'].extend([
            "Review file access patterns for anomalies",
            "Check for unauthorized file modifications",
            "Analyze timeline for suspicious activity periods",
            "Validate file integrity using hash verification"
        ])

        return report

def main():
    """Main filesystem analyzer demo"""
    print("📁 File System Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_20240115_143000"
    analyzer = FileSystemAnalyzer(case_id)

    # Create test directory structure
    test_dir = "test_data/filesystem_test"
    os.makedirs(test_dir, exist_ok=True)

    # Create sample files for analysis
    sample_files = {
        'normal_document.txt': 'This is a normal document.',
        'password_file.txt': 'admin:password123\nuser:secret456',
        '.hidden_config': 'secret_key=abc123\napi_endpoint=evil.com',
        'large_data.bin': b'X' * (50 * 1024 * 1024),  # 50MB file
        'suspicious.exe': b'\x4d\x5a\x90\x00' + b'malware_code' * 1000
    }

    for filename, content in sample_files.items():
        file_path = os.path.join(test_dir, filename)
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(file_path, mode) as f:
            f.write(content)

    print(f"✅ Created test filesystem in {test_dir}")

    # Analyze filesystem
    analysis_results = analyzer.analyze_directory(test_dir)

    # Simulate deleted file recovery
    deleted_files = analyzer.simulate_deleted_file_recovery()

    # Generate report
    report = analyzer.generate_filesystem_report()

    # Save report
    report_file = f"reports/{case_id}_filesystem_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Filesystem analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Analysis Summary:")
    print(f"   Files analyzed: {report['summary']['total_files_analyzed']}")
    print(f"   Suspicious files: {report['summary']['suspicious_files_found']}")
    print(f"   Deleted files recovered: {report['summary']['deleted_files_recovered']}")

    print(f"\n🔍 File Type Distribution:")
    for file_type, count in report['file_type_distribution'].items():
        print(f"   {file_type}: {count}")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: Hash calculation fails on large files
**Solution**: Read files in chunks rather than loading entirely into memory

### Issue: Permission denied accessing system files
**Solution**: Run with appropriate privileges or focus on accessible areas

### Issue: Deleted file simulation not realistic
**Solution**: Use actual file recovery tools or create more sophisticated simulation

### Issue: Timeline analysis becomes complex
**Solution**: Focus on key events and use visualization tools

## ✅ Testing Workflow

```bash
# Run evidence manager demo
python evidence_manager.py

# Run filesystem analyzer
python filesystem_analyzer.py

# Test complete forensics workflow
python -c "
from evidence_manager import EvidenceManager
from filesystem_analyzer import FileSystemAnalyzer

# Create case and acquire evidence
manager = EvidenceManager('Test Investigation', 'Analyst')
manager.create_test_evidence()

# Analyze evidence
case_id = manager.case_id
analyzer = FileSystemAnalyzer(case_id)
results = analyzer.analyze_directory('test_data')

print(f'Analysis complete - found {len(results[\"suspicious_patterns\"])} suspicious patterns')
"
```

## 📁 Expected File Structure
```
week10-digital-forensics/
├── evidence_manager.py            # Evidence acquisition and preservation
├── filesystem_analyzer.py         # File system parsing and analysis
├── timeline_builder.py            # Event timeline reconstruction
├── artifact_extractor.py          # Deleted file and metadata recovery
├── forensic_reporter.py           # Professional report generation
├── evidence/
│   ├── CASE_*_evidence.db         # Evidence databases
│   ├── *_forensic_image.dd        # Forensic images
│   └── chain_of_custody_*.json    # Chain of custody records
├── analysis/
│   ├── *_filesystem_analysis.db   # Analysis databases
│   └── *_timeline.json            # Timeline data
├── reports/
│   ├── *_evidence_report.json     # Evidence reports
│   ├── *_filesystem_report.json   # Filesystem analysis
│   └── *_final_report.pdf         # Final case reports
└── test_data/
    ├── suspicious_document.txt     # Test evidence files
    ├── deleted_email.eml
    └── filesystem_test/            # Test filesystem structure
```

## 🎯 Grading Focus Areas

1. **Evidence Acquisition (5 points)**: Proper evidence handling with integrity verification
2. **File System Analysis (5 points)**: Comprehensive file system examination
3. **Timeline & Artifact Recovery (5 points)**: Timeline construction and deleted file recovery
4. **Forensic Reporting (5 points)**: Professional documentation and chain of custody
5. **Chain of Custody Management (5 points)**: Complete audit trail from acquisition to analysis

## 💡 Pro Tips

1. **Always Verify Integrity**: Hash everything and verify constantly
2. **Document Everything**: Forensic work requires meticulous documentation
3. **Use Write Protection**: Never modify original evidence
4. **Focus on Admissibility**: Evidence must be legally acceptable
5. **Think Like a Detective**: Follow the evidence where it leads

## 🔍 Key Forensics Concepts

### Digital Evidence Lifecycle:
1. **Identification**: Recognizing potential evidence
2. **Collection**: Acquiring evidence using forensic procedures
3. **Examination**: Analyzing evidence for relevant information
4. **Analysis**: Interpreting findings in context
5. **Reporting**: Documenting findings and conclusions

### Chain of Custody Requirements:
- **Who**: Person handling evidence
- **What**: What was done with evidence
- **When**: Date and time of actions
- **Where**: Location of evidence handling
- **Why**: Reason for evidence handling

## 🚀 Extension Ideas (Optional)

- Add network packet analysis capabilities
- Implement memory dump analysis
- Create automated report generation
- Add support for mobile device forensics
- Implement advanced file carving techniques

## ⏱️ Time Management

- **Focus on core forensics principles**: Chain of custody and integrity verification
- **Start with simple file analysis**: Build complexity gradually
- **Document as you code**: Forensics is all about documentation
- **Test with realistic scenarios**: Use actual suspicious file patterns

Remember: Digital forensics requires precision and attention to detail. Understanding evidence handling and analysis techniques will help you investigate security incidents and support legal proceedings!