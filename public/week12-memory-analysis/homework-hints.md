# Week 12 Homework Hints: Memory Analysis and Malware Detection

## 🎯 Quick Start Guide (4 hours total)

### Time Breakdown
- **Memory Forensics Concepts**: 30 minutes
- **Memory Dump Analysis**: 2 hours
- **Malware Detection Engine**: 1 hour
- **Reporting and Visualization**: 30 minutes

## 📋 Step-by-Step Implementation

### Step 1: Memory Forensics Fundamentals (30 minutes)

**Key Memory Forensics Concepts:**
- **Volatile Evidence**: Data that exists only in RAM
- **Process Analysis**: Examining running processes and their memory
- **Network Connections**: Active network sessions
- **Code Injection**: Malicious code injected into legitimate processes
- **Memory Artifacts**: Registry handles, file handles, mutex objects

**Common Memory Analysis Techniques:**
- **Process Listing**: Identifying all running processes
- **DLL Analysis**: Examining loaded libraries
- **Network Connection Mapping**: Active TCP/UDP connections
- **Registry Handle Analysis**: Open registry keys
- **String Extraction**: Finding readable text in memory

### Step 2: Environment Setup (15 minutes)

```bash
pip install psutil struct sqlite3 matplotlib

mkdir week12-memory-analysis
cd week12-memory-analysis
mkdir memory_dumps analysis_results malware_signatures reports

touch memory_analyzer.py
touch process_analyzer.py
touch malware_detector.py
touch memory_visualizer.py
```

### Step 3: Memory Dump Analyzer (120 minutes)

```python
# memory_analyzer.py
import struct
import json
import sqlite3
import psutil
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import os
import re
import hashlib

class ProcessInfo:
    def __init__(self, pid: int, name: str, cmdline: List[str]):
        self.pid = pid
        self.name = name
        self.cmdline = cmdline
        self.ppid = 0
        self.create_time = datetime.now()
        self.memory_info = {}
        self.open_files = []
        self.network_connections = []
        self.loaded_modules = []
        self.threads = []
        self.handles = []
        self.suspicious_indicators = []

    def to_dict(self):
        return {
            'pid': self.pid,
            'name': self.name,
            'cmdline': self.cmdline,
            'ppid': self.ppid,
            'create_time': self.create_time.isoformat(),
            'memory_info': self.memory_info,
            'open_files': self.open_files,
            'network_connections': self.network_connections,
            'loaded_modules': self.loaded_modules,
            'threads': len(self.threads),
            'handles': len(self.handles),
            'suspicious_indicators': self.suspicious_indicators
        }

class MemoryArtifact:
    def __init__(self, artifact_type: str, data: Any, offset: int = 0):
        self.artifact_type = artifact_type
        self.data = data
        self.offset = offset
        self.discovered_at = datetime.now()
        self.confidence = 0.5
        self.context = {}

    def to_dict(self):
        return {
            'type': self.artifact_type,
            'data': str(self.data),
            'offset': self.offset,
            'discovered_at': self.discovered_at.isoformat(),
            'confidence': self.confidence,
            'context': self.context
        }

class MemoryAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.processes = {}
        self.memory_artifacts = []
        self.network_connections = []
        self.suspicious_processes = []
        self.injected_code_findings = []

        # Initialize analysis database
        self.db_path = f"memory_dumps/{case_id}_memory_analysis.db"
        self.init_database()

        # Load malware signatures
        self.load_malware_signatures()

    def init_database(self):
        """Initialize memory analysis database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processes (
                pid INTEGER PRIMARY KEY,
                name TEXT,
                cmdline TEXT,
                ppid INTEGER,
                create_time TEXT,
                memory_info TEXT,
                suspicious_score INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memory_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_type TEXT,
                data TEXT,
                offset INTEGER,
                discovered_at TEXT,
                confidence REAL,
                context TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                status TEXT,
                protocol TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT,
                pid INTEGER,
                description TEXT,
                severity TEXT,
                evidence TEXT,
                discovered_at TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def load_malware_signatures(self):
        """Load malware detection signatures"""
        self.malware_signatures = {
            'suspicious_processes': [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe'
            ],
            'malware_strings': [
                b'CreateRemoteThread',
                b'VirtualAllocEx',
                b'WriteProcessMemory',
                b'SetWindowsHookEx',
                b'keylogger',
                b'backdoor',
                b'trojan',
                b'rootkit'
            ],
            'suspicious_paths': [
                'temp', 'appdata', 'programdata', 'windows\\system32',
                'users\\public', 'startup'
            ],
            'network_indicators': [
                '127.0.0.1', 'localhost', '0.0.0.0',
                # Add known malicious IPs
                '10.0.0.666', '192.168.1.666'
            ]
        }

    def simulate_memory_dump_analysis(self) -> Dict:
        """Simulate memory dump analysis using live system data"""
        print("🧠 Analyzing system memory (simulated memory dump)...")

        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'total_processes': 0,
            'suspicious_processes': 0,
            'network_connections': 0,
            'memory_artifacts': 0,
            'malware_indicators': []
        }

        # Analyze running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'create_time']):
            try:
                proc_info = ProcessInfo(
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['cmdline'] or []
                )
                proc_info.ppid = proc.info['ppid']

                if proc.info['create_time']:
                    proc_info.create_time = datetime.fromtimestamp(proc.info['create_time'])

                # Get additional process information
                self.analyze_process_details(proc, proc_info)

                # Check for suspicious indicators
                self.check_suspicious_process(proc_info)

                self.processes[proc_info.pid] = proc_info
                analysis_results['total_processes'] += 1

                if proc_info.suspicious_indicators:
                    analysis_results['suspicious_processes'] += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Analyze network connections
        self.analyze_network_connections()
        analysis_results['network_connections'] = len(self.network_connections)

        # Extract memory artifacts
        self.extract_memory_artifacts()
        analysis_results['memory_artifacts'] = len(self.memory_artifacts)

        # Detect code injection
        self.detect_code_injection()

        print(f"✅ Memory analysis complete:")
        print(f"   Processes analyzed: {analysis_results['total_processes']}")
        print(f"   Suspicious processes: {analysis_results['suspicious_processes']}")
        print(f"   Network connections: {analysis_results['network_connections']}")
        print(f"   Memory artifacts: {analysis_results['memory_artifacts']}")

        return analysis_results

    def analyze_process_details(self, proc: psutil.Process, proc_info: ProcessInfo):
        """Analyze detailed process information"""
        try:
            # Memory information
            memory_info = proc.memory_info()
            proc_info.memory_info = {
                'rss': memory_info.rss,  # Resident Set Size
                'vms': memory_info.vms,  # Virtual Memory Size
                'percent': proc.memory_percent()
            }

            # Open files
            try:
                proc_info.open_files = [f.path for f in proc.open_files()]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Network connections for this process
            try:
                connections = proc.connections()
                for conn in connections:
                    conn_info = {
                        'local_addr': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_addr': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'family': str(conn.family),
                        'type': str(conn.type)
                    }
                    proc_info.network_connections.append(conn_info)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Threads
            try:
                proc_info.threads = proc.threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def check_suspicious_process(self, proc_info: ProcessInfo):
        """Check process for suspicious indicators"""
        suspicious_score = 0
        indicators = []

        # Check process name
        if proc_info.name.lower() in [s.lower() for s in self.malware_signatures['suspicious_processes']]:
            suspicious_score += 3
            indicators.append(f"Suspicious process name: {proc_info.name}")

        # Check command line
        cmdline_str = ' '.join(proc_info.cmdline).lower()
        suspicious_cmdline_patterns = [
            'powershell -e', 'cmd /c', 'wscript', 'cscript',
            'base64', 'invoke-expression', 'downloadstring',
            'bypass', 'hidden', 'noprofile'
        ]

        for pattern in suspicious_cmdline_patterns:
            if pattern in cmdline_str:
                suspicious_score += 2
                indicators.append(f"Suspicious command line pattern: {pattern}")

        # Check file paths
        for file_path in proc_info.open_files:
            for sus_path in self.malware_signatures['suspicious_paths']:
                if sus_path.lower() in file_path.lower():
                    suspicious_score += 1
                    indicators.append(f"File in suspicious location: {file_path}")

        # Check network connections
        for conn in proc_info.network_connections:
            if conn['remote_addr'] in self.malware_signatures['network_indicators']:
                suspicious_score += 4
                indicators.append(f"Connection to suspicious IP: {conn['remote_addr']}")

            # Check for suspicious ports
            suspicious_ports = [1337, 31337, 4444, 5555, 6666]
            if conn['remote_port'] in suspicious_ports or conn['local_port'] in suspicious_ports:
                suspicious_score += 2
                indicators.append(f"Connection on suspicious port: {conn['remote_port'] or conn['local_port']}")

        # Check for process hollowing indicators
        if self.check_process_hollowing(proc_info):
            suspicious_score += 5
            indicators.append("Potential process hollowing detected")

        # Store results
        if suspicious_score > 0:
            proc_info.suspicious_indicators = indicators
            if suspicious_score >= 5:
                self.suspicious_processes.append(proc_info)

    def check_process_hollowing(self, proc_info: ProcessInfo) -> bool:
        """Check for process hollowing indicators"""
        # Simplified check - in real analysis, would examine memory pages
        cmdline_str = ' '.join(proc_info.cmdline)

        # Check for mismatched process name and command line
        if proc_info.name.lower() in ['svchost.exe', 'explorer.exe', 'winlogon.exe']:
            # These processes should have specific command line patterns
            if 'temp' in cmdline_str.lower() or 'appdata' in cmdline_str.lower():
                return True

        # Check for unsigned executables in system directories
        for file_path in proc_info.open_files:
            if 'system32' in file_path.lower() and 'temp' in file_path.lower():
                return True

        return False

    def analyze_network_connections(self):
        """Analyze all network connections"""
        print("🌐 Analyzing network connections...")

        connections = psutil.net_connections()
        for conn in connections:
            conn_info = {
                'pid': conn.pid,
                'local_addr': conn.laddr.ip if conn.laddr else '',
                'local_port': conn.laddr.port if conn.laddr else 0,
                'remote_addr': conn.raddr.ip if conn.raddr else '',
                'remote_port': conn.raddr.port if conn.raddr else 0,
                'status': conn.status,
                'family': str(conn.family),
                'type': str(conn.type)
            }

            self.network_connections.append(conn_info)

            # Check for suspicious connections
            if conn_info['remote_addr'] in self.malware_signatures['network_indicators']:
                self.suspicious_processes.append({
                    'type': 'Suspicious Network Connection',
                    'pid': conn_info['pid'],
                    'description': f"Connection to suspicious IP: {conn_info['remote_addr']}",
                    'severity': 'HIGH'
                })

    def extract_memory_artifacts(self):
        """Extract artifacts from memory (simulated)"""
        print("🔍 Extracting memory artifacts...")

        # Simulate finding strings in memory
        simulated_strings = [
            "http://malware.evil.com/payload.exe",
            "C:\\Users\\victim\\AppData\\Local\\Temp\\backdoor.exe",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "admin:password123",
            "keylogger_data.txt",
            "C2_SERVER=192.168.1.666"
        ]

        for i, string_data in enumerate(simulated_strings):
            artifact = MemoryArtifact(
                "String",
                string_data,
                i * 0x1000  # Simulated memory offset
            )

            # Determine confidence based on content
            if any(sig in string_data.encode() for sig in self.malware_signatures['malware_strings']):
                artifact.confidence = 0.9
                artifact.context['malware_signature'] = True
            elif 'http://' in string_data or 'https://' in string_data:
                artifact.confidence = 0.7
                artifact.context['network_indicator'] = True
            elif 'password' in string_data.lower():
                artifact.confidence = 0.8
                artifact.context['credential'] = True

            self.memory_artifacts.append(artifact)

        # Simulate registry keys in memory
        simulated_registry_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"
        ]

        for reg_key in simulated_registry_keys:
            artifact = MemoryArtifact("Registry Key", reg_key)
            artifact.confidence = 0.8
            artifact.context['persistence_mechanism'] = True
            self.memory_artifacts.append(artifact)

    def detect_code_injection(self):
        """Detect code injection techniques"""
        print("💉 Detecting code injection...")

        # Simulate detection of various injection techniques
        injection_indicators = [
            {
                'type': 'DLL Injection',
                'pid': 1234,
                'description': 'Suspicious DLL loaded into legitimate process',
                'evidence': 'malicious.dll loaded into explorer.exe',
                'technique': 'SetWindowsHookEx'
            },
            {
                'type': 'Process Hollowing',
                'pid': 5678,
                'description': 'Process memory replaced with malicious code',
                'evidence': 'svchost.exe with unexpected memory layout',
                'technique': 'NtUnmapViewOfSection'
            },
            {
                'type': 'Reflective DLL Loading',
                'pid': 9999,
                'description': 'DLL loaded without file system presence',
                'evidence': 'Executable code in unexpected memory region',
                'technique': 'Manual DLL mapping'
            }
        ]

        for injection in injection_indicators:
            self.injected_code_findings.append(injection)

            # Create corresponding memory artifact
            artifact = MemoryArtifact(
                "Code Injection",
                injection['description']
            )
            artifact.confidence = 0.85
            artifact.context = {
                'injection_type': injection['type'],
                'technique': injection['technique'],
                'target_pid': injection['pid']
            }
            self.memory_artifacts.append(artifact)

    def save_analysis_results(self):
        """Save memory analysis results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save processes
        for proc in self.processes.values():
            cursor.execute('''
                INSERT OR REPLACE INTO processes
                (pid, name, cmdline, ppid, create_time, memory_info, suspicious_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                proc.pid,
                proc.name,
                json.dumps(proc.cmdline),
                proc.ppid,
                proc.create_time.isoformat(),
                json.dumps(proc.memory_info),
                len(proc.suspicious_indicators)
            ))

        # Save memory artifacts
        for artifact in self.memory_artifacts:
            cursor.execute('''
                INSERT INTO memory_artifacts
                (artifact_type, data, offset, discovered_at, confidence, context)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                artifact.artifact_type,
                artifact.data,
                artifact.offset,
                artifact.discovered_at.isoformat(),
                artifact.confidence,
                json.dumps(artifact.context)
            ))

        # Save network connections
        for conn_info in self.network_connections:
            cursor.execute('''
                INSERT INTO network_connections
                (pid, local_addr, local_port, remote_addr, remote_port, status, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                conn_info.get('pid'),
                conn_info['local_addr'],
                conn_info['local_port'],
                conn_info['remote_addr'],
                conn_info['remote_port'],
                conn_info['status'],
                conn_info['type']
            ))

        # Save suspicious findings
        for finding in self.injected_code_findings:
            cursor.execute('''
                INSERT INTO suspicious_findings
                (finding_type, pid, description, severity, evidence, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                finding['type'],
                finding['pid'],
                finding['description'],
                'HIGH',
                finding['evidence'],
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

    def generate_memory_report(self) -> Dict:
        """Generate comprehensive memory analysis report"""
        report = {
            'case_id': self.case_id,
            'analysis_date': datetime.now().isoformat(),
            'summary': {
                'total_processes': len(self.processes),
                'suspicious_processes': len(self.suspicious_processes),
                'memory_artifacts': len(self.memory_artifacts),
                'network_connections': len(self.network_connections),
                'code_injection_findings': len(self.injected_code_findings)
            },
            'process_analysis': {
                'suspicious_processes': [
                    {
                        'pid': proc.pid,
                        'name': proc.name,
                        'indicators': proc.suspicious_indicators
                    }
                    for proc in self.suspicious_processes
                    if hasattr(proc, 'pid')  # Filter out non-process findings
                ],
                'top_memory_consumers': self.get_top_memory_consumers(),
                'unusual_network_activity': self.get_unusual_network_activity()
            },
            'memory_artifacts': [
                {
                    'type': artifact.artifact_type,
                    'data': artifact.data,
                    'confidence': artifact.confidence,
                    'context': artifact.context
                }
                for artifact in self.memory_artifacts
                if artifact.confidence > 0.7  # High confidence artifacts only
            ],
            'code_injection_analysis': self.injected_code_findings,
            'recommendations': self.generate_memory_recommendations()
        }

        return report

    def get_top_memory_consumers(self) -> List[Dict]:
        """Get processes consuming the most memory"""
        memory_consumers = []

        for proc in self.processes.values():
            if proc.memory_info and 'rss' in proc.memory_info:
                memory_consumers.append({
                    'pid': proc.pid,
                    'name': proc.name,
                    'memory_mb': proc.memory_info['rss'] / (1024 * 1024),
                    'memory_percent': proc.memory_info.get('percent', 0)
                })

        return sorted(memory_consumers, key=lambda x: x['memory_mb'], reverse=True)[:10]

    def get_unusual_network_activity(self) -> List[Dict]:
        """Get unusual network connections"""
        unusual_connections = []

        for conn in self.network_connections:
            # Check for unusual ports
            unusual_ports = [1337, 31337, 4444, 5555, 6666, 8080, 9999]
            if (conn['local_port'] in unusual_ports or
                conn['remote_port'] in unusual_ports):

                unusual_connections.append({
                    'pid': conn['pid'],
                    'local_endpoint': f"{conn['local_addr']}:{conn['local_port']}",
                    'remote_endpoint': f"{conn['remote_addr']}:{conn['remote_port']}",
                    'status': conn['status'],
                    'reason': 'Unusual port number'
                })

            # Check for suspicious IPs
            if conn['remote_addr'] in self.malware_signatures['network_indicators']:
                unusual_connections.append({
                    'pid': conn['pid'],
                    'local_endpoint': f"{conn['local_addr']}:{conn['local_port']}",
                    'remote_endpoint': f"{conn['remote_addr']}:{conn['remote_port']}",
                    'status': conn['status'],
                    'reason': 'Suspicious IP address'
                })

        return unusual_connections

    def generate_memory_recommendations(self) -> List[str]:
        """Generate memory analysis recommendations"""
        recommendations = []

        if self.suspicious_processes:
            recommendations.append(f"Investigate {len(self.suspicious_processes)} suspicious processes immediately")

        if self.injected_code_findings:
            recommendations.append("Code injection detected - perform full malware analysis")

        high_confidence_artifacts = [a for a in self.memory_artifacts if a.confidence > 0.8]
        if high_confidence_artifacts:
            recommendations.append(f"Analyze {len(high_confidence_artifacts)} high-confidence memory artifacts")

        recommendations.extend([
            "Perform full disk scan for malware persistence",
            "Check registry for malicious entries",
            "Analyze network traffic for C2 communications",
            "Implement endpoint detection and response (EDR)",
            "Regular memory analysis and baseline establishment"
        ])

        return recommendations

def main():
    """Main memory analyzer demo"""
    print("🧠 Memory Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_MEM_20240115"
    analyzer = MemoryAnalyzer(case_id)

    # Perform memory analysis
    analysis_results = analyzer.simulate_memory_dump_analysis()

    # Save results
    analyzer.save_analysis_results()

    # Generate report
    report = analyzer.generate_memory_report()

    # Save report
    report_file = f"reports/{case_id}_memory_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Memory analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Memory Analysis Summary:")
    print(f"   Processes analyzed: {report['summary']['total_processes']}")
    print(f"   Suspicious processes: {report['summary']['suspicious_processes']}")
    print(f"   Memory artifacts: {report['summary']['memory_artifacts']}")
    print(f"   Code injection findings: {report['summary']['code_injection_findings']}")

    if report['process_analysis']['suspicious_processes']:
        print(f"\n🚨 Suspicious Processes:")
        for proc in report['process_analysis']['suspicious_processes'][:5]:
            print(f"   • PID {proc['pid']} ({proc['name']}): {len(proc['indicators'])} indicators")

if __name__ == "__main__":
    main()
```

### Step 4: Malware Detection Engine (60 minutes)

```python
# malware_detector.py
import hashlib
import yara  # Note: This would require yara-python package
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import re
import base64

class MalwareSignature:
    def __init__(self, name: str, signature_type: str, pattern: str, description: str):
        self.name = name
        self.signature_type = signature_type  # 'string', 'regex', 'hash', 'yara'
        self.pattern = pattern
        self.description = description
        self.severity = "MEDIUM"
        self.created_at = datetime.now()

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.signature_type,
            'pattern': self.pattern,
            'description': self.description,
            'severity': self.severity,
            'created_at': self.created_at.isoformat()
        }

class MalwareDetectionEngine:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.signatures = []
        self.detection_results = []
        self.analyzed_samples = {}

        # Load built-in signatures
        self.load_builtin_signatures()

    def load_builtin_signatures(self):
        """Load built-in malware detection signatures"""

        # String-based signatures
        string_signatures = [
            {
                'name': 'Remote Access Tool Strings',
                'pattern': 'CreateRemoteThread|VirtualAllocEx|WriteProcessMemory',
                'description': 'Common API calls used by RATs and injectors',
                'severity': 'HIGH'
            },
            {
                'name': 'Keylogger Indicators',
                'pattern': 'GetAsyncKeyState|SetWindowsHookEx|keylog',
                'description': 'Keylogger functionality indicators',
                'severity': 'HIGH'
            },
            {
                'name': 'Anti-Analysis Techniques',
                'pattern': 'IsDebuggerPresent|FindWindow.*ollydbg|debugger',
                'description': 'Anti-debugging and analysis evasion',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Network Command & Control',
                'pattern': 'HttpSendRequest|InternetConnect|socket|connect',
                'description': 'Network communication capabilities',
                'severity': 'MEDIUM'
            },
            {
                'name': 'Persistence Mechanisms',
                'pattern': 'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|StartupApproved',
                'description': 'Registry persistence mechanisms',
                'severity': 'MEDIUM'
            }
        ]

        for sig_data in string_signatures:
            signature = MalwareSignature(
                sig_data['name'],
                'regex',
                sig_data['pattern'],
                sig_data['description']
            )
            signature.severity = sig_data['severity']
            self.signatures.append(signature)

        # Hash-based signatures (known malware hashes)
        hash_signatures = [
            {
                'name': 'Known Malware Hash 1',
                'pattern': 'd41d8cd98f00b204e9800998ecf8427e',  # MD5 of empty file
                'description': 'Known malware sample hash',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Suspicious PowerShell',
                'pattern': 'powershell.*-encodedcommand|powershell.*-e ',
                'description': 'Encoded PowerShell execution',
                'severity': 'HIGH'
            }
        ]

        for sig_data in hash_signatures:
            signature = MalwareSignature(
                sig_data['name'],
                'regex',
                sig_data['pattern'],
                sig_data['description']
            )
            signature.severity = sig_data['severity']
            self.signatures.append(signature)

    def analyze_memory_sample(self, memory_data: bytes, sample_name: str) -> Dict:
        """Analyze memory sample for malware indicators"""
        print(f"🔍 Analyzing memory sample: {sample_name}")

        analysis_result = {
            'sample_name': sample_name,
            'size': len(memory_data),
            'md5': hashlib.md5(memory_data).hexdigest(),
            'sha256': hashlib.sha256(memory_data).hexdigest(),
            'detection_results': [],
            'confidence_score': 0,
            'malware_family': 'Unknown',
            'analysis_timestamp': datetime.now().isoformat()
        }

        # Convert bytes to string for pattern matching
        try:
            memory_str = memory_data.decode('utf-8', errors='ignore')
        except:
            memory_str = str(memory_data)

        # Run signature detection
        for signature in self.signatures:
            matches = self.run_signature_detection(signature, memory_data, memory_str)
            if matches:
                analysis_result['detection_results'].extend(matches)

        # Calculate confidence score
        analysis_result['confidence_score'] = self.calculate_confidence_score(
            analysis_result['detection_results']
        )

        # Attempt malware family classification
        analysis_result['malware_family'] = self.classify_malware_family(
            analysis_result['detection_results']
        )

        # Store analysis result
        self.analyzed_samples[sample_name] = analysis_result
        self.detection_results.append(analysis_result)

        print(f"✅ Analysis complete - {len(analysis_result['detection_results'])} detections")
        print(f"   Confidence: {analysis_result['confidence_score']:.2f}")
        print(f"   Family: {analysis_result['malware_family']}")

        return analysis_result

    def run_signature_detection(self, signature: MalwareSignature,
                              raw_data: bytes, text_data: str) -> List[Dict]:
        """Run individual signature detection"""
        matches = []

        if signature.signature_type == 'regex':
            # Regex pattern matching
            try:
                pattern_matches = re.finditer(signature.pattern, text_data, re.IGNORECASE)
                for match in pattern_matches:
                    matches.append({
                        'signature_name': signature.name,
                        'pattern': signature.pattern,
                        'match_text': match.group(0),
                        'match_offset': match.start(),
                        'severity': signature.severity,
                        'description': signature.description
                    })
            except re.error:
                pass

        elif signature.signature_type == 'string':
            # Simple string matching
            if signature.pattern.lower() in text_data.lower():
                matches.append({
                    'signature_name': signature.name,
                    'pattern': signature.pattern,
                    'match_text': signature.pattern,
                    'match_offset': text_data.lower().find(signature.pattern.lower()),
                    'severity': signature.severity,
                    'description': signature.description
                })

        elif signature.signature_type == 'hash':
            # Hash-based detection
            md5_hash = hashlib.md5(raw_data).hexdigest()
            sha256_hash = hashlib.sha256(raw_data).hexdigest()

            if signature.pattern.lower() in [md5_hash, sha256_hash]:
                matches.append({
                    'signature_name': signature.name,
                    'pattern': signature.pattern,
                    'match_text': f"Hash match: {signature.pattern}",
                    'match_offset': 0,
                    'severity': signature.severity,
                    'description': signature.description
                })

        return matches

    def calculate_confidence_score(self, detection_results: List[Dict]) -> float:
        """Calculate malware confidence score based on detections"""
        if not detection_results:
            return 0.0

        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }

        total_score = 0
        max_possible_score = 0

        for detection in detection_results:
            severity = detection.get('severity', 'LOW')
            weight = severity_weights.get(severity, 0.2)
            total_score += weight
            max_possible_score += 1.0

        if max_possible_score == 0:
            return 0.0

        # Normalize to 0-1 range
        confidence = min(total_score / max_possible_score, 1.0)
        return confidence

    def classify_malware_family(self, detection_results: List[Dict]) -> str:
        """Attempt to classify malware family based on detections"""
        families = {
            'RAT': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
            'Keylogger': ['GetAsyncKeyState', 'SetWindowsHookEx', 'keylog'],
            'Backdoor': ['socket', 'connect', 'InternetConnect'],
            'Trojan': ['persistence', 'registry', 'startup'],
            'Rootkit': ['NtQuerySystemInformation', 'ZwQuerySystemInformation'],
            'Ransomware': ['CryptEncrypt', 'encryption', 'ransom']
        }

        family_scores = {}

        for detection in detection_results:
            match_text = detection.get('match_text', '').lower()

            for family, indicators in families.items():
                score = 0
                for indicator in indicators:
                    if indicator.lower() in match_text:
                        score += 1

                if score > 0:
                    family_scores[family] = family_scores.get(family, 0) + score

        if not family_scores:
            return 'Unknown'

        # Return family with highest score
        return max(family_scores.items(), key=lambda x: x[1])[0]

    def create_sample_malware(self) -> Dict:
        """Create sample malware for testing detection"""
        print("🦠 Creating sample malware for testing...")

        samples = {
            'suspected_rat.bin': (
                b'This is a sample file containing suspicious strings like '
                b'CreateRemoteThread and VirtualAllocEx for testing purposes. '
                b'Also contains WriteProcessMemory and other injection APIs.'
            ),
            'keylogger_sample.exe': (
                b'Sample keylogger with GetAsyncKeyState and SetWindowsHookEx '
                b'functionality for capturing user keystrokes and logging data.'
            ),
            'persistence_malware.dll': (
                b'Malware sample using SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run '
                b'for persistence and startup execution mechanisms.'
            ),
            'powershell_dropper.ps1': (
                b'powershell.exe -encodedcommand AQBJAAB3AGUAIAA= -ExecutionPolicy Bypass '
                b'containing base64 encoded malicious payload for execution.'
            )
        }

        analysis_results = {}

        for sample_name, sample_data in samples.items():
            result = self.analyze_memory_sample(sample_data, sample_name)
            analysis_results[sample_name] = result

        return analysis_results

    def generate_detection_report(self) -> Dict:
        """Generate comprehensive malware detection report"""
        report = {
            'case_id': self.case_id,
            'analysis_date': datetime.now().isoformat(),
            'summary': {
                'total_samples_analyzed': len(self.analyzed_samples),
                'malware_detected': len([s for s in self.analyzed_samples.values()
                                       if s['confidence_score'] > 0.5]),
                'high_confidence_detections': len([s for s in self.analyzed_samples.values()
                                                 if s['confidence_score'] > 0.8]),
                'signatures_used': len(self.signatures)
            },
            'detection_results': [],
            'malware_families': {},
            'high_risk_samples': [],
            'recommendations': []
        }

        # Process analysis results
        family_counts = {}

        for sample_name, analysis in self.analyzed_samples.items():
            # Add to detection results
            report['detection_results'].append({
                'sample_name': sample_name,
                'confidence_score': analysis['confidence_score'],
                'malware_family': analysis['malware_family'],
                'detection_count': len(analysis['detection_results']),
                'hash_md5': analysis['md5'],
                'hash_sha256': analysis['sha256']
            })

            # Count malware families
            family = analysis['malware_family']
            family_counts[family] = family_counts.get(family, 0) + 1

            # High-risk samples
            if analysis['confidence_score'] > 0.8:
                report['high_risk_samples'].append({
                    'sample_name': sample_name,
                    'confidence_score': analysis['confidence_score'],
                    'malware_family': analysis['malware_family'],
                    'top_detections': analysis['detection_results'][:3]
                })

        report['malware_families'] = family_counts

        # Generate recommendations
        if report['summary']['malware_detected'] > 0:
            report['recommendations'].append("Immediate containment of infected systems required")

        if report['summary']['high_confidence_detections'] > 0:
            report['recommendations'].append("High-confidence malware detected - perform full incident response")

        report['recommendations'].extend([
            "Update anti-malware signatures",
            "Perform network isolation for affected systems",
            "Check for lateral movement",
            "Review system logs for persistence mechanisms",
            "Implement enhanced monitoring"
        ])

        return report

def main():
    """Main malware detection demo"""
    print("🦠 Malware Detection Engine")
    print("=" * 40)

    # Create detection engine
    case_id = "CASE_MAL_20240115"
    detector = MalwareDetectionEngine(case_id)

    print(f"🛡️ Loaded {len(detector.signatures)} detection signatures")

    # Create and analyze sample malware
    analysis_results = detector.create_sample_malware()

    # Generate detection report
    report = detector.generate_detection_report()

    # Save report
    report_file = f"reports/{case_id}_malware_detection_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Malware detection report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Detection Summary:")
    print(f"   Samples analyzed: {report['summary']['total_samples_analyzed']}")
    print(f"   Malware detected: {report['summary']['malware_detected']}")
    print(f"   High confidence: {report['summary']['high_confidence_detections']}")

    print(f"\n🦠 Malware Families Detected:")
    for family, count in report['malware_families'].items():
        print(f"   {family}: {count}")

    if report['high_risk_samples']:
        print(f"\n⚠️ High-Risk Samples:")
        for sample in report['high_risk_samples']:
            print(f"   • {sample['sample_name']} ({sample['malware_family']}) - {sample['confidence_score']:.2f}")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: Permission denied accessing process memory
**Solution**: Run with administrator privileges or focus on accessible information

### Issue: YARA library not installed
**Solution**: Use string/regex matching instead: `pip install yara-python` (optional)

### Issue: Large memory dumps cause performance issues
**Solution**: Process memory in chunks and implement sampling

### Issue: False positives in malware detection
**Solution**: Implement confidence scoring and require multiple indicators

## ✅ Testing Workflow

```bash
# Run memory analysis
python memory_analyzer.py

# Run malware detection
python malware_detector.py

# Test integrated analysis
python -c "
from memory_analyzer import MemoryAnalyzer
from malware_detector import MalwareDetectionEngine

# Memory analysis
mem_analyzer = MemoryAnalyzer('CASE_TEST')
mem_results = mem_analyzer.simulate_memory_dump_analysis()

# Malware detection
mal_detector = MalwareDetectionEngine('CASE_TEST')
mal_results = mal_detector.create_sample_malware()

print(f'Memory: {mem_results[\"suspicious_processes\"]} suspicious processes')
print(f'Malware: {len(mal_results)} samples analyzed')
"
```

## 📁 Expected File Structure
```
week12-memory-analysis/
├── memory_analyzer.py              # Memory dump analysis
├── process_analyzer.py             # Process-specific analysis
├── malware_detector.py             # Malware detection engine
├── memory_visualizer.py            # Analysis visualization
├── memory_dumps/
│   ├── *_memory_analysis.db        # Memory analysis databases
│   └── sample_memory.dmp           # Sample memory dumps
├── analysis_results/
│   ├── *_process_analysis.json     # Process analysis results
│   └── *_artifact_extraction.json # Extracted artifacts
├── malware_signatures/
│   ├── string_signatures.txt       # String-based signatures
│   └── yara_rules.yar              # YARA rules
└── reports/
    ├── *_memory_report.json        # Memory analysis reports
    └── *_malware_detection_report.json # Malware detection results
```

## 🎯 Grading Focus Areas

1. **Memory Analysis**: Comprehensive analysis of processes and memory artifacts
2. **Malware Detection**: Effective identification of malicious code
3. **Code Injection Detection**: Recognition of injection techniques
4. **Artifact Extraction**: Recovery of valuable forensic evidence
5. **Professional Reporting**: Clear documentation of findings

## 💡 Pro Tips

1. **Focus on Behavioral Analysis**: Look for what processes are doing, not just what they are
2. **Correlate Multiple Indicators**: Single indicators can be false positives
3. **Understand Normal System Behavior**: Know what legitimate processes look like
4. **Use Confidence Scoring**: Not all detections are equally reliable
5. **Document Methodology**: Explain how conclusions were reached

## 🔍 Key Memory Analysis Concepts

### Memory Forensics Artifacts:
- **Process Lists**: Running and terminated processes
- **Network Connections**: Active TCP/UDP sessions
- **Registry Handles**: Open registry keys
- **File Handles**: Open files and directory handles
- **Loaded Modules**: DLLs and executables in memory

### Code Injection Techniques:
- **DLL Injection**: Injecting malicious DLL into legitimate process
- **Process Hollowing**: Replacing legitimate process memory with malicious code
- **Reflective DLL Loading**: Loading DLL directly from memory
- **Thread Hijacking**: Modifying thread execution to run malicious code

## 🚀 Extension Ideas (Optional)

- Add YARA rule support for advanced pattern matching
- Implement memory visualization tools
- Add support for different memory dump formats
- Create automated malware family classification
- Implement machine learning for anomaly detection

## ⏱️ Time Management

- **Start with live system analysis**: Easier than parsing memory dumps
- **Focus on high-impact indicators**: Not every string is important
- **Use confidence scoring**: Helps prioritize findings
- **Test with known malware samples**: Validate detection capabilities

Remember: Memory analysis provides unique insight into running malware that may not be visible on disk. Understanding process behavior and memory artifacts is crucial for advanced threat detection!