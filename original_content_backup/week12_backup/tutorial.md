# Week 12 Tutorial: Memory Analysis & Malware Forensics

**Estimated Time**: 4 hours (4 modules)  
**Prerequisites**: Weeks 10-11 digital forensics foundations completed

## Learning Objectives

By completing this tutorial, you will:
1. **Perform comprehensive memory analysis** using Volatility Framework
2. **Detect and analyze malware** in memory dumps and system artifacts  
3. **Reconstruct advanced attacks** including code injection and rootkits
4. **Integrate memory findings** with previous forensic evidence
5. **Build advanced analysis capabilities** for sophisticated threat investigation

---

## Module 1: Memory Forensics Fundamentals (60 minutes)

### Memory Acquisition and Analysis Framework

```python
import volatility3
import os
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional
import yara
import subprocess

class MemoryForensicsFramework:
    def __init__(self):
        self.volatility_path = "/usr/local/bin/vol.py"
        self.memory_dumps = {}
        self.analysis_results = {}
        self.malware_signatures = {}
        self.investigation_timeline = []
        self._setup_analysis_environment()
    
    def _setup_analysis_environment(self):
        """Initialize memory analysis environment"""
        
        # Volatility profile detection
        self.supported_profiles = [
            "Win10x64_19041",
            "Win10x64_18362", 
            "Win7SP1x64",
            "LinuxUbuntu2004x64",
            "MacOSMonterey_x64"
        ]
        
        # YARA rules for malware detection
        self.yara_rules = {
            "persistence_mechanisms": """
                rule Persistence_Registry {
                    strings:
                        $run1 = "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
                        $run2 = "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
                        $service = "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services"
                    condition:
                        any of them
                }
            """,
            
            "code_injection": """
                rule Code_Injection_Indicators {
                    strings:
                        $api1 = "VirtualAllocEx" ascii
                        $api2 = "WriteProcessMemory" ascii
                        $api3 = "CreateRemoteThread" ascii
                        $api4 = "SetWindowsHookEx" ascii
                    condition:
                        2 of them
                }
            """,
            
            "network_communication": """
                rule Suspicious_Network_Activity {
                    strings:
                        $http1 = "User-Agent:" ascii
                        $http2 = "POST" ascii
                        $crypto = { 89 50 4E 47 0D 0A 1A 0A }  // PNG header often used to hide data
                        $b64 = /[A-Za-z0-9+\/]{20,}={0,2}/
                    condition:
                        ($http1 and $http2) or ($crypto and $b64)
                }
            """
        }
        
        # Compile YARA rules
        self.compiled_rules = {}
        for rule_name, rule_content in self.yara_rules.items():
            try:
                self.compiled_rules[rule_name] = yara.compile(source=rule_content)
            except Exception as e:
                print(f"Error compiling YARA rule {rule_name}: {e}")
    
    def acquire_memory_dump(self, target_system: str, dump_path: str) -> Dict:
        """Acquire memory dump with integrity verification"""
        
        acquisition_metadata = {
            "timestamp": datetime.now().isoformat(),
            "target_system": target_system,
            "dump_path": dump_path,
            "acquisition_method": "live_acquisition",
            "tools_used": ["dd", "lime", "winpmem"],
            "integrity_hashes": {}
        }
        
        # Simulate memory acquisition (in practice, use tools like winpmem, lime, etc.)
        if os.path.exists(dump_path):
            # Calculate integrity hashes
            with open(dump_path, 'rb') as dump_file:
                dump_data = dump_file.read(1024 * 1024)  # Read 1MB for hash calculation
                
                acquisition_metadata["integrity_hashes"] = {
                    "md5": hashlib.md5(dump_data).hexdigest(),
                    "sha256": hashlib.sha256(dump_data).hexdigest(),
                    "sha512": hashlib.sha512(dump_data).hexdigest()
                }
                
                acquisition_metadata["file_size"] = os.path.getsize(dump_path)
                acquisition_metadata["status"] = "success"
        else:
            acquisition_metadata["status"] = "failed"
            acquisition_metadata["error"] = "Dump file not found"
        
        self.memory_dumps[target_system] = acquisition_metadata
        return acquisition_metadata
    
    def detect_memory_profile(self, dump_path: str) -> Dict:
        """Detect appropriate Volatility profile for memory dump"""
        
        profile_detection = {
            "detected_profiles": [],
            "recommended_profile": None,
            "confidence": 0,
            "detection_method": "volatility_imageinfo"
        }
        
        try:
            # Use Volatility to detect profile
            cmd = [
                "python3", self.volatility_path,
                "-f", dump_path,
                "windows.info.Info"  # Volatility 3 syntax
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse Volatility output for profile information
                if "Windows 10" in output:
                    profile_detection["detected_profiles"].append("Win10x64_19041")
                    profile_detection["recommended_profile"] = "Win10x64_19041"
                    profile_detection["confidence"] = 0.95
                elif "Windows 7" in output:
                    profile_detection["detected_profiles"].append("Win7SP1x64")
                    profile_detection["recommended_profile"] = "Win7SP1x64"
                    profile_detection["confidence"] = 0.90
                else:
                    profile_detection["confidence"] = 0.5
                    
            else:
                profile_detection["error"] = result.stderr
                
        except Exception as e:
            profile_detection["error"] = str(e)
        
        return profile_detection

# Initialize memory forensics framework
memory_framework = MemoryForensicsFramework()

# Example: Acquire and analyze memory dump
dump_metadata = memory_framework.acquire_memory_dump(
    "workstation_01", 
    "/forensics/memory_dumps/ws01_memory.dump"
)

profile_info = memory_framework.detect_memory_profile(
    "/forensics/memory_dumps/ws01_memory.dump"
)

print(f"Memory dump acquired: {dump_metadata['status']}")
print(f"Recommended profile: {profile_info.get('recommended_profile', 'Unknown')}")
```

### Checkpoint 1: Memory Acquisition Setup
```python
# Validate memory forensics setup
print(f"YARA rules compiled: {len(memory_framework.compiled_rules)}")
print(f"Supported profiles: {len(memory_framework.supported_profiles)}")
```

---

## Module 2: Process Analysis & Malware Detection (60 minutes)

### Comprehensive Process and Malware Analysis

```python
class MalwareAnalysisEngine:
    def __init__(self, memory_framework: MemoryForensicsFramework):
        self.memory_framework = memory_framework
        self.process_analysis = {}
        self.malware_indicators = {}
        self.network_analysis = {}
        self.behavioral_patterns = {}
    
    def analyze_running_processes(self, dump_path: str, profile: str) -> Dict:
        """Comprehensive process analysis using Volatility"""
        
        process_analysis = {
            "timestamp": datetime.now().isoformat(),
            "total_processes": 0,
            "suspicious_processes": [],
            "process_tree": {},
            "network_connections": [],
            "injected_processes": []
        }
        
        try:
            # Get process list
            processes_cmd = [
                "python3", self.memory_framework.volatility_path,
                "-f", dump_path,
                "windows.pslist.PsList"
            ]
            
            result = subprocess.run(processes_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse process list
                lines = result.stdout.split('\n')
                process_count = 0
                
                for line in lines:
                    if 'PID' in line and 'PPID' in line:  # Header line
                        continue
                    if line.strip():
                        process_count += 1
                        process_info = self._parse_process_line(line)
                        
                        if process_info:
                            # Check for suspicious characteristics
                            if self._is_suspicious_process(process_info):
                                process_analysis["suspicious_processes"].append(process_info)
                
                process_analysis["total_processes"] = process_count
            
            # Analyze network connections
            netstat_cmd = [
                "python3", self.memory_framework.volatility_path,
                "-f", dump_path,
                "windows.netscan.NetScan"
            ]
            
            net_result = subprocess.run(netstat_cmd, capture_output=True, text=True, timeout=300)
            
            if net_result.returncode == 0:
                connections = self._parse_network_connections(net_result.stdout)
                process_analysis["network_connections"] = connections
            
            # Check for code injection indicators
            injection_analysis = self._detect_code_injection(dump_path, profile)
            process_analysis["injected_processes"] = injection_analysis
            
        except Exception as e:
            process_analysis["error"] = str(e)
        
        self.process_analysis[dump_path] = process_analysis
        return process_analysis
    
    def _parse_process_line(self, line: str) -> Optional[Dict]:
        """Parse individual process line from Volatility output"""
        try:
            parts = line.split()
            if len(parts) >= 6:
                return {
                    "name": parts[0],
                    "pid": int(parts[1]),
                    "ppid": int(parts[2]),
                    "threads": int(parts[3]) if parts[3].isdigit() else 0,
                    "handles": int(parts[4]) if parts[4].isdigit() else 0,
                    "start_time": " ".join(parts[5:7]) if len(parts) > 6 else "unknown"
                }
        except (ValueError, IndexError):
            return None
        return None
    
    def _is_suspicious_process(self, process_info: Dict) -> bool:
        """Identify suspicious process characteristics"""
        suspicious_indicators = [
            # Processes running from unusual locations
            process_info["name"].lower() in ["svchost.exe", "explorer.exe", "winlogon.exe"] and process_info["ppid"] == 0,
            
            # Suspicious process names
            any(keyword in process_info["name"].lower() for keyword in ["temp", "tmp", "zzz", "aaa"]),
            
            # Abnormal parent-child relationships
            process_info["name"].lower() == "explorer.exe" and process_info["ppid"] != self._get_winlogon_pid(),
            
            # Processes with unusual thread/handle counts
            process_info["threads"] == 0 or process_info["handles"] == 0,
        ]
        
        return any(suspicious_indicators)
    
    def _get_winlogon_pid(self) -> int:
        """Get winlogon.exe PID for parent process validation"""
        # Simplified implementation - in practice, would query from process list
        return 500
    
    def _parse_network_connections(self, netstat_output: str) -> List[Dict]:
        """Parse network connections from Volatility netscan output"""
        connections = []
        
        for line in netstat_output.split('\n'):
            if ':' in line and 'TCP' in line or 'UDP' in line:
                try:
                    parts = line.split()
                    if len(parts) >= 5:
                        connection = {
                            "protocol": parts[0],
                            "local_address": parts[1],
                            "remote_address": parts[2] if len(parts) > 2 else "N/A",
                            "state": parts[3] if len(parts) > 3 else "N/A",
                            "pid": parts[4] if len(parts) > 4 and parts[4].isdigit() else "unknown"
                        }
                        connections.append(connection)
                except Exception:
                    continue
        
        return connections
    
    def _detect_code_injection(self, dump_path: str, profile: str) -> List[Dict]:
        """Detect code injection indicators"""
        injection_indicators = []
        
        try:
            # Use Volatility malfind plugin to detect injected code
            malfind_cmd = [
                "python3", self.memory_framework.volatility_path,
                "-f", dump_path,
                "windows.malfind.Malfind"
            ]
            
            result = subprocess.run(malfind_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse malfind results
                for line in result.stdout.split('\n'):
                    if 'PID' in line and 'Address' in line:
                        injection_info = self._parse_malfind_line(line)
                        if injection_info:
                            injection_indicators.append(injection_info)
            
        except Exception as e:
            injection_indicators.append({"error": str(e)})
        
        return injection_indicators
    
    def _parse_malfind_line(self, line: str) -> Optional[Dict]:
        """Parse malfind output line"""
        try:
            if "Process:" in line:
                parts = line.split()
                return {
                    "process": parts[1] if len(parts) > 1 else "unknown",
                    "pid": parts[3] if len(parts) > 3 else "unknown",
                    "type": "code_injection_detected",
                    "confidence": "high"
                }
        except Exception:
            pass
        return None
    
    def perform_yara_scan(self, dump_path: str) -> Dict:
        """Perform YARA scanning on memory dump"""
        
        yara_results = {
            "timestamp": datetime.now().isoformat(),
            "total_matches": 0,
            "rule_matches": {},
            "high_confidence_threats": []
        }
        
        for rule_name, compiled_rule in self.memory_framework.compiled_rules.items():
            try:
                # Scan memory dump with YARA rule
                matches = compiled_rule.match(dump_path)
                
                if matches:
                    rule_matches = []
                    for match in matches:
                        match_info = {
                            "rule": match.rule,
                            "offset": hex(match.strings[0].offset) if match.strings else "unknown",
                            "matched_strings": [str(string) for string in match.strings[:3]]  # Limit output
                        }
                        rule_matches.append(match_info)
                        yara_results["total_matches"] += 1
                    
                    yara_results["rule_matches"][rule_name] = rule_matches
                    
                    # Flag high-confidence threats
                    if rule_name in ["code_injection", "persistence_mechanisms"]:
                        yara_results["high_confidence_threats"].extend(rule_matches)
            
            except Exception as e:
                yara_results["rule_matches"][rule_name] = {"error": str(e)}
        
        return yara_results

# Perform comprehensive malware analysis
malware_engine = MalwareAnalysisEngine(memory_framework)

# Analyze processes
process_results = malware_engine.analyze_running_processes(
    "/forensics/memory_dumps/ws01_memory.dump",
    "Win10x64_19041"
)

# Perform YARA scanning
yara_results = malware_engine.perform_yara_scan(
    "/forensics/memory_dumps/ws01_memory.dump"
)

print(f"Processes analyzed: {process_results.get('total_processes', 0)}")
print(f"Suspicious processes: {len(process_results.get('suspicious_processes', []))}")
print(f"YARA matches: {yara_results.get('total_matches', 0)}")
```

### Checkpoint 2: Malware Detection Validation
```python
# Validate malware detection capabilities
print(f"Network connections found: {len(process_results.get('network_connections', []))}")
print(f"High confidence threats: {len(yara_results.get('high_confidence_threats', []))}")
```

---

## Module 3: Advanced Threat Reconstruction (60 minutes)

### Attack Timeline and Persistence Analysis

```python
class AdvancedThreatAnalysis:
    def __init__(self, malware_engine: MalwareAnalysisEngine):
        self.malware_engine = malware_engine
        self.attack_timeline = []
        self.persistence_mechanisms = {}
        self.lateral_movement = {}
        self.data_exfiltration = {}
    
    def reconstruct_attack_timeline(self, dump_path: str, external_evidence: Dict = None) -> Dict:
        """Reconstruct comprehensive attack timeline from memory and external sources"""
        
        timeline_reconstruction = {
            "attack_phases": {},
            "indicators_of_compromise": [],
            "persistence_mechanisms": [],
            "lateral_movement_evidence": [],
            "data_exfiltration_indicators": [],
            "confidence_assessment": {}
        }
        
        # Phase 1: Initial Access Analysis
        initial_access = self._analyze_initial_access(dump_path)
        timeline_reconstruction["attack_phases"]["initial_access"] = initial_access
        
        # Phase 2: Persistence Mechanism Detection
        persistence = self._detect_persistence_mechanisms(dump_path)
        timeline_reconstruction["persistence_mechanisms"] = persistence
        
        # Phase 3: Privilege Escalation Analysis
        privilege_escalation = self._analyze_privilege_escalation(dump_path)
        timeline_reconstruction["attack_phases"]["privilege_escalation"] = privilege_escalation
        
        # Phase 4: Defense Evasion Techniques
        evasion = self._detect_defense_evasion(dump_path)
        timeline_reconstruction["attack_phases"]["defense_evasion"] = evasion
        
        # Phase 5: Lateral Movement Detection
        lateral_movement = self._analyze_lateral_movement(dump_path)
        timeline_reconstruction["lateral_movement_evidence"] = lateral_movement
        
        # Phase 6: Data Exfiltration Analysis
        exfiltration = self._analyze_data_exfiltration(dump_path)
        timeline_reconstruction["data_exfiltration_indicators"] = exfiltration
        
        # Integrate with external evidence (Week 10-11 findings)
        if external_evidence:
            timeline_reconstruction = self._integrate_external_evidence(
                timeline_reconstruction, external_evidence
            )
        
        # Calculate confidence scores
        timeline_reconstruction["confidence_assessment"] = self._calculate_confidence(
            timeline_reconstruction
        )
        
        return timeline_reconstruction
    
    def _analyze_initial_access(self, dump_path: str) -> Dict:
        """Analyze initial access vector indicators in memory"""
        
        initial_access = {
            "potential_vectors": [],
            "evidence_found": [],
            "confidence": 0
        }
        
        # Check for common initial access indicators
        access_indicators = [
            {
                "vector": "spear_phishing",
                "indicators": ["outlook.exe", "iexplore.exe", "chrome.exe"],
                "memory_artifacts": ["suspicious_downloads", "email_attachments"]
            },
            {
                "vector": "exploit_kit", 
                "indicators": ["java.exe", "flash", "acrobat"],
                "memory_artifacts": ["heap_spray", "rop_chains"]
            },
            {
                "vector": "remote_service_exploitation",
                "indicators": ["smss.exe", "lsass.exe", "services.exe"],
                "memory_artifacts": ["abnormal_authentication", "service_creation"]
            }
        ]
        
        for vector_info in access_indicators:
            evidence_count = 0
            vector_evidence = []
            
            # Check for process indicators
            if self.malware_engine.process_analysis.get(dump_path):
                processes = self.malware_engine.process_analysis[dump_path].get("suspicious_processes", [])
                
                for process in processes:
                    if any(indicator in process["name"].lower() for indicator in vector_info["indicators"]):
                        evidence_count += 1
                        vector_evidence.append({
                            "type": "suspicious_process",
                            "process": process["name"],
                            "pid": process["pid"]
                        })
            
            if evidence_count > 0:
                initial_access["potential_vectors"].append({
                    "vector": vector_info["vector"],
                    "evidence_count": evidence_count,
                    "evidence": vector_evidence,
                    "confidence": min(evidence_count * 0.3, 1.0)
                })
        
        # Calculate overall confidence
        if initial_access["potential_vectors"]:
            initial_access["confidence"] = max([v["confidence"] for v in initial_access["potential_vectors"]])
        
        return initial_access
    
    def _detect_persistence_mechanisms(self, dump_path: str) -> List[Dict]:
        """Detect persistence mechanisms in memory"""
        
        persistence_indicators = []
        
        # Registry-based persistence
        registry_persistence = {
            "type": "registry_persistence",
            "locations": [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            ],
            "indicators_found": [],
            "confidence": 0
        }
        
        # Service-based persistence  
        service_persistence = {
            "type": "service_persistence",
            "suspicious_services": [],
            "service_modifications": [],
            "confidence": 0
        }
        
        # Scheduled task persistence
        task_persistence = {
            "type": "scheduled_task_persistence", 
            "suspicious_tasks": [],
            "task_modifications": [],
            "confidence": 0
        }
        
        # WMI persistence
        wmi_persistence = {
            "type": "wmi_persistence",
            "wmi_subscriptions": [],
            "wmi_consumers": [],
            "confidence": 0
        }
        
        persistence_indicators.extend([
            registry_persistence, service_persistence, 
            task_persistence, wmi_persistence
        ])
        
        return persistence_indicators
    
    def _analyze_privilege_escalation(self, dump_path: str) -> Dict:
        """Analyze privilege escalation indicators"""
        
        privilege_escalation = {
            "techniques_detected": [],
            "privilege_changes": [],
            "exploit_indicators": [],
            "confidence": 0
        }
        
        # UAC bypass indicators
        uac_bypass = {
            "technique": "uac_bypass",
            "indicators": ["eventvwr.exe", "fodhelper.exe", "computerdefaults.exe"],
            "evidence": []
        }
        
        # Token manipulation
        token_manipulation = {
            "technique": "token_manipulation",
            "indicators": ["lsass.exe access", "SeDebugPrivilege", "token_duplication"],
            "evidence": []
        }
        
        # Service escalation
        service_escalation = {
            "technique": "service_escalation", 
            "indicators": ["unquoted_service_paths", "service_permissions", "dll_hijacking"],
            "evidence": []
        }
        
        privilege_escalation["techniques_detected"] = [
            uac_bypass, token_manipulation, service_escalation
        ]
        
        return privilege_escalation
    
    def _detect_defense_evasion(self, dump_path: str) -> Dict:
        """Detect defense evasion techniques"""
        
        defense_evasion = {
            "techniques": [],
            "anti_analysis": [],
            "obfuscation": [],
            "confidence": 0
        }
        
        # Process hollowing detection
        process_hollowing = {
            "technique": "process_hollowing",
            "indicators": ["suspended_processes", "image_modifications", "memory_inconsistencies"],
            "confidence": 0
        }
        
        # DLL injection detection  
        dll_injection = {
            "technique": "dll_injection",
            "indicators": ["SetWindowsHookEx", "CreateRemoteThread", "VirtualAllocEx"],
            "confidence": 0
        }
        
        # Rootkit indicators
        rootkit_detection = {
            "technique": "rootkit",
            "indicators": ["ssdt_hooks", "hidden_processes", "modified_system_calls"],
            "confidence": 0
        }
        
        defense_evasion["techniques"] = [
            process_hollowing, dll_injection, rootkit_detection
        ]
        
        return defense_evasion
    
    def _analyze_lateral_movement(self, dump_path: str) -> List[Dict]:
        """Analyze lateral movement indicators"""
        
        lateral_movement = []
        
        # Remote desktop usage
        rdp_movement = {
            "technique": "remote_desktop",
            "indicators": ["mstsc.exe", "rdp_connections", "terminal_services"],
            "evidence": []
        }
        
        # SMB/CIFS usage
        smb_movement = {
            "technique": "smb_shares",
            "indicators": ["net.exe", "smb_connections", "share_access"],
            "evidence": []
        }
        
        # WMI remote execution
        wmi_movement = {
            "technique": "wmi_remote_execution",
            "indicators": ["wmic.exe", "wmi_processes", "remote_wmi"],
            "evidence": []
        }
        
        # PowerShell remoting
        ps_movement = {
            "technique": "powershell_remoting",
            "indicators": ["powershell.exe", "winrm", "ps_sessions"],
            "evidence": []
        }
        
        lateral_movement.extend([rdp_movement, smb_movement, wmi_movement, ps_movement])
        
        return lateral_movement
    
    def _analyze_data_exfiltration(self, dump_path: str) -> List[Dict]:
        """Analyze data exfiltration indicators"""
        
        exfiltration_indicators = []
        
        # Network exfiltration
        network_exfiltration = {
            "method": "network_exfiltration",
            "indicators": ["unusual_outbound_connections", "large_data_transfers", "encrypted_channels"],
            "evidence": []
        }
        
        # USB/removable media
        usb_exfiltration = {
            "method": "usb_exfiltration", 
            "indicators": ["usb_device_connection", "file_copying", "removable_storage"],
            "evidence": []
        }
        
        # Cloud storage exfiltration
        cloud_exfiltration = {
            "method": "cloud_exfiltration",
            "indicators": ["cloud_sync_clients", "browser_uploads", "api_connections"],
            "evidence": []
        }
        
        exfiltration_indicators.extend([
            network_exfiltration, usb_exfiltration, cloud_exfiltration
        ])
        
        return exfiltration_indicators
    
    def _integrate_external_evidence(self, timeline: Dict, external_evidence: Dict) -> Dict:
        """Integrate findings from Weeks 10-11 investigations"""
        
        # Correlate with file system evidence
        if "file_system_analysis" in external_evidence:
            file_evidence = external_evidence["file_system_analysis"]
            
            # Cross-reference deleted files with memory artifacts
            if "deleted_files" in file_evidence:
                for deleted_file in file_evidence["deleted_files"]:
                    # Check if file appears in process memory
                    timeline["indicators_of_compromise"].append({
                        "type": "deleted_file_in_memory",
                        "file": deleted_file,
                        "source": "cross_reference_analysis"
                    })
        
        # Correlate with network evidence  
        if "network_analysis" in external_evidence:
            network_evidence = external_evidence["network_analysis"]
            
            # Match network connections with memory analysis
            if "suspicious_connections" in network_evidence:
                for connection in network_evidence["suspicious_connections"]:
                    timeline["lateral_movement_evidence"].append({
                        "type": "confirmed_network_connection",
                        "connection": connection,
                        "source": "network_memory_correlation"
                    })
        
        return timeline
    
    def _calculate_confidence(self, timeline: Dict) -> Dict:
        """Calculate confidence scores for timeline reconstruction"""
        
        confidence_assessment = {
            "overall_confidence": 0,
            "phase_confidence": {},
            "evidence_quality": {},
            "reliability_score": 0
        }
        
        # Calculate confidence for each attack phase
        for phase, data in timeline.get("attack_phases", {}).items():
            phase_confidence = data.get("confidence", 0)
            confidence_assessment["phase_confidence"][phase] = phase_confidence
        
        # Calculate overall confidence
        if confidence_assessment["phase_confidence"]:
            confidence_assessment["overall_confidence"] = sum(
                confidence_assessment["phase_confidence"].values()
            ) / len(confidence_assessment["phase_confidence"])
        
        # Evidence quality assessment
        evidence_sources = ["memory_analysis", "yara_detection", "behavioral_analysis"]
        for source in evidence_sources:
            confidence_assessment["evidence_quality"][source] = 0.8  # Placeholder scoring
        
        # Reliability score based on evidence correlation
        correlation_count = len(timeline.get("indicators_of_compromise", []))
        confidence_assessment["reliability_score"] = min(correlation_count * 0.1, 1.0)
        
        return confidence_assessment

# Perform advanced threat analysis
threat_analyzer = AdvancedThreatAnalysis(malware_engine)

# Integrate with previous investigation findings
external_evidence = {
    "file_system_analysis": {
        "deleted_files": ["temp_payload.exe", "config.dat"],
        "suspicious_files": ["system32_update.exe"]
    },
    "network_analysis": {
        "suspicious_connections": ["192.168.1.100:4444", "malicious-c2.com:443"]
    }
}

# Reconstruct attack timeline
attack_timeline = threat_analyzer.reconstruct_attack_timeline(
    "/forensics/memory_dumps/ws01_memory.dump",
    external_evidence
)

print(f"Attack phases identified: {len(attack_timeline.get('attack_phases', {}))}")
print(f"IOCs identified: {len(attack_timeline.get('indicators_of_compromise', []))}")
print(f"Overall confidence: {attack_timeline['confidence_assessment']['overall_confidence']:.2f}")
```

### Checkpoint 3: Threat Reconstruction Validation
```python
# Validate advanced threat analysis
print(f"Persistence mechanisms: {len(attack_timeline.get('persistence_mechanisms', []))}")
print(f"Lateral movement evidence: {len(attack_timeline.get('lateral_movement_evidence', []))}")
```

---

## Module 4: Professional Forensic Integration (60 minutes)

### Memory Forensics Integration with Investigation Platform

```python
class ForensicIntegrationPlatform:
    def __init__(self, threat_analyzer: AdvancedThreatAnalysis):
        self.threat_analyzer = threat_analyzer
        self.case_management = {}
        self.evidence_correlation = {}
        self.reporting_engine = {}
        self.expert_testimony_prep = {}
    
    def create_comprehensive_case_file(self, case_id: str, memory_analysis: Dict, 
                                     previous_findings: Dict) -> Dict:
        """Create comprehensive forensic case file integrating all evidence"""
        
        case_file = {
            "case_metadata": {
                "case_id": case_id,
                "creation_timestamp": datetime.now().isoformat(),
                "analyst": "forensic_examiner",
                "case_type": "advanced_persistent_threat",
                "evidence_sources": ["memory_dump", "file_system", "network_traffic", "logs"]
            },
            
            "executive_summary": {
                "incident_overview": "",
                "key_findings": [],
                "impact_assessment": {},
                "recommendations": []
            },
            
            "technical_analysis": {
                "memory_forensics": memory_analysis,
                "correlation_results": {},
                "timeline_reconstruction": {},
                "indicators_of_compromise": []
            },
            
            "legal_admissibility": {
                "chain_of_custody": [],
                "evidence_integrity": {},
                "expert_witness_preparation": {},
                "daubert_compliance": {}
            }
        }
        
        # Generate executive summary
        case_file["executive_summary"] = self._generate_executive_summary(
            memory_analysis, previous_findings
        )
        
        # Perform comprehensive evidence correlation
        case_file["technical_analysis"]["correlation_results"] = self._correlate_all_evidence(
            memory_analysis, previous_findings
        )
        
        # Create integrated timeline
        case_file["technical_analysis"]["timeline_reconstruction"] = self._create_integrated_timeline(
            memory_analysis, previous_findings
        )
        
        # Prepare for legal proceedings
        case_file["legal_admissibility"] = self._prepare_legal_documentation(
            memory_analysis, previous_findings
        )
        
        self.case_management[case_id] = case_file
        return case_file
    
    def _generate_executive_summary(self, memory_analysis: Dict, previous_findings: Dict) -> Dict:
        """Generate executive summary for management and legal teams"""
        
        summary = {
            "incident_overview": """
            Advanced persistent threat (APT) investigation revealed sophisticated multi-stage attack 
            involving initial access through spear-phishing, privilege escalation, persistence 
            establishment, lateral movement, and data exfiltration. Memory forensics analysis 
            corroborates file system and network evidence, providing high-confidence attack 
            reconstruction.
            """,
            
            "key_findings": [
                "Advanced malware with anti-forensics capabilities detected in memory",
                "Multiple persistence mechanisms established across enterprise infrastructure", 
                "Evidence of lateral movement to critical business systems",
                "Data exfiltration to external command and control servers confirmed",
                "Attack demonstrates sophisticated threat actor with advanced capabilities"
            ],
            
            "impact_assessment": {
                "data_compromise": "High - sensitive business data accessed and exfiltrated",
                "system_compromise": "Critical - multiple enterprise systems compromised",
                "business_impact": "Significant - operational disruption and regulatory implications",
                "recovery_complexity": "Complex - requires comprehensive system rebuild and monitoring"
            },
            
            "recommendations": [
                "Immediate containment and isolation of affected systems",
                "Comprehensive threat hunting across entire enterprise infrastructure",
                "Enhanced monitoring and detection capabilities implementation",
                "Incident response process review and improvement",
                "Employee security awareness training enhancement",
                "Third-party security assessment and architecture review"
            ]
        }
        
        return summary
    
    def _correlate_all_evidence(self, memory_analysis: Dict, previous_findings: Dict) -> Dict:
        """Correlate evidence across all investigation sources"""
        
        correlation_results = {
            "high_confidence_correlations": [],
            "medium_confidence_correlations": [],
            "timeline_correlations": [],
            "ioc_correlations": []
        }
        
        # Memory-File System Correlations
        if "file_analysis" in previous_findings:
            file_evidence = previous_findings["file_analysis"]
            
            # Correlate processes with file modifications
            for process in memory_analysis.get("suspicious_processes", []):
                process_name = process.get("name", "")
                
                for file_mod in file_evidence.get("file_modifications", []):
                    if process_name.lower() in file_mod.get("process", "").lower():
                        correlation_results["high_confidence_correlations"].append({
                            "type": "process_file_correlation",
                            "process": process_name,
                            "file_modification": file_mod,
                            "confidence": 0.95
                        })
        
        # Memory-Network Correlations  
        if "network_analysis" in previous_findings:
            network_evidence = previous_findings["network_analysis"]
            
            # Correlate network connections with process activity
            for connection in memory_analysis.get("network_connections", []):
                for network_event in network_evidence.get("suspicious_connections", []):
                    if connection.get("remote_address") in network_event.get("destination", ""):
                        correlation_results["high_confidence_correlations"].append({
                            "type": "network_process_correlation",
                            "memory_connection": connection,
                            "network_event": network_event,
                            "confidence": 0.90
                        })
        
        # Memory-SIEM Log Correlations
        if "siem_analysis" in previous_findings:
            siem_evidence = previous_findings["siem_analysis"]
            
            # Correlate authentication events with process activity
            for auth_event in siem_evidence.get("authentication_events", []):
                auth_time = auth_event.get("timestamp")
                
                # Find processes starting around authentication time
                for process in memory_analysis.get("suspicious_processes", []):
                    if self._time_correlation(auth_time, process.get("start_time")):
                        correlation_results["medium_confidence_correlations"].append({
                            "type": "authentication_process_correlation",
                            "auth_event": auth_event,
                            "process": process,
                            "confidence": 0.75
                        })
        
        return correlation_results
    
    def _create_integrated_timeline(self, memory_analysis: Dict, previous_findings: Dict) -> Dict:
        """Create comprehensive timeline integrating all evidence sources"""
        
        integrated_timeline = {
            "timeline_events": [],
            "attack_phases": {},
            "evidence_confidence": {},
            "reconstruction_methodology": "multi_source_correlation"
        }
        
        # Collect events from all sources
        all_events = []
        
        # Memory analysis events
        for process in memory_analysis.get("suspicious_processes", []):
            all_events.append({
                "timestamp": process.get("start_time", "unknown"),
                "event_type": "process_creation",
                "source": "memory_analysis",
                "details": process,
                "confidence": 0.90
            })
        
        # File system events
        if "file_analysis" in previous_findings:
            for file_event in previous_findings["file_analysis"].get("file_modifications", []):
                all_events.append({
                    "timestamp": file_event.get("timestamp", "unknown"),
                    "event_type": "file_modification",
                    "source": "file_system_analysis", 
                    "details": file_event,
                    "confidence": 0.85
                })
        
        # Network events
        if "network_analysis" in previous_findings:
            for network_event in previous_findings["network_analysis"].get("connections", []):
                all_events.append({
                    "timestamp": network_event.get("timestamp", "unknown"),
                    "event_type": "network_connection",
                    "source": "network_analysis",
                    "details": network_event,
                    "confidence": 0.80
                })
        
        # Sort events chronologically
        sorted_events = sorted(all_events, key=lambda x: x.get("timestamp", "0"))
        integrated_timeline["timeline_events"] = sorted_events
        
        # Identify attack phases based on timeline
        integrated_timeline["attack_phases"] = self._identify_attack_phases(sorted_events)
        
        return integrated_timeline
    
    def _prepare_legal_documentation(self, memory_analysis: Dict, previous_findings: Dict) -> Dict:
        """Prepare documentation for legal proceedings"""
        
        legal_documentation = {
            "chain_of_custody": {
                "evidence_items": [],
                "custody_transfers": [],
                "integrity_verification": {}
            },
            
            "expert_witness_preparation": {
                "qualifications": {
                    "education": "Computer Science/Digital Forensics",
                    "certifications": ["GCFA", "CCE", "CISSP"],
                    "experience_years": "5+",
                    "case_experience": "100+ digital forensic investigations"
                },
                
                "methodology_validation": {
                    "tools_used": ["Volatility", "Autopsy", "Wireshark", "YARA"],
                    "standards_followed": ["NIST SP 800-86", "RFC 3227", "ISO/IEC 27037"],
                    "quality_assurance": "Peer review and validation performed",
                    "reproducibility": "Analysis steps documented and repeatable"
                },
                
                "findings_summary": {
                    "key_conclusions": [],
                    "confidence_levels": {},
                    "limitations": [],
                    "alternative_explanations": []
                }
            },
            
            "daubert_compliance": {
                "scientific_validity": {
                    "peer_reviewed_methods": True,
                    "known_error_rates": "Low - established forensic techniques",
                    "general_acceptance": "Widely accepted in digital forensics community",
                    "testing_validation": "Extensive validation in forensic community"
                },
                
                "relevance_reliability": {
                    "directly_relevant": True,
                    "methodology_appropriate": True,
                    "conclusions_supported": True,
                    "expert_qualified": True
                }
            }
        }
        
        # Populate evidence items for chain of custody
        evidence_items = [
            {
                "item_id": "MEM_001",
                "description": "Memory dump from workstation_01",
                "collection_timestamp": datetime.now().isoformat(),
                "collector": "forensic_analyst",
                "integrity_hash": "sha256_hash_value"
            }
        ]
        
        legal_documentation["chain_of_custody"]["evidence_items"] = evidence_items
        
        return legal_documentation
    
    def generate_expert_witness_report(self, case_id: str) -> Dict:
        """Generate comprehensive expert witness report"""
        
        if case_id not in self.case_management:
            return {"error": "Case not found"}
        
        case_data = self.case_management[case_id]
        
        expert_report = {
            "report_metadata": {
                "case_id": case_id,
                "report_date": datetime.now().isoformat(),
                "expert_name": "Digital Forensics Expert",
                "report_version": "1.0"
            },
            
            "expert_qualifications": case_data["legal_admissibility"]["expert_witness_preparation"]["qualifications"],
            
            "scope_of_examination": {
                "evidence_examined": ["Memory dumps", "File system images", "Network captures", "System logs"],
                "analysis_period": "2023-01-01 to 2023-12-31",
                "methodology_used": ["Memory forensics", "File system analysis", "Network forensics", "Timeline analysis"],
                "tools_utilized": ["Volatility Framework", "Autopsy", "Wireshark", "YARA"]
            },
            
            "executive_summary": case_data["executive_summary"],
            
            "technical_findings": {
                "memory_analysis_results": case_data["technical_analysis"]["memory_forensics"],
                "correlation_analysis": case_data["technical_analysis"]["correlation_results"],
                "timeline_reconstruction": case_data["technical_analysis"]["timeline_reconstruction"],
                "confidence_assessment": "High confidence in findings based on multiple corroborating evidence sources"
            },
            
            "conclusions_and_opinions": {
                "primary_conclusions": case_data["executive_summary"]["key_findings"],
                "confidence_levels": {
                    "attack_occurred": "Very High (95%+)",
                    "timeline_accuracy": "High (85%+)", 
                    "attribution_confidence": "Medium (70%+)",
                    "impact_assessment": "High (90%+)"
                },
                "limitations_disclaimers": [
                    "Analysis limited to available evidence",
                    "Some artifacts may have been destroyed or overwritten",
                    "Analysis represents point-in-time snapshot",
                    "Conclusions based on available digital evidence only"
                ]
            },
            
            "appendices": {
                "detailed_technical_analysis": "Available upon request",
                "tool_validation_reports": "Available upon request", 
                "raw_analysis_output": "Available upon request",
                "cv_and_qualifications": "Available upon request"
            }
        }
        
        return expert_report
    
    def _time_correlation(self, time1: str, time2: str) -> bool:
        """Check if two timestamps are closely correlated"""
        # Simplified time correlation - in practice would use proper datetime parsing
        return abs(hash(time1) - hash(time2)) < 1000000  # Placeholder logic
    
    def _identify_attack_phases(self, events: List[Dict]) -> Dict:
        """Identify attack phases from chronological events"""
        
        phases = {
            "initial_access": [],
            "execution": [], 
            "persistence": [],
            "privilege_escalation": [],
            "defense_evasion": [],
            "credential_access": [],
            "discovery": [],
            "lateral_movement": [],
            "collection": [],
            "exfiltration": []
        }
        
        # Classify events into attack phases based on characteristics
        for event in events:
            event_type = event.get("event_type", "")
            details = event.get("details", {})
            
            if event_type == "process_creation":
                if "browser" in details.get("name", "").lower():
                    phases["initial_access"].append(event)
                elif "service" in details.get("name", "").lower():
                    phases["persistence"].append(event)
                else:
                    phases["execution"].append(event)
            
            elif event_type == "network_connection":
                if details.get("direction") == "outbound":
                    phases["exfiltration"].append(event)
                else:
                    phases["lateral_movement"].append(event)
            
            elif event_type == "file_modification":
                if "system32" in details.get("path", "").lower():
                    phases["defense_evasion"].append(event)
                else:
                    phases["collection"].append(event)
        
        return phases

# Create comprehensive forensic integration
integration_platform = ForensicIntegrationPlatform(threat_analyzer)

# Create comprehensive case file
comprehensive_case = integration_platform.create_comprehensive_case_file(
    "CASE_2023_001",
    {
        "suspicious_processes": process_results.get("suspicious_processes", []),
        "network_connections": process_results.get("network_connections", []),
        "yara_matches": yara_results.get("rule_matches", {})
    },
    {
        "file_analysis": {"file_modifications": []},
        "network_analysis": {"suspicious_connections": []},
        "siem_analysis": {"authentication_events": []}
    }
)

# Generate expert witness report
expert_report = integration_platform.generate_expert_witness_report("CASE_2023_001")

print(f"Case file created: {comprehensive_case['case_metadata']['case_id']}")
print(f"Executive summary findings: {len(comprehensive_case['executive_summary']['key_findings'])}")
print(f"Expert report confidence: {expert_report['conclusions_and_opinions']['confidence_levels']['attack_occurred']}")
```

### Checkpoint 4: Forensic Integration Validation
```python
# Validate comprehensive forensic integration
print(f"Timeline events integrated: {len(comprehensive_case['technical_analysis']['timeline_reconstruction']['timeline_events'])}")
print(f"Legal admissibility prepared: {'daubert_compliance' in comprehensive_case['legal_admissibility']}")
```

## Tutorial Completion

🎉 **Congratulations!** You've mastered advanced memory analysis and malware forensics.

### What You've Accomplished:
1. **Comprehensive Memory Analysis** with Volatility Framework
2. **Advanced Malware Detection** using YARA and behavioral analysis
3. **Sophisticated Threat Reconstruction** with multi-source correlation
4. **Professional Forensic Integration** ready for legal proceedings

### Next Steps:
- **Week 12 Assignment**: Advanced memory forensics investigation
- **Project 3 Development**: Advanced Analysis Toolkit implementation
- **Week 13 Preview**: Mobile forensics and advanced analysis techniques

### Professional Applications:
- **Malware Analyst** roles requiring advanced threat investigation
- **Incident Response** specialist focusing on APT investigations
- **Expert Witness** testimony in digital forensics cases
- **Threat Hunter** using memory analysis for detection

You're now equipped for the most sophisticated digital forensics investigations! 🔍