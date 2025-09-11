# Week 11 Tutorial: Advanced Digital Forensics & Multi-Source Investigation

**Estimated Time**: 4 hours (self-paced)  
**Prerequisites**: Week 10 completed, understanding of basic forensics methodology
**Project Context**: Completing Project 2 - Incident Investigation Platform

## 🎯 Tutorial Goals

This tutorial completes your advanced digital forensics training by integrating network forensics, database forensics, cross-source correlation, and advanced artifact analysis into a comprehensive investigation platform.

**Learning Progression:**
1. **Module 1** (60 min): Network Forensics & Packet Analysis
2. **Module 2** (60 min): Database Forensics & Transaction Log Analysis  
3. **Module 3** (60 min): Cross-Source Evidence Correlation & Timeline Integration
4. **Module 4** (60 min): Advanced Artifact Analysis & Expert Reporting

### 📊 Self-Paced Progress Tracking
Check off each section as you complete it:

- [ ] Module 1: Network Forensics & SIEM Integration ✅ Ready for Module 2
- [ ] Module 2: Database & Application Forensics ✅ Ready for Module 3  
- [ ] Module 3: Cross-Source Correlation Engine ✅ Ready for Module 4
- [ ] Module 4: Advanced Reporting & Expert Testimony ✅ Tutorial Complete

## 🔧 Advanced Environment Setup

Set up your comprehensive forensics laboratory:

```bash
# Advanced forensics environment
python --version  # Should be 3.11+

# Install comprehensive forensics toolkit
pip install scapy dpkt pyshark sqlite3 pandas matplotlib networkx
pip install email-parser hashlib re json datetime typing dataclasses
pip install plotly dash flask-security cryptography yara-python

# Optional professional tools
# Wireshark: https://www.wireshark.org/
# Volatility3: https://github.com/volatilityfoundation/volatility3
# Autopsy: https://www.autopsy.com/

# Create advanced working directory
mkdir week11-advanced-forensics
cd week11-advanced-forensics
mkdir {network,database,correlation,reports,evidence}
```

---

## 📘 Module 1: Network Forensics & SIEM Integration (60 minutes)

**Learning Objective**: Master network packet analysis integrated with SIEM data from Week 7

**What you'll build**: Advanced network forensics analyzer with SIEM correlation

### Step 1: Advanced Network Packet Analysis

Create `advanced_network_forensics.py`:

```python
import scapy.all as scapy
import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
import hashlib
import re
import matplotlib.pyplot as plt
import networkx as nx

@dataclass 
class NetworkFlow:
    """Advanced network flow representation for forensic analysis"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime]
    bytes_sent: int
    bytes_received: int
    packet_count: int
    flags: Set[str]
    payload_samples: List[str]
    
    def duration(self) -> timedelta:
        if self.end_time:
            return self.end_time - self.start_time
        return timedelta(0)
    
    def throughput(self) -> float:
        """Calculate bytes per second"""
        duration_seconds = self.duration().total_seconds()
        if duration_seconds > 0:
            return (self.bytes_sent + self.bytes_received) / duration_seconds
        return 0.0
    
    def is_suspicious(self) -> bool:
        """Advanced suspicious activity detection"""
        # High throughput
        if self.throughput() > 10_000_000:  # 10MB/s
            return True
        # Unusual ports
        suspicious_ports = {4444, 5555, 6666, 31337, 1337, 8080, 9999}
        if self.dst_port in suspicious_ports:
            return True
        # Long duration connections
        if self.duration().total_seconds() > 3600:  # 1 hour
            return True
        # High packet count with small payload
        if self.packet_count > 1000 and (self.bytes_sent + self.bytes_received) < 10000:
            return True
        return False

class AdvancedNetworkForensics:
    """Comprehensive network forensics analysis platform"""
    
    def __init__(self):
        self.flows = []
        self.dns_queries = []
        self.http_sessions = []
        self.suspicious_activities = []
        self.malware_indicators = []
        self.siem_correlations = []
        
        print("🌐 Advanced Network Forensics Platform initialized")
        print("   Capabilities: Packet analysis, Flow reconstruction, SIEM integration")
    
    def analyze_pcap_advanced(self, pcap_file: str) -> Dict:
        """
        Comprehensive PCAP analysis with advanced techniques
        
        Args:
            pcap_file: Path to PCAP file or simulated data
            
        Returns:
            Dict: Complete network analysis results
        """
        print(f"📊 Performing advanced PCAP analysis...")
        
        # For demonstration, we'll create realistic simulated data
        analysis_results = {
            'flow_analysis': self._analyze_network_flows(),
            'protocol_distribution': self._analyze_protocol_distribution(),
            'communication_patterns': self._analyze_communication_patterns(),
            'anomaly_detection': self._detect_network_anomalies(),
            'threat_indicators': self._extract_threat_indicators(),
            'geolocation_analysis': self._perform_geolocation_analysis(),
            'timeline_reconstruction': self._reconstruct_network_timeline()
        }
        
        print(f"   ✅ Analysis complete:")
        print(f"      Network flows: {len(analysis_results['flow_analysis'])}")
        print(f"      Anomalies detected: {len(analysis_results['anomaly_detection'])}")
        print(f"      Threat indicators: {len(analysis_results['threat_indicators'])}")
        
        return analysis_results
    
    def correlate_with_siem(self, siem_events: List[Dict]) -> List[Dict]:
        """
        Correlate network traffic with SIEM events from Week 7
        
        Args:
            siem_events: SIEM security events
            
        Returns:
            List of correlated incidents
        """
        print("🔗 Correlating network traffic with SIEM events...")
        
        correlations = []
        
        # Simulate SIEM events from Week 7 security infrastructure
        if not siem_events:
            siem_events = self._create_sample_siem_events()
        
        # Time-based correlation
        for siem_event in siem_events:
            siem_time = datetime.fromisoformat(siem_event['timestamp'])
            
            # Find network flows within 5 minutes of SIEM event
            for flow in self.flows:
                if abs((flow.start_time - siem_time).total_seconds()) < 300:  # 5 minutes
                    correlation = {
                        'correlation_id': hashlib.md5(f"{siem_event['event_id']}{flow.src_ip}{flow.dst_ip}".encode()).hexdigest()[:8],
                        'siem_event': siem_event,
                        'network_flow': flow,
                        'correlation_type': 'TEMPORAL',
                        'confidence_score': self._calculate_correlation_confidence(siem_event, flow),
                        'potential_attack_vector': self._identify_attack_vector(siem_event, flow)
                    }
                    correlations.append(correlation)
        
        # IP-based correlation
        for siem_event in siem_events:
            if 'source_ip' in siem_event:
                for flow in self.flows:
                    if flow.src_ip == siem_event['source_ip'] or flow.dst_ip == siem_event['source_ip']:
                        correlation = {
                            'correlation_id': hashlib.md5(f"{siem_event['event_id']}{flow.src_ip}".encode()).hexdigest()[:8],
                            'siem_event': siem_event,
                            'network_flow': flow,
                            'correlation_type': 'IP_BASED',
                            'confidence_score': 0.8,
                            'potential_attack_vector': 'IP_ACTIVITY_CORRELATION'
                        }
                        correlations.append(correlation)
        
        print(f"   Found {len(correlations)} network-SIEM correlations")
        return correlations
    
    def reconstruct_attack_timeline(self, correlations: List[Dict]) -> Dict:
        """
        Reconstruct complete attack timeline from network and SIEM data
        
        Args:
            correlations: Network-SIEM correlations
            
        Returns:
            Dict: Timeline reconstruction
        """
        print("📅 Reconstructing comprehensive attack timeline...")
        
        timeline_events = []
        
        # Extract all events from correlations
        for corr in correlations:
            # Add SIEM event
            timeline_events.append({
                'timestamp': datetime.fromisoformat(corr['siem_event']['timestamp']),
                'event_type': 'SIEM',
                'source': 'Security Infrastructure',
                'description': corr['siem_event']['description'],
                'severity': corr['siem_event'].get('severity', 'medium'),
                'source_ip': corr['siem_event'].get('source_ip', 'unknown'),
                'correlation_id': corr['correlation_id']
            })
            
            # Add network flow event
            timeline_events.append({
                'timestamp': corr['network_flow'].start_time,
                'event_type': 'NETWORK_FLOW',
                'source': 'Network Traffic',
                'description': f"Connection {corr['network_flow'].src_ip}:{corr['network_flow'].src_port} -> {corr['network_flow'].dst_ip}:{corr['network_flow'].dst_port}",
                'severity': 'high' if corr['network_flow'].is_suspicious() else 'low',
                'source_ip': corr['network_flow'].src_ip,
                'correlation_id': corr['correlation_id']
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        # Group events into attack phases
        attack_phases = self._identify_attack_phases(timeline_events)
        
        timeline = {
            'events': timeline_events,
            'attack_phases': attack_phases,
            'total_duration': self._calculate_attack_duration(timeline_events),
            'affected_systems': self._extract_affected_systems(timeline_events),
            'attack_vector_summary': self._summarize_attack_vectors(timeline_events)
        }
        
        print(f"   Timeline contains {len(timeline_events)} events across {len(attack_phases)} phases")
        return timeline
    
    def generate_network_topology(self, flows: List[NetworkFlow]) -> nx.Graph:
        """
        Generate network topology graph from traffic flows
        
        Args:
            flows: Network flows to analyze
            
        Returns:
            NetworkX graph of network topology
        """
        print("🗺️  Generating network topology visualization...")
        
        G = nx.Graph()
        
        for flow in flows:
            # Add nodes
            G.add_node(flow.src_ip, node_type='source', 
                      packets_sent=flow.packet_count, 
                      bytes_sent=flow.bytes_sent)
            G.add_node(flow.dst_ip, node_type='destination',
                      packets_received=flow.packet_count,
                      bytes_received=flow.bytes_received)
            
            # Add edge with flow information
            if G.has_edge(flow.src_ip, flow.dst_ip):
                # Update existing edge
                G[flow.src_ip][flow.dst_ip]['weight'] += flow.packet_count
                G[flow.src_ip][flow.dst_ip]['flows'].append(flow)
            else:
                # Create new edge
                G.add_edge(flow.src_ip, flow.dst_ip,
                          weight=flow.packet_count,
                          flows=[flow],
                          suspicious=flow.is_suspicious())
        
        # Calculate network centrality metrics
        centrality_metrics = {
            'betweenness': nx.betweenness_centrality(G),
            'closeness': nx.closeness_centrality(G),
            'degree': nx.degree_centrality(G),
            'eigenvector': nx.eigenvector_centrality(G, max_iter=1000)
        }
        
        # Identify key nodes (potential pivot points)
        key_nodes = self._identify_key_network_nodes(G, centrality_metrics)
        
        print(f"   Network topology: {G.number_of_nodes()} nodes, {G.number_of_edges()} connections")
        print(f"   Key nodes identified: {len(key_nodes)}")
        
        return G
    
    def _analyze_network_flows(self) -> List[Dict]:
        """Generate sample network flows for analysis"""
        # Create realistic network flows
        flows = [
            NetworkFlow(
                src_ip="192.168.1.100", dst_ip="203.0.113.1",
                src_port=54321, dst_port=80, protocol="HTTP",
                start_time=datetime(2024, 1, 15, 10, 30, 0),
                end_time=datetime(2024, 1, 15, 10, 35, 0),
                bytes_sent=2048, bytes_received=50000, packet_count=75,
                flags={"SYN", "ACK", "FIN"},
                payload_samples=["GET /index.html HTTP/1.1"]
            ),
            NetworkFlow(
                src_ip="192.168.1.100", dst_ip="203.0.113.2", 
                src_port=54322, dst_port=4444, protocol="TCP",
                start_time=datetime(2024, 1, 15, 10, 45, 0),
                end_time=datetime(2024, 1, 15, 12, 45, 0),
                bytes_sent=1000000, bytes_received=500000, packet_count=2000,
                flags={"SYN", "ACK", "PSH"},
                payload_samples=["binary_data_sample"]
            )
        ]
        
        self.flows = flows
        return [self._flow_to_dict(flow) for flow in flows]
    
    def _flow_to_dict(self, flow: NetworkFlow) -> Dict:
        """Convert NetworkFlow to dictionary"""
        return {
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol,
            'start_time': flow.start_time.isoformat(),
            'end_time': flow.end_time.isoformat() if flow.end_time else None,
            'bytes_sent': flow.bytes_sent,
            'bytes_received': flow.bytes_received,
            'packet_count': flow.packet_count,
            'duration_seconds': flow.duration().total_seconds(),
            'throughput_bps': flow.throughput(),
            'is_suspicious': flow.is_suspicious(),
            'flags': list(flow.flags),
            'payload_samples': flow.payload_samples[:5]  # First 5 samples
        }
    
    def _create_sample_siem_events(self) -> List[Dict]:
        """Create sample SIEM events correlating with Week 7 security infrastructure"""
        return [
            {
                'event_id': 'SIEM_001',
                'timestamp': '2024-01-15T10:30:15',
                'source': 'PKI_Certificate_Authority',
                'event_type': 'CERTIFICATE_VALIDATION_FAILURE',
                'description': 'Certificate validation failed for client',
                'source_ip': '192.168.1.100',
                'severity': 'high',
                'category': 'authentication'
            },
            {
                'event_id': 'SIEM_002',
                'timestamp': '2024-01-15T10:32:00',
                'source': 'MFA_System',
                'event_type': 'MFA_BYPASS_ATTEMPT',
                'description': 'Multiple failed MFA attempts detected',
                'source_ip': '192.168.1.100',
                'severity': 'critical',
                'category': 'authentication'
            },
            {
                'event_id': 'SIEM_003',
                'timestamp': '2024-01-15T10:44:30',
                'source': 'RBAC_System',
                'event_type': 'PRIVILEGE_ESCALATION',
                'description': 'Unauthorized access to admin resources',
                'source_ip': '192.168.1.100',
                'severity': 'critical',
                'category': 'authorization'
            },
            {
                'event_id': 'SIEM_004',
                'timestamp': '2024-01-15T10:46:00',
                'source': 'Network_IDS',
                'event_type': 'SUSPICIOUS_OUTBOUND_CONNECTION',
                'description': 'Outbound connection to known malicious IP',
                'source_ip': '192.168.1.100',
                'destination_ip': '203.0.113.2',
                'severity': 'critical',
                'category': 'network'
            }
        ]
    
    def _analyze_protocol_distribution(self) -> Dict:
        """Analyze protocol distribution in network traffic"""
        protocols = {}
        for flow in self.flows:
            protocols[flow.protocol] = protocols.get(flow.protocol, 0) + 1
        
        return {
            'distribution': protocols,
            'total_flows': len(self.flows),
            'unique_protocols': len(protocols)
        }
    
    def _detect_network_anomalies(self) -> List[Dict]:
        """Detect network anomalies and suspicious patterns"""
        anomalies = []
        
        for flow in self.flows:
            if flow.is_suspicious():
                anomaly = {
                    'flow_id': f"{flow.src_ip}_{flow.dst_ip}_{flow.start_time.timestamp()}",
                    'type': 'SUSPICIOUS_FLOW',
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'reasons': [],
                    'severity': 'high'
                }
                
                # Identify specific reasons
                if flow.throughput() > 10_000_000:
                    anomaly['reasons'].append('HIGH_THROUGHPUT')
                if flow.dst_port in {4444, 5555, 6666, 31337}:
                    anomaly['reasons'].append('SUSPICIOUS_PORT')
                if flow.duration().total_seconds() > 3600:
                    anomaly['reasons'].append('LONG_DURATION')
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _extract_threat_indicators(self) -> List[Dict]:
        """Extract indicators of compromise (IOCs)"""
        indicators = []
        
        for flow in self.flows:
            # Check for known malicious IPs (simulated)
            malicious_ips = {'203.0.113.2', '198.51.100.5', '192.0.2.100'}
            if flow.dst_ip in malicious_ips:
                indicators.append({
                    'type': 'IP',
                    'value': flow.dst_ip,
                    'description': 'Communication with known malicious IP',
                    'confidence': 0.9,
                    'first_seen': flow.start_time.isoformat()
                })
            
            # Check for suspicious ports
            if flow.dst_port in {4444, 5555, 6666}:
                indicators.append({
                    'type': 'PORT',
                    'value': flow.dst_port,
                    'description': 'Communication on suspicious port',
                    'confidence': 0.7,
                    'context': f"Connection to {flow.dst_ip}:{flow.dst_port}"
                })
        
        return indicators
    
    def _calculate_correlation_confidence(self, siem_event: Dict, flow: NetworkFlow) -> float:
        """Calculate confidence score for SIEM-network correlation"""
        confidence = 0.0
        
        # Temporal proximity (closer in time = higher confidence)
        siem_time = datetime.fromisoformat(siem_event['timestamp'])
        time_diff = abs((flow.start_time - siem_time).total_seconds())
        if time_diff < 60:  # Within 1 minute
            confidence += 0.4
        elif time_diff < 300:  # Within 5 minutes  
            confidence += 0.2
        
        # IP address match
        if siem_event.get('source_ip') == flow.src_ip:
            confidence += 0.3
        
        # Event type correlation
        if siem_event.get('category') == 'network' and flow.is_suspicious():
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    def _identify_attack_vector(self, siem_event: Dict, flow: NetworkFlow) -> str:
        """Identify potential attack vector from correlated events"""
        if 'MFA_BYPASS' in siem_event.get('event_type', ''):
            return 'CREDENTIAL_COMPROMISE'
        elif 'PRIVILEGE_ESCALATION' in siem_event.get('event_type', ''):
            return 'LATERAL_MOVEMENT'
        elif flow.dst_port in {4444, 5555, 6666}:
            return 'COMMAND_AND_CONTROL'
        elif flow.bytes_sent > 1000000:
            return 'DATA_EXFILTRATION'
        else:
            return 'UNKNOWN'

def demo_advanced_network_forensics():
    """Comprehensive demonstration of advanced network forensics"""
    print("🌐 Advanced Network Forensics & SIEM Integration Demo")
    print("="*60)
    print("Module 1: Building comprehensive network investigation capabilities")
    
    # Initialize advanced forensics platform
    nf = AdvancedNetworkForensics()
    
    # Demo 1: Advanced PCAP Analysis
    print(f"\n📋 Demo 1: Advanced Network Traffic Analysis")
    analysis = nf.analyze_pcap_advanced("sample_capture.pcap")
    
    print(f"   Protocol Distribution:")
    for protocol, count in analysis['protocol_distribution']['distribution'].items():
        percentage = (count / analysis['protocol_distribution']['total_flows']) * 100
        print(f"     {protocol}: {count} flows ({percentage:.1f}%)")
    
    # Demo 2: SIEM Correlation
    print(f"\n📋 Demo 2: Network-SIEM Event Correlation")
    siem_events = []  # Will use sample events
    correlations = nf.correlate_with_siem(siem_events)
    
    print(f"   Found {len(correlations)} correlations:")
    for i, corr in enumerate(correlations[:3]):  # Show first 3
        print(f"     Correlation {i+1}:")
        print(f"       Type: {corr['correlation_type']}")
        print(f"       Confidence: {corr['confidence_score']:.2f}")
        print(f"       Attack Vector: {corr['potential_attack_vector']}")
    
    # Demo 3: Attack Timeline Reconstruction
    print(f"\n📋 Demo 3: Comprehensive Attack Timeline")
    timeline = nf.reconstruct_attack_timeline(correlations)
    
    print(f"   Timeline Summary:")
    print(f"     Total Events: {len(timeline['events'])}")
    print(f"     Attack Phases: {len(timeline['attack_phases'])}")
    print(f"     Duration: {timeline['total_duration']}")
    print(f"     Affected Systems: {', '.join(timeline['affected_systems'])}")
    
    # Demo 4: Network Topology Analysis
    print(f"\n📋 Demo 4: Network Topology Visualization")
    topology = nf.generate_network_topology(nf.flows)
    
    print(f"   Network Structure:")
    print(f"     Nodes: {topology.number_of_nodes()}")
    print(f"     Connections: {topology.number_of_edges()}")
    print(f"     Average Degree: {sum(dict(topology.degree()).values()) / topology.number_of_nodes():.2f}")
    
    print(f"\n✅ Module 1 Complete: Advanced Network Forensics")
    print(f"   Next: Module 2 - Database Forensics & Transaction Analysis")

if __name__ == "__main__":
    demo_advanced_network_forensics()
```

### Module 1 Self-Check Questions
Before proceeding, ensure you understand:
- How to correlate network traffic with SIEM events from Week 7?
- What network patterns indicate command and control communication?
- How can network topology analysis reveal pivot points in an attack?

**Ready for Module 2? ✅ Check the box above when ready.**

---

## 📘 Module 2: Database Forensics & Application Analysis (60 minutes)

**Learning Objective**: Master database transaction forensics and web application investigation

**What you'll build**: Comprehensive database and application forensics platform

### Step 2: Advanced Database Transaction Analysis

Create `database_application_forensics.py`:

```python
import sqlite3
import json
import re
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import os
from pathlib import Path

class DatabaseTransactionAnalyzer:
    """Advanced database forensics with transaction log analysis"""
    
    def __init__(self):
        self.transaction_logs = []
        self.deleted_records = []
        self.schema_changes = []
        self.user_activities = []
        
        print("🗃️  Database Transaction Analyzer initialized")
        print("   Capabilities: Transaction logs, deleted records, schema analysis")
    
    def analyze_transaction_logs(self, log_file: str) -> Dict:
        """
        Comprehensive transaction log analysis for forensic investigation
        
        Args:
            log_file: Database transaction log file
            
        Returns:
            Dict: Complete transaction analysis
        """
        print(f"📊 Analyzing database transaction logs...")
        
        # For demonstration, create comprehensive transaction analysis
        analysis = {
            'transaction_summary': self._analyze_transaction_patterns(),
            'user_activity_timeline': self._reconstruct_user_activities(),
            'data_modification_analysis': self._analyze_data_modifications(),
            'suspicious_transactions': self._detect_suspicious_transactions(),
            'rollback_analysis': self._analyze_rollback_patterns(),
            'privilege_escalation_attempts': self._detect_privilege_escalations()
        }
        
        print(f"   ✅ Transaction analysis complete:")
        print(f"      Total transactions: {analysis['transaction_summary']['total_transactions']}")
        print(f"      Suspicious activities: {len(analysis['suspicious_transactions'])}")
        print(f"      Rollback events: {len(analysis['rollback_analysis'])}")
        
        return analysis
    
    def recover_deleted_records(self, database_path: str, table_name: str) -> List[Dict]:
        """
        Advanced deleted record recovery from database pages
        
        Args:
            database_path: Path to database file
            table_name: Target table for recovery
            
        Returns:
            List of recovered records with metadata
        """
        print(f"🔍 Recovering deleted records from table: {table_name}")
        
        recovered_records = []
        
        try:
            # Connect to database for schema analysis
            conn = sqlite3.connect(database_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name})")
            schema = cursor.fetchall()
            
            # Simulate advanced page-level recovery
            for record_id in range(1, 6):  # Simulate 5 recovered records
                recovered_record = {
                    'recovery_metadata': {
                        'record_id': f'recovered_{record_id}',
                        'table': table_name,
                        'recovery_confidence': 0.8 + (record_id * 0.02),  # Varying confidence
                        'page_offset': f'0x{1024 * record_id:08X}',
                        'recovery_timestamp': datetime.now().isoformat(),
                        'partial_recovery': record_id > 3  # Last records partially damaged
                    },
                    'record_data': self._simulate_recovered_data(schema, record_id),
                    'forensic_markers': {
                        'deletion_timestamp': (datetime.now() - timedelta(days=record_id)).isoformat(),
                        'last_modification': (datetime.now() - timedelta(days=record_id+1)).isoformat(),
                        'deletion_method': 'LOGICAL_DELETE' if record_id <= 3 else 'PHYSICAL_DELETE'
                    }
                }
                recovered_records.append(recovered_record)
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Recovery error: {e}")
            return []
        
        print(f"   ✅ Recovered {len(recovered_records)} deleted records")
        for record in recovered_records[:3]:  # Show first 3
            confidence = record['recovery_metadata']['recovery_confidence']
            print(f"      Record {record['recovery_metadata']['record_id']}: {confidence:.2f} confidence")
        
        return recovered_records
    
    def analyze_web_application_logs(self, log_files: List[str]) -> Dict:
        """
        Comprehensive web application log analysis
        
        Args:
            log_files: List of web server log files
            
        Returns:
            Dict: Web application forensic analysis
        """
        print("🌐 Analyzing web application logs for forensic evidence...")
        
        # Create comprehensive web application analysis
        analysis = {
            'attack_patterns': self._detect_web_attacks(),
            'user_sessions': self._reconstruct_user_sessions(),
            'file_access_patterns': self._analyze_file_access(),
            'injection_attempts': self._detect_injection_attacks(),
            'authentication_events': self._analyze_auth_events(),
            'suspicious_uploads': self._detect_malicious_uploads(),
            'data_exfiltration': self._detect_data_exfiltration()
        }
        
        print(f"   ✅ Web application analysis complete:")
        print(f"      Attack patterns: {len(analysis['attack_patterns'])}")
        print(f"      User sessions: {len(analysis['user_sessions'])}")  
        print(f"      Injection attempts: {len(analysis['injection_attempts'])}")
        
        return analysis
    
    def correlate_database_web_activity(self, db_analysis: Dict, web_analysis: Dict) -> List[Dict]:
        """
        Correlate database transactions with web application activity
        
        Args:
            db_analysis: Database forensic analysis
            web_analysis: Web application analysis
            
        Returns:
            List of correlated activities
        """
        print("🔗 Correlating database and web application activities...")
        
        correlations = []
        
        # Time-based correlation
        db_transactions = db_analysis.get('user_activity_timeline', [])
        web_sessions = web_analysis.get('user_sessions', [])
        
        for db_activity in db_transactions:
            db_time = datetime.fromisoformat(db_activity['timestamp'])
            
            for web_session in web_sessions:
                web_time = datetime.fromisoformat(web_session['start_time'])
                
                # Check if activities are within 1 minute
                if abs((db_time - web_time).total_seconds()) < 60:
                    correlation = {
                        'correlation_id': hashlib.md5(f"{db_activity['transaction_id']}{web_session['session_id']}".encode()).hexdigest()[:8],
                        'database_activity': db_activity,
                        'web_activity': web_session,
                        'correlation_type': 'TEMPORAL',
                        'confidence_score': self._calculate_db_web_confidence(db_activity, web_session),
                        'potential_attack': self._identify_combined_attack_pattern(db_activity, web_session)
                    }
                    correlations.append(correlation)
        
        # User-based correlation  
        for db_activity in db_transactions:
            if 'user' in db_activity:
                for web_session in web_sessions:
                    if web_session.get('username') == db_activity['user']:
                        correlation = {
                            'correlation_id': hashlib.md5(f"{db_activity['user']}{web_session['session_id']}".encode()).hexdigest()[:8],
                            'database_activity': db_activity,
                            'web_activity': web_session,
                            'correlation_type': 'USER_BASED',
                            'confidence_score': 0.9,  # High confidence for user match
                            'potential_attack': 'USER_ACTIVITY_CORRELATION'
                        }
                        correlations.append(correlation)
        
        print(f"   Found {len(correlations)} database-web correlations")
        return correlations
    
    def _analyze_transaction_patterns(self) -> Dict:
        """Analyze database transaction patterns for anomalies"""
        return {
            'total_transactions': 1247,
            'transaction_types': {
                'INSERT': 421,
                'UPDATE': 298, 
                'DELETE': 157,
                'SELECT': 371
            },
            'peak_activity_hours': [10, 14, 16],
            'unusual_patterns': [
                {
                    'type': 'BULK_DELETE_OPERATION',
                    'timestamp': '2024-01-15T11:45:00',
                    'records_affected': 523,
                    'user': 'system_admin',
                    'description': 'Mass deletion of audit records'
                },
                {
                    'type': 'AFTER_HOURS_ACTIVITY',
                    'timestamp': '2024-01-15T23:30:00',
                    'duration': '2 hours 15 minutes',
                    'user': 'maintenance_user',
                    'description': 'Extensive database modifications outside business hours'
                }
            ]
        }
    
    def _detect_suspicious_transactions(self) -> List[Dict]:
        """Detect suspicious database transactions"""
        return [
            {
                'transaction_id': 'TXN_001',
                'timestamp': '2024-01-15T11:45:30',
                'user': 'system_admin',
                'operation': 'DELETE',
                'table': 'audit_logs',
                'records_affected': 523,
                'suspicion_reasons': ['BULK_AUDIT_DELETION', 'PRIVILEGED_USER'],
                'severity': 'critical'
            },
            {
                'transaction_id': 'TXN_002', 
                'timestamp': '2024-01-15T12:15:00',
                'user': 'web_service',
                'operation': 'UPDATE',
                'table': 'user_permissions',
                'records_affected': 1,
                'suspicion_reasons': ['PRIVILEGE_ESCALATION', 'UNAUTHORIZED_MODIFICATION'],
                'severity': 'high'
            }
        ]
    
    def _detect_web_attacks(self) -> List[Dict]:
        """Detect web application attack patterns"""
        return [
            {
                'attack_type': 'SQL_INJECTION',
                'timestamp': '2024-01-15T12:14:45',
                'source_ip': '192.168.1.100',
                'target_url': '/login.php',
                'payload': "' OR '1'='1' --",
                'user_agent': 'Mozilla/5.0 (malicious scanner)',
                'status_code': 200,
                'severity': 'critical'
            },
            {
                'attack_type': 'XSS_ATTEMPT',
                'timestamp': '2024-01-15T12:16:00',
                'source_ip': '192.168.1.100',
                'target_url': '/search.php',
                'payload': '<script>alert("XSS")</script>',
                'user_agent': 'Mozilla/5.0 (malicious scanner)',
                'status_code': 403,
                'severity': 'high'
            }
        ]
    
    def _reconstruct_user_sessions(self) -> List[Dict]:
        """Reconstruct user web sessions"""
        return [
            {
                'session_id': 'SESS_001',
                'username': 'admin_user',
                'start_time': '2024-01-15T12:10:00',
                'end_time': '2024-01-15T12:45:00', 
                'source_ip': '192.168.1.100',
                'pages_accessed': ['/admin/dashboard', '/admin/users', '/admin/logs'],
                'actions_performed': ['VIEW_USERS', 'MODIFY_PERMISSIONS', 'DELETE_LOGS'],
                'suspicious_activity': True,
                'risk_score': 0.9
            }
        ]

def demo_database_application_forensics():
    """Comprehensive database and web application forensics demonstration"""
    print("🗃️  Database & Web Application Forensics Demo")
    print("="*60)
    print("Module 2: Advanced database transaction and web application analysis")
    
    # Initialize database analyzer
    db_analyzer = DatabaseTransactionAnalyzer()
    
    # Demo 1: Transaction Log Analysis
    print(f"\n📋 Demo 1: Database Transaction Analysis")
    tx_analysis = db_analyzer.analyze_transaction_logs("app_transactions.log")
    
    print(f"   Transaction Summary:")
    for tx_type, count in tx_analysis['transaction_summary']['transaction_types'].items():
        print(f"     {tx_type}: {count} operations")
    
    print(f"   Suspicious Transactions:")
    for tx in tx_analysis['suspicious_transactions']:
        print(f"     {tx['transaction_id']}: {tx['operation']} on {tx['table']} ({tx['severity']})")
    
    # Demo 2: Deleted Record Recovery
    print(f"\n📋 Demo 2: Deleted Record Recovery")
    
    # Create sample database for recovery demonstration
    sample_db = "forensics_sample.db"
    conn = sqlite3.connect(sample_db)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE user_actions (
            id INTEGER PRIMARY KEY,
            username TEXT,
            action TEXT,
            timestamp DATETIME,
            ip_address TEXT
        )
    ''')
    
    cursor.execute("INSERT INTO user_actions VALUES (1, 'admin', 'LOGIN', '2024-01-15 10:00:00', '192.168.1.100')")
    cursor.execute("INSERT INTO user_actions VALUES (2, 'admin', 'DELETE_LOGS', '2024-01-15 11:45:00', '192.168.1.100')")
    conn.commit()
    
    # Simulate record deletion
    cursor.execute("DELETE FROM user_actions WHERE id = 2")
    conn.commit()
    conn.close()
    
    # Perform recovery
    recovered = db_analyzer.recover_deleted_records(sample_db, "user_actions")
    
    print(f"   Recovery Results:")
    for record in recovered[:2]:  # Show first 2
        meta = record['recovery_metadata']
        print(f"     Record {meta['record_id']}: {meta['recovery_confidence']:.2f} confidence")
        print(f"       Deletion method: {record['forensic_markers']['deletion_method']}")
    
    # Demo 3: Web Application Log Analysis
    print(f"\n📋 Demo 3: Web Application Attack Detection")
    web_analysis = db_analyzer.analyze_web_application_logs([])
    
    print(f"   Attack Patterns Detected:")
    for attack in web_analysis['attack_patterns']:
        print(f"     {attack['attack_type']}: {attack['source_ip']} -> {attack['target_url']}")
        print(f"       Severity: {attack['severity']}")
    
    # Demo 4: Database-Web Correlation
    print(f"\n📋 Demo 4: Database-Web Activity Correlation") 
    correlations = db_analyzer.correlate_database_web_activity(tx_analysis, web_analysis)
    
    print(f"   Correlations Found: {len(correlations)}")
    for corr in correlations[:2]:  # Show first 2
        print(f"     Correlation {corr['correlation_id']}:")
        print(f"       Type: {corr['correlation_type']}")
        print(f"       Confidence: {corr['confidence_score']:.2f}")
        print(f"       Potential Attack: {corr['potential_attack']}")
    
    print(f"\n✅ Module 2 Complete: Database & Web Application Forensics")
    print(f"   Next: Module 3 - Cross-Source Evidence Correlation")
    
    # Cleanup
    os.remove(sample_db)

if __name__ == "__main__":
    demo_database_application_forensics()
```

### Module 2 Self-Check Questions
Verify your understanding:
- How can transaction logs reveal evidence tampering attempts?
- What database artifacts persist after record deletion?
- How do you correlate web application attacks with database modifications?

**Ready for Module 3? ✅ Check the box above when ready.**

---

## 📘 Module 3: Cross-Source Evidence Correlation (60 minutes)

**Learning Objective**: Master advanced multi-source evidence correlation and timeline integration

**What you'll build**: Comprehensive evidence correlation engine

### Step 3: Advanced Evidence Correlation Platform

Create `evidence_correlation_engine.py`:

```python
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import hashlib
import numpy as np
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt

@dataclass
class EvidenceItem:
    """Standardized evidence item for cross-source correlation"""
    evidence_id: str
    source_system: str
    timestamp: datetime
    event_type: str
    details: Dict
    confidence_score: float = 1.0
    tags: Set[str] = field(default_factory=set)
    related_entities: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict:
        return {
            'evidence_id': self.evidence_id,
            'source_system': self.source_system,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'details': self.details,
            'confidence_score': self.confidence_score,
            'tags': list(self.tags),
            'related_entities': list(self.related_entities)
        }

@dataclass 
class CorrelationCluster:
    """Group of correlated evidence items"""
    cluster_id: str
    evidence_items: List[EvidenceItem]
    correlation_strength: float
    time_span: timedelta
    primary_entities: Set[str]
    attack_phase: Optional[str] = None
    confidence_level: str = "medium"
    
    def get_timeline(self) -> List[EvidenceItem]:
        return sorted(self.evidence_items, key=lambda x: x.timestamp)

class AdvancedCorrelationEngine:
    """Advanced multi-source evidence correlation platform"""
    
    def __init__(self):
        self.evidence_repository = []
        self.correlation_clusters = []
        self.entity_relationship_graph = nx.Graph()
        self.temporal_patterns = {}
        self.correlation_rules = self._initialize_correlation_rules()
        
        print("🔗 Advanced Evidence Correlation Engine initialized")
        print("   Capabilities: Multi-source correlation, temporal analysis, entity relationships")
    
    def ingest_evidence(self, evidence_sources: Dict[str, List[Dict]]) -> int:
        """
        Ingest evidence from multiple sources and standardize format
        
        Args:
            evidence_sources: Dictionary of source_name -> evidence_items
            
        Returns:
            int: Number of evidence items ingested
        """
        print("📥 Ingesting evidence from multiple sources...")
        
        total_ingested = 0
        
        for source_name, evidence_list in evidence_sources.items():
            print(f"   Processing {source_name}: {len(evidence_list)} items")
            
            for evidence_data in evidence_list:
                evidence_item = self._standardize_evidence(source_name, evidence_data)
                if evidence_item:
                    self.evidence_repository.append(evidence_item)
                    total_ingested += 1
        
        print(f"   ✅ Ingested {total_ingested} evidence items from {len(evidence_sources)} sources")
        return total_ingested
    
    def perform_correlation_analysis(self, time_window_minutes: int = 30) -> List[CorrelationCluster]:
        """
        Perform comprehensive cross-source evidence correlation
        
        Args:
            time_window_minutes: Time window for temporal correlation
            
        Returns:
            List of correlation clusters
        """
        print(f"🔍 Performing correlation analysis with {time_window_minutes}-minute windows...")
        
        # Step 1: Temporal correlation
        temporal_clusters = self._perform_temporal_correlation(time_window_minutes)
        
        # Step 2: Entity-based correlation
        entity_clusters = self._perform_entity_correlation()
        
        # Step 3: Behavioral pattern correlation
        behavioral_clusters = self._perform_behavioral_correlation()
        
        # Step 4: Merge and rank clusters
        all_clusters = temporal_clusters + entity_clusters + behavioral_clusters
        merged_clusters = self._merge_overlapping_clusters(all_clusters)
        
        # Step 5: Score and classify clusters
        classified_clusters = self._classify_correlation_clusters(merged_clusters)
        
        self.correlation_clusters = classified_clusters
        
        print(f"   ✅ Correlation analysis complete:")
        print(f"      Temporal clusters: {len(temporal_clusters)}")
        print(f"      Entity clusters: {len(entity_clusters)}")
        print(f"      Behavioral clusters: {len(behavioral_clusters)}")
        print(f"      Final merged clusters: {len(classified_clusters)}")
        
        return classified_clusters
    
    def reconstruct_attack_timeline(self, cluster: CorrelationCluster) -> Dict:
        """
        Reconstruct detailed attack timeline from correlation cluster
        
        Args:
            cluster: Correlation cluster to analyze
            
        Returns:
            Dict: Detailed timeline reconstruction
        """
        print(f"📅 Reconstructing attack timeline for cluster {cluster.cluster_id}...")
        
        timeline_events = cluster.get_timeline()
        
        # Identify attack phases
        phases = self._identify_attack_phases(timeline_events)
        
        # Calculate progression metrics
        attack_metrics = self._calculate_attack_metrics(timeline_events)
        
        # Identify key pivot points
        pivot_points = self._identify_pivot_points(timeline_events)
        
        # Generate impact assessment
        impact_assessment = self._assess_attack_impact(timeline_events)
        
        timeline_reconstruction = {
            'cluster_id': cluster.cluster_id,
            'total_events': len(timeline_events),
            'time_span': cluster.time_span.total_seconds(),
            'attack_phases': phases,
            'timeline_events': [event.to_dict() for event in timeline_events],
            'attack_metrics': attack_metrics,
            'pivot_points': pivot_points,
            'impact_assessment': impact_assessment,
            'confidence_level': cluster.confidence_level,
            'primary_targets': list(cluster.primary_entities)
        }
        
        print(f"   ✅ Timeline reconstruction complete:")
        print(f"      Events: {len(timeline_events)}")
        print(f"      Attack phases: {len(phases)}")
        print(f"      Pivot points: {len(pivot_points)}")
        
        return timeline_reconstruction
    
    def generate_entity_relationship_map(self) -> nx.Graph:
        """
        Generate comprehensive entity relationship map from all evidence
        
        Returns:
            NetworkX graph of entity relationships
        """
        print("🗺️  Generating entity relationship map...")
        
        # Clear existing graph
        self.entity_relationship_graph.clear()
        
        # Add nodes and edges from evidence
        for evidence in self.evidence_repository:
            # Add evidence as a node
            self.entity_relationship_graph.add_node(
                evidence.evidence_id,
                type='evidence',
                source=evidence.source_system,
                timestamp=evidence.timestamp,
                event_type=evidence.event_type
            )
            
            # Add related entities
            for entity in evidence.related_entities:
                if not self.entity_relationship_graph.has_node(entity):
                    self.entity_relationship_graph.add_node(
                        entity,
                        type='entity',
                        first_seen=evidence.timestamp
                    )
                
                # Connect evidence to entities
                self.entity_relationship_graph.add_edge(
                    evidence.evidence_id,
                    entity,
                    relationship_type='involves',
                    timestamp=evidence.timestamp
                )
        
        # Calculate centrality metrics
        centrality_metrics = {
            'betweenness': nx.betweenness_centrality(self.entity_relationship_graph),
            'closeness': nx.closeness_centrality(self.entity_relationship_graph),
            'degree': nx.degree_centrality(self.entity_relationship_graph)
        }
        
        # Identify key entities
        key_entities = self._identify_key_entities(centrality_metrics)
        
        print(f"   ✅ Entity relationship map generated:")
        print(f"      Nodes: {self.entity_relationship_graph.number_of_nodes()}")
        print(f"      Connections: {self.entity_relationship_graph.number_of_edges()}")
        print(f"      Key entities: {len(key_entities)}")
        
        return self.entity_relationship_graph
    
    def detect_evidence_gaps(self, timeline: List[EvidenceItem]) -> List[Dict]:
        """
        Detect gaps in evidence timeline that may indicate tampering
        
        Args:
            timeline: Sorted list of evidence items
            
        Returns:
            List of detected gaps
        """
        print("🕳️  Detecting evidence gaps and anomalies...")
        
        gaps = []
        
        for i in range(len(timeline) - 1):
            current_time = timeline[i].timestamp
            next_time = timeline[i + 1].timestamp
            gap_duration = next_time - current_time
            
            # Detect unusual gaps (>30 minutes during active period)
            if gap_duration.total_seconds() > 1800:  # 30 minutes
                # Check if this is during an active attack period
                activity_context = self._analyze_gap_context(timeline, i)
                
                if activity_context['is_suspicious']:
                    gap = {
                        'gap_id': f"GAP_{i}_{i+1}",
                        'start_time': current_time.isoformat(),
                        'end_time': next_time.isoformat(),
                        'duration_seconds': gap_duration.total_seconds(),
                        'context': activity_context,
                        'suspicion_level': 'high' if gap_duration.total_seconds() > 3600 else 'medium',
                        'potential_causes': [
                            'Log rotation',
                            'Evidence tampering', 
                            'System shutdown',
                            'Selective deletion'
                        ]
                    }
                    gaps.append(gap)
        
        print(f"   Found {len(gaps)} suspicious evidence gaps")
        return gaps
    
    def calculate_correlation_confidence(self, evidence_items: List[EvidenceItem]) -> float:
        """Calculate overall confidence score for evidence correlation"""
        if not evidence_items:
            return 0.0
        
        # Base confidence on individual evidence confidence
        base_confidence = np.mean([item.confidence_score for item in evidence_items])
        
        # Bonus for multiple sources
        unique_sources = len(set(item.source_system for item in evidence_items))
        source_bonus = min(0.2, unique_sources * 0.05)
        
        # Bonus for temporal clustering
        time_span = max(item.timestamp for item in evidence_items) - min(item.timestamp for item in evidence_items)
        temporal_bonus = 0.1 if time_span.total_seconds() < 1800 else 0.0  # 30 minutes
        
        # Penalty for large time gaps
        time_penalty = max(0.0, (time_span.total_seconds() - 3600) / 10800 * 0.2)  # Penalty after 1 hour
        
        total_confidence = base_confidence + source_bonus + temporal_bonus - time_penalty
        return max(0.0, min(1.0, total_confidence))
    
    def _standardize_evidence(self, source_name: str, evidence_data: Dict) -> Optional[EvidenceItem]:
        """Convert source-specific evidence to standardized format"""
        try:
            # Generate unique evidence ID
            evidence_id = hashlib.md5(
                f"{source_name}_{evidence_data.get('timestamp', '')}_{str(evidence_data)[:100]}".encode()
            ).hexdigest()[:12]
            
            # Parse timestamp
            timestamp_str = evidence_data.get('timestamp', evidence_data.get('time', ''))
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.now()
            
            # Extract related entities based on source type
            related_entities = set()
            
            # Network evidence
            if 'src_ip' in evidence_data:
                related_entities.add(evidence_data['src_ip'])
            if 'dst_ip' in evidence_data:
                related_entities.add(evidence_data['dst_ip'])
            if 'source_ip' in evidence_data:
                related_entities.add(evidence_data['source_ip'])
            
            # User-related evidence
            if 'username' in evidence_data:
                related_entities.add(evidence_data['username'])
            if 'user' in evidence_data:
                related_entities.add(evidence_data['user'])
            
            # System-related evidence
            if 'hostname' in evidence_data:
                related_entities.add(evidence_data['hostname'])
            if 'system' in evidence_data:
                related_entities.add(evidence_data['system'])
            
            # Determine event type
            event_type = evidence_data.get('event_type', evidence_data.get('type', 'UNKNOWN'))
            
            return EvidenceItem(
                evidence_id=evidence_id,
                source_system=source_name,
                timestamp=timestamp,
                event_type=event_type,
                details=evidence_data,
                confidence_score=evidence_data.get('confidence', 1.0),
                related_entities=related_entities
            )
            
        except Exception as e:
            print(f"   ⚠️  Failed to standardize evidence: {e}")
            return None
    
    def _perform_temporal_correlation(self, window_minutes: int) -> List[CorrelationCluster]:
        """Perform temporal correlation analysis"""
        clusters = []
        
        # Sort evidence by timestamp
        sorted_evidence = sorted(self.evidence_repository, key=lambda x: x.timestamp)
        
        i = 0
        while i < len(sorted_evidence):
            cluster_evidence = [sorted_evidence[i]]
            window_start = sorted_evidence[i].timestamp
            window_end = window_start + timedelta(minutes=window_minutes)
            
            # Collect evidence within time window
            j = i + 1
            while j < len(sorted_evidence) and sorted_evidence[j].timestamp <= window_end:
                cluster_evidence.append(sorted_evidence[j])
                j += 1
            
            # Create cluster if multiple items found
            if len(cluster_evidence) > 1:
                cluster_id = f"TEMPORAL_{hashlib.md5(f'{window_start}_{len(cluster_evidence)}'.encode()).hexdigest()[:8]}"
                
                # Calculate cluster metrics
                time_span = cluster_evidence[-1].timestamp - cluster_evidence[0].timestamp
                all_entities = set()
                for evidence in cluster_evidence:
                    all_entities.update(evidence.related_entities)
                
                correlation_strength = self.calculate_correlation_confidence(cluster_evidence)
                
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    evidence_items=cluster_evidence,
                    correlation_strength=correlation_strength,
                    time_span=time_span,
                    primary_entities=all_entities
                )
                
                clusters.append(cluster)
            
            i = j if j > i + 1 else i + 1
        
        return clusters
    
    def _perform_entity_correlation(self) -> List[CorrelationCluster]:
        """Perform entity-based correlation analysis"""
        entity_groups = defaultdict(list)
        
        # Group evidence by shared entities
        for evidence in self.evidence_repository:
            for entity in evidence.related_entities:
                entity_groups[entity].append(evidence)
        
        clusters = []
        for entity, evidence_list in entity_groups.items():
            if len(evidence_list) > 1:  # Multiple evidence items for same entity
                cluster_id = f"ENTITY_{entity}_{hashlib.md5(entity.encode()).hexdigest()[:8]}"
                
                sorted_evidence = sorted(evidence_list, key=lambda x: x.timestamp)
                time_span = sorted_evidence[-1].timestamp - sorted_evidence[0].timestamp
                
                correlation_strength = self.calculate_correlation_confidence(evidence_list)
                
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    evidence_items=evidence_list,
                    correlation_strength=correlation_strength,
                    time_span=time_span,
                    primary_entities={entity}
                )
                
                clusters.append(cluster)
        
        return clusters
    
    def _identify_attack_phases(self, timeline_events: List[EvidenceItem]) -> List[Dict]:
        """Identify attack phases from timeline"""
        phases = []
        
        # Common attack phase patterns
        phase_patterns = {
            'RECONNAISSANCE': ['port_scan', 'dns_query', 'ping', 'reconnaissance'],
            'INITIAL_ACCESS': ['login_attempt', 'credential_compromise', 'exploit_attempt'],
            'EXECUTION': ['command_execution', 'process_creation', 'script_execution'],
            'PERSISTENCE': ['file_creation', 'registry_modification', 'scheduled_task'],
            'PRIVILEGE_ESCALATION': ['privilege_escalation', 'admin_access', 'token_manipulation'],
            'LATERAL_MOVEMENT': ['remote_connection', 'credential_reuse', 'service_execution'],
            'COLLECTION': ['file_access', 'data_collection', 'screen_capture'],
            'EXFILTRATION': ['data_transfer', 'network_upload', 'external_connection']
        }
        
        # Analyze events for phase indicators
        current_phase = None
        phase_start = None
        phase_events = []
        
        for event in timeline_events:
            event_type = event.event_type.lower()
            detected_phase = None
            
            # Determine phase based on event type
            for phase, patterns in phase_patterns.items():
                if any(pattern in event_type for pattern in patterns):
                    detected_phase = phase
                    break
            
            if detected_phase != current_phase:
                # Close previous phase
                if current_phase and phase_events:
                    phases.append({
                        'phase': current_phase,
                        'start_time': phase_start.isoformat(),
                        'end_time': phase_events[-1].timestamp.isoformat(),
                        'duration_seconds': (phase_events[-1].timestamp - phase_start).total_seconds(),
                        'event_count': len(phase_events),
                        'key_events': [e.event_type for e in phase_events[:3]]  # First 3 events
                    })
                
                # Start new phase
                current_phase = detected_phase
                phase_start = event.timestamp
                phase_events = [event]
            else:
                phase_events.append(event)
        
        # Close final phase
        if current_phase and phase_events:
            phases.append({
                'phase': current_phase,
                'start_time': phase_start.isoformat(),
                'end_time': phase_events[-1].timestamp.isoformat(),
                'duration_seconds': (phase_events[-1].timestamp - phase_start).total_seconds(),
                'event_count': len(phase_events),
                'key_events': [e.event_type for e in phase_events[:3]]
            })
        
        return phases

def create_comprehensive_evidence_dataset() -> Dict[str, List[Dict]]:
    """Create comprehensive multi-source evidence dataset for demonstration"""
    base_time = datetime(2024, 1, 15, 10, 30, 0)
    
    return {
        'Network_Traffic': [
            {
                'timestamp': (base_time + timedelta(minutes=0)).isoformat(),
                'event_type': 'port_scan',
                'src_ip': '192.168.1.100',
                'dst_ip': '203.0.113.1',
                'ports_scanned': [80, 443, 22, 3389],
                'confidence': 0.9
            },
            {
                'timestamp': (base_time + timedelta(minutes=5)).isoformat(),
                'event_type': 'credential_compromise',
                'src_ip': '192.168.1.100',
                'dst_ip': '203.0.113.1',
                'protocol': 'HTTP',
                'confidence': 0.8
            }
        ],
        'SIEM_Events': [
            {
                'timestamp': (base_time + timedelta(minutes=2)).isoformat(),
                'event_type': 'authentication_failure',
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'attempts': 5,
                'confidence': 0.95
            },
            {
                'timestamp': (base_time + timedelta(minutes=7)).isoformat(),
                'event_type': 'privilege_escalation',
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'target_resource': '/admin/users',
                'confidence': 0.9
            }
        ],
        'Database_Transactions': [
            {
                'timestamp': (base_time + timedelta(minutes=8)).isoformat(),
                'event_type': 'bulk_delete',
                'table': 'audit_logs',
                'user': 'admin',
                'records_affected': 523,
                'confidence': 1.0
            }
        ],
        'Web_Application': [
            {
                'timestamp': (base_time + timedelta(minutes=6)).isoformat(),
                'event_type': 'admin_login_success',
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'session_id': 'SESS_12345',
                'confidence': 0.9
            },
            {
                'timestamp': (base_time + timedelta(minutes=10)).isoformat(),
                'event_type': 'suspicious_file_upload',
                'source_ip': '192.168.1.100',
                'filename': 'backdoor.php',
                'user': 'admin',
                'confidence': 0.95
            }
        ]
    }

def demo_evidence_correlation():
    """Comprehensive evidence correlation demonstration"""
    print("🔗 Advanced Evidence Correlation Engine Demo")
    print("="*60)
    print("Module 3: Multi-source evidence correlation and timeline reconstruction")
    
    # Initialize correlation engine
    correlator = AdvancedCorrelationEngine()
    
    # Demo 1: Evidence Ingestion
    print(f"\n📋 Demo 1: Multi-Source Evidence Ingestion")
    evidence_sources = create_comprehensive_evidence_dataset()
    
    total_ingested = correlator.ingest_evidence(evidence_sources)
    print(f"   Total evidence items: {total_ingested}")
    
    # Demo 2: Correlation Analysis
    print(f"\n📋 Demo 2: Cross-Source Correlation Analysis")
    clusters = correlator.perform_correlation_analysis(time_window_minutes=15)
    
    print(f"   Correlation Results:")
    for cluster in clusters[:3]:  # Show first 3 clusters
        print(f"     Cluster {cluster.cluster_id}:")
        print(f"       Evidence items: {len(cluster.evidence_items)}")
        print(f"       Correlation strength: {cluster.correlation_strength:.2f}")
        print(f"       Primary entities: {', '.join(list(cluster.primary_entities)[:3])}")
    
    # Demo 3: Attack Timeline Reconstruction
    print(f"\n📋 Demo 3: Attack Timeline Reconstruction")
    if clusters:
        timeline = correlator.reconstruct_attack_timeline(clusters[0])
        
        print(f"   Timeline for cluster {timeline['cluster_id']}:")
        print(f"     Total events: {timeline['total_events']}")
        print(f"     Attack phases: {len(timeline['attack_phases'])}")
        print(f"     Time span: {timeline['time_span']:.0f} seconds")
        
        print(f"   Attack Phases:")
        for phase in timeline['attack_phases']:
            print(f"     • {phase['phase']}: {phase['event_count']} events")
    
    # Demo 4: Entity Relationship Mapping
    print(f"\n📋 Demo 4: Entity Relationship Analysis")
    relationship_graph = correlator.generate_entity_relationship_map()
    
    print(f"   Relationship Map:")
    print(f"     Entities: {relationship_graph.number_of_nodes()}")
    print(f"     Relationships: {relationship_graph.number_of_edges()}")
    
    # Demo 5: Evidence Gap Detection
    print(f"\n📋 Demo 5: Evidence Gap Analysis")
    if clusters:
        timeline_events = clusters[0].get_timeline()
        gaps = correlator.detect_evidence_gaps(timeline_events)
        
        print(f"   Evidence gaps detected: {len(gaps)}")
        for gap in gaps:
            print(f"     Gap {gap['gap_id']}: {gap['duration_seconds']:.0f} seconds")
            print(f"       Suspicion level: {gap['suspicion_level']}")
    
    print(f"\n✅ Module 3 Complete: Evidence Correlation Engine")
    print(f"   Next: Module 4 - Advanced Reporting & Expert Testimony")

if __name__ == "__main__":
    demo_evidence_correlation()
```

### Module 3 Self-Check Questions
Ensure you understand:
- How to correlate evidence across different time windows and sources?
- What patterns indicate coordinated attack activities?
- How can evidence gaps suggest tampering or evasion attempts?

**Ready for Module 4? ✅ Check the box above when ready.**

---

## 📘 Module 4: Advanced Reporting & Expert Testimony Preparation (60 minutes)

**Learning Objective**: Master professional forensic reporting and expert testimony preparation

**What you'll build**: Comprehensive forensic reporting and expert witness platform

### Step 4: Expert Forensic Reporting System

Create `expert_forensic_reporting.py`:

```python
import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import base64
from io import BytesIO

class ExpertForensicReporter:
    """Professional forensic reporting and expert testimony platform"""
    
    def __init__(self):
        self.investigation_metadata = {}
        self.evidence_chain_of_custody = []
        self.analysis_findings = {}
        self.expert_opinions = []
        self.technical_appendices = []
        
        print("📄 Expert Forensic Reporter initialized")
        print("   Capabilities: Professional reports, expert testimony, legal admissibility")
    
    def generate_comprehensive_report(self, investigation_data: Dict) -> Dict:
        """
        Generate comprehensive forensic investigation report
        
        Args:
            investigation_data: Complete investigation analysis
            
        Returns:
            Dict: Structured forensic report
        """
        print("📊 Generating comprehensive forensic investigation report...")
        
        report = {
            'executive_summary': self._generate_executive_summary(investigation_data),
            'investigation_overview': self._generate_investigation_overview(investigation_data),
            'methodology': self._document_forensic_methodology(),
            'evidence_analysis': self._document_evidence_analysis(investigation_data),
            'findings_and_conclusions': self._generate_findings_conclusions(investigation_data),
            'expert_opinions': self._formulate_expert_opinions(investigation_data),
            'recommendations': self._generate_recommendations(investigation_data),
            'technical_appendices': self._create_technical_appendices(investigation_data),
            'chain_of_custody': self._document_chain_of_custody(),
            'report_metadata': self._generate_report_metadata()
        }
        
        print(f"   ✅ Comprehensive report generated:")
        print(f"      Executive summary: {len(report['executive_summary']['key_findings'])} key findings")
        print(f"      Evidence items analyzed: {report['evidence_analysis']['total_evidence_items']}")
        print(f"      Expert opinions: {len(report['expert_opinions'])}")
        
        return report
    
    def prepare_expert_testimony(self, report: Dict) -> Dict:
        """
        Prepare expert testimony materials for court presentation
        
        Args:
            report: Comprehensive forensic report
            
        Returns:
            Dict: Expert testimony preparation materials
        """
        print("👨‍⚖️ Preparing expert testimony materials...")
        
        testimony_materials = {
            'expert_qualifications': self._document_expert_qualifications(),
            'testimony_outline': self._create_testimony_outline(report),
            'visual_exhibits': self._prepare_visual_exhibits(report),
            'technical_explanations': self._prepare_technical_explanations(),
            'potential_cross_examination': self._prepare_cross_examination_responses(report),
            'demonstrative_evidence': self._prepare_demonstrative_evidence(report),
            'expert_declaration': self._generate_expert_declaration(report)
        }
        
        print(f"   ✅ Expert testimony materials prepared:")
        print(f"      Visual exhibits: {len(testimony_materials['visual_exhibits'])}")
        print(f"      Technical explanations: {len(testimony_materials['technical_explanations'])}")
        print(f"      Cross-examination topics: {len(testimony_materials['potential_cross_examination'])}")
        
        return testimony_materials
    
    def validate_legal_admissibility(self, report: Dict) -> Dict:
        """
        Validate report for legal admissibility standards
        
        Args:
            report: Forensic report to validate
            
        Returns:
            Dict: Admissibility validation results
        """
        print("⚖️ Validating legal admissibility standards...")
        
        validation_results = {
            'daubert_criteria': self._validate_daubert_criteria(report),
            'federal_rules_compliance': self._validate_federal_rules(report),
            'chain_of_custody_integrity': self._validate_chain_of_custody(),
            'methodology_reliability': self._validate_methodology_reliability(report),
            'peer_review_standards': self._validate_peer_review_standards(report),
            'error_rate_analysis': self._analyze_error_rates(report),
            'general_acceptance': self._validate_general_acceptance(report),
            'admissibility_score': 0.0
        }
        
        # Calculate overall admissibility score
        criteria_scores = [
            validation_results['daubert_criteria']['score'],
            validation_results['federal_rules_compliance']['score'],
            validation_results['chain_of_custody_integrity']['score'],
            validation_results['methodology_reliability']['score']
        ]
        
        validation_results['admissibility_score'] = sum(criteria_scores) / len(criteria_scores)
        validation_results['admissibility_rating'] = self._get_admissibility_rating(validation_results['admissibility_score'])
        
        print(f"   ✅ Legal admissibility validation complete:")
        print(f"      Overall score: {validation_results['admissibility_score']:.2f}/1.0")
        print(f"      Rating: {validation_results['admissibility_rating']}")
        
        return validation_results
    
    def generate_timeline_visualization(self, timeline_data: List[Dict]) -> str:
        """
        Generate professional timeline visualization for court presentation
        
        Args:
            timeline_data: Timeline events
            
        Returns:
            str: Base64 encoded timeline image
        """
        print("📊 Creating professional timeline visualization...")
        
        if not timeline_data:
            return ""
        
        # Create timeline plot
        fig, ax = plt.subplots(figsize=(16, 10))
        
        # Extract data for plotting
        times = [datetime.fromisoformat(event['timestamp']) for event in timeline_data]
        events = [event['event_type'] for event in timeline_data]
        sources = [event.get('source_system', 'Unknown') for event in timeline_data]
        
        # Create color map for different sources
        unique_sources = list(set(sources))
        colors = plt.cm.Set3(range(len(unique_sources)))
        color_map = dict(zip(unique_sources, colors))
        
        # Plot timeline
        for i, (time, event, source) in enumerate(zip(times, events, sources)):
            color = color_map[source]
            ax.scatter(time, i, c=[color], s=100, alpha=0.7)
            ax.annotate(f"{event}\n({source})", 
                       (time, i), 
                       xytext=(10, 0), 
                       textcoords='offset points',
                       fontsize=8,
                       ha='left')
        
        # Format plot
        ax.set_xlabel('Time', fontsize=12)
        ax.set_ylabel('Event Sequence', fontsize=12)
        ax.set_title('Forensic Investigation Timeline', fontsize=16, fontweight='bold')
        ax.grid(True, alpha=0.3)
        
        # Add legend
        legend_elements = [plt.Line2D([0], [0], marker='o', color='w', 
                                    markerfacecolor=color_map[source], markersize=10, 
                                    label=source) for source in unique_sources]
        ax.legend(handles=legend_elements, loc='upper right')
        
        # Format time axis
        fig.autofmt_xdate()
        plt.tight_layout()
        
        # Convert to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        print("   ✅ Timeline visualization generated")
        return image_base64
    
    def _generate_executive_summary(self, investigation_data: Dict) -> Dict:
        """Generate executive summary for business stakeholders"""
        return {
            'incident_type': 'Advanced Persistent Threat (APT) Campaign',
            'incident_scope': 'Multi-system compromise with data exfiltration',
            'key_findings': [
                'Unauthorized access gained through compromised credentials',
                'Privilege escalation achieved through system vulnerabilities',
                'Evidence of lateral movement across network infrastructure',
                'Significant data exfiltration to external command and control servers',
                'Attempted evidence destruction through log deletion'
            ],
            'business_impact': {
                'confidentiality': 'HIGH - Sensitive data accessed and exfiltrated',
                'integrity': 'MEDIUM - Some system configurations modified',
                'availability': 'LOW - No significant system downtime observed'
            },
            'timeline_summary': 'Attack occurred over 2-hour period from 10:30-12:30 on January 15, 2024',
            'attribution_confidence': 'MEDIUM - Tactics consistent with known threat group',
            'recommended_actions': [
                'Immediate credential reset for all compromised accounts',
                'Implementation of additional monitoring for lateral movement',
                'Patching of identified vulnerabilities used in privilege escalation',
                'Review and strengthening of data loss prevention controls'
            ]
        }
    
    def _document_forensic_methodology(self) -> Dict:
        """Document forensic methodology for legal scrutiny"""
        return {
            'standards_followed': [
                'NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response',
                'RFC 3227: Guidelines for Evidence Collection and Archiving', 
                'ISO/IEC 27037: Guidelines for identification, collection, acquisition and preservation',
                'SWGDE Best Practices for Digital Evidence'
            ],
            'tools_and_techniques': [
                {
                    'tool': 'Network Traffic Analysis',
                    'version': 'Custom Python/Scapy Framework v2.4',
                    'purpose': 'Packet capture analysis and flow reconstruction',
                    'validation': 'Peer-reviewed methodology, published research backing'
                },
                {
                    'tool': 'Database Forensics Engine',
                    'version': 'SQLite Analysis Framework v1.0',
                    'purpose': 'Transaction log analysis and deleted record recovery',
                    'validation': 'Based on established database forensics principles'
                },
                {
                    'tool': 'Evidence Correlation Platform',
                    'version': 'Multi-Source Correlation Engine v1.0', 
                    'purpose': 'Cross-source evidence correlation and timeline reconstruction',
                    'validation': 'Algorithm validation through controlled test scenarios'
                }
            ],
            'quality_assurance': {
                'peer_review': 'Analysis reviewed by senior forensic investigator',
                'validation_testing': 'Methodology validated against known test scenarios',
                'error_checking': 'Multi-stage verification of analysis results',
                'documentation': 'Complete audit trail of analysis steps maintained'
            },
            'limitations': [
                'Analysis limited to available log data and system artifacts',
                'Some network traffic may not have been captured',
                'Timestamp accuracy dependent on system clock synchronization',
                'Recovery of deleted data subject to disk overwrite patterns'
            ]
        }
    
    def _formulate_expert_opinions(self, investigation_data: Dict) -> List[Dict]:
        """Formulate expert opinions based on analysis"""
        return [
            {
                'opinion_id': 'EXPERT_001',
                'topic': 'Attack Attribution and Sophistication',
                'opinion': 'Based on the tactics, techniques, and procedures observed, this attack demonstrates characteristics consistent with an advanced persistent threat campaign. The systematic approach to privilege escalation, lateral movement, and evidence destruction indicates a sophisticated adversary.',
                'basis': [
                    'Multi-stage attack progression following MITRE ATT&CK framework',
                    'Use of legitimate tools for malicious purposes (living off the land)',
                    'Attempts to destroy forensic evidence through log deletion',
                    'Careful timing to avoid detection during business hours'
                ],
                'confidence': 'HIGH',
                'supporting_evidence': ['correlation_cluster_001', 'timeline_analysis', 'behavioral_patterns']
            },
            {
                'opinion_id': 'EXPERT_002', 
                'topic': 'Data Exfiltration Scope and Methods',
                'opinion': 'The evidence clearly demonstrates unauthorized data exfiltration through command and control channels. The volume and timing of outbound connections strongly indicates systematic data theft rather than opportunistic access.',
                'basis': [
                    'Large volume outbound connections to external IP addresses',
                    'Timing correlation with database access events',
                    'Use of non-standard ports for data transfer',
                    'Encrypted communication channels to evade detection'
                ],
                'confidence': 'HIGH',
                'supporting_evidence': ['network_flow_analysis', 'database_correlation', 'timeline_reconstruction']
            }
        ]
    
    def _validate_daubert_criteria(self, report: Dict) -> Dict:
        """Validate against Daubert admissibility criteria"""
        return {
            'testability': {
                'score': 0.9,
                'assessment': 'Forensic methodologies can be tested and validated',
                'evidence': 'Controlled testing scenarios demonstrate methodology reliability'
            },
            'peer_review': {
                'score': 0.8,
                'assessment': 'Methodologies based on peer-reviewed forensic science',
                'evidence': 'Analysis techniques published in forensic journals'
            },
            'error_rates': {
                'score': 0.85,
                'assessment': 'Known error rates for correlation algorithms documented',
                'evidence': 'Statistical analysis of false positive/negative rates'
            },
            'general_acceptance': {
                'score': 0.9,
                'assessment': 'Techniques widely accepted in forensic community',
                'evidence': 'Standard practices in digital forensics field'
            },
            'overall_score': 0.8625
        }
    
    def _prepare_visual_exhibits(self, report: Dict) -> List[Dict]:
        """Prepare visual exhibits for court presentation"""
        return [
            {
                'exhibit_id': 'EXHIBIT_A',
                'title': 'Attack Timeline Visualization',
                'description': 'Comprehensive timeline showing correlated attack activities across multiple systems',
                'type': 'timeline_chart',
                'complexity': 'medium',
                'explanation_required': True
            },
            {
                'exhibit_id': 'EXHIBIT_B',
                'title': 'Network Communication Diagram',
                'description': 'Visual representation of network communications showing command and control channels',
                'type': 'network_diagram',
                'complexity': 'high',
                'explanation_required': True
            },
            {
                'exhibit_id': 'EXHIBIT_C',
                'title': 'Evidence Correlation Matrix',
                'description': 'Matrix showing relationships between different types of evidence',
                'type': 'correlation_matrix',
                'complexity': 'medium',
                'explanation_required': True
            }
        ]

def create_sample_investigation_data() -> Dict:
    """Create comprehensive sample investigation data"""
    return {
        'investigation_id': 'INV_2024_001',
        'case_title': 'GlobalTech Enterprises Data Breach Investigation',
        'incident_date': '2024-01-15',
        'investigator': 'Senior Digital Forensics Analyst',
        'evidence_sources': 4,
        'correlation_clusters': 3,
        'timeline_events': 15,
        'expert_findings': 8,
        'business_impact': 'HIGH'
    }

def demo_expert_forensic_reporting():
    """Comprehensive forensic reporting demonstration"""
    print("📄 Expert Forensic Reporting & Testimony Demo")
    print("="*60)
    print("Module 4: Professional forensic reporting and expert witness preparation")
    
    # Initialize reporter
    reporter = ExpertForensicReporter()
    
    # Create sample investigation data
    investigation_data = create_sample_investigation_data()
    
    # Demo 1: Comprehensive Report Generation
    print(f"\n📋 Demo 1: Comprehensive Forensic Report Generation")
    forensic_report = reporter.generate_comprehensive_report(investigation_data)
    
    print(f"   Report Sections Generated:")
    print(f"     • Executive Summary: {len(forensic_report['executive_summary']['key_findings'])} key findings")
    print(f"     • Methodology: {len(forensic_report['methodology']['tools_and_techniques'])} tools documented")
    print(f"     • Expert Opinions: {len(forensic_report['expert_opinions'])} opinions")
    
    print(f"   Executive Summary Highlights:")
    for finding in forensic_report['executive_summary']['key_findings'][:3]:
        print(f"     • {finding}")
    
    # Demo 2: Expert Testimony Preparation
    print(f"\n📋 Demo 2: Expert Testimony Materials")
    testimony_materials = reporter.prepare_expert_testimony(forensic_report)
    
    print(f"   Testimony Materials Prepared:")
    print(f"     • Visual exhibits: {len(testimony_materials['visual_exhibits'])}")
    print(f"     • Technical explanations: {len(testimony_materials['technical_explanations'])}")
    print(f"     • Cross-examination prep: {len(testimony_materials['potential_cross_examination'])}")
    
    # Demo 3: Legal Admissibility Validation
    print(f"\n📋 Demo 3: Legal Admissibility Validation")
    admissibility = reporter.validate_legal_admissibility(forensic_report)
    
    print(f"   Admissibility Assessment:")
    print(f"     • Overall Score: {admissibility['admissibility_score']:.2f}/1.0")
    print(f"     • Rating: {admissibility['admissibility_rating']}")
    
    print(f"   Daubert Criteria Compliance:")
    for criterion, details in admissibility['daubert_criteria'].items():
        if isinstance(details, dict) and 'score' in details:
            print(f"     • {criterion.title()}: {details['score']:.2f}")
    
    # Demo 4: Timeline Visualization
    print(f"\n📋 Demo 4: Professional Timeline Visualization")
    
    sample_timeline = [
        {
            'timestamp': '2024-01-15T10:30:00',
            'event_type': 'Initial_Access',
            'source_system': 'Network_IDS'
        },
        {
            'timestamp': '2024-01-15T10:35:00',
            'event_type': 'Credential_Compromise',
            'source_system': 'SIEM'
        },
        {
            'timestamp': '2024-01-15T10:40:00',
            'event_type': 'Privilege_Escalation',
            'source_system': 'Database'
        }
    ]
    
    timeline_viz = reporter.generate_timeline_visualization(sample_timeline)
    
    if timeline_viz:
        print(f"   ✅ Professional timeline visualization created")
        print(f"   Timeline shows {len(sample_timeline)} key events across multiple sources")
    else:
        print(f"   ⚠️  Timeline visualization creation skipped (no display available)")
    
    print(f"\n✅ Module 4 Complete: Expert Forensic Reporting")
    print(f"   Advanced Digital Forensics Tutorial Complete!")
    print(f"   Ready for advanced forensics investigation assignment")

if __name__ == "__main__":
    demo_expert_forensic_reporting()
```

### Module 4 Self-Check Questions
Final understanding check:
- What elements make forensic testimony legally admissible under Daubert standards?
- How do you prepare technical findings for non-technical audiences?
- What documentation is required for expert witness qualification?

**Tutorial Complete? ✅ Check the box above when you've mastered all concepts.**

---

## ✅ Tutorial Completion Checklist

Master these advanced forensics capabilities:

- [ ] Advanced network forensics with SIEM correlation from Week 7 systems
- [ ] Database transaction analysis and deleted record recovery
- [ ] Cross-source evidence correlation with high-confidence scoring
- [ ] Professional timeline reconstruction with attack phase identification
- [ ] Expert-quality forensic reporting meeting legal admissibility standards
- [ ] Integration of all security infrastructure from Weeks 3-9 into investigations

## 🎓 Learning Integration: Complete Forensics Foundation

This tutorial completes your **Project 2: Incident Investigation Platform** by integrating:

**From Previous Weeks:**
- Week 3 PKI: Certificate validation logs and digital signature verification
- Week 4 MFA: Multi-factor authentication bypass detection and analysis
- Week 5 RBAC: Role-based access control audit trails and privilege escalations
- Week 6 Network: Network security monitoring data and traffic analysis
- Week 7 SIEM: Security information and event correlation for comprehensive investigations
- Week 8-9: Penetration testing results and forensic-ready architecture analysis

**Advanced Capabilities Added:**
- Multi-source evidence correlation with confidence scoring
- Professional expert witness testimony preparation
- Legal admissibility validation under Daubert standards
- Advanced timeline reconstruction with attack phase identification
- Comprehensive forensic reporting for business and legal audiences

## 🚀 Ready for the Assignment?

Your comprehensive forensics platform can now investigate complex multi-source incidents across the entire security infrastructure you've built throughout the course. The assignment will test your ability to correlate evidence from network traffic, database transactions, authentication systems, and SIEM data into expert-quality investigations.

**Next Step**: Complete [assignment.md](assignment.md) - Advanced Multi-Source Forensic Investigation

## 💡 Professional Development

This tutorial prepares you for advanced forensics roles requiring:
- **Expert Witness Testimony** in legal proceedings
- **Advanced Persistent Threat (APT) Investigation** across enterprise infrastructure  
- **Multi-Source Evidence Correlation** for complex incident response
- **Professional Forensic Reporting** for executive and legal audiences
- **Integration Skills** connecting preventive security with forensic investigation

Your skills now span the complete cybersecurity lifecycle from prevention (Weeks 3-9) to investigation (Weeks 10-11), with specialization still to come in memory forensics (Week 12) and mobile forensics (Week 13).