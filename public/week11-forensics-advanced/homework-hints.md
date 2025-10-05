# Week 11 Homework Hints: Advanced Multi-Source Forensic Investigation

## 🎯 Quick Start Guide (5-6 hours total)

### Time Breakdown
- **Multi-Source Evidence Integration**: 1 hour
- **Network Forensics with SIEM Correlation**: 1.5 hours
- **Database Forensics and User Activity**: 1.5 hours
- **Evidence Correlation and Timeline**: 1.5 hours
- **Professional Investigation Report**: 30 minutes

**Note**: This assignment builds on security infrastructure from Weeks 3-9. Focus on practical correlation techniques rather than building enterprise-scale platforms.

## 📋 Step-by-Step Implementation

### Step 1: Advanced Forensics Concepts (30 minutes)

**Advanced Investigation Approach:**
- **Multi-Source Evidence**: Integrate network, database, and system logs
- **Correlation Analysis**: Connect events across different security systems
- **Timeline Reconstruction**: Build comprehensive attack timeline
- **Professional Reporting**: Expert-level investigation documentation
- **Legal Readiness**: Ensure evidence handling meets court standards

**Integration with Previous Weeks:**
- **Week 3**: PKI certificate validation logs
- **Week 4**: MFA authentication events
- **Week 5**: RBAC access control modifications
- **Week 6**: Network security monitoring data
- **Week 7**: SIEM correlation and alerts
- **Week 8**: Vulnerability assessment findings

### Step 2: Environment Setup (15 minutes)

```bash
pip install scapy pandas networkx matplotlib plotly sqlite3

mkdir week11-multi-source-investigation
cd week11-multi-source-investigation
mkdir evidence sources analysis reports

touch evidence_integrator.py
touch network_database_correlator.py
touch timeline_reconstructor.py
touch investigation_reporter.py
touch test_investigation_scenario.py
```

### Step 3: Multi-Source Evidence Integration (60 minutes)

**Assignment Focus**: Create a system to standardize and correlate evidence from multiple security sources

```python
# evidence_integrator.py
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib

@dataclass
class SecurityEvidence:
    """Standardized evidence format for all security sources"""
    source_system: str  # 'PKI', 'MFA', 'RBAC', 'Network', 'SIEM', 'Database'
    timestamp: datetime
    event_type: str
    event_details: Dict
    affected_entities: List[str]  # users, IPs, systems
    confidence_score: float  # 0.0 to 1.0
    week_source: int  # Which week's system generated this
    evidence_hash: str = ""

    def __post_init__(self):
        if not self.evidence_hash:
            content = f"{self.source_system}{self.timestamp.isoformat()}{self.event_type}"
            self.evidence_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

class EvidenceIntegrator:
    """Integrate evidence from all security infrastructure sources"""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_items = []
        self.source_statistics = {}

        # Initialize evidence database
        self.db_path = f"evidence/{case_id}_integrated_evidence.db"
        self.init_database()

    def init_database(self):
        """Initialize integrated evidence database"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_hash TEXT UNIQUE,
                source_system TEXT,
                timestamp TEXT,
                event_type TEXT,
                event_details TEXT,
                affected_entities TEXT,
                confidence_score REAL,
                week_source INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id TEXT,
                evidence_hashes TEXT,
                correlation_type TEXT,
                correlation_score REAL,
                created_at TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def ingest_pki_evidence(self, pki_logs: List[Dict]) -> int:
        """Ingest PKI certificate validation evidence"""
        count = 0
        for log_entry in pki_logs:
            evidence = SecurityEvidence(
                source_system="PKI",
                timestamp=datetime.fromisoformat(log_entry['timestamp']),
                event_type=log_entry.get('event_type', 'certificate_validation'),
                event_details={
                    'certificate_subject': log_entry.get('subject', ''),
                    'validation_result': log_entry.get('result', ''),
                    'issuer': log_entry.get('issuer', ''),
                    'serial_number': log_entry.get('serial', '')
                },
                affected_entities=[log_entry.get('client_ip', ''), log_entry.get('subject', '')],
                confidence_score=0.9,
                week_source=3
            )
            self.evidence_items.append(evidence)
            count += 1

        return count

    def ingest_mfa_evidence(self, mfa_events: List[Dict]) -> int:
        """Ingest MFA authentication events"""
        count = 0
        for event in mfa_events:
            evidence = SecurityEvidence(
                source_system="MFA",
                timestamp=datetime.fromisoformat(event['timestamp']),
                event_type=event.get('event_type', 'authentication_attempt'),
                event_details={
                    'username': event.get('username', ''),
                    'mfa_method': event.get('method', ''),
                    'result': event.get('result', ''),
                    'source_ip': event.get('source_ip', ''),
                    'user_agent': event.get('user_agent', '')
                },
                affected_entities=[event.get('username', ''), event.get('source_ip', '')],
                confidence_score=0.95,
                week_source=4
            )
            self.evidence_items.append(evidence)
            count += 1

        return count

    def ingest_rbac_evidence(self, rbac_changes: List[Dict]) -> int:
        """Ingest RBAC permission changes"""
        count = 0
        for change in rbac_changes:
            evidence = SecurityEvidence(
                source_system="RBAC",
                timestamp=datetime.fromisoformat(change['timestamp']),
                event_type=change.get('event_type', 'permission_change'),
                event_details={
                    'user_affected': change.get('user', ''),
                    'permission_change': change.get('change_type', ''),
                    'resource': change.get('resource', ''),
                    'administrator': change.get('admin', ''),
                    'old_permissions': change.get('old_perms', ''),
                    'new_permissions': change.get('new_perms', '')
                },
                affected_entities=[change.get('user', ''), change.get('admin', '')],
                confidence_score=0.9,
                week_source=5
            )
            self.evidence_items.append(evidence)
            count += 1

        return count

    def ingest_network_evidence(self, network_flows: List[Dict]) -> int:
        """Ingest network security monitoring data"""
        count = 0
        for flow in network_flows:
            evidence = SecurityEvidence(
                source_system="Network",
                timestamp=datetime.fromisoformat(flow['timestamp']),
                event_type=flow.get('event_type', 'network_flow'),
                event_details={
                    'src_ip': flow.get('src_ip', ''),
                    'dst_ip': flow.get('dst_ip', ''),
                    'src_port': flow.get('src_port', 0),
                    'dst_port': flow.get('dst_port', 0),
                    'protocol': flow.get('protocol', ''),
                    'bytes_transferred': flow.get('bytes', 0),
                    'flags': flow.get('flags', [])
                },
                affected_entities=[flow.get('src_ip', ''), flow.get('dst_ip', '')],
                confidence_score=0.8,
                week_source=6
            )
            self.evidence_items.append(evidence)
            count += 1

        return count

    def ingest_siem_evidence(self, siem_alerts: List[Dict]) -> int:
        """Ingest SIEM correlation alerts"""
        count = 0
        for alert in siem_alerts:
            evidence = SecurityEvidence(
                source_system="SIEM",
                timestamp=datetime.fromisoformat(alert['timestamp']),
                event_type=alert.get('event_type', 'security_alert'),
                event_details={
                    'alert_name': alert.get('name', ''),
                    'severity': alert.get('severity', ''),
                    'description': alert.get('description', ''),
                    'source_events': alert.get('source_events', []),
                    'mitre_technique': alert.get('mitre_id', ''),
                    'affected_systems': alert.get('systems', [])
                },
                affected_entities=alert.get('entities', []),
                confidence_score=0.85,
                week_source=7
            )
            self.evidence_items.append(evidence)
            count += 1

        return count

    def save_evidence_items(self):
        """Save all evidence items to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for evidence in self.evidence_items:
            cursor.execute('''
                INSERT OR REPLACE INTO evidence_items
                (evidence_hash, source_system, timestamp, event_type, event_details,
                 affected_entities, confidence_score, week_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                evidence.evidence_hash,
                evidence.source_system,
                evidence.timestamp.isoformat(),
                evidence.event_type,
                json.dumps(evidence.event_details),
                json.dumps(evidence.affected_entities),
                evidence.confidence_score,
                evidence.week_source
            ))

        conn.commit()
        conn.close()

    def generate_sample_evidence(self):
        """Generate sample evidence from all security systems"""
        base_time = datetime.now() - timedelta(days=1)

        # Sample PKI evidence
        pki_logs = [
            {
                'timestamp': (base_time + timedelta(minutes=10)).isoformat(),
                'event_type': 'certificate_validation_failed',
                'subject': 'CN=suspicious.example.com',
                'result': 'FAILED',
                'issuer': 'CN=Unknown CA',
                'client_ip': '192.168.1.50'
            },
            {
                'timestamp': (base_time + timedelta(minutes=15)).isoformat(),
                'event_type': 'certificate_validation_success',
                'subject': 'CN=admin.company.com',
                'result': 'SUCCESS',
                'issuer': 'CN=Company Root CA',
                'client_ip': '192.168.1.100'
            }
        ]

        # Sample MFA evidence
        mfa_events = [
            {
                'timestamp': (base_time + timedelta(minutes=20)).isoformat(),
                'event_type': 'mfa_bypass_attempt',
                'username': 'admin@company.com',
                'method': 'TOTP',
                'result': 'FAILED',
                'source_ip': '192.168.1.50'
            },
            {
                'timestamp': (base_time + timedelta(minutes=25)).isoformat(),
                'event_type': 'mfa_success',
                'username': 'admin@company.com',
                'method': 'TOTP',
                'result': 'SUCCESS',
                'source_ip': '192.168.1.50'
            }
        ]

        # Sample RBAC evidence
        rbac_changes = [
            {
                'timestamp': (base_time + timedelta(minutes=30)).isoformat(),
                'event_type': 'privilege_escalation',
                'user': 'admin@company.com',
                'change_type': 'GRANT',
                'resource': 'database_admin',
                'admin': 'admin@company.com',
                'old_perms': 'read',
                'new_perms': 'read,write,admin'
            }
        ]

        # Sample SIEM evidence
        siem_alerts = [
            {
                'timestamp': (base_time + timedelta(minutes=35)).isoformat(),
                'event_type': 'correlated_attack',
                'name': 'Privilege Escalation Chain',
                'severity': 'HIGH',
                'description': 'Multiple privilege escalation events detected',
                'entities': ['admin@company.com', '192.168.1.50'],
                'mitre_id': 'T1068'
            }
        ]

        # Ingest all evidence
        print("📥 Ingesting sample evidence from all sources...")
        pki_count = self.ingest_pki_evidence(pki_logs)
        mfa_count = self.ingest_mfa_evidence(mfa_events)
        rbac_count = self.ingest_rbac_evidence(rbac_changes)
        siem_count = self.ingest_siem_evidence(siem_alerts)

        print(f"✅ Evidence ingested:")
        print(f"   PKI events: {pki_count}")
        print(f"   MFA events: {mfa_count}")
        print(f"   RBAC changes: {rbac_count}")
        print(f"   SIEM alerts: {siem_count}")
        print(f"   Total evidence items: {len(self.evidence_items)}")

        return {
            'pki': pki_count,
            'mfa': mfa_count,
            'rbac': rbac_count,
            'siem': siem_count,
            'total': len(self.evidence_items)
        }

def main():
    """Main evidence integration demo"""
    print("📋 Multi-Source Evidence Integration")
    print("=" * 40)

    # Create integrator
    integrator = EvidenceIntegrator("CASE_MULTI_20240115")

    # Generate and ingest sample evidence
    stats = integrator.generate_sample_evidence()

    # Save evidence
    integrator.save_evidence_items()

    print(f"\n✅ Evidence integration complete!")
    print(f"Integrated {stats['total']} evidence items from {len(stats)-1} security systems")

if __name__ == "__main__":
    main()
```

### Step 4: Network and Database Correlation Analysis (90 minutes)

```python
# network_database_correlator.py
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import pandas as pd
from dataclasses import dataclass

@dataclass
class CorrelationCluster:
    """Group of correlated events across multiple sources"""
    cluster_id: str
    evidence_items: List[str]  # evidence hashes
    correlation_type: str
    correlation_score: float
    attack_phase: str = "unknown"
    entities_involved: List[str] = None

    def __post_init__(self):
        if self.entities_involved is None:
            self.entities_involved = []

class AdvancedCorrelationEngine:
    """Correlate evidence across network, database, and security events"""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_db_path = f"evidence/{case_id}_integrated_evidence.db"
        self.correlation_clusters = []
        self.attack_patterns = {
            'privilege_escalation': {
                'phases': ['initial_access', 'privilege_escalation', 'persistence'],
                'indicators': ['mfa_bypass', 'permission_change', 'admin_access']
            },
            'data_exfiltration': {
                'phases': ['collection', 'exfiltration'],
                'indicators': ['large_transfer', 'suspicious_connection', 'file_access']
            },
            'lateral_movement': {
                'phases': ['discovery', 'lateral_movement'],
                'indicators': ['network_scan', 'credential_access', 'remote_login']
            }
        }

    def load_evidence_items(self) -> List[Dict]:
        """Load evidence items from integrated database"""
        conn = sqlite3.connect(self.evidence_db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT evidence_hash, source_system, timestamp, event_type,
                   event_details, affected_entities, confidence_score, week_source
            FROM evidence_items
            ORDER BY timestamp
        ''')

        evidence_items = []
        for row in cursor.fetchall():
            evidence_items.append({
                'evidence_hash': row[0],
                'source_system': row[1],
                'timestamp': datetime.fromisoformat(row[2]),
                'event_type': row[3],
                'event_details': json.loads(row[4]),
                'affected_entities': json.loads(row[5]),
                'confidence_score': row[6],
                'week_source': row[7]
            })

        conn.close()
        return evidence_items

    def perform_temporal_correlation(self, evidence_items: List[Dict],
                                   time_window_minutes: int = 30) -> List[CorrelationCluster]:
        """Correlate events that occur within a time window"""
        clusters = []
        used_evidence = set()

        for i, evidence in enumerate(evidence_items):
            if evidence['evidence_hash'] in used_evidence:
                continue

            # Find events within time window
            cluster_evidence = [evidence['evidence_hash']]
            cluster_entities = set(evidence['affected_entities'])

            time_window_start = evidence['timestamp']
            time_window_end = time_window_start + timedelta(minutes=time_window_minutes)

            for j, other_evidence in enumerate(evidence_items[i+1:], i+1):
                if other_evidence['evidence_hash'] in used_evidence:
                    continue

                if other_evidence['timestamp'] > time_window_end:
                    break

                # Check for entity overlap
                other_entities = set(other_evidence['affected_entities'])
                if cluster_entities.intersection(other_entities):
                    cluster_evidence.append(other_evidence['evidence_hash'])
                    cluster_entities.update(other_entities)
                    used_evidence.add(other_evidence['evidence_hash'])

            if len(cluster_evidence) > 1:
                cluster_id = f"TEMPORAL_{len(clusters)+1}_{time_window_start.strftime('%H%M%S')}"
                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    evidence_items=cluster_evidence,
                    correlation_type="temporal",
                    correlation_score=min(1.0, len(cluster_evidence) * 0.2),
                    entities_involved=list(cluster_entities)
                )
                clusters.append(cluster)
                used_evidence.add(evidence['evidence_hash'])

        return clusters

    def perform_entity_correlation(self, evidence_items: List[Dict]) -> List[CorrelationCluster]:
        """Correlate events that affect the same entities"""
        entity_groups = defaultdict(list)

        # Group evidence by affected entities
        for evidence in evidence_items:
            for entity in evidence['affected_entities']:
                entity_groups[entity].append(evidence)

        clusters = []
        for entity, entity_evidence in entity_groups.items():
            if len(entity_evidence) >= 2:
                cluster_id = f"ENTITY_{len(clusters)+1}_{entity.replace('@', '_').replace('.', '_')}"
                evidence_hashes = [e['evidence_hash'] for e in entity_evidence]

                # Calculate correlation score based on evidence diversity
                source_systems = set(e['source_system'] for e in entity_evidence)
                correlation_score = min(1.0, len(source_systems) * 0.3)

                cluster = CorrelationCluster(
                    cluster_id=cluster_id,
                    evidence_items=evidence_hashes,
                    correlation_type="entity_based",
                    correlation_score=correlation_score,
                    entities_involved=[entity]
                )
                clusters.append(cluster)

        return clusters

    def identify_attack_patterns(self, clusters: List[CorrelationCluster],
                               evidence_items: List[Dict]) -> List[CorrelationCluster]:
        """Identify known attack patterns in correlation clusters"""
        evidence_lookup = {e['evidence_hash']: e for e in evidence_items}

        for cluster in clusters:
            cluster_events = [evidence_lookup[hash_] for hash_ in cluster.evidence_items]

            # Check each attack pattern
            for pattern_name, pattern_def in self.attack_patterns.items():
                match_score = 0
                matched_indicators = []

                for event in cluster_events:
                    event_type = event['event_type'].lower()

                    for indicator in pattern_def['indicators']:
                        if indicator in event_type:
                            match_score += 1
                            matched_indicators.append(indicator)

                # If we match multiple indicators, classify the attack pattern
                if match_score >= 2:
                    cluster.attack_phase = pattern_name
                    cluster.correlation_score = min(1.0, cluster.correlation_score + (match_score * 0.1))
                    print(f"🎯 Identified {pattern_name} pattern in {cluster.cluster_id}")
                    print(f"   Matched indicators: {matched_indicators}")

        return clusters

    def analyze_database_activity_correlation(self, clusters: List[CorrelationCluster],
                                            evidence_items: List[Dict]) -> Dict:
        """Analyze database activities correlated with security events"""
        evidence_lookup = {e['evidence_hash']: e for e in evidence_items}
        database_correlations = []

        for cluster in clusters:
            cluster_events = [evidence_lookup[hash_] for hash_ in cluster.evidence_items]

            # Look for database-related activities
            auth_events = [e for e in cluster_events if e['source_system'] in ['MFA', 'RBAC']]
            network_events = [e for e in cluster_events if e['source_system'] == 'Network']

            if auth_events and network_events:
                # Potential database access correlation
                correlation = {
                    'cluster_id': cluster.cluster_id,
                    'correlation_type': 'database_access_correlation',
                    'auth_events': len(auth_events),
                    'network_events': len(network_events),
                    'entities': cluster.entities_involved,
                    'analysis': self.analyze_database_access_pattern(auth_events, network_events)
                }
                database_correlations.append(correlation)

        return {
            'total_correlations': len(database_correlations),
            'correlations': database_correlations,
            'summary': self.summarize_database_correlations(database_correlations)
        }

    def analyze_database_access_pattern(self, auth_events: List[Dict],
                                      network_events: List[Dict]) -> Dict:
        """Analyze patterns in database access attempts"""
        analysis = {
            'auth_success_rate': 0.0,
            'privilege_changes': 0,
            'suspicious_network_activity': 0,
            'risk_score': 0.0
        }

        # Analyze authentication success rate
        successful_auths = sum(1 for event in auth_events
                             if event['event_details'].get('result') == 'SUCCESS')
        if auth_events:
            analysis['auth_success_rate'] = successful_auths / len(auth_events)

        # Count privilege changes
        analysis['privilege_changes'] = sum(1 for event in auth_events
                                          if 'privilege' in event['event_type'] or
                                             'permission' in event['event_type'])

        # Analyze network activity
        suspicious_ports = [1433, 3306, 5432, 1521]  # Common database ports
        analysis['suspicious_network_activity'] = sum(1 for event in network_events
                                                    if event['event_details'].get('dst_port') in suspicious_ports)

        # Calculate risk score
        risk_factors = [
            analysis['auth_success_rate'] < 0.5,  # Low success rate
            analysis['privilege_changes'] > 0,    # Privilege escalation
            analysis['suspicious_network_activity'] > 0  # Database connections
        ]
        analysis['risk_score'] = sum(risk_factors) / len(risk_factors)

        return analysis

    def summarize_database_correlations(self, correlations: List[Dict]) -> Dict:
        """Summarize database correlation findings"""
        if not correlations:
            return {'high_risk_clusters': 0, 'recommendations': []}

        high_risk_clusters = sum(1 for corr in correlations
                                if corr['analysis']['risk_score'] > 0.6)

        recommendations = []
        if high_risk_clusters > 0:
            recommendations.append(f"Investigate {high_risk_clusters} high-risk database access patterns")

        privilege_escalations = sum(corr['analysis']['privilege_changes'] for corr in correlations)
        if privilege_escalations > 0:
            recommendations.append(f"Review {privilege_escalations} privilege escalation events")

        return {
            'high_risk_clusters': high_risk_clusters,
            'total_privilege_escalations': privilege_escalations,
            'recommendations': recommendations
        }

    def save_correlation_results(self, clusters: List[CorrelationCluster]):
        """Save correlation results to database"""
        conn = sqlite3.connect(self.evidence_db_path)
        cursor = conn.cursor()

        for cluster in clusters:
            cursor.execute('''
                INSERT OR REPLACE INTO correlation_clusters
                (cluster_id, evidence_hashes, correlation_type, correlation_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                cluster.cluster_id,
                json.dumps(cluster.evidence_items),
                cluster.correlation_type,
                cluster.correlation_score,
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

def main():
    """Main correlation analysis demo"""
    print("🔗 Advanced Multi-Source Correlation Analysis")
    print("=" * 50)

    # Create correlation engine
    correlator = AdvancedCorrelationEngine("CASE_MULTI_20240115")

    # Load evidence items
    evidence_items = correlator.load_evidence_items()
    print(f"📊 Loaded {len(evidence_items)} evidence items for correlation")

    if not evidence_items:
        print("❌ No evidence items found. Run evidence_integrator.py first.")
        return

    # Perform correlation analysis
    print("\n🕒 Performing temporal correlation...")
    temporal_clusters = correlator.perform_temporal_correlation(evidence_items)

    print("\n👥 Performing entity-based correlation...")
    entity_clusters = correlator.perform_entity_correlation(evidence_items)

    # Combine all clusters
    all_clusters = temporal_clusters + entity_clusters

    # Identify attack patterns
    print("\n🎯 Identifying attack patterns...")
    all_clusters = correlator.identify_attack_patterns(all_clusters, evidence_items)

    # Analyze database correlations
    print("\n🗄️ Analyzing database activity correlations...")
    db_analysis = correlator.analyze_database_activity_correlation(all_clusters, evidence_items)

    # Save results
    correlator.save_correlation_results(all_clusters)

    # Display results
    print(f"\n📈 Correlation Analysis Results:")
    print(f"   Temporal clusters: {len(temporal_clusters)}")
    print(f"   Entity-based clusters: {len(entity_clusters)}")
    print(f"   Total clusters: {len(all_clusters)}")
    print(f"   Database correlations: {db_analysis['total_correlations']}")

    # Show high-scoring clusters
    high_score_clusters = [c for c in all_clusters if c.correlation_score > 0.5]
    if high_score_clusters:
        print(f"\n🚨 High-confidence correlations:")
        for cluster in high_score_clusters:
            print(f"   • {cluster.cluster_id}: {cluster.correlation_type} (score: {cluster.correlation_score:.2f})")
            if cluster.attack_phase != "unknown":
                print(f"     Attack pattern: {cluster.attack_phase}")

    # Database analysis summary
    if db_analysis['correlations']:
        print(f"\n🗄️ Database Analysis Summary:")
        summary = db_analysis['summary']
        print(f"   High-risk clusters: {summary['high_risk_clusters']}")
        for rec in summary['recommendations']:
            print(f"   • {rec}")

if __name__ == "__main__":
    main()
```

class NetworkForensicsAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.connections = {}
        self.dns_queries = []
        self.http_requests = []
        self.suspicious_activities = []
        self.network_timeline = []

        # Initialize analysis database
        self.db_path = f"network_captures/{case_id}_network_analysis.db"
        self.init_database()

        # Suspicious indicators
        self.suspicious_ips = [
            '10.0.0.666',  # Fake suspicious IP
            '192.168.1.666',
            '172.16.0.666'
        ]

        self.suspicious_domains = [
            'malware.evil.com',
            'c2.badguys.net',
            'phishing.scam.org'
        ]

        self.suspicious_ports = [1337, 31337, 4444, 5555, 6666]

    def init_database(self):
        """Initialize network forensics database"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT UNIQUE,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time TEXT,
                end_time TEXT,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                packet_count INTEGER,
                suspicious_score INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS http_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                method TEXT,
                url TEXT,
                user_agent TEXT,
                response_code INTEGER,
                content_length INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                query_name TEXT,
                query_type TEXT,
                response_ip TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                activity_type TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                description TEXT,
                severity TEXT,
                indicators TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def analyze_pcap_file(self, pcap_file: str) -> Dict:
        """Analyze network capture file"""
        print(f"🔍 Analyzing network capture: {pcap_file}")

        analysis_results = {
            'file': pcap_file,
            'total_packets': 0,
            'unique_connections': 0,
            'protocols': defaultdict(int),
            'suspicious_activities': [],
            'timeline_events': []
        }

        try:
            packets = scapy.rdpcap(pcap_file)
            analysis_results['total_packets'] = len(packets)

            for packet in packets:
                packet_info = self.analyze_packet(packet)
                if packet_info:
                    analysis_results['protocols'][packet_info['protocol']] += 1
                    analysis_results['timeline_events'].append(packet_info)

            # Analyze connections
            analysis_results['unique_connections'] = len(self.connections)

            # Detect suspicious activities
            self.detect_suspicious_activities()
            analysis_results['suspicious_activities'] = self.suspicious_activities

            print(f"✅ Analysis complete:")
            print(f"   Total packets: {analysis_results['total_packets']}")
            print(f"   Unique connections: {analysis_results['unique_connections']}")
            print(f"   Suspicious activities: {len(analysis_results['suspicious_activities'])}")

        except Exception as e:
            print(f"❌ Error analyzing pcap: {e}")
            analysis_results['error'] = str(e)

        return analysis_results

    def analyze_packet(self, packet) -> Optional[Dict]:
        """Analyze individual network packet"""
        packet_info = {
            'timestamp': datetime.fromtimestamp(float(packet.time)),
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'direction': 'unknown'
        }

        try:
            # Analyze IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst

                # Determine direction (simplified)
                if ip_layer.src.startswith('192.168.') or ip_layer.src.startswith('10.'):
                    packet_info['direction'] = 'outbound'
                else:
                    packet_info['direction'] = 'inbound'

            # Analyze TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport

                # Track connection
                self.track_connection(packet_info, 'TCP')

                # Analyze HTTP traffic
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    self.analyze_http_traffic(packet, packet_info)

            # Analyze UDP layer
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport

                # Track connection
                self.track_connection(packet_info, 'UDP')

                # Check for DNS traffic
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    self.analyze_dns_traffic(packet, packet_info)

            # Analyze ICMP
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                # ICMP analysis for ping sweeps, tunneling, etc.

            return packet_info

        except Exception as e:
            packet_info['error'] = str(e)
            return packet_info

    def track_connection(self, packet_info: Dict, protocol: str):
        """Track network connections"""
        if not all([packet_info['src_ip'], packet_info['dst_ip'],
                   packet_info['src_port'], packet_info['dst_port']]):
            return

        # Create connection identifier
        conn_key = f"{packet_info['src_ip']}:{packet_info['src_port']}-{packet_info['dst_ip']}:{packet_info['dst_port']}-{protocol}"

        if conn_key not in self.connections:
            connection = NetworkConnection(
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['src_port'],
                packet_info['dst_port'],
                protocol
            )
            self.connections[conn_key] = connection
        else:
            connection = self.connections[conn_key]

        connection.add_packet(packet_info)

    def analyze_http_traffic(self, packet, packet_info: Dict):
        """Analyze HTTP traffic for suspicious activities"""
        if packet.haslayer(HTTPRequest):
            request = packet[HTTPRequest]
            http_info = {
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'method': request.Method.decode() if request.Method else '',
                'url': request.Path.decode() if request.Path else '',
                'host': request.Host.decode() if request.Host else '',
                'user_agent': request.User_Agent.decode() if request.User_Agent else ''
            }

            self.http_requests.append(http_info)

            # Check for suspicious HTTP patterns
            self.check_suspicious_http(http_info)

    def analyze_dns_traffic(self, packet, packet_info: Dict):
        """Analyze DNS traffic for suspicious domains"""
        try:
            # Simplified DNS analysis (real implementation would use DNS layer parsing)
            dns_info = {
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info['src_ip'],
                'query_name': 'unknown',
                'query_type': 'A'
            }

            # Check for suspicious domains
            if any(domain in dns_info['query_name'] for domain in self.suspicious_domains):
                self.suspicious_activities.append({
                    'timestamp': dns_info['timestamp'],
                    'type': 'Suspicious DNS Query',
                    'src_ip': dns_info['src_ip'],
                    'description': f"DNS query to suspicious domain: {dns_info['query_name']}",
                    'severity': 'HIGH'
                })

            self.dns_queries.append(dns_info)

        except Exception as e:
            pass

    def check_suspicious_http(self, http_info: Dict):
        """Check HTTP traffic for suspicious patterns"""
        # Check for suspicious URLs
        suspicious_patterns = [
            '/admin/config.php',
            '/etc/passwd',
            '../../../',
            'cmd.exe',
            'powershell',
            'base64'
        ]

        for pattern in suspicious_patterns:
            if pattern in http_info['url']:
                self.suspicious_activities.append({
                    'timestamp': http_info['timestamp'],
                    'type': 'Suspicious HTTP Request',
                    'src_ip': http_info['src_ip'],
                    'dst_ip': http_info['dst_ip'],
                    'description': f"Suspicious URL pattern: {pattern} in {http_info['url']}",
                    'severity': 'MEDIUM'
                })

        # Check for suspicious user agents
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'burp']
        user_agent = http_info.get('user_agent', '').lower()

        for agent in suspicious_agents:
            if agent in user_agent:
                self.suspicious_activities.append({
                    'timestamp': http_info['timestamp'],
                    'type': 'Suspicious User Agent',
                    'src_ip': http_info['src_ip'],
                    'description': f"Suspicious user agent detected: {agent}",
                    'severity': 'HIGH'
                })

    def detect_suspicious_activities(self):
        """Detect various suspicious network activities"""

        # Detect port scanning
        self.detect_port_scanning()

        # Detect data exfiltration
        self.detect_data_exfiltration()

        # Detect suspicious connections
        self.detect_suspicious_connections()

    def detect_port_scanning(self):
        """Detect port scanning activities"""
        # Group connections by source IP
        ip_connections = defaultdict(list)
        for conn in self.connections.values():
            ip_connections[conn.src_ip].append(conn)

        for src_ip, connections in ip_connections.items():
            # Check for connections to many different ports
            unique_dst_ports = set(conn.dst_port for conn in connections)
            unique_dst_ips = set(conn.dst_ip for conn in connections)

            if len(unique_dst_ports) > 20:  # Threshold for port scan
                self.suspicious_activities.append({
                    'timestamp': datetime.now(),
                    'type': 'Port Scanning',
                    'src_ip': src_ip,
                    'description': f"Port scanning detected: {len(unique_dst_ports)} unique ports scanned",
                    'severity': 'HIGH',
                    'indicators': f"Ports: {sorted(list(unique_dst_ports))[:10]}..."
                })

            if len(unique_dst_ips) > 50:  # Network scanning
                self.suspicious_activities.append({
                    'timestamp': datetime.now(),
                    'type': 'Network Scanning',
                    'src_ip': src_ip,
                    'description': f"Network scanning detected: {len(unique_dst_ips)} unique IPs contacted",
                    'severity': 'HIGH'
                })

    def detect_data_exfiltration(self):
        """Detect potential data exfiltration"""
        for conn in self.connections.values():
            # Large outbound data transfers
            if conn.bytes_sent > 100 * 1024 * 1024:  # 100MB threshold
                self.suspicious_activities.append({
                    'timestamp': conn.start_time if conn.start_time else datetime.now(),
                    'type': 'Large Data Transfer',
                    'src_ip': conn.src_ip,
                    'dst_ip': conn.dst_ip,
                    'description': f"Large outbound transfer: {conn.bytes_sent:,} bytes",
                    'severity': 'MEDIUM'
                })

            # Connections to suspicious ports
            if conn.dst_port in self.suspicious_ports:
                self.suspicious_activities.append({
                    'timestamp': conn.start_time if conn.start_time else datetime.now(),
                    'type': 'Suspicious Port Connection',
                    'src_ip': conn.src_ip,
                    'dst_ip': conn.dst_ip,
                    'description': f"Connection to suspicious port: {conn.dst_port}",
                    'severity': 'HIGH'
                })

    def detect_suspicious_connections(self):
        """Detect connections to suspicious IPs"""
        for conn in self.connections.values():
            if conn.dst_ip in self.suspicious_ips:
                self.suspicious_activities.append({
                    'timestamp': conn.start_time if conn.start_time else datetime.now(),
                    'type': 'Suspicious IP Connection',
                    'src_ip': conn.src_ip,
                    'dst_ip': conn.dst_ip,
                    'description': f"Connection to known malicious IP: {conn.dst_ip}",
                    'severity': 'CRITICAL'
                })

    def create_sample_pcap(self):
        """Create sample network traffic for testing"""
        print("📦 Creating sample network traffic...")

        # Create sample packets
        packets = []

        # Normal web traffic
        packets.append(scapy.IP(src="192.168.1.100", dst="8.8.8.8")/scapy.UDP(sport=1234, dport=53))
        packets.append(scapy.IP(src="192.168.1.100", dst="93.184.216.34")/scapy.TCP(sport=1235, dport=80))

        # Suspicious traffic
        packets.append(scapy.IP(src="192.168.1.100", dst="10.0.0.666")/scapy.TCP(sport=1236, dport=1337))
        packets.append(scapy.IP(src="192.168.1.100", dst="172.16.0.1")/scapy.TCP(sport=1237, dport=22))

        # Port scan simulation
        for port in range(20, 30):
            packets.append(scapy.IP(src="10.0.0.50", dst="192.168.1.10")/scapy.TCP(sport=12345, dport=port))

        # Save sample pcap
        pcap_file = "network_captures/sample_traffic.pcap"
        scapy.wrpcap(pcap_file, packets)

        print(f"✅ Sample traffic saved to {pcap_file}")
        return pcap_file

    def save_analysis_results(self):
        """Save analysis results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save connections
        for connection in self.connections.values():
            cursor.execute('''
                INSERT OR REPLACE INTO network_connections
                (connection_id, src_ip, dst_ip, src_port, dst_port, protocol,
                 start_time, end_time, bytes_sent, bytes_received, packet_count, suspicious_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                connection.get_connection_id(),
                connection.src_ip,
                connection.dst_ip,
                connection.src_port,
                connection.dst_port,
                connection.protocol,
                connection.start_time.isoformat() if connection.start_time else '',
                connection.end_time.isoformat() if connection.end_time else '',
                connection.bytes_sent,
                connection.bytes_received,
                len(connection.packets),
                len(connection.suspicious_indicators)
            ))

        # Save suspicious activities
        for activity in self.suspicious_activities:
            cursor.execute('''
                INSERT INTO suspicious_activities
                (timestamp, activity_type, src_ip, dst_ip, description, severity, indicators)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                activity['timestamp'].isoformat() if isinstance(activity['timestamp'], datetime) else activity['timestamp'],
                activity['type'],
                activity.get('src_ip', ''),
                activity.get('dst_ip', ''),
                activity['description'],
                activity['severity'],
                activity.get('indicators', '')
            ))

        conn.commit()
        conn.close()

    def generate_network_report(self) -> Dict:
        """Generate comprehensive network forensics report"""
        report = {
            'case_id': self.case_id,
            'analysis_date': datetime.now().isoformat(),
            'summary': {
                'total_connections': len(self.connections),
                'suspicious_activities': len(self.suspicious_activities),
                'protocols_observed': len(set(conn.protocol for conn in self.connections.values())),
                'unique_source_ips': len(set(conn.src_ip for conn in self.connections.values())),
                'unique_destination_ips': len(set(conn.dst_ip for conn in self.connections.values()))
            },
            'top_talkers': self.get_top_talkers(),
            'suspicious_activities': [
                {
                    'timestamp': activity['timestamp'].isoformat() if isinstance(activity['timestamp'], datetime) else activity['timestamp'],
                    'type': activity['type'],
                    'description': activity['description'],
                    'severity': activity['severity']
                }
                for activity in self.suspicious_activities
            ],
            'recommendations': self.generate_network_recommendations()
        }

        return report

    def get_top_talkers(self) -> List[Dict]:
        """Get top network talkers by data volume"""
        ip_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_received': 0, 'connections': 0})

        for conn in self.connections.values():
            ip_stats[conn.src_ip]['bytes_sent'] += conn.bytes_sent
            ip_stats[conn.src_ip]['connections'] += 1
            ip_stats[conn.dst_ip]['bytes_received'] += conn.bytes_received

        # Sort by total traffic
        top_talkers = []
        for ip, stats in ip_stats.items():
            total_traffic = stats['bytes_sent'] + stats['bytes_received']
            top_talkers.append({
                'ip': ip,
                'total_traffic': total_traffic,
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'connections': stats['connections']
            })

        return sorted(top_talkers, key=lambda x: x['total_traffic'], reverse=True)[:10]

    def generate_network_recommendations(self) -> List[str]:
        """Generate network security recommendations"""
        recommendations = []

        if any(activity['severity'] == 'CRITICAL' for activity in self.suspicious_activities):
            recommendations.append("IMMEDIATE: Investigate critical security incidents")

        if any('Port Scanning' in activity['type'] for activity in self.suspicious_activities):
            recommendations.append("Implement network segmentation to limit scan impact")

        if any('Large Data Transfer' in activity['type'] for activity in self.suspicious_activities):
            recommendations.append("Review data loss prevention policies")

        recommendations.extend([
            "Deploy network monitoring for continuous analysis",
            "Implement intrusion detection system (IDS)",
            "Review firewall rules and access controls",
            "Conduct regular network security assessments"
        ])

        return recommendations

def main():
    """Main network forensics demo"""
    print("🌐 Network Traffic Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_NET_20240115"
    analyzer = NetworkForensicsAnalyzer(case_id)

    # Create sample traffic
    pcap_file = analyzer.create_sample_pcap()

    # Analyze traffic
    analysis_results = analyzer.analyze_pcap_file(pcap_file)

    # Save results
    analyzer.save_analysis_results()

    # Generate report
    report = analyzer.generate_network_report()

    # Save report
    report_file = f"reports/{case_id}_network_report.json"
    import os
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Network analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Network Analysis Summary:")
    print(f"   Total connections: {report['summary']['total_connections']}")
    print(f"   Suspicious activities: {report['summary']['suspicious_activities']}")
    print(f"   Unique source IPs: {report['summary']['unique_source_ips']}")

    if report['suspicious_activities']:
        print(f"\n🚨 Suspicious Activities:")
        for activity in report['suspicious_activities'][:5]:
            print(f"   • {activity['type']}: {activity['description']} ({activity['severity']})")

if __name__ == "__main__":
    main()
```

### Step 5: Timeline Reconstruction and Professional Reporting (90 minutes)

```python
# timeline_reconstructor.py
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

class TimelineEvent:
    """Individual event in the investigation timeline"""

    def __init__(self, timestamp: datetime, event_type: str, source_system: str,
                 description: str, entities: List[str], evidence_hash: str,
                 severity: str = "INFO"):
        self.timestamp = timestamp
        self.event_type = event_type
        self.source_system = source_system
        self.description = description
        self.entities = entities
        self.evidence_hash = evidence_hash
        self.severity = severity
        self.mitre_technique = ""
        self.attack_phase = ""

    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'source_system': self.source_system,
            'description': self.description,
            'entities': self.entities,
            'evidence_hash': self.evidence_hash,
            'severity': self.severity,
            'mitre_technique': self.mitre_technique,
            'attack_phase': self.attack_phase
        }

class InvestigationTimelineReconstructor:
    """Reconstruct comprehensive investigation timeline"""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_db_path = f"evidence/{case_id}_integrated_evidence.db"
        self.timeline_events = []

        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'certificate_validation_failed': 'T1553.004',  # Subvert Trust Controls
            'mfa_bypass_attempt': 'T1556',  # Modify Authentication Process
            'privilege_escalation': 'T1068',  # Exploitation for Privilege Escalation
            'permission_change': 'T1484',  # Domain Policy Modification
            'correlated_attack': 'T1071',  # Application Layer Protocol
        }

        # Attack phase mapping
        self.attack_phases = {
            'certificate_validation_failed': 'Initial Access',
            'mfa_bypass_attempt': 'Defense Evasion',
            'privilege_escalation': 'Privilege Escalation',
            'permission_change': 'Persistence',
            'correlated_attack': 'Command and Control'
        }

    def load_evidence_and_correlations(self) -> Tuple[List[Dict], List[Dict]]:
        """Load evidence items and correlation clusters"""
        conn = sqlite3.connect(self.evidence_db_path)
        cursor = conn.cursor()

        # Load evidence items
        cursor.execute('''
            SELECT evidence_hash, source_system, timestamp, event_type,
                   event_details, affected_entities, confidence_score
            FROM evidence_items
            ORDER BY timestamp
        ''')

        evidence_items = []
        for row in cursor.fetchall():
            evidence_items.append({
                'evidence_hash': row[0],
                'source_system': row[1],
                'timestamp': datetime.fromisoformat(row[2]),
                'event_type': row[3],
                'event_details': json.loads(row[4]),
                'affected_entities': json.loads(row[5]),
                'confidence_score': row[6]
            })

        # Load correlation clusters
        cursor.execute('''
            SELECT cluster_id, evidence_hashes, correlation_type, correlation_score
            FROM correlation_clusters
        ''')

        correlation_clusters = []
        for row in cursor.fetchall():
            correlation_clusters.append({
                'cluster_id': row[0],
                'evidence_hashes': json.loads(row[1]),
                'correlation_type': row[2],
                'correlation_score': row[3]
            })

        conn.close()
        return evidence_items, correlation_clusters

    def create_timeline_events(self, evidence_items: List[Dict]) -> List[TimelineEvent]:
        """Convert evidence items to timeline events"""
        timeline_events = []

        for evidence in evidence_items:
            # Determine severity based on event type and content
            severity = self.determine_event_severity(evidence)

            # Create timeline event
            event = TimelineEvent(
                timestamp=evidence['timestamp'],
                event_type=evidence['event_type'],
                source_system=evidence['source_system'],
                description=self.generate_event_description(evidence),
                entities=evidence['affected_entities'],
                evidence_hash=evidence['evidence_hash'],
                severity=severity
            )

            # Add MITRE mapping
            event.mitre_technique = self.mitre_mapping.get(evidence['event_type'], '')
            event.attack_phase = self.attack_phases.get(evidence['event_type'], 'Unknown')

            timeline_events.append(event)

        return timeline_events

    def determine_event_severity(self, evidence: Dict) -> str:
        """Determine event severity based on type and content"""
        event_type = evidence['event_type'].lower()

        if any(term in event_type for term in ['failed', 'bypass', 'escalation', 'attack']):
            return "HIGH"
        elif any(term in event_type for term in ['change', 'modification', 'access']):
            return "MEDIUM"
        else:
            return "INFO"

    def generate_event_description(self, evidence: Dict) -> str:
        """Generate human-readable event description"""
        event_type = evidence['event_type']
        details = evidence['event_details']
        entities = evidence['affected_entities']

        if event_type == 'certificate_validation_failed':
            return f"Certificate validation failed for {details.get('certificate_subject', 'unknown')} from {entities[0] if entities else 'unknown'}"
        elif event_type == 'mfa_bypass_attempt':
            return f"MFA bypass attempt for user {details.get('username', 'unknown')} from {details.get('source_ip', 'unknown')}"
        elif event_type == 'privilege_escalation':
            return f"Privilege escalation: {details.get('user_affected', 'unknown')} granted {details.get('new_permissions', 'unknown')} permissions"
        elif event_type == 'correlated_attack':
            return f"SIEM correlation: {details.get('alert_name', 'unknown')} affecting {len(entities)} entities"
        else:
            return f"{event_type.replace('_', ' ').title()} event involving {entities[0] if entities else 'unknown'}"

    def identify_attack_progression(self, timeline_events: List[TimelineEvent],
                                  correlation_clusters: List[Dict]) -> List[Dict]:
        """Identify attack progression phases"""
        attack_progressions = []

        # Group events by correlation clusters
        cluster_events = defaultdict(list)
        evidence_to_cluster = {}

        for cluster in correlation_clusters:
            for evidence_hash in cluster['evidence_hashes']:
                evidence_to_cluster[evidence_hash] = cluster['cluster_id']

        for event in timeline_events:
            cluster_id = evidence_to_cluster.get(event.evidence_hash, 'UNCLUSTERED')
            cluster_events[cluster_id].append(event)

        # Analyze each cluster for attack progression
        for cluster_id, events in cluster_events.items():
            if cluster_id == 'UNCLUSTERED' or len(events) < 2:
                continue

            # Sort events by timestamp
            events.sort(key=lambda x: x.timestamp)

            # Identify progression phases
            phases = []
            current_phase = None

            for event in events:
                if event.attack_phase != current_phase:
                    phases.append({
                        'phase': event.attack_phase,
                        'start_time': event.timestamp,
                        'events': [event],
                        'mitre_techniques': [event.mitre_technique] if event.mitre_technique else []
                    })
                    current_phase = event.attack_phase
                else:
                    phases[-1]['events'].append(event)
                    if event.mitre_technique and event.mitre_technique not in phases[-1]['mitre_techniques']:
                        phases[-1]['mitre_techniques'].append(event.mitre_technique)

            if len(phases) > 1:
                progression = {
                    'cluster_id': cluster_id,
                    'progression_type': 'multi_phase_attack',
                    'total_phases': len(phases),
                    'duration': (events[-1].timestamp - events[0].timestamp).total_seconds() / 60,  # minutes
                    'phases': phases,
                    'entities_involved': list(set(entity for event in events for entity in event.entities)),
                    'severity': 'HIGH' if any(e.severity == 'HIGH' for e in events) else 'MEDIUM'
                }
                attack_progressions.append(progression)

        return attack_progressions

    def detect_timeline_gaps(self, timeline_events: List[TimelineEvent]) -> List[Dict]:
        """Detect suspicious gaps in the timeline"""
        if len(timeline_events) < 2:
            return []

        gaps = []
        sorted_events = sorted(timeline_events, key=lambda x: x.timestamp)

        for i in range(len(sorted_events) - 1):
            current_event = sorted_events[i]
            next_event = sorted_events[i + 1]

            time_gap = (next_event.timestamp - current_event.timestamp).total_seconds() / 60  # minutes

            # Flag gaps longer than 2 hours during what appears to be active periods
            if time_gap > 120:  # 2 hours
                # Check if this is during an active attack period
                if (current_event.severity in ['HIGH', 'MEDIUM'] and
                    next_event.severity in ['HIGH', 'MEDIUM']):

                    gaps.append({
                        'gap_start': current_event.timestamp,
                        'gap_end': next_event.timestamp,
                        'gap_duration_minutes': time_gap,
                        'before_event': current_event.description,
                        'after_event': next_event.description,
                        'potential_tampering': time_gap > 360,  # 6 hours
                        'severity': 'HIGH' if time_gap > 360 else 'MEDIUM'
                    })

        return gaps

    def generate_professional_timeline_report(self, timeline_events: List[TimelineEvent],
                                            attack_progressions: List[Dict],
                                            timeline_gaps: List[Dict]) -> Dict:
        """Generate comprehensive timeline analysis report"""
        # Sort events by timestamp
        sorted_events = sorted(timeline_events, key=lambda x: x.timestamp)

        # Calculate summary statistics
        total_duration = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 3600  # hours
        severity_counts = defaultdict(int)
        source_counts = defaultdict(int)
        phase_counts = defaultdict(int)

        for event in timeline_events:
            severity_counts[event.severity] += 1
            source_counts[event.source_system] += 1
            phase_counts[event.attack_phase] += 1

        # Create executive summary
        executive_summary = {
            'investigation_period': {
                'start': sorted_events[0].timestamp.isoformat(),
                'end': sorted_events[-1].timestamp.isoformat(),
                'duration_hours': round(total_duration, 2)
            },
            'event_summary': {
                'total_events': len(timeline_events),
                'high_severity': severity_counts['HIGH'],
                'medium_severity': severity_counts['MEDIUM'],
                'info_events': severity_counts['INFO']
            },
            'attack_analysis': {
                'multi_phase_attacks': len(attack_progressions),
                'timeline_gaps': len(timeline_gaps),
                'suspicious_gaps': len([g for g in timeline_gaps if g['potential_tampering']]),
                'mitre_techniques_observed': len(set(e.mitre_technique for e in timeline_events if e.mitre_technique))
            },
            'key_findings': self.generate_key_findings(attack_progressions, timeline_gaps, severity_counts)
        }

        # Create detailed timeline
        detailed_timeline = [event.to_dict() for event in sorted_events]

        # Create attack progression analysis
        progression_analysis = {
            'identified_progressions': attack_progressions,
            'progression_summary': self.summarize_attack_progressions(attack_progressions)
        }

        return {
            'case_id': self.case_id,
            'report_generated': datetime.now().isoformat(),
            'executive_summary': executive_summary,
            'detailed_timeline': detailed_timeline,
            'attack_progression_analysis': progression_analysis,
            'timeline_gaps_analysis': {
                'detected_gaps': timeline_gaps,
                'gap_summary': self.summarize_timeline_gaps(timeline_gaps)
            },
            'mitre_attack_mapping': self.create_mitre_attack_summary(timeline_events),
            'recommendations': self.generate_timeline_recommendations(attack_progressions, timeline_gaps)
        }

    def generate_key_findings(self, attack_progressions: List[Dict],
                            timeline_gaps: List[Dict], severity_counts: Dict) -> List[str]:
        """Generate key findings for executive summary"""
        findings = []

        if severity_counts['HIGH'] > 0:
            findings.append(f"Identified {severity_counts['HIGH']} high-severity security events requiring immediate attention")

        if attack_progressions:
            multi_phase_attacks = len(attack_progressions)
            findings.append(f"Detected {multi_phase_attacks} coordinated multi-phase attack{'s' if multi_phase_attacks > 1 else ''}")

        suspicious_gaps = [g for g in timeline_gaps if g['potential_tampering']]
        if suspicious_gaps:
            findings.append(f"Found {len(suspicious_gaps)} suspicious timeline gap{'s' if len(suspicious_gaps) > 1 else ''} indicating potential evidence tampering")

        if not findings:
            findings.append("Timeline analysis shows normal security operations with no critical attack patterns detected")

        return findings

    def summarize_attack_progressions(self, progressions: List[Dict]) -> Dict:
        """Summarize attack progression findings"""
        if not progressions:
            return {'total_progressions': 0, 'recommendations': []}

        total_duration = sum(p['duration'] for p in progressions)
        avg_duration = total_duration / len(progressions)

        phase_frequency = defaultdict(int)
        for progression in progressions:
            for phase_info in progression['phases']:
                phase_frequency[phase_info['phase']] += 1

        return {
            'total_progressions': len(progressions),
            'average_duration_minutes': round(avg_duration, 2),
            'common_attack_phases': dict(phase_frequency),
            'recommendations': [
                "Investigate multi-phase attack sequences for coordinated threat activity",
                "Review security controls for attack phase transitions",
                "Implement additional monitoring for identified attack patterns"
            ]
        }

    def summarize_timeline_gaps(self, gaps: List[Dict]) -> Dict:
        """Summarize timeline gap analysis"""
        if not gaps:
            return {'total_gaps': 0, 'potential_tampering': 0, 'recommendations': []}

        potential_tampering = sum(1 for gap in gaps if gap['potential_tampering'])
        avg_gap_duration = sum(gap['gap_duration_minutes'] for gap in gaps) / len(gaps)

        recommendations = []
        if potential_tampering > 0:
            recommendations.append(f"Investigate {potential_tampering} suspicious timeline gaps for evidence tampering")
        recommendations.append("Review log retention and collection policies to minimize evidence gaps")

        return {
            'total_gaps': len(gaps),
            'potential_tampering': potential_tampering,
            'average_gap_duration_minutes': round(avg_gap_duration, 2),
            'recommendations': recommendations
        }

    def create_mitre_attack_summary(self, timeline_events: List[TimelineEvent]) -> Dict:
        """Create MITRE ATT&CK technique summary"""
        technique_counts = defaultdict(int)
        phase_techniques = defaultdict(set)

        for event in timeline_events:
            if event.mitre_technique:
                technique_counts[event.mitre_technique] += 1
                phase_techniques[event.attack_phase].add(event.mitre_technique)

        return {
            'techniques_observed': dict(technique_counts),
            'techniques_by_phase': {phase: list(techniques) for phase, techniques in phase_techniques.items()},
            'total_unique_techniques': len(technique_counts)
        }

    def generate_timeline_recommendations(self, attack_progressions: List[Dict],
                                        timeline_gaps: List[Dict]) -> List[str]:
        """Generate timeline-based recommendations"""
        recommendations = []

        if attack_progressions:
            recommendations.append("Implement behavioral analytics to detect multi-phase attack patterns")
            recommendations.append("Enhance correlation rules to identify attack progression sequences")

        if timeline_gaps:
            recommendations.append("Review and strengthen log collection and retention policies")
            recommendations.append("Implement continuous monitoring to minimize evidence gaps")

        recommendations.extend([
            "Regular timeline analysis for incident response procedures",
            "Cross-reference findings with threat intelligence sources",
            "Validate timeline reconstruction methodology for legal admissibility",
            "Document chain of custody for all timeline evidence"
        ])

        return recommendations

def main():
    """Main timeline reconstruction demo"""
    print("⏰ Investigation Timeline Reconstruction")
    print("=" * 45)

    # Create timeline reconstructor
    reconstructor = InvestigationTimelineReconstructor("CASE_MULTI_20240115")

    # Load evidence and correlations
    evidence_items, correlation_clusters = reconstructor.load_evidence_and_correlations()

    if not evidence_items:
        print("❌ No evidence items found. Run previous analysis steps first.")
        return

    print(f"📊 Loaded {len(evidence_items)} evidence items and {len(correlation_clusters)} correlation clusters")

    # Create timeline events
    timeline_events = reconstructor.create_timeline_events(evidence_items)

    # Identify attack progressions
    attack_progressions = reconstructor.identify_attack_progression(timeline_events, correlation_clusters)

    # Detect timeline gaps
    timeline_gaps = reconstructor.detect_timeline_gaps(timeline_events)

    # Generate comprehensive report
    timeline_report = reconstructor.generate_professional_timeline_report(
        timeline_events, attack_progressions, timeline_gaps
    )

    # Save report
    report_file = f"reports/{reconstructor.case_id}_timeline_report.json"
    import os
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(timeline_report, f, indent=2)

    print(f"\n📄 Timeline reconstruction report saved to: {report_file}")

    # Display summary
    summary = timeline_report['executive_summary']
    print(f"\n📈 Timeline Analysis Summary:")
    print(f"   Investigation period: {summary['investigation_period']['duration_hours']:.1f} hours")
    print(f"   Total events: {summary['event_summary']['total_events']}")
    print(f"   High-severity events: {summary['event_summary']['high_severity']}")
    print(f"   Multi-phase attacks: {summary['attack_analysis']['multi_phase_attacks']}")
    print(f"   Timeline gaps: {summary['attack_analysis']['timeline_gaps']}")

    # Show key findings
    print(f"\n🔍 Key Findings:")
    for finding in summary['key_findings']:
        print(f"   • {finding}")

if __name__ == "__main__":
    main()
```

# investigation_reporter.py
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
from pathlib import Path

class ProfessionalInvestigationReporter:
    """Generate professional forensic investigation reports"""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.evidence_db_path = f"evidence/{case_id}_integrated_evidence.db"
        self.report_metadata = {
            'case_id': case_id,
            'investigator': 'Digital Forensics Analyst',
            'organization': 'Security Investigation Team',
            'report_date': datetime.now().isoformat(),
            'methodology': 'Multi-Source Evidence Correlation and Timeline Analysis',
            'legal_standards': ['Daubert Criteria', 'Federal Rules of Evidence 702-705']
        }

    def load_all_investigation_data(self) -> Dict:
        """Load all investigation data for comprehensive reporting"""
        try:
            # Load timeline report
            timeline_file = f"reports/{self.case_id}_timeline_report.json"
            with open(timeline_file, 'r') as f:
                timeline_data = json.load(f)

            # Load evidence items
            conn = sqlite3.connect(self.evidence_db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM evidence_items')
            total_evidence = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM correlation_clusters')
            total_clusters = cursor.fetchone()[0]

            conn.close()

            return {
                'timeline_analysis': timeline_data,
                'evidence_statistics': {
                    'total_evidence_items': total_evidence,
                    'correlation_clusters': total_clusters
                },
                'status': 'complete'
            }
        except FileNotFoundError as e:
            return {'status': 'incomplete', 'error': str(e)}

    def generate_executive_summary(self, investigation_data: Dict) -> Dict:
        """Generate executive summary for senior management"""
        timeline_data = investigation_data.get('timeline_analysis', {})
        exec_summary = timeline_data.get('executive_summary', {})

        return {
            'incident_overview': {
                'case_id': self.case_id,
                'investigation_scope': 'Multi-source security event correlation and timeline analysis',
                'investigation_period': exec_summary.get('investigation_period', {}),
                'systems_analyzed': ['PKI Certificate System', 'MFA Authentication', 'RBAC Authorization', 'Network Security', 'SIEM Platform'],
                'evidence_sources': 5
            },
            'key_findings': exec_summary.get('key_findings', []),
            'security_impact': self.assess_security_impact(exec_summary),
            'business_impact': self.assess_business_impact(exec_summary),
            'immediate_actions_required': self.generate_immediate_actions(exec_summary),
            'investigation_confidence': self.calculate_investigation_confidence(investigation_data)
        }

    def assess_security_impact(self, exec_summary: Dict) -> Dict:
        """Assess overall security impact"""
        event_summary = exec_summary.get('event_summary', {})
        attack_analysis = exec_summary.get('attack_analysis', {})

        high_severity = event_summary.get('high_severity', 0)
        multi_phase_attacks = attack_analysis.get('multi_phase_attacks', 0)

        if high_severity > 3 or multi_phase_attacks > 1:
            impact_level = 'HIGH'
            description = 'Coordinated attack with multiple high-severity events detected'
        elif high_severity > 0 or multi_phase_attacks > 0:
            impact_level = 'MEDIUM'
            description = 'Security incidents requiring investigation and remediation'
        else:
            impact_level = 'LOW'
            description = 'Normal security operations with routine monitoring events'

        return {
            'impact_level': impact_level,
            'description': description,
            'affected_systems': ['Authentication Systems', 'Network Infrastructure', 'Access Controls'],
            'data_at_risk': 'User credentials, system access logs, network communications'
        }

    def assess_business_impact(self, exec_summary: Dict) -> Dict:
        """Assess business impact of security events"""
        attack_analysis = exec_summary.get('attack_analysis', {})

        if attack_analysis.get('multi_phase_attacks', 0) > 0:
            return {
                'impact_level': 'MEDIUM-HIGH',
                'description': 'Potential compromise of critical security infrastructure',
                'operational_impact': 'May require system isolation and credential resets',
                'compliance_impact': 'Potential reporting requirements under security frameworks',
                'reputation_risk': 'Moderate risk if attack progression continues unmitigated'
            }
        else:
            return {
                'impact_level': 'LOW',
                'description': 'Routine security events within normal operational parameters',
                'operational_impact': 'Minimal disruption to business operations',
                'compliance_impact': 'Standard security monitoring and documentation',
                'reputation_risk': 'No significant reputation risk identified'
            }

    def generate_immediate_actions(self, exec_summary: Dict) -> List[str]:
        """Generate immediate action items"""
        actions = []

        event_summary = exec_summary.get('event_summary', {})
        attack_analysis = exec_summary.get('attack_analysis', {})

        if event_summary.get('high_severity', 0) > 0:
            actions.append("Investigate all high-severity security events immediately")

        if attack_analysis.get('multi_phase_attacks', 0) > 0:
            actions.append("Analyze coordinated attack patterns for ongoing threats")

        if attack_analysis.get('suspicious_gaps', 0) > 0:
            actions.append("Investigate timeline gaps for potential evidence tampering")

        actions.extend([
            "Review and update security monitoring coverage",
            "Validate incident response procedures",
            "Document lessons learned for future investigations"
        ])

        return actions

    def calculate_investigation_confidence(self, investigation_data: Dict) -> Dict:
        """Calculate confidence in investigation findings"""
        evidence_stats = investigation_data.get('evidence_statistics', {})
        timeline_data = investigation_data.get('timeline_analysis', {})

        evidence_count = evidence_stats.get('total_evidence_items', 0)
        correlation_count = evidence_stats.get('correlation_clusters', 0)

        # Calculate confidence based on evidence quantity and correlation
        if evidence_count >= 5 and correlation_count >= 2:
            confidence_level = 'HIGH'
            description = 'Multiple correlated evidence sources provide high confidence in findings'
        elif evidence_count >= 3:
            confidence_level = 'MEDIUM'
            description = 'Adequate evidence sources support investigation conclusions'
        else:
            confidence_level = 'LOW'
            description = 'Limited evidence sources require additional investigation'

        return {
            'confidence_level': confidence_level,
            'description': description,
            'evidence_sources': evidence_count,
            'correlation_clusters': correlation_count,
            'methodology_validation': 'Forensic analysis follows NIST SP 800-86 guidelines'
        }

    def generate_technical_analysis_section(self, investigation_data: Dict) -> Dict:
        """Generate detailed technical analysis section"""
        timeline_data = investigation_data.get('timeline_analysis', {})

        return {
            'methodology': {
                'approach': 'Multi-source evidence correlation with timeline reconstruction',
                'tools_used': ['Custom Python forensic analysis platform', 'SQLite evidence database', 'Statistical correlation algorithms'],
                'standards_followed': ['NIST SP 800-86', 'ISO/IEC 27037', 'MITRE ATT&CK Framework'],
                'validation_performed': 'Cross-source evidence validation and confidence scoring'
            },
            'evidence_analysis': {
                'sources_integrated': ['PKI Certificate Validation', 'MFA Authentication Events', 'RBAC Permission Changes', 'Network Security Monitoring', 'SIEM Correlation Alerts'],
                'correlation_techniques': ['Temporal correlation within 30-minute windows', 'Entity-based correlation', 'Attack pattern recognition'],
                'timeline_reconstruction': timeline_data.get('detailed_timeline', [])[:10],  # First 10 events
                'mitre_attack_mapping': timeline_data.get('mitre_attack_mapping', {})
            },
            'correlation_findings': timeline_data.get('attack_progression_analysis', {}),
            'gap_analysis': timeline_data.get('timeline_gaps_analysis', {})
        }

    def generate_legal_admissibility_section(self) -> Dict:
        """Generate legal admissibility and chain of custody section"""
        return {
            'chain_of_custody': {
                'evidence_handling': 'All digital evidence handled according to forensic best practices',
                'integrity_verification': 'SHA-256 hash verification performed on all evidence items',
                'access_controls': 'Evidence database protected with access logging and integrity monitoring',
                'documentation': 'Complete audit trail maintained for all evidence handling activities'
            },
            'methodology_validation': {
                'scientific_reliability': 'Correlation algorithms based on established forensic methodologies',
                'peer_review': 'Analysis techniques validated against industry standards',
                'error_rate': 'Statistical confidence measures applied to all correlations',
                'general_acceptance': 'Methods align with NIST and ISO forensic guidelines'
            },
            'daubert_criteria_compliance': {
                'testability': 'Correlation algorithms can be independently verified',
                'peer_review_publication': 'Methodology follows published forensic analysis standards',
                'error_rate': 'Confidence scoring provides quantitative accuracy measures',
                'general_acceptance': 'Techniques accepted in digital forensics community'
            },
            'expert_qualifications': {
                'investigator_credentials': 'Certified digital forensics analyst',
                'methodology_expertise': 'Specialized training in multi-source evidence correlation',
                'continuing_education': 'Regular updates on forensic analysis best practices'
            }
        }

    def generate_comprehensive_report(self) -> Dict:
        """Generate complete professional investigation report"""
        # Load all investigation data
        investigation_data = self.load_all_investigation_data()

        if investigation_data.get('status') != 'complete':
            return {
                'status': 'error',
                'message': 'Investigation data incomplete. Run all analysis steps first.',
                'missing_data': investigation_data.get('error', '')
            }

        # Generate report sections
        report = {
            'report_metadata': self.report_metadata,
            'executive_summary': self.generate_executive_summary(investigation_data),
            'technical_analysis': self.generate_technical_analysis_section(investigation_data),
            'legal_admissibility': self.generate_legal_admissibility_section(),
            'conclusions_and_recommendations': self.generate_conclusions_recommendations(investigation_data),
            'appendices': {
                'full_timeline': investigation_data['timeline_analysis'].get('detailed_timeline', []),
                'evidence_inventory': f"Total evidence items: {investigation_data['evidence_statistics']['total_evidence_items']}",
                'correlation_details': investigation_data['timeline_analysis'].get('attack_progression_analysis', {})
            }
        }

        return report

    def generate_conclusions_recommendations(self, investigation_data: Dict) -> Dict:
        """Generate conclusions and recommendations"""
        timeline_data = investigation_data.get('timeline_analysis', {})

        return {
            'investigation_conclusions': [
                'Multi-source evidence correlation successfully reconstructed security event timeline',
                'Investigation methodology provides legally admissible findings',
                'Evidence integrity maintained throughout analysis process'
            ],
            'security_recommendations': timeline_data.get('recommendations', []),
            'process_improvements': [
                'Implement automated correlation for real-time threat detection',
                'Enhance log collection coverage for comprehensive evidence gathering',
                'Regular validation of forensic analysis procedures'
            ],
            'follow_up_actions': [
                'Monitor identified entities for continued suspicious activity',
                'Update security controls based on attack pattern analysis',
                'Schedule follow-up investigation in 30 days'
            ]
        }

def main():
    """Main investigation reporting demo"""
    print("📋 Professional Investigation Report Generation")
    print("=" * 50)

    # Create reporter
    reporter = ProfessionalInvestigationReporter("CASE_MULTI_20240115")

    # Generate comprehensive report
    investigation_report = reporter.generate_comprehensive_report()

    if investigation_report.get('status') == 'error':
        print(f"❌ {investigation_report['message']}")
        return

    # Save report
    report_file = f"reports/{reporter.case_id}_final_investigation_report.json"
    with open(report_file, 'w') as f:
        json.dump(investigation_report, f, indent=2)

    print(f"📄 Comprehensive investigation report saved to: {report_file}")

    # Display executive summary
    exec_summary = investigation_report['executive_summary']
    print(f"\n📊 Executive Summary:")
    print(f"   Case ID: {exec_summary['incident_overview']['case_id']}")
    print(f"   Security Impact: {exec_summary['security_impact']['impact_level']}")
    print(f"   Business Impact: {exec_summary['business_impact']['impact_level']}")
    print(f"   Investigation Confidence: {exec_summary['investigation_confidence']['confidence_level']}")

    # Show key findings
    print(f"\n🔍 Key Findings:")
    for finding in exec_summary['key_findings']:
        print(f"   • {finding}")

    # Show immediate actions
    print(f"\n⚡ Immediate Actions Required:")
    for action in exec_summary['immediate_actions_required'][:3]:
        print(f"   • {action}")

if __name__ == "__main__":
    main()
```
    def __init__(self, path: str, name: str, value: Any, reg_type: str):
        self.path = path
        self.name = name
        self.value = value
        self.reg_type = reg_type
        self.last_modified = datetime.now()
        self.suspicious_score = 0
        self.analysis_notes = []

    def to_dict(self):
        return {
            'path': self.path,
            'name': self.name,
            'value': str(self.value) if self.value is not None else '',
            'type': self.reg_type,
            'last_modified': self.last_modified.isoformat(),
            'suspicious_score': self.suspicious_score,
            'analysis_notes': self.analysis_notes
        }

class RegistryAnalyzer:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.registry_keys = {}
        self.suspicious_findings = []
        self.persistence_mechanisms = []
        self.user_activities = []

        # Initialize analysis database
        self.db_path = f"registry_dumps/{case_id}_registry_analysis.db"
        self.init_database()

        # Load suspicious patterns
        self.load_suspicious_patterns()

    def init_database(self):
        """Initialize registry analysis database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registry_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                name TEXT,
                value TEXT,
                reg_type TEXT,
                last_modified TEXT,
                suspicious_score INTEGER,
                analysis_notes TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_type TEXT,
                registry_path TEXT,
                description TEXT,
                severity TEXT,
                indicators TEXT,
                discovered_at TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_type TEXT,
                user_sid TEXT,
                timestamp TEXT,
                description TEXT,
                registry_evidence TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def load_suspicious_patterns(self):
        """Load patterns for detecting suspicious registry activities"""
        self.suspicious_patterns = {
            'persistence_locations': [
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
                r'HKLM\SYSTEM\CurrentControlSet\Services'
            ],
            'suspicious_executables': [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
                'regsvr32.exe', 'rundll32.exe', 'mshta.exe'
            ],
            'malware_indicators': [
                'temp', 'appdata', 'windows\\system32', 'programdata',
                'startup', 'roaming', 'local\\temp'
            ],
            'encoding_indicators': [
                'base64', 'powershell -e', 'invoke-expression', 'downloadstring'
            ]
        }

    def simulate_registry_dump(self):
        """Simulate Windows registry dump for analysis"""
        print("📋 Simulating Windows registry dump...")

        # Simulate common registry entries
        registry_entries = [
            # Normal entries
            {
                'path': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'SecurityHealth',
                'value': r'%windir%\system32\SecurityHealthSystray.exe',
                'type': 'REG_SZ'
            },
            {
                'path': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'WindowsDefender',
                'value': r'%ProgramFiles%\Windows Defender\MSASCuiL.exe',
                'type': 'REG_SZ'
            },

            # Suspicious entries
            {
                'path': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'SystemUpdate',
                'value': r'%TEMP%\update.exe',
                'type': 'REG_SZ'
            },
            {
                'path': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'GoogleUpdate',
                'value': r'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\script.ps1',
                'type': 'REG_SZ'
            },
            {
                'path': r'HKLM\SYSTEM\CurrentControlSet\Services\Backdoor',
                'name': 'ImagePath',
                'value': r'C:\Windows\System32\svchost.exe -k netsvcs',
                'type': 'REG_SZ'
            },

            # User activity traces
            {
                'path': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                'name': '.txt',
                'value': 'confidential_data.txt',
                'type': 'REG_BINARY'
            },
            {
                'path': r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
                'name': 'HRZR_PGYFRFFVBA',  # ROT13 encoded
                'value': '00000005000000000000000000000000',
                'type': 'REG_BINARY'
            },

            # Network configuration
            {
                'path': r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{12345678-1234-1234-1234-123456789012}',
                'name': 'DhcpNameServer',
                'value': '8.8.8.8 8.8.4.4',
                'type': 'REG_SZ'
            }
        ]

        # Create registry key objects
        for entry in registry_entries:
            key = RegistryKey(
                entry['path'],
                entry['name'],
                entry['value'],
                entry['type']
            )

            key_id = f"{entry['path']}\\{entry['name']}"
            self.registry_keys[key_id] = key

        print(f"✅ Simulated {len(registry_entries)} registry entries")

    def analyze_registry(self) -> Dict:
        """Perform comprehensive registry analysis"""
        print("🔍 Analyzing registry for suspicious activities...")

        analysis_results = {
            'total_keys_analyzed': len(self.registry_keys),
            'persistence_mechanisms': [],
            'user_activities': [],
            'suspicious_findings': [],
            'malware_indicators': [],
            'timeline_events': []
        }

        # Analyze each registry key
        for key_id, reg_key in self.registry_keys.items():
            # Check for persistence mechanisms
            self.check_persistence_mechanisms(reg_key, analysis_results)

            # Check for user activities
            self.check_user_activities(reg_key, analysis_results)

            # Check for malware indicators
            self.check_malware_indicators(reg_key, analysis_results)

            # Add to timeline
            analysis_results['timeline_events'].append({
                'timestamp': reg_key.last_modified,
                'type': 'Registry Modification',
                'path': reg_key.path,
                'description': f"Registry key {reg_key.name} modified"
            })

        print(f"✅ Registry analysis complete:")
        print(f"   Persistence mechanisms: {len(analysis_results['persistence_mechanisms'])}")
        print(f"   User activities: {len(analysis_results['user_activities'])}")
        print(f"   Suspicious findings: {len(analysis_results['suspicious_findings'])}")

        return analysis_results

    def check_persistence_mechanisms(self, reg_key: RegistryKey, results: Dict):
        """Check for malware persistence mechanisms"""
        # Check if key is in known persistence location
        for persistence_path in self.suspicious_patterns['persistence_locations']:
            if persistence_path.lower() in reg_key.path.lower():

                # Analyze the value for suspicious content
                suspicious_score = 0
                indicators = []

                # Check for suspicious executables
                for sus_exe in self.suspicious_patterns['suspicious_executables']:
                    if sus_exe.lower() in reg_key.value.lower():
                        suspicious_score += 3
                        indicators.append(f"Uses suspicious executable: {sus_exe}")

                # Check for suspicious paths
                for mal_indicator in self.suspicious_patterns['malware_indicators']:
                    if mal_indicator.lower() in reg_key.value.lower():
                        suspicious_score += 2
                        indicators.append(f"Suspicious path: {mal_indicator}")

                # Check for encoding
                for encoding in self.suspicious_patterns['encoding_indicators']:
                    if encoding.lower() in reg_key.value.lower():
                        suspicious_score += 4
                        indicators.append(f"Potential encoding/obfuscation: {encoding}")

                if suspicious_score > 0:
                    reg_key.suspicious_score = suspicious_score
                    reg_key.analysis_notes.extend(indicators)

                    finding = {
                        'type': 'Persistence Mechanism',
                        'path': reg_key.path,
                        'name': reg_key.name,
                        'value': reg_key.value,
                        'suspicious_score': suspicious_score,
                        'indicators': indicators,
                        'severity': 'HIGH' if suspicious_score >= 5 else 'MEDIUM'
                    }

                    results['persistence_mechanisms'].append(finding)
                    self.persistence_mechanisms.append(finding)

                    if suspicious_score >= 5:
                        results['suspicious_findings'].append({
                            'type': 'High-Risk Persistence',
                            'description': f"Highly suspicious persistence mechanism in {reg_key.path}",
                            'evidence': reg_key.value,
                            'severity': 'HIGH'
                        })

    def check_user_activities(self, reg_key: RegistryKey, results: Dict):
        """Check for user activity traces"""
        user_activity_paths = [
            r'RecentDocs',
            r'UserAssist',
            r'MUICache',
            r'ComDlg32\OpenSavePidlMRU',
            r'ComDlg32\LastVisitedPidlMRU'
        ]

        for activity_path in user_activity_paths:
            if activity_path.lower() in reg_key.path.lower():

                activity = {
                    'type': self.get_activity_type(activity_path),
                    'path': reg_key.path,
                    'evidence': reg_key.value,
                    'timestamp': reg_key.last_modified,
                    'description': self.interpret_user_activity(activity_path, reg_key)
                }

                results['user_activities'].append(activity)
                self.user_activities.append(activity)

                # Check if activity is suspicious
                if self.is_suspicious_user_activity(activity):
                    results['suspicious_findings'].append({
                        'type': 'Suspicious User Activity',
                        'description': activity['description'],
                        'evidence': reg_key.path,
                        'severity': 'MEDIUM'
                    })

    def check_malware_indicators(self, reg_key: RegistryKey, results: Dict):
        """Check for malware-related indicators"""
        malware_indicators = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit',
            'keylogger', 'botnet', 'c2', 'command', 'control'
        ]

        for indicator in malware_indicators:
            if indicator.lower() in reg_key.value.lower() or indicator.lower() in reg_key.name.lower():
                finding = {
                    'type': 'Malware Indicator',
                    'path': reg_key.path,
                    'indicator': indicator,
                    'evidence': reg_key.value,
                    'severity': 'HIGH'
                }

                results['malware_indicators'].append(finding)
                results['suspicious_findings'].append({
                    'type': 'Malware Indicator',
                    'description': f"Potential malware indicator '{indicator}' found",
                    'evidence': f"{reg_key.path}\\{reg_key.name}",
                    'severity': 'HIGH'
                })

    def get_activity_type(self, path: str) -> str:
        """Determine activity type from registry path"""
        activity_map = {
            'RecentDocs': 'Recent Documents',
            'UserAssist': 'Program Execution',
            'MUICache': 'Application Usage',
            'OpenSavePidlMRU': 'File Dialog Activity',
            'LastVisitedPidlMRU': 'Folder Access'
        }

        for key, activity_type in activity_map.items():
            if key.lower() in path.lower():
                return activity_type

        return 'Unknown Activity'

    def interpret_user_activity(self, activity_path: str, reg_key: RegistryKey) -> str:
        """Interpret user activity based on registry data"""
        if 'RecentDocs' in activity_path:
            return f"User accessed document: {reg_key.value}"
        elif 'UserAssist' in activity_path:
            # Decode ROT13 if present
            try:
                decoded = ''.join([chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if c.isupper()
                                 else chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if c.islower()
                                 else c for c in reg_key.name])
                return f"User executed program: {decoded}"
            except:
                return f"User executed program: {reg_key.name}"
        elif 'MUICache' in activity_path:
            return f"Application used: {reg_key.name}"
        else:
            return f"User activity detected: {reg_key.value}"

    def is_suspicious_user_activity(self, activity: Dict) -> bool:
        """Determine if user activity is suspicious"""
        suspicious_files = [
            'confidential', 'secret', 'password', 'admin', 'private',
            'malware', 'hack', 'exploit', 'payload'
        ]

        evidence = activity['evidence'].lower()
        return any(sus_file in evidence for sus_file in suspicious_files)

    def save_analysis_results(self):
        """Save registry analysis results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save registry keys
        for reg_key in self.registry_keys.values():
            cursor.execute('''
                INSERT OR REPLACE INTO registry_keys
                (path, name, value, reg_type, last_modified, suspicious_score, analysis_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                reg_key.path,
                reg_key.name,
                reg_key.value,
                reg_key.reg_type,
                reg_key.last_modified.isoformat(),
                reg_key.suspicious_score,
                json.dumps(reg_key.analysis_notes)
            ))

        # Save suspicious findings
        for finding in self.suspicious_findings:
            cursor.execute('''
                INSERT INTO suspicious_findings
                (finding_type, registry_path, description, severity, indicators, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                finding['type'],
                finding.get('path', ''),
                finding['description'],
                finding['severity'],
                json.dumps(finding.get('indicators', [])),
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

    def generate_registry_report(self) -> Dict:
        """Generate comprehensive registry analysis report"""
        report = {
            'case_id': self.case_id,
            'analysis_date': datetime.now().isoformat(),
            'summary': {
                'total_keys_analyzed': len(self.registry_keys),
                'persistence_mechanisms_found': len(self.persistence_mechanisms),
                'user_activities_traced': len(self.user_activities),
                'high_risk_findings': len([f for f in self.suspicious_findings if f.get('severity') == 'HIGH'])
            },
            'persistence_analysis': self.persistence_mechanisms,
            'user_activity_timeline': sorted(self.user_activities,
                                           key=lambda x: x['timestamp'], reverse=True),
            'suspicious_findings': self.suspicious_findings,
            'recommendations': self.generate_registry_recommendations()
        }

        return report

    def generate_registry_recommendations(self) -> List[str]:
        """Generate registry security recommendations"""
        recommendations = []

        if self.persistence_mechanisms:
            recommendations.append("Investigate and remove suspicious persistence mechanisms")

        if any(f['severity'] == 'HIGH' for f in self.suspicious_findings):
            recommendations.append("Immediate investigation required for high-risk findings")

        recommendations.extend([
            "Regular registry monitoring and baselines",
            "Implement registry change auditing",
            "Use application whitelisting to prevent unauthorized persistence",
            "Regular malware scans focusing on registry modifications",
            "Monitor AutoRun locations for changes"
        ])

        return recommendations

def main():
    """Main registry analyzer demo"""
    print("📋 Windows Registry Forensic Analysis")
    print("=" * 40)

    # Create analyzer
    case_id = "CASE_REG_20240115"
    analyzer = RegistryAnalyzer(case_id)

    # Simulate registry dump
    analyzer.simulate_registry_dump()

    # Analyze registry
    analysis_results = analyzer.analyze_registry()

    # Save results
    analyzer.save_analysis_results()

    # Generate report
    report = analyzer.generate_registry_report()

    # Save report
    report_file = f"reports/{case_id}_registry_report.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Registry analysis report saved to: {report_file}")

    # Display summary
    print(f"\n📊 Registry Analysis Summary:")
    print(f"   Keys analyzed: {report['summary']['total_keys_analyzed']}")
    print(f"   Persistence mechanisms: {report['summary']['persistence_mechanisms_found']}")
    print(f"   User activities: {report['summary']['user_activities_traced']}")
    print(f"   High-risk findings: {report['summary']['high_risk_findings']}")

    if report['suspicious_findings']:
        print(f"\n🚨 Suspicious Findings:")
        for finding in report['suspicious_findings'][:5]:
            print(f"   • {finding['type']}: {finding['description']} ({finding['severity']})")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: Evidence from different sources has inconsistent timestamps
**Solution**: Standardize all timestamps to UTC during evidence ingestion

### Issue: Correlation algorithms produce too many false positives
**Solution**: Implement confidence scoring and adjust correlation thresholds

### Issue: Timeline reconstruction becomes overwhelming with large datasets
**Solution**: Focus on high-severity events and use clustering to group related activities

### Issue: Report generation fails due to missing data
**Solution**: Implement data validation checks and provide clear error messages for missing components

## ✅ Complete Investigation Workflow

```bash
# Step 1: Integrate evidence from all sources
python evidence_integrator.py

# Step 2: Perform correlation analysis
python network_database_correlator.py

# Step 3: Reconstruct timeline
python timeline_reconstructor.py

# Step 4: Generate professional report
python investigation_reporter.py

# Run complete investigation workflow
python test_investigation_scenario.py
```

### Complete Investigation Test Script

```python
# test_investigation_scenario.py
from evidence_integrator import EvidenceIntegrator
from network_database_correlator import AdvancedCorrelationEngine
from timeline_reconstructor import InvestigationTimelineReconstructor
from investigation_reporter import ProfessionalInvestigationReporter

def run_complete_investigation():
    """Run complete multi-source investigation scenario"""
    case_id = "CASE_MULTI_20240115"

    print("🔬 Running Complete Multi-Source Investigation")
    print("=" * 55)

    # Step 1: Evidence Integration
    print("\n1️⃣ Integrating evidence from all security sources...")
    integrator = EvidenceIntegrator(case_id)
    stats = integrator.generate_sample_evidence()
    integrator.save_evidence_items()
    print(f"   ✅ Integrated {stats['total']} evidence items")

    # Step 2: Correlation Analysis
    print("\n2️⃣ Performing advanced correlation analysis...")
    correlator = AdvancedCorrelationEngine(case_id)
    evidence_items = correlator.load_evidence_items()

    temporal_clusters = correlator.perform_temporal_correlation(evidence_items)
    entity_clusters = correlator.perform_entity_correlation(evidence_items)
    all_clusters = temporal_clusters + entity_clusters

    all_clusters = correlator.identify_attack_patterns(all_clusters, evidence_items)
    correlator.save_correlation_results(all_clusters)
    print(f"   ✅ Created {len(all_clusters)} correlation clusters")

    # Step 3: Timeline Reconstruction
    print("\n3️⃣ Reconstructing investigation timeline...")
    reconstructor = InvestigationTimelineReconstructor(case_id)
    evidence_items, correlation_clusters = reconstructor.load_evidence_and_correlations()

    timeline_events = reconstructor.create_timeline_events(evidence_items)
    attack_progressions = reconstructor.identify_attack_progression(timeline_events, correlation_clusters)
    timeline_gaps = reconstructor.detect_timeline_gaps(timeline_events)

    timeline_report = reconstructor.generate_professional_timeline_report(
        timeline_events, attack_progressions, timeline_gaps
    )

    import os
    os.makedirs("reports", exist_ok=True)
    import json
    with open(f"reports/{case_id}_timeline_report.json", 'w') as f:
        json.dump(timeline_report, f, indent=2)
    print(f"   ✅ Generated timeline with {len(timeline_events)} events")

    # Step 4: Professional Reporting
    print("\n4️⃣ Generating professional investigation report...")
    reporter = ProfessionalInvestigationReporter(case_id)
    investigation_report = reporter.generate_comprehensive_report()

    with open(f"reports/{case_id}_final_investigation_report.json", 'w') as f:
        json.dump(investigation_report, f, indent=2)
    print(f"   ✅ Generated comprehensive investigation report")

    # Display Results Summary
    print("\n📊 Investigation Results Summary:")
    exec_summary = investigation_report['executive_summary']
    print(f"   Security Impact: {exec_summary['security_impact']['impact_level']}")
    print(f"   Investigation Confidence: {exec_summary['investigation_confidence']['confidence_level']}")
    print(f"   Evidence Sources: {exec_summary['incident_overview']['evidence_sources']}")
    print(f"   Key Findings: {len(exec_summary['key_findings'])}")

    print("\n🎯 Key Investigation Findings:")
    for finding in exec_summary['key_findings']:
        print(f"   • {finding}")

    print("\n✅ Complete multi-source investigation successfully completed!")
    print(f"📁 All reports saved to reports/ directory")

if __name__ == "__main__":
    run_complete_investigation()
```
```

## 📁 Expected File Structure
```
week11-multi-source-investigation/
├── evidence_integrator.py           # Multi-source evidence integration
├── network_database_correlator.py   # Advanced correlation engine
├── timeline_reconstructor.py        # Timeline reconstruction and analysis
├── investigation_reporter.py        # Professional report generation
├── test_investigation_scenario.py   # Complete investigation workflow
├── evidence/
│   └── *_integrated_evidence.db    # Integrated evidence database
├── sources/
│   ├── pki_logs.json               # PKI certificate validation logs
│   ├── mfa_events.json             # MFA authentication events
│   ├── rbac_changes.json           # RBAC permission modifications
│   ├── network_flows.json          # Network security monitoring
│   └── siem_alerts.json            # SIEM correlation alerts
├── analysis/
│   ├── correlation_clusters.json   # Evidence correlation results
│   └── attack_patterns.json        # Identified attack patterns
└── reports/
    ├── *_timeline_report.json       # Timeline reconstruction
    ├── *_correlation_analysis.json  # Correlation analysis results
    └── *_final_investigation_report.json # Professional investigation report
```

## 🎯 Grading Focus Areas

1. **Multi-Source Evidence Integration (5 points)**: Effective standardization and ingestion of evidence from all security infrastructure sources
2. **Advanced Correlation Analysis (5 points)**: Sophisticated correlation techniques with confidence scoring and attack pattern recognition
3. **Professional Timeline Reconstruction (5 points)**: Comprehensive timeline with MITRE ATT&CK mapping and gap analysis
4. **Expert Investigation Reporting (5 points)**: Professional-quality reports meeting legal admissibility standards
5. **Integration and Methodology (5 points)**: Proper integration of Weeks 3-9 security systems with validated forensic methodology

## 💡 Pro Tips

1. **Start with Evidence Integration**: Proper standardization is key to effective correlation
2. **Use Confidence Scoring**: Not all correlations are equally reliable
3. **Focus on Attack Patterns**: Look for coordinated activities across multiple systems
4. **Document Chain of Custody**: Legal admissibility requires proper evidence handling
5. **Validate Against MITRE ATT&CK**: Use established frameworks for attack classification

## 🔍 Key Advanced Investigation Concepts

### Multi-Source Evidence Correlation:
- **Temporal Correlation**: Events occurring within time windows
- **Entity-Based Correlation**: Activities affecting the same users/systems
- **Attack Pattern Recognition**: Identifying coordinated threat activities
- **Confidence Scoring**: Statistical measures of correlation reliability

### Professional Investigation Methodology:
- **Evidence Standardization**: Common format across all security sources
- **Chain of Custody**: Complete audit trail for legal admissibility
- **Timeline Reconstruction**: Comprehensive event sequencing with gap analysis
- **Expert Reporting**: Professional documentation meeting legal standards

## 🚀 Extension Ideas (Optional)

- Implement real-time correlation for live incident response
- Add machine learning for automated attack pattern recognition
- Create interactive timeline visualization with filtering
- Integrate with threat intelligence feeds for IOC correlation
- Add support for additional security system log formats

## ⏱️ Time Management

- **Focus on integration first** (1 hour): Get evidence standardization working properly
- **Build correlation systematically** (1.5 hours): Start with temporal, then entity-based correlation
- **Emphasize timeline quality** (1.5 hours): Professional timeline reconstruction is critical
- **Generate comprehensive reports** (1-1.5 hours): Professional documentation is essential for legal admissibility

**Note**: This assignment demonstrates advanced forensic investigation skills by integrating all course security systems. Focus on practical correlation techniques and professional reporting rather than building enterprise-scale platforms.

Remember: Multi-source forensic investigation requires systematic methodology and professional documentation. Understanding how to correlate evidence across security systems and present findings professionally is critical for incident response and legal proceedings!