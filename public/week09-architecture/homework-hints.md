# Week 9 Homework Hints: Security Architecture and Design

## 🎯 Quick Start Guide (4 hours total)

### Time Breakdown
- **Security Architecture Concepts**: 45 minutes
- **Threat Modeling Implementation**: 1.5 hours
- **Secure Design Patterns**: 1.5 hours
- **Architecture Documentation**: 30 minutes

## 📋 Step-by-Step Implementation

### Step 1: Understanding Security Architecture (30 minutes)

**Key Security Architecture Principles:**
- **Defense in Depth**: Multiple layers of security controls
- **Principle of Least Privilege**: Minimal necessary access
- **Fail Secure**: System fails to a secure state
- **Separation of Duties**: No single person has complete control
- **Zero Trust**: Never trust, always verify

**Common Architecture Patterns:**
- **DMZ (Demilitarized Zone)**: Network buffer between internal and external
- **Air Gapping**: Physical isolation of critical systems
- **Micro-segmentation**: Fine-grained network isolation
- **Service Mesh**: Secure service-to-service communication

### Step 2: Environment Setup (15 minutes)

```bash
pip install matplotlib networkx graphviz pydot

mkdir week09-security-architecture
cd week09-security-architecture
mkdir models diagrams reports templates

touch threat_modeler.py
touch architecture_analyzer.py
touch secure_patterns.py
touch documentation_generator.py
```

### Step 3: Threat Modeling Engine (90 minutes)

```python
# threat_modeler.py
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
import matplotlib.pyplot as plt
import networkx as nx

class ThreatCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class AssetType(Enum):
    WEB_APPLICATION = "Web Application"
    DATABASE = "Database"
    API_SERVICE = "API Service"
    USER_DEVICE = "User Device"
    NETWORK_DEVICE = "Network Device"
    CLOUD_SERVICE = "Cloud Service"
    FILE_SYSTEM = "File System"

class TrustLevel(Enum):
    UNTRUSTED = "Untrusted"
    LOW_TRUST = "Low Trust"
    MEDIUM_TRUST = "Medium Trust"
    HIGH_TRUST = "High Trust"
    FULL_TRUST = "Full Trust"

class Asset:
    def __init__(self, name: str, asset_type: AssetType, trust_level: TrustLevel = TrustLevel.MEDIUM_TRUST):
        self.name = name
        self.asset_type = asset_type
        self.trust_level = trust_level
        self.data_classification = "Internal"  # Public, Internal, Confidential, Restricted
        self.security_controls = []
        self.connections = []
        self.threats = []

    def add_security_control(self, control: str):
        self.security_controls.append(control)

    def add_connection(self, target_asset: str, protocol: str, authentication: str = "None"):
        connection = {
            'target': target_asset,
            'protocol': protocol,
            'authentication': authentication,
            'encrypted': 'TLS' in protocol or 'HTTPS' in protocol
        }
        self.connections.append(connection)

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.asset_type.value,
            'trust_level': self.trust_level.value,
            'data_classification': self.data_classification,
            'security_controls': self.security_controls,
            'connections': self.connections,
            'threats': [threat.to_dict() for threat in self.threats]
        }

class Threat:
    def __init__(self, name: str, category: ThreatCategory, description: str,
                 likelihood: str = "Medium", impact: str = "Medium"):
        self.name = name
        self.category = category
        self.description = description
        self.likelihood = likelihood  # Low, Medium, High
        self.impact = impact  # Low, Medium, High
        self.attack_vectors = []
        self.mitigations = []
        self.residual_risk = "Medium"

    def add_attack_vector(self, vector: str):
        self.attack_vectors.append(vector)

    def add_mitigation(self, mitigation: str):
        self.mitigations.append(mitigation)

    def calculate_risk_score(self) -> int:
        """Calculate numerical risk score"""
        likelihood_scores = {"Low": 1, "Medium": 2, "High": 3}
        impact_scores = {"Low": 1, "Medium": 2, "High": 3}

        return likelihood_scores[self.likelihood] * impact_scores[self.impact]

    def to_dict(self):
        return {
            'name': self.name,
            'category': self.category.value,
            'description': self.description,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'risk_score': self.calculate_risk_score(),
            'attack_vectors': self.attack_vectors,
            'mitigations': self.mitigations,
            'residual_risk': self.residual_risk
        }

class ThreatModel:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.assets = {}
        self.trust_boundaries = []
        self.data_flows = []
        self.threats = []
        self.created_at = datetime.now()

    def add_asset(self, asset: Asset):
        self.assets[asset.name] = asset

    def add_trust_boundary(self, name: str, assets: List[str], trust_level: TrustLevel):
        boundary = {
            'name': name,
            'assets': assets,
            'trust_level': trust_level.value,
            'controls': []
        }
        self.trust_boundaries.append(boundary)

    def add_data_flow(self, source: str, destination: str, data_type: str,
                     protocol: str = "HTTP", authentication: str = "None"):
        flow = {
            'source': source,
            'destination': destination,
            'data_type': data_type,
            'protocol': protocol,
            'authentication': authentication,
            'encrypted': 'TLS' in protocol or 'HTTPS' in protocol
        }
        self.data_flows.append(flow)

    def add_threat(self, threat: Threat, affected_assets: List[str]):
        threat_entry = {
            'threat': threat,
            'affected_assets': affected_assets,
            'identified_at': datetime.now()
        }
        self.threats.append(threat_entry)

        # Add threat to affected assets
        for asset_name in affected_assets:
            if asset_name in self.assets:
                self.assets[asset_name].threats.append(threat)

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'assets': {name: asset.to_dict() for name, asset in self.assets.items()},
            'trust_boundaries': self.trust_boundaries,
            'data_flows': self.data_flows,
            'threats': [
                {
                    'threat': threat_entry['threat'].to_dict(),
                    'affected_assets': threat_entry['affected_assets'],
                    'identified_at': threat_entry['identified_at'].isoformat()
                }
                for threat_entry in self.threats
            ]
        }

class ThreatModelingEngine:
    def __init__(self):
        self.models = {}
        self.threat_library = self.load_threat_library()

    def load_threat_library(self) -> Dict:
        """Load common threats for different asset types"""
        return {
            AssetType.WEB_APPLICATION: [
                {
                    'name': 'SQL Injection',
                    'category': ThreatCategory.TAMPERING,
                    'description': 'Malicious SQL code injection through input fields',
                    'likelihood': 'High',
                    'impact': 'High',
                    'attack_vectors': ['Form inputs', 'URL parameters', 'HTTP headers'],
                    'mitigations': ['Input validation', 'Parameterized queries', 'WAF']
                },
                {
                    'name': 'Cross-Site Scripting (XSS)',
                    'category': ThreatCategory.TAMPERING,
                    'description': 'Malicious scripts executed in user browsers',
                    'likelihood': 'Medium',
                    'impact': 'Medium',
                    'attack_vectors': ['User input fields', 'URL parameters', 'File uploads'],
                    'mitigations': ['Output encoding', 'Content Security Policy', 'Input validation']
                },
                {
                    'name': 'Session Hijacking',
                    'category': ThreatCategory.SPOOFING,
                    'description': 'Unauthorized access through stolen session tokens',
                    'likelihood': 'Medium',
                    'impact': 'High',
                    'attack_vectors': ['Network sniffing', 'XSS attacks', 'Man-in-the-middle'],
                    'mitigations': ['HTTPS only', 'Secure session management', 'Session regeneration']
                }
            ],
            AssetType.DATABASE: [
                {
                    'name': 'Unauthorized Data Access',
                    'category': ThreatCategory.INFORMATION_DISCLOSURE,
                    'description': 'Unauthorized access to sensitive database information',
                    'likelihood': 'Medium',
                    'impact': 'High',
                    'attack_vectors': ['SQL injection', 'Privilege escalation', 'Weak authentication'],
                    'mitigations': ['Access controls', 'Database encryption', 'Audit logging']
                },
                {
                    'name': 'Data Tampering',
                    'category': ThreatCategory.TAMPERING,
                    'description': 'Unauthorized modification of database records',
                    'likelihood': 'Low',
                    'impact': 'High',
                    'attack_vectors': ['Insider threats', 'Application vulnerabilities', 'Direct database access'],
                    'mitigations': ['Integrity checks', 'Audit trails', 'Access controls']
                }
            ],
            AssetType.API_SERVICE: [
                {
                    'name': 'API Key Exposure',
                    'category': ThreatCategory.INFORMATION_DISCLOSURE,
                    'description': 'Exposure of API keys or authentication tokens',
                    'likelihood': 'Medium',
                    'impact': 'Medium',
                    'attack_vectors': ['Source code exposure', 'Log files', 'Network interception'],
                    'mitigations': ['Secure key storage', 'Token rotation', 'Rate limiting']
                },
                {
                    'name': 'API Abuse',
                    'category': ThreatCategory.DENIAL_OF_SERVICE,
                    'description': 'Excessive API calls leading to service degradation',
                    'likelihood': 'High',
                    'impact': 'Medium',
                    'attack_vectors': ['Automated tools', 'Botnet attacks', 'Legitimate client misuse'],
                    'mitigations': ['Rate limiting', 'API quotas', 'Monitoring and alerting']
                }
            ]
        }

    def create_model(self, name: str, description: str = "") -> ThreatModel:
        """Create new threat model"""
        model = ThreatModel(name, description)
        self.models[name] = model
        return model

    def analyze_model(self, model_name: str) -> Dict:
        """Perform comprehensive threat analysis"""
        if model_name not in self.models:
            return {'error': 'Model not found'}

        model = self.models[model_name]
        analysis = {
            'model_name': model_name,
            'analysis_date': datetime.now().isoformat(),
            'asset_analysis': self.analyze_assets(model),
            'data_flow_analysis': self.analyze_data_flows(model),
            'threat_analysis': self.analyze_threats(model),
            'recommendations': self.generate_recommendations(model)
        }

        return analysis

    def analyze_assets(self, model: ThreatModel) -> Dict:
        """Analyze security posture of assets"""
        analysis = {
            'total_assets': len(model.assets),
            'by_type': {},
            'by_trust_level': {},
            'high_risk_assets': [],
            'security_coverage': {}
        }

        for asset in model.assets.values():
            # Count by type
            asset_type = asset.asset_type.value
            analysis['by_type'][asset_type] = analysis['by_type'].get(asset_type, 0) + 1

            # Count by trust level
            trust_level = asset.trust_level.value
            analysis['by_trust_level'][trust_level] = analysis['by_trust_level'].get(trust_level, 0) + 1

            # Identify high-risk assets
            threat_count = len(asset.threats)
            control_count = len(asset.security_controls)

            risk_score = threat_count - control_count
            if risk_score > 2:
                analysis['high_risk_assets'].append({
                    'name': asset.name,
                    'risk_score': risk_score,
                    'threat_count': threat_count,
                    'control_count': control_count
                })

            # Calculate security coverage
            if asset.asset_type in self.threat_library:
                expected_threats = len(self.threat_library[asset.asset_type])
                actual_mitigations = len(asset.security_controls)
                coverage = min(actual_mitigations / expected_threats * 100, 100) if expected_threats > 0 else 0
                analysis['security_coverage'][asset.name] = coverage

        return analysis

    def analyze_data_flows(self, model: ThreatModel) -> Dict:
        """Analyze security of data flows"""
        analysis = {
            'total_flows': len(model.data_flows),
            'encrypted_flows': 0,
            'authenticated_flows': 0,
            'insecure_flows': [],
            'cross_boundary_flows': []
        }

        for flow in model.data_flows:
            if flow['encrypted']:
                analysis['encrypted_flows'] += 1

            if flow['authentication'] != "None":
                analysis['authenticated_flows'] += 1

            # Identify insecure flows
            if not flow['encrypted'] and flow['data_type'] in ['PII', 'Financial', 'Credentials']:
                analysis['insecure_flows'].append({
                    'source': flow['source'],
                    'destination': flow['destination'],
                    'data_type': flow['data_type'],
                    'issue': 'Sensitive data transmitted without encryption'
                })

            if flow['authentication'] == "None" and flow['data_type'] != 'Public':
                analysis['insecure_flows'].append({
                    'source': flow['source'],
                    'destination': flow['destination'],
                    'data_type': flow['data_type'],
                    'issue': 'No authentication for non-public data'
                })

        return analysis

    def analyze_threats(self, model: ThreatModel) -> Dict:
        """Analyze identified threats"""
        analysis = {
            'total_threats': len(model.threats),
            'by_category': {},
            'by_risk_level': {},
            'high_priority_threats': [],
            'unmitigated_threats': []
        }

        for threat_entry in model.threats:
            threat = threat_entry['threat']

            # Count by category
            category = threat.category.value
            analysis['by_category'][category] = analysis['by_category'].get(category, 0) + 1

            # Count by risk level
            risk_score = threat.calculate_risk_score()
            if risk_score >= 6:
                risk_level = "High"
            elif risk_score >= 4:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            analysis['by_risk_level'][risk_level] = analysis['by_risk_level'].get(risk_level, 0) + 1

            # Identify high priority threats
            if risk_score >= 6:
                analysis['high_priority_threats'].append({
                    'name': threat.name,
                    'category': threat.category.value,
                    'risk_score': risk_score,
                    'affected_assets': threat_entry['affected_assets']
                })

            # Identify unmitigated threats
            if len(threat.mitigations) == 0:
                analysis['unmitigated_threats'].append({
                    'name': threat.name,
                    'category': threat.category.value,
                    'affected_assets': threat_entry['affected_assets']
                })

        return analysis

    def generate_recommendations(self, model: ThreatModel) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Analyze current state
        asset_analysis = self.analyze_assets(model)
        flow_analysis = self.analyze_data_flows(model)
        threat_analysis = self.analyze_threats(model)

        # Asset-based recommendations
        if asset_analysis['high_risk_assets']:
            recommendations.append(f"Address {len(asset_analysis['high_risk_assets'])} high-risk assets with insufficient security controls")

        # Data flow recommendations
        unencrypted_sensitive = len([f for f in flow_analysis['insecure_flows'] if 'encryption' in f['issue']])
        if unencrypted_sensitive > 0:
            recommendations.append(f"Encrypt {unencrypted_sensitive} data flows containing sensitive information")

        unauthenticated_flows = len([f for f in flow_analysis['insecure_flows'] if 'authentication' in f['issue']])
        if unauthenticated_flows > 0:
            recommendations.append(f"Implement authentication for {unauthenticated_flows} data flows")

        # Threat-based recommendations
        if threat_analysis['unmitigated_threats']:
            recommendations.append(f"Implement mitigations for {len(threat_analysis['unmitigated_threats'])} unmitigated threats")

        high_priority = len(threat_analysis['high_priority_threats'])
        if high_priority > 0:
            recommendations.append(f"Prioritize remediation of {high_priority} high-risk threats")

        # General recommendations
        recommendations.extend([
            "Implement defense-in-depth security architecture",
            "Regular security assessments and threat model updates",
            "Security awareness training for development teams",
            "Incident response and recovery procedures"
        ])

        return recommendations

    def save_model(self, model_name: str, filename: str = None):
        """Save threat model to file"""
        if model_name not in self.models:
            raise ValueError("Model not found")

        if not filename:
            filename = f"models/{model_name.replace(' ', '_')}_threat_model.json"

        with open(filename, 'w') as f:
            json.dump(self.models[model_name].to_dict(), f, indent=2)

        print(f"✅ Threat model saved to {filename}")

    def load_model(self, filename: str) -> str:
        """Load threat model from file"""
        with open(filename, 'r') as f:
            data = json.load(f)

        # Reconstruct model (simplified for demo)
        model = ThreatModel(data['name'], data['description'])
        model.created_at = datetime.fromisoformat(data['created_at'])

        # Reconstruct assets
        for asset_name, asset_data in data['assets'].items():
            asset_type = AssetType(asset_data['type'])
            trust_level = TrustLevel(asset_data['trust_level'])
            asset = Asset(asset_name, asset_type, trust_level)
            asset.data_classification = asset_data['data_classification']
            asset.security_controls = asset_data['security_controls']
            asset.connections = asset_data['connections']
            model.add_asset(asset)

        self.models[model.name] = model
        print(f"✅ Threat model loaded from {filename}")
        return model.name

def create_sample_threat_model():
    """Create a sample e-commerce threat model"""
    engine = ThreatModelingEngine()

    # Create threat model
    model = engine.create_model(
        "E-commerce Platform",
        "Threat model for online shopping platform"
    )

    # Add assets
    web_app = Asset("Web Application", AssetType.WEB_APPLICATION, TrustLevel.MEDIUM_TRUST)
    web_app.data_classification = "Internal"
    web_app.add_security_control("WAF")
    web_app.add_security_control("Input validation")
    web_app.add_security_control("HTTPS")
    model.add_asset(web_app)

    database = Asset("Customer Database", AssetType.DATABASE, TrustLevel.HIGH_TRUST)
    database.data_classification = "Confidential"
    database.add_security_control("Access controls")
    database.add_security_control("Encryption at rest")
    database.add_security_control("Audit logging")
    model.add_asset(database)

    api_service = Asset("Payment API", AssetType.API_SERVICE, TrustLevel.HIGH_TRUST)
    api_service.data_classification = "Restricted"
    api_service.add_security_control("API gateway")
    api_service.add_security_control("Rate limiting")
    api_service.add_security_control("Token authentication")
    model.add_asset(api_service)

    user_device = Asset("Customer Device", AssetType.USER_DEVICE, TrustLevel.UNTRUSTED)
    user_device.data_classification = "Public"
    model.add_asset(user_device)

    # Add data flows
    model.add_data_flow("Customer Device", "Web Application", "HTTP Requests", "HTTPS", "Session tokens")
    model.add_data_flow("Web Application", "Customer Database", "SQL Queries", "TLS", "Database credentials")
    model.add_data_flow("Web Application", "Payment API", "Payment Data", "HTTPS", "API keys")

    # Add threats
    sql_injection = Threat(
        "SQL Injection Attack",
        ThreatCategory.TAMPERING,
        "Malicious SQL code injected through web application inputs",
        "High", "High"
    )
    sql_injection.add_attack_vector("Form input fields")
    sql_injection.add_attack_vector("URL parameters")
    sql_injection.add_mitigation("Input validation and sanitization")
    sql_injection.add_mitigation("Parameterized queries")
    model.add_threat(sql_injection, ["Web Application", "Customer Database"])

    session_hijacking = Threat(
        "Session Hijacking",
        ThreatCategory.SPOOFING,
        "Unauthorized access through stolen session tokens",
        "Medium", "High"
    )
    session_hijacking.add_attack_vector("Network interception")
    session_hijacking.add_attack_vector("XSS attacks")
    session_hijacking.add_mitigation("Secure session management")
    session_hijacking.add_mitigation("HTTPS enforcement")
    model.add_threat(session_hijacking, ["Web Application", "Customer Device"])

    return engine, model

def main():
    """Main threat modeling demo"""
    print("🎯 Creating Sample Threat Model")
    print("=" * 40)

    # Create sample model
    engine, model = create_sample_threat_model()

    # Perform analysis
    analysis = engine.analyze_model(model.name)

    print(f"\n📊 Threat Model Analysis for '{model.name}'")
    print("=" * 50)

    # Asset analysis
    asset_analysis = analysis['asset_analysis']
    print(f"\n🏗️ Assets: {asset_analysis['total_assets']}")
    for asset_type, count in asset_analysis['by_type'].items():
        print(f"   {asset_type}: {count}")

    # Threat analysis
    threat_analysis = analysis['threat_analysis']
    print(f"\n🚨 Threats: {threat_analysis['total_threats']}")
    for risk_level, count in threat_analysis['by_risk_level'].items():
        print(f"   {risk_level} Risk: {count}")

    # High priority threats
    if threat_analysis['high_priority_threats']:
        print(f"\n⚠️ High Priority Threats:")
        for threat in threat_analysis['high_priority_threats']:
            print(f"   • {threat['name']} (Score: {threat['risk_score']})")

    # Recommendations
    print(f"\n💡 Recommendations:")
    for i, rec in enumerate(analysis['recommendations'][:5], 1):
        print(f"   {i}. {rec}")

    # Save model
    engine.save_model(model.name)

    print(f"\n✅ Threat model analysis complete!")

if __name__ == "__main__":
    main()
```

### Step 4: Secure Architecture Patterns (45 minutes)

```python
# secure_patterns.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from enum import Enum

class SecurityPattern(ABC):
    """Base class for security architecture patterns"""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.components = []
        self.security_controls = []

    @abstractmethod
    def implement(self) -> Dict[str, Any]:
        """Implement the security pattern"""
        pass

    @abstractmethod
    def validate(self) -> List[str]:
        """Validate pattern implementation"""
        pass

class ZeroTrustPattern(SecurityPattern):
    """Zero Trust security architecture pattern"""

    def __init__(self):
        super().__init__(
            "Zero Trust Architecture",
            "Never trust, always verify - comprehensive identity verification for every transaction"
        )
        self.identity_verification = True
        self.least_privilege_access = True
        self.continuous_monitoring = True
        self.micro_segmentation = True

    def implement(self) -> Dict[str, Any]:
        """Implement Zero Trust pattern"""
        implementation = {
            'pattern_name': self.name,
            'components': {
                'identity_provider': {
                    'type': 'Identity and Access Management',
                    'features': ['Multi-factor authentication', 'Single sign-on', 'Identity verification'],
                    'security_controls': ['Strong authentication', 'Identity governance', 'Access reviews']
                },
                'policy_engine': {
                    'type': 'Policy Decision Point',
                    'features': ['Dynamic access policies', 'Risk-based decisions', 'Context awareness'],
                    'security_controls': ['Attribute-based access control', 'Policy validation', 'Audit logging']
                },
                'micro_segmentation': {
                    'type': 'Network Security',
                    'features': ['Software-defined perimeters', 'Application-level controls', 'Encrypted communications'],
                    'security_controls': ['Network isolation', 'Traffic inspection', 'Encrypted tunnels']
                },
                'monitoring_system': {
                    'type': 'Security Operations',
                    'features': ['Continuous monitoring', 'Behavior analytics', 'Threat detection'],
                    'security_controls': ['SIEM integration', 'User behavior analytics', 'Incident response']
                }
            },
            'implementation_steps': [
                'Inventory all assets and data flows',
                'Implement strong identity verification',
                'Deploy micro-segmentation',
                'Establish continuous monitoring',
                'Enforce least privilege access',
                'Implement encrypted communications'
            ],
            'benefits': [
                'Reduced attack surface',
                'Improved visibility and control',
                'Enhanced data protection',
                'Better compliance posture'
            ],
            'challenges': [
                'Complex implementation',
                'Performance considerations',
                'User experience impact',
                'High initial costs'
            ]
        }
        return implementation

    def validate(self) -> List[str]:
        """Validate Zero Trust implementation"""
        validation_checks = []

        if not self.identity_verification:
            validation_checks.append("❌ Identity verification not properly implemented")
        else:
            validation_checks.append("✅ Identity verification implemented")

        if not self.least_privilege_access:
            validation_checks.append("❌ Least privilege access not enforced")
        else:
            validation_checks.append("✅ Least privilege access enforced")

        if not self.continuous_monitoring:
            validation_checks.append("❌ Continuous monitoring not implemented")
        else:
            validation_checks.append("✅ Continuous monitoring implemented")

        if not self.micro_segmentation:
            validation_checks.append("❌ Micro-segmentation not deployed")
        else:
            validation_checks.append("✅ Micro-segmentation deployed")

        return validation_checks

class DefenseInDepthPattern(SecurityPattern):
    """Defense in Depth security architecture pattern"""

    def __init__(self):
        super().__init__(
            "Defense in Depth",
            "Multiple layers of security controls to protect against various attack vectors"
        )
        self.layers = {
            'perimeter': [],
            'network': [],
            'host': [],
            'application': [],
            'data': []
        }

    def add_control(self, layer: str, control: str):
        """Add security control to specified layer"""
        if layer in self.layers:
            self.layers[layer].append(control)

    def implement(self) -> Dict[str, Any]:
        """Implement Defense in Depth pattern"""
        implementation = {
            'pattern_name': self.name,
            'layers': {
                'perimeter_security': {
                    'description': 'External boundary protection',
                    'controls': ['Firewall', 'IDS/IPS', 'DDoS protection', 'VPN'],
                    'technologies': ['Next-gen firewall', 'Web application firewall', 'Load balancers']
                },
                'network_security': {
                    'description': 'Internal network protection',
                    'controls': ['Network segmentation', 'VLANs', 'Network monitoring', 'Access control'],
                    'technologies': ['Software-defined networking', 'Network access control', 'SIEM']
                },
                'host_security': {
                    'description': 'Server and endpoint protection',
                    'controls': ['Antivirus', 'Host-based IDS', 'Patch management', 'Configuration management'],
                    'technologies': ['Endpoint detection and response', 'Vulnerability scanners', 'Configuration tools']
                },
                'application_security': {
                    'description': 'Application-level protection',
                    'controls': ['Input validation', 'Authentication', 'Authorization', 'Session management'],
                    'technologies': ['Web application firewall', 'Runtime application protection', 'Code analysis']
                },
                'data_security': {
                    'description': 'Data protection controls',
                    'controls': ['Encryption', 'Access controls', 'Data loss prevention', 'Backup and recovery'],
                    'technologies': ['Database encryption', 'File encryption', 'Rights management', 'Backup systems']
                }
            },
            'implementation_principles': [
                'No single point of failure',
                'Redundant security controls',
                'Layered protection approach',
                'Comprehensive coverage'
            ]
        }
        return implementation

    def validate(self) -> List[str]:
        """Validate Defense in Depth implementation"""
        validation_checks = []

        for layer_name, controls in self.layers.items():
            if len(controls) >= 2:
                validation_checks.append(f"✅ {layer_name.title()} layer has sufficient controls ({len(controls)})")
            elif len(controls) == 1:
                validation_checks.append(f"⚠️ {layer_name.title()} layer has minimal controls ({len(controls)})")
            else:
                validation_checks.append(f"❌ {layer_name.title()} layer has no security controls")

        return validation_checks

class ServiceMeshPattern(SecurityPattern):
    """Service Mesh security architecture pattern"""

    def __init__(self):
        super().__init__(
            "Service Mesh Security",
            "Secure service-to-service communication in microservices architecture"
        )
        self.mutual_tls = True
        self.service_identity = True
        self.policy_enforcement = True
        self.observability = True

    def implement(self) -> Dict[str, Any]:
        """Implement Service Mesh pattern"""
        implementation = {
            'pattern_name': self.name,
            'components': {
                'control_plane': {
                    'description': 'Central management and policy enforcement',
                    'features': ['Service discovery', 'Certificate management', 'Policy distribution'],
                    'security_controls': ['Identity management', 'Policy validation', 'Audit logging']
                },
                'data_plane': {
                    'description': 'Sidecar proxies for service communication',
                    'features': ['Traffic interception', 'Encryption', 'Access control'],
                    'security_controls': ['Mutual TLS', 'Traffic encryption', 'Request authentication']
                },
                'policy_engine': {
                    'description': 'Dynamic policy enforcement',
                    'features': ['Authorization policies', 'Traffic policies', 'Security policies'],
                    'security_controls': ['RBAC enforcement', 'Rate limiting', 'Traffic validation']
                },
                'observability': {
                    'description': 'Monitoring and metrics collection',
                    'features': ['Traffic metrics', 'Security events', 'Performance monitoring'],
                    'security_controls': ['Security monitoring', 'Anomaly detection', 'Audit trails']
                }
            },
            'security_features': [
                'Automatic mutual TLS between services',
                'Fine-grained access control policies',
                'Traffic encryption and authentication',
                'Comprehensive security monitoring',
                'Identity-based service communication'
            ],
            'implementation_steps': [
                'Deploy service mesh infrastructure',
                'Configure service identities',
                'Enable mutual TLS',
                'Define security policies',
                'Implement monitoring and observability'
            ]
        }
        return implementation

    def validate(self) -> List[str]:
        """Validate Service Mesh implementation"""
        validation_checks = []

        checks = [
            (self.mutual_tls, "Mutual TLS enabled"),
            (self.service_identity, "Service identity implemented"),
            (self.policy_enforcement, "Policy enforcement active"),
            (self.observability, "Observability configured")
        ]

        for check, description in checks:
            if check:
                validation_checks.append(f"✅ {description}")
            else:
                validation_checks.append(f"❌ {description} - NOT IMPLEMENTED")

        return validation_checks

class SecureArchitectureDesigner:
    """Main class for designing secure architectures"""

    def __init__(self):
        self.patterns = {
            'zero_trust': ZeroTrustPattern(),
            'defense_in_depth': DefenseInDepthPattern(),
            'service_mesh': ServiceMeshPattern()
        }
        self.architecture_models = {}

    def create_architecture(self, name: str, description: str, patterns: List[str]) -> Dict:
        """Create a new secure architecture using specified patterns"""
        architecture = {
            'name': name,
            'description': description,
            'patterns': [],
            'components': {},
            'security_controls': [],
            'implementation_plan': [],
            'validation_results': {}
        }

        for pattern_name in patterns:
            if pattern_name in self.patterns:
                pattern = self.patterns[pattern_name]
                pattern_impl = pattern.implement()
                architecture['patterns'].append(pattern_impl)

                # Merge components and controls
                if 'components' in pattern_impl:
                    architecture['components'].update(pattern_impl['components'])

                if 'implementation_steps' in pattern_impl:
                    architecture['implementation_plan'].extend(pattern_impl['implementation_steps'])

                # Validate pattern
                validation = pattern.validate()
                architecture['validation_results'][pattern_name] = validation

        self.architecture_models[name] = architecture
        return architecture

    def generate_architecture_report(self, architecture_name: str) -> str:
        """Generate comprehensive architecture report"""
        if architecture_name not in self.architecture_models:
            return "Architecture not found"

        arch = self.architecture_models[architecture_name]

        report = f"""
# Secure Architecture Report: {arch['name']}

## Overview
{arch['description']}

## Security Patterns Implemented
"""

        for pattern in arch['patterns']:
            report += f"\n### {pattern['pattern_name']}\n"
            if 'components' in pattern:
                report += "**Components:**\n"
                for comp_name, comp_details in pattern['components'].items():
                    report += f"- **{comp_name}**: {comp_details.get('description', '')}\n"

        report += "\n## Security Controls\n"
        for comp_name, comp_details in arch['components'].items():
            if 'security_controls' in comp_details:
                report += f"\n### {comp_name}\n"
                for control in comp_details['security_controls']:
                    report += f"- {control}\n"

        report += "\n## Implementation Plan\n"
        for i, step in enumerate(arch['implementation_plan'], 1):
            report += f"{i}. {step}\n"

        report += "\n## Validation Results\n"
        for pattern_name, validations in arch['validation_results'].items():
            report += f"\n### {pattern_name}\n"
            for validation in validations:
                report += f"{validation}\n"

        return report

def main():
    """Main secure architecture demo"""
    print("🏗️ Secure Architecture Design Demo")
    print("=" * 40)

    designer = SecureArchitectureDesigner()

    # Create a comprehensive enterprise architecture
    architecture = designer.create_architecture(
        "Enterprise Security Architecture",
        "Comprehensive security architecture for enterprise applications",
        ['zero_trust', 'defense_in_depth', 'service_mesh']
    )

    print(f"\n📋 Architecture: {architecture['name']}")
    print(f"Patterns implemented: {len(architecture['patterns'])}")
    print(f"Components: {len(architecture['components'])}")
    print(f"Implementation steps: {len(architecture['implementation_plan'])}")

    # Show validation results
    print(f"\n🔍 Validation Results:")
    for pattern_name, validations in architecture['validation_results'].items():
        print(f"\n{pattern_name.replace('_', ' ').title()}:")
        for validation in validations:
            print(f"  {validation}")

    # Generate and save report
    report = designer.generate_architecture_report("Enterprise Security Architecture")

    with open("reports/architecture_report.md", "w") as f:
        f.write(report)

    print(f"\n📄 Architecture report saved to reports/architecture_report.md")

if __name__ == "__main__":
    main()
```

## 🐛 Common Issues & Solutions

### Issue: Complex threat model becomes unwieldy
**Solution**: Break down into smaller, focused models by system or boundary

### Issue: Too many threats identified
**Solution**: Focus on high-impact, likely threats first; use risk scoring

### Issue: Difficulty visualizing architecture
**Solution**: Use diagramming tools like draw.io or Lucidchart alongside code

### Issue: Security patterns conflict with performance
**Solution**: Balance security and performance; implement monitoring

## ✅ Testing Workflow

```bash
# Create and analyze threat model
python threat_modeler.py

# Test security patterns
python secure_patterns.py

# Generate architecture documentation
python -c "
from threat_modeler import create_sample_threat_model
from secure_patterns import SecureArchitectureDesigner

# Create threat model
engine, model = create_sample_threat_model()
analysis = engine.analyze_model(model.name)
print('Threat model created and analyzed')

# Create secure architecture
designer = SecureArchitectureDesigner()
arch = designer.create_architecture('Test Architecture', 'Test', ['zero_trust'])
print('Architecture created')
"
```

## 📁 Expected File Structure
```
week09-security-architecture/
├── threat_modeler.py              # Threat modeling engine
├── architecture_analyzer.py       # Architecture analysis tools
├── secure_patterns.py             # Security pattern library
├── documentation_generator.py     # Documentation automation
├── models/
│   ├── threat_model_*.json        # Threat models
│   └── architecture_*.json        # Architecture definitions
├── diagrams/
│   ├── threat_model_*.png         # Threat model visualizations
│   └── architecture_*.png         # Architecture diagrams
├── reports/
│   ├── threat_analysis_*.md       # Threat analysis reports
│   └── architecture_report.md     # Architecture documentation
└── templates/
    ├── threat_model_template.json # Templates for models
    └── architecture_template.md   # Documentation templates
```

## 🎯 Grading Focus Areas

1. **Threat Modeling**: Comprehensive identification and analysis of threats
2. **Security Patterns**: Correct implementation of security architecture patterns
3. **Risk Analysis**: Proper risk assessment and prioritization
4. **Documentation**: Clear, actionable architecture documentation

## 💡 Pro Tips

1. **Start with Business Context**: Understand what you're protecting and why
2. **Use Established Frameworks**: STRIDE, PASTA, or OCTAVE for threat modeling
3. **Focus on High-Value Assets**: Prioritize protection of critical resources
4. **Think Like an Attacker**: Consider how systems could be compromised
5. **Document Assumptions**: Make security assumptions explicit

## 🔍 Key Architecture Concepts

### Security Architecture Principles:
- **Defense in Depth**: Multiple layers of protection
- **Fail Secure**: Systems fail to a secure state
- **Least Privilege**: Minimal necessary access
- **Separation of Duties**: No single point of control
- **Zero Trust**: Verify everything, trust nothing

### Threat Modeling Methodologies:
- **STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **PASTA**: Process for Attack Simulation and Threat Analysis
- **OCTAVE**: Operationally Critical Threat, Asset, and Vulnerability Evaluation

## 🚀 Extension Ideas (Optional)

- Add visual diagram generation using Graphviz
- Implement attack tree analysis
- Create compliance mapping (SOX, PCI DSS, etc.)
- Add cost-benefit analysis for security controls
- Integrate with vulnerability databases

## ⏱️ Time Management

- **Focus on methodology**: Understanding the process is more important than perfect implementation
- **Use templates**: Create reusable patterns and templates
- **Prioritize threats**: Don't try to model every possible threat
- **Document as you go**: Keep documentation up-to-date with design

Remember: Security architecture is about building systems that are secure by design. Understanding how to model threats and implement security patterns will help you create more resilient applications and systems!