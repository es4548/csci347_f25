# Week 9 Tutorial: Security Architecture Design

**Estimated Time**: 4 hours (4 modules)  
**Prerequisites**: Weeks 3-8 completed (complete security infrastructure)

## Learning Objectives

By completing this tutorial, you will:
1. **Design enterprise security architectures** using industry frameworks
2. **Implement threat modeling** with STRIDE methodology  
3. **Create Zero Trust architectures** with forensic readiness
4. **Integrate all security domains** from Weeks 3-8 into cohesive designs
5. **Document professional architectures** for compliance and operations

---

## Module 1: Enterprise Security Architecture (60 minutes)

### Security Architecture Framework

```python
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from enum import Enum
import json

class SecurityDomain(Enum):
    IDENTITY = "identity_access_management"
    NETWORK = "network_security"
    APPLICATION = "application_security"
    DATA = "data_protection"
    ENDPOINT = "endpoint_security"
    MONITORING = "security_monitoring"
    INCIDENT_RESPONSE = "incident_response"

@dataclass
class SecurityControl:
    control_id: str
    name: str
    description: str
    domain: SecurityDomain
    implementation_weeks: List[int]  # Which weeks implemented this
    nist_mapping: str
    criticality: str  # "High", "Medium", "Low"

class SecurityArchitecture:
    def __init__(self, organization_name: str):
        self.organization = organization_name
        self.domains = {}
        self.controls = {}
        self.integration_points = []
        self.threat_model = None
        self.compliance_requirements = set()
        self._initialize_domains()
    
    def _initialize_domains(self):
        """Initialize security domains with controls from Weeks 3-8"""
        
        # Week 3: PKI and Certificate Management
        pki_controls = [
            SecurityControl("PKI-001", "Certificate Authority", 
                           "Root and intermediate CA management", 
                           SecurityDomain.IDENTITY, [3], "SC-17", "High"),
            SecurityControl("PKI-002", "Certificate Lifecycle", 
                           "Certificate issuance, renewal, revocation",
                           SecurityDomain.IDENTITY, [3], "SC-17", "High")
        ]
        
        # Week 4: Authentication Systems  
        auth_controls = [
            SecurityControl("AUTH-001", "Multi-Factor Authentication",
                           "TOTP, SMS, email verification systems",
                           SecurityDomain.IDENTITY, [4], "IA-2", "High"),
            SecurityControl("AUTH-002", "Risk-Based Authentication",
                           "Context-aware authentication decisions", 
                           SecurityDomain.IDENTITY, [4], "IA-8", "Medium")
        ]
        
        # Week 5: Access Control
        access_controls = [
            SecurityControl("AC-001", "Role-Based Access Control",
                           "Hierarchical role and permission system",
                           SecurityDomain.IDENTITY, [5], "AC-2", "High"),
            SecurityControl("AC-002", "Policy Engine",
                           "Attribute-based access decisions",
                           SecurityDomain.IDENTITY, [5], "AC-3", "High")
        ]
        
        # Week 6: Network Security
        network_controls = [
            SecurityControl("NET-001", "Network Segmentation", 
                           "VLAN and subnet isolation",
                           SecurityDomain.NETWORK, [6], "SC-7", "High"),
            SecurityControl("NET-002", "Firewall Management",
                           "Identity-aware firewall rules",
                           SecurityDomain.NETWORK, [6], "SC-7", "High")
        ]
        
        # Week 7: Security Monitoring
        monitoring_controls = [
            SecurityControl("MON-001", "SIEM Platform",
                           "Centralized log analysis and correlation",
                           SecurityDomain.MONITORING, [7], "AU-6", "High"),
            SecurityControl("MON-002", "Behavioral Analytics", 
                           "User and entity behavior analysis",
                           SecurityDomain.MONITORING, [7], "SI-4", "Medium")
        ]
        
        # Week 8: Security Assessment
        assessment_controls = [
            SecurityControl("ASSESS-001", "Vulnerability Management",
                           "Continuous vulnerability assessment",
                           SecurityDomain.MONITORING, [8], "RA-5", "High"),
            SecurityControl("ASSESS-002", "Penetration Testing",
                           "Regular security assessment program", 
                           SecurityDomain.MONITORING, [8], "CA-8", "Medium")
        ]
        
        # Organize by domain
        all_controls = pki_controls + auth_controls + access_controls + network_controls + monitoring_controls + assessment_controls
        
        for control in all_controls:
            if control.domain not in self.domains:
                self.domains[control.domain] = []
            self.domains[control.domain].append(control)
            self.controls[control.control_id] = control

    def design_integration_architecture(self) -> Dict:
        """Design integration between all security domains"""
        
        integration_patterns = {
            "identity_network_integration": {
                "description": "Identity-aware network access control",
                "components": ["PKI-001", "AUTH-001", "AC-001", "NET-001"],
                "data_flows": [
                    "User authenticates → Role determined → Network access granted",
                    "Certificate issued → Network device trust → VPN access"
                ],
                "integration_points": [
                    "RADIUS integration for network authentication",
                    "Certificate-based device authentication",
                    "Role-based VLAN assignment"
                ]
            },
            
            "monitoring_integration": {
                "description": "Comprehensive security monitoring across all domains", 
                "components": ["MON-001", "MON-002", "ASSESS-001"],
                "data_flows": [
                    "All systems → SIEM → Correlation → Alerts",
                    "Identity events → Behavior analysis → Risk scoring",
                    "Vulnerability data → Risk assessment → Remediation"
                ],
                "integration_points": [
                    "Centralized logging from all security controls",
                    "Identity correlation across network and application logs",
                    "Automated vulnerability-to-incident correlation"
                ]
            },
            
            "forensic_readiness": {
                "description": "Architecture supporting digital forensics",
                "components": ["MON-001", "NET-001", "PKI-001"],
                "data_flows": [
                    "Security events → Evidence collection → Chain of custody",
                    "Network traffic → Packet capture → Forensic analysis",
                    "Digital signatures → Evidence integrity → Court admissibility"
                ],
                "integration_points": [
                    "Tamper-evident logging with digital signatures",
                    "Network packet capture with proper timestamps",
                    "Evidence preservation and chain of custody tracking"
                ]
            }
        }
        
        self.integration_points = integration_patterns
        return integration_patterns

# Create enterprise architecture
enterprise_arch = SecurityArchitecture("SecureCorp Enterprises")
integration_design = enterprise_arch.design_integration_architecture()

print("Enterprise Security Architecture Domains:")
for domain, controls in enterprise_arch.domains.items():
    print(f"  {domain.value}: {len(controls)} controls")
```

### Checkpoint 1: Architecture Foundation
```python
# Test your architecture design
print(f"Total security controls: {len(enterprise_arch.controls)}")
print(f"Integration patterns: {len(integration_design)}")
print(f"Forensic readiness: {'forensic_readiness' in integration_design}")
```

---

## Module 2: Threat Modeling (60 minutes)

### STRIDE Threat Model Implementation

```python
from dataclasses import dataclass
from typing import List

class ThreatCategory(Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"  
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"

@dataclass
class ThreatScenario:
    threat_id: str
    category: ThreatCategory
    description: str
    affected_components: List[str]
    likelihood: str  # "Low", "Medium", "High"
    impact: str     # "Low", "Medium", "High"
    existing_controls: List[str]
    additional_mitigations: List[str]

class ThreatModel:
    def __init__(self, system_name: str, architecture: SecurityArchitecture):
        self.system_name = system_name
        self.architecture = architecture
        self.threats = []
        self.assets = []
        self.trust_boundaries = []
        self._model_threats()
    
    def _model_threats(self):
        """Model threats against integrated security architecture"""
        
        # Spoofing threats
        spoofing_threats = [
            ThreatScenario("T001", ThreatCategory.SPOOFING,
                          "Attacker impersonates legitimate user to bypass MFA",
                          ["AUTH-001", "AC-001"], "Medium", "High",
                          ["TOTP verification", "Risk-based authentication"],
                          ["Device fingerprinting", "Behavioral biometrics"]),
            
            ThreatScenario("T002", ThreatCategory.SPOOFING,
                          "Certificate spoofing to gain network access", 
                          ["PKI-001", "NET-001"], "Low", "High",
                          ["Certificate validation", "CRL checking"],
                          ["Certificate transparency monitoring", "OCSP stapling"])
        ]
        
        # Tampering threats
        tampering_threats = [
            ThreatScenario("T003", ThreatCategory.TAMPERING,
                          "Log tampering to hide malicious activity",
                          ["MON-001"], "Medium", "High", 
                          ["Digital signatures on logs", "Centralized logging"],
                          ["Immutable log storage", "Blockchain logging"]),
            
            ThreatScenario("T004", ThreatCategory.TAMPERING,
                          "Firewall rule manipulation",
                          ["NET-002"], "Low", "High",
                          ["Administrative access controls", "Change management"],
                          ["Firewall rule integrity monitoring", "Automated restoration"])
        ]
        
        # Information Disclosure threats  
        disclosure_threats = [
            ThreatScenario("T005", ThreatCategory.INFORMATION_DISCLOSURE,
                          "Unauthorized access to sensitive data through privilege escalation",
                          ["AC-001", "AC-002"], "Medium", "High",
                          ["RBAC enforcement", "Policy engine validation"],
                          ["Zero trust architecture", "Data loss prevention"]),
            
            ThreatScenario("T006", ThreatCategory.INFORMATION_DISCLOSURE,
                          "Network traffic interception",
                          ["NET-001"], "Medium", "Medium",
                          ["Network encryption", "VPN tunneling"],
                          ["Perfect forward secrecy", "Traffic analysis prevention"])
        ]
        
        # Denial of Service threats
        dos_threats = [
            ThreatScenario("T007", ThreatCategory.DENIAL_OF_SERVICE,
                          "Authentication system overload preventing legitimate access",
                          ["AUTH-001"], "High", "Medium",
                          ["Rate limiting", "Load balancing"],
                          ["Adaptive rate limiting", "CAPTCHA integration"]),
            
            ThreatScenario("T008", ThreatCategory.DENIAL_OF_SERVICE,
                          "SIEM log flooding to hide attacks",
                          ["MON-001"], "Medium", "Medium", 
                          ["Log rate limiting", "Anomaly detection"],
                          ["Intelligent log filtering", "Distributed SIEM"])
        ]
        
        self.threats = spoofing_threats + tampering_threats + disclosure_threats + dos_threats
    
    def calculate_risk_matrix(self) -> Dict:
        """Calculate risk levels for all threats"""
        risk_matrix = {"High": [], "Medium": [], "Low": []}
        
        for threat in self.threats:
            # Simple risk calculation: combine likelihood and impact
            if threat.likelihood == "High" and threat.impact == "High":
                risk_level = "High"
            elif threat.likelihood == "Low" and threat.impact == "Low":
                risk_level = "Low"
            else:
                risk_level = "Medium"
            
            risk_matrix[risk_level].append(threat)
        
        return risk_matrix
    
    def generate_mitigation_plan(self) -> Dict:
        """Generate prioritized mitigation recommendations"""
        risk_matrix = self.calculate_risk_matrix()
        
        mitigation_plan = {
            "immediate_actions": [],  # High risk threats
            "planned_improvements": [],  # Medium risk threats
            "monitoring_enhancements": []  # Low risk threats
        }
        
        # High risk - immediate action required
        for threat in risk_matrix["High"]:
            mitigation_plan["immediate_actions"].extend(threat.additional_mitigations)
        
        # Medium risk - planned improvements
        for threat in risk_matrix["Medium"]:
            mitigation_plan["planned_improvements"].extend(threat.additional_mitigations)
            
        # Low risk - enhanced monitoring
        for threat in risk_matrix["Low"]:
            mitigation_plan["monitoring_enhancements"].extend(threat.additional_mitigations)
        
        return mitigation_plan

# Create threat model
threat_model = ThreatModel("Enterprise Security System", enterprise_arch)
risk_matrix = threat_model.calculate_risk_matrix()
mitigation_plan = threat_model.generate_mitigation_plan()

print(f"Threat Model Analysis:")
print(f"  High Risk Threats: {len(risk_matrix['High'])}")
print(f"  Medium Risk Threats: {len(risk_matrix['Medium'])}")  
print(f"  Low Risk Threats: {len(risk_matrix['Low'])}")
```

### Checkpoint 2: Threat Model Validation
```python
# Validate threat model completeness
total_threats = len(threat_model.threats)
print(f"Total threats modeled: {total_threats}")
print(f"Immediate mitigations needed: {len(mitigation_plan['immediate_actions'])}")
```

---

## Module 3: Zero Trust Architecture (60 minutes)

### Zero Trust Implementation Framework

```python
class ZeroTrustPrinciple(Enum):
    VERIFY_EXPLICITLY = "verify_explicitly"
    LEAST_PRIVILEGE_ACCESS = "least_privilege_access" 
    ASSUME_BREACH = "assume_breach"

@dataclass
class ZeroTrustComponent:
    component_id: str
    name: str
    principle: ZeroTrustPrinciple
    verification_methods: List[str]
    access_controls: List[str]
    monitoring_capabilities: List[str]

class ZeroTrustArchitecture:
    def __init__(self, base_architecture: SecurityArchitecture):
        self.base_arch = base_architecture
        self.zero_trust_components = {}
        self.policy_engine = None
        self.continuous_verification = {}
        self._design_zero_trust()
    
    def _design_zero_trust(self):
        """Design Zero Trust overlay on existing architecture"""
        
        # Identity and Device Verification (Verify Explicitly)
        identity_verification = ZeroTrustComponent(
            "ZT-IDENTITY", "Continuous Identity Verification",
            ZeroTrustPrinciple.VERIFY_EXPLICITLY,
            verification_methods=[
                "Multi-factor authentication (Week 4)",
                "Device certificates (Week 3)", 
                "Behavioral biometrics",
                "Risk-based authentication (Week 4)"
            ],
            access_controls=[
                "RBAC with dynamic roles (Week 5)",
                "Attribute-based policies (Week 5)",
                "Context-aware access decisions"
            ],
            monitoring_capabilities=[
                "User behavior analytics (Week 7)",
                "Device behavior analysis", 
                "Identity risk scoring"
            ]
        )
        
        # Network Micro-Segmentation (Least Privilege)
        network_segmentation = ZeroTrustComponent(
            "ZT-NETWORK", "Micro-Segmentation",
            ZeroTrustPrinciple.LEAST_PRIVILEGE_ACCESS,
            verification_methods=[
                "Per-session authentication",
                "Application-specific certificates (Week 3)",
                "Dynamic trust evaluation"
            ],
            access_controls=[
                "Software-defined perimeter",
                "Identity-aware proxy (Week 6)",
                "Just-in-time access provisioning"
            ],
            monitoring_capabilities=[
                "Network traffic analysis (Week 7)",
                "East-west traffic monitoring",
                "Anomalous connection detection"
            ]
        )
        
        # Continuous Monitoring (Assume Breach)
        breach_detection = ZeroTrustComponent(
            "ZT-MONITORING", "Assume Breach Detection",
            ZeroTrustPrinciple.ASSUME_BREACH,
            verification_methods=[
                "Continuous risk assessment",
                "Real-time threat intelligence",
                "Behavioral anomaly detection"
            ],
            access_controls=[
                "Adaptive access controls",
                "Automated threat response",
                "Dynamic policy adjustment"
            ],
            monitoring_capabilities=[
                "Advanced SIEM correlation (Week 7)",
                "UEBA integration",
                "Automated incident response"
            ]
        )
        
        self.zero_trust_components = {
            "identity": identity_verification,
            "network": network_segmentation, 
            "monitoring": breach_detection
        }
    
    def implement_policy_engine(self) -> Dict:
        """Implement Zero Trust policy engine"""
        
        policy_engine_config = {
            "decision_framework": {
                "identity_trust_score": {
                    "factors": ["authentication_strength", "device_trust", "behavior_score"],
                    "weights": [0.4, 0.3, 0.3],
                    "threshold": 0.7
                },
                "resource_sensitivity": {
                    "public": 0.1,
                    "internal": 0.5, 
                    "confidential": 0.8,
                    "restricted": 1.0
                },
                "context_factors": {
                    "location": 0.2,
                    "time": 0.1,
                    "device_posture": 0.3,
                    "network_risk": 0.4
                }
            },
            
            "access_decision_logic": {
                "grant_conditions": [
                    "identity_trust_score >= resource_sensitivity",
                    "context_risk_score < 0.5",
                    "no_active_security_incidents"
                ],
                "continuous_evaluation": True,
                "reevaluation_triggers": [
                    "behavior_anomaly_detected",
                    "device_posture_change",
                    "threat_intelligence_update"
                ]
            },
            
            "forensic_integration": {
                "decision_logging": {
                    "log_all_decisions": True,
                    "include_decision_factors": True,
                    "digital_signatures": True  # Week 3 PKI
                },
                "evidence_preservation": {
                    "access_trails": True,
                    "policy_change_history": True,
                    "incident_correlation": True
                }
            }
        }
        
        self.policy_engine = policy_engine_config
        return policy_engine_config

# Implement Zero Trust
zero_trust = ZeroTrustArchitecture(enterprise_arch)
policy_engine = zero_trust.implement_policy_engine()

print("Zero Trust Implementation:")
for component_name, component in zero_trust.zero_trust_components.items():
    print(f"  {component.name}: {component.principle.value}")
```

### Checkpoint 3: Zero Trust Validation
```python
# Validate Zero Trust implementation
print(f"Zero Trust components: {len(zero_trust.zero_trust_components)}")
print(f"Policy engine configured: {zero_trust.policy_engine is not None}")
print(f"Forensic integration: {'forensic_integration' in policy_engine}")
```

---

## Module 4: Forensic-Ready Architecture (60 minutes)

### Architecture for Digital Forensics

```python
class EvidenceType(Enum):
    NETWORK_TRAFFIC = "network_traffic"
    SYSTEM_LOGS = "system_logs"
    APPLICATION_LOGS = "application_logs"
    DATABASE_TRANSACTIONS = "database_transactions"
    FILE_SYSTEM_CHANGES = "file_system_changes"
    MEMORY_DUMPS = "memory_dumps"

@dataclass
class ForensicCapability:
    capability_id: str
    name: str
    evidence_types: List[EvidenceType]
    collection_method: str
    preservation_requirements: List[str]
    chain_of_custody: bool
    court_admissibility: str

class ForensicReadyArchitecture:
    def __init__(self, security_arch: SecurityArchitecture, zero_trust: ZeroTrustArchitecture):
        self.security_arch = security_arch
        self.zero_trust = zero_trust
        self.forensic_capabilities = {}
        self.evidence_collection_points = []
        self.chain_of_custody_system = None
        self._design_forensic_capabilities()
    
    def _design_forensic_capabilities(self):
        """Design comprehensive forensic collection capabilities"""
        
        # Network Forensics (builds on Week 6)
        network_forensics = ForensicCapability(
            "FORENSIC-NET", "Network Traffic Forensics",
            [EvidenceType.NETWORK_TRAFFIC],
            collection_method="Full packet capture with metadata",
            preservation_requirements=[
                "Tamper-evident storage",
                "Cryptographic hashing (Week 2)",
                "Digital signatures (Week 3)",
                "Timestamping with trusted source"
            ],
            chain_of_custody=True,
            court_admissibility="High - RFC 3227 compliant"
        )
        
        # Identity and Access Forensics (builds on Weeks 4-5)
        identity_forensics = ForensicCapability(
            "FORENSIC-IAM", "Identity and Access Forensics", 
            [EvidenceType.SYSTEM_LOGS, EvidenceType.APPLICATION_LOGS],
            collection_method="Comprehensive authentication and authorization logging",
            preservation_requirements=[
                "Immutable log storage",
                "Digital signatures on log entries (Week 3)",
                "Centralized collection (Week 7)",
                "Detailed context preservation"
            ],
            chain_of_custody=True,
            court_admissibility="High - detailed audit trails"
        )
        
        # Security Monitoring Forensics (builds on Week 7)
        monitoring_forensics = ForensicCapability(
            "FORENSIC-SIEM", "Security Event Forensics",
            [EvidenceType.SYSTEM_LOGS, EvidenceType.APPLICATION_LOGS],
            collection_method="SIEM-based evidence correlation and preservation",
            preservation_requirements=[
                "Event correlation preservation", 
                "Raw log retention alongside processed events",
                "Analyst decision tracking",
                "Incident timeline reconstruction"
            ],
            chain_of_custody=True,
            court_admissibility="Medium - requires expert testimony"
        )
        
        self.forensic_capabilities = {
            "network": network_forensics,
            "identity": identity_forensics,
            "monitoring": monitoring_forensics
        }
    
    def implement_chain_of_custody(self) -> Dict:
        """Implement digital chain of custody system"""
        
        chain_of_custody_system = {
            "evidence_identification": {
                "unique_evidence_id": "UUID + timestamp + hash",
                "evidence_metadata": [
                    "collection_timestamp",
                    "collection_method", 
                    "collector_identity",
                    "source_system",
                    "evidence_type",
                    "preservation_method"
                ],
                "digital_signature": "PKI-based evidence signing (Week 3)"
            },
            
            "evidence_handling": {
                "collection_procedures": [
                    "Automated collection where possible",
                    "Manual collection with dual-control", 
                    "Immediate hashing and signing",
                    "Secure transport to evidence store"
                ],
                "storage_requirements": [
                    "Tamper-evident storage",
                    "Access logging and monitoring",
                    "Encryption at rest (Week 1)",
                    "Geographic redundancy"
                ],
                "access_controls": [
                    "Role-based access (Week 5)",
                    "Need-to-know principle",
                    "Multi-person integrity",
                    "Complete access audit trail"
                ]
            },
            
            "admissibility_support": {
                "technical_documentation": [
                    "Collection tool validation",
                    "Process documentation",
                    "Quality assurance procedures",
                    "Expert witness preparation"
                ],
                "legal_framework": [
                    "Federal Rules of Evidence compliance",
                    "Industry standard adherence",
                    "Chain of custody documentation",
                    "Evidence authenticity proof"
                ]
            }
        }
        
        self.chain_of_custody_system = chain_of_custody_system
        return chain_of_custody_system
    
    def generate_forensic_architecture_document(self) -> Dict:
        """Generate complete forensic readiness architecture"""
        
        forensic_architecture = {
            "executive_summary": {
                "purpose": "Enable comprehensive digital forensics investigation capabilities",
                "scope": "Enterprise security architecture with forensic readiness",
                "compliance": ["RFC 3227", "NIST SP 800-86", "Federal Rules of Evidence"]
            },
            
            "forensic_capabilities": {
                cap_id: {
                    "name": cap.name,
                    "evidence_types": [et.value for et in cap.evidence_types],
                    "admissibility": cap.court_admissibility,
                    "integration_points": self._map_integration_points(cap)
                }
                for cap_id, cap in self.forensic_capabilities.items()
            },
            
            "architecture_integration": {
                "security_controls": list(self.security_arch.controls.keys()),
                "zero_trust_components": list(self.zero_trust.zero_trust_components.keys()),
                "evidence_collection_points": self._identify_collection_points(),
                "forensic_workflows": self._define_forensic_workflows()
            },
            
            "implementation_roadmap": {
                "phase_1": "Basic evidence collection (Weeks 3-8 systems)",
                "phase_2": "Advanced correlation and analysis", 
                "phase_3": "Full forensic investigation capability",
                "validation": "Forensic capability testing and validation"
            }
        }
        
        return forensic_architecture
    
    def _map_integration_points(self, capability: ForensicCapability) -> List[str]:
        """Map forensic capability to security architecture integration points"""
        integration_points = []
        
        if EvidenceType.NETWORK_TRAFFIC in capability.evidence_types:
            integration_points.extend(["NET-001", "NET-002", "MON-001"])
        
        if EvidenceType.SYSTEM_LOGS in capability.evidence_types:
            integration_points.extend(["MON-001", "AUTH-001", "AC-001"])
            
        if EvidenceType.APPLICATION_LOGS in capability.evidence_types:
            integration_points.extend(["AC-002", "MON-002"])
        
        return integration_points
    
    def _identify_collection_points(self) -> List[str]:
        """Identify all evidence collection points in architecture"""
        return [
            "Network boundaries (firewalls, routers)",
            "Authentication systems (MFA, SSO)", 
            "Access control systems (RBAC, policies)",
            "SIEM and monitoring platforms",
            "Database transaction logs",
            "Application audit trails"
        ]
    
    def _define_forensic_workflows(self) -> Dict:
        """Define forensic investigation workflows"""
        return {
            "incident_detection": "SIEM alerts → Initial triage → Evidence preservation",
            "evidence_collection": "Automated collection → Manual validation → Chain of custody",
            "analysis": "Timeline reconstruction → Correlation analysis → Impact assessment",
            "reporting": "Technical findings → Executive summary → Legal documentation"
        }

# Implement forensic-ready architecture
forensic_arch = ForensicReadyArchitecture(enterprise_arch, zero_trust)
chain_of_custody = forensic_arch.implement_chain_of_custody()
forensic_doc = forensic_arch.generate_forensic_architecture_document()

print("Forensic-Ready Architecture:")
print(f"  Forensic capabilities: {len(forensic_arch.forensic_capabilities)}")
print(f"  Evidence collection points: {len(forensic_doc['architecture_integration']['evidence_collection_points'])}")
print(f"  Chain of custody implemented: {forensic_arch.chain_of_custody_system is not None}")
```

### Checkpoint 4: Forensic Architecture Validation
```python
# Validate forensic readiness
print(f"Court-admissible capabilities: {sum(1 for cap in forensic_arch.forensic_capabilities.values() if 'High' in cap.court_admissibility)}")
print(f"Integration points mapped: {len(forensic_doc['architecture_integration']['security_controls'])}")
```

## Tutorial Completion

🎉 **Congratulations!** You've designed a comprehensive security architecture that bridges preventive and reactive security.

### What You've Accomplished:
1. **Enterprise Security Architecture** integrating all Weeks 3-8 systems
2. **Comprehensive Threat Model** using STRIDE methodology
3. **Zero Trust Architecture** with continuous verification
4. **Forensic-Ready Design** supporting digital investigations

### Next Steps:
- **Week 9 Assignment**: Design complete security architecture for fictional organization
- **Week 10 Preview**: Digital forensics investigation using your forensic-ready architecture
- **Part II Transition**: From preventive to reactive security

### Professional Applications:
- **Security Architect** roles requiring comprehensive system design
- **Chief Information Security Officer** strategic planning
- **Forensic Readiness** for compliance and incident response
- **Zero Trust Implementation** in modern enterprises

You're now ready to design enterprise-grade security architectures! 🏗️