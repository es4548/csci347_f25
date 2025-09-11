# Week 14 Assignment: Capstone Security Operations Platform

**Due**: End of Week 14 (see Canvas for exact deadline)  
**Points**: 25 points  
**Estimated Time**: 8 hours  
**Submission**: Submit Pull Request URL to Canvas

## 🎯 Assignment Overview

Create focused incident response platform that demonstrates integration of core cybersecurity concepts from the course. This capstone assignment emphasizes incident response coordination using provided templates and simplified automation workflows.

## 📋 Learning Outcomes

This capstone assignment assesses your ability to:

1. **Incident Response Coordination** (15 points)
2. **Security Integration & Automation** (5 points)
3. **Professional Documentation** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build focused incident response platform:

```python
# Core platform modules
incident_coordinator.py  # NIST-aligned incident response workflows
automation_engine.py     # Basic security automation and notifications
reporting_system.py      # Incident reporting and documentation
```

### Required Libraries
```python
import asyncio
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
import json
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from flask import Flask, render_template, request, jsonify
import threading
from concurrent.futures import ThreadPoolExecutor
```

## 📝 Detailed Requirements

### 1. Incident Response Coordination (15 points)

**Focus Area: NIST-Aligned Incident Response with Course Concept Integration**

**Required Features:**
- **NIST IR lifecycle** implementation (Preparation, Detection, Containment, Eradication, Recovery) with provided templates
- **Evidence management** with basic chain of custody tracking
- **Stakeholder notification** system with escalation workflows
- **Integration touchpoints** with course security concepts (PKI validation, MFA verification, network analysis, forensics collection)
- **Incident classification** and priority assignment based on business impact
- **Basic automation** for routine incident response tasks

**Deliverable:** `incident_coordinator.py` with NIST-aligned IR workflows

*Note: Incident response templates and playbooks provided*

### 2. Security Integration & Automation (5 points)

**Required Features:**
- **Basic automation** for security tool coordination (simulated integrations)
- **Notification system** for stakeholder alerts and updates
- **Simple workflow** automation for common incident response actions
- **Status tracking** and progress monitoring for active incidents

**Deliverable:** `automation_engine.py` with basic security automation

### 3. Professional Documentation (5 points)

**Required Features:**
- **System architecture** documentation with component relationships
- **User guide** for incident response coordinators
- **Integration guide** showing course concept touchpoints
- **Deployment instructions** with setup procedures

**Deliverable:** `reporting_system.py` with comprehensive documentation generation

## 💻 Implementation Guidelines

### Platform Architecture
```
incident_response_platform/
├── src/
│   ├── incident_coordinator.py   # Main incident response coordination
│   ├── automation_engine.py      # Basic security automation
│   └── reporting_system.py       # Documentation and reporting
├── templates/
│   ├── incident_response_playbooks/  # Provided NIST IR templates
│   ├── notification_templates/      # Alert and update templates
│   └── documentation_templates/     # Report and guide templates
├── data/
│   ├── incidents.db              # Incident tracking database
│   └── stakeholders.json         # Contact and escalation info
├── docs/
│   ├── system_architecture.md    # Platform architecture
│   ├── user_guide.md             # Usage instructions
│   └── course_integration.md     # How platform integrates course concepts
└── README.md
```

### Sample Incident Management
```python
@dataclass
class SecurityIncident:
    incident_id: str
    title: str
    description: str
    severity: str  # low, medium, high, critical
    category: str  # malware, phishing, data_breach, etc.
    status: str   # new, assigned, investigating, contained, resolved
    created_time: datetime
    assigned_analyst: Optional[str] = None
    evidence: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    
    def execute_containment(self) -> bool:
        """Execute automated containment actions"""
        containment_actions = [
            self.isolate_affected_systems(),
            self.block_malicious_iocs(),
            self.preserve_evidence(),
            self.notify_stakeholders()
        ]
        
        success = all(containment_actions)
        
        if success:
            self.status = "contained"
            self.timeline.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'containment_completed',
                'details': 'Automated containment successful'
            })
        
        return success

class IncidentManager:
    def __init__(self):
        self.incidents: Dict[str, SecurityIncident] = {}
        self.playbooks: Dict[str, Dict] = self.load_playbooks()
        self.escalation_matrix = self.load_escalation_rules()
    
    def create_incident(self, alert_data: Dict) -> str:
        """Create new incident from alert"""
        incident_id = self.generate_incident_id()
        
        incident = SecurityIncident(
            incident_id=incident_id,
            title=alert_data['title'],
            description=alert_data['description'],
            severity=self.calculate_severity(alert_data),
            category=self.classify_incident(alert_data),
            status='new',
            created_time=datetime.now(),
            affected_systems=alert_data.get('affected_systems', [])
        )
        
        # Auto-assign based on severity and availability
        incident.assigned_analyst = self.auto_assign_analyst(incident)
        
        # Execute initial response playbook
        self.execute_playbook('initial_response', incident)
        
        self.incidents[incident_id] = incident
        return incident_id
    
    def execute_playbook(self, playbook_name: str, incident: SecurityIncident):
        """Execute incident response playbook"""
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            return
        
        for step in playbook['steps']:
            if step['type'] == 'automated':
                self.execute_automated_action(step, incident)
            elif step['type'] == 'manual':
                self.create_analyst_task(step, incident)
            elif step['type'] == 'decision':
                self.handle_decision_point(step, incident)
```

### Sample Threat Hunting
```python
class ThreatHunter:
    def __init__(self):
        self.hypotheses: List[Dict] = []
        self.hunt_results: List[Dict] = []
        self.ioc_feeds: Dict[str, List] = self.load_threat_intelligence()
        
    def create_hunt_hypothesis(self, hypothesis: Dict) -> str:
        """Create new threat hunting hypothesis"""
        hunt_id = self.generate_hunt_id()
        
        hypothesis_record = {
            'hunt_id': hunt_id,
            'title': hypothesis['title'],
            'description': hypothesis['description'],
            'mitre_techniques': hypothesis.get('mitre_techniques', []),
            'data_sources': hypothesis['data_sources'],
            'queries': hypothesis['queries'],
            'created_time': datetime.now().isoformat(),
            'status': 'pending'
        }
        
        self.hypotheses.append(hypothesis_record)
        return hunt_id
    
    def execute_hunt(self, hunt_id: str) -> Dict:
        """Execute threat hunting hypothesis"""
        hypothesis = self.find_hypothesis(hunt_id)
        if not hypothesis:
            return {'error': 'Hypothesis not found'}
        
        results = {
            'hunt_id': hunt_id,
            'execution_time': datetime.now().isoformat(),
            'findings': [],
            'ioc_matches': [],
            'false_positives': 0,
            'confidence_score': 0.0
        }
        
        # Execute queries across data sources
        for data_source in hypothesis['data_sources']:
            for query in hypothesis['queries']:
                query_results = self.execute_query(data_source, query)
                results['findings'].extend(query_results)
        
        # Cross-reference with threat intelligence
        results['ioc_matches'] = self.check_ioc_matches(results['findings'])
        
        # Calculate confidence score
        results['confidence_score'] = self.calculate_confidence(results)
        
        # Update hypothesis status
        hypothesis['status'] = 'completed'
        self.hunt_results.append(results)
        
        return results
    
    def hunt_for_lateral_movement(self) -> List[Dict]:
        """Hunt for lateral movement indicators"""
        indicators = []
        
        # Look for authentication patterns
        auth_events = self.get_authentication_events()
        
        # Analyze for rapid authentication across multiple hosts
        for user in self.get_unique_users(auth_events):
            user_auths = [event for event in auth_events if event['user'] == user]
            
            # Check for rapid host-hopping
            if self.detect_rapid_host_changes(user_auths):
                indicators.append({
                    'type': 'lateral_movement',
                    'user': user,
                    'technique': 'Rapid Authentication Pattern',
                    'confidence': 0.7,
                    'evidence': user_auths[:10]  # First 10 events
                })
        
        return indicators
```

### Sample SOAR Platform
```python
class SOARPlatform:
    def __init__(self):
        self.playbooks: Dict[str, Dict] = {}
        self.active_executions: Dict[str, Dict] = {}
        self.tool_connectors = self.initialize_connectors()
        
    def create_playbook(self, playbook_def: Dict) -> str:
        """Create new automation playbook"""
        playbook_id = self.generate_playbook_id()
        
        playbook = {
            'playbook_id': playbook_id,
            'name': playbook_def['name'],
            'description': playbook_def['description'],
            'trigger_conditions': playbook_def['trigger_conditions'],
            'actions': playbook_def['actions'],
            'approval_required': playbook_def.get('approval_required', False),
            'created_time': datetime.now().isoformat()
        }
        
        # Validate playbook structure
        if self.validate_playbook(playbook):
            self.playbooks[playbook_id] = playbook
            return playbook_id
        else:
            raise ValueError("Invalid playbook structure")
    
    def execute_playbook(self, playbook_id: str, trigger_data: Dict) -> str:
        """Execute automation playbook"""
        execution_id = self.generate_execution_id()
        
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        execution = {
            'execution_id': execution_id,
            'playbook_id': playbook_id,
            'trigger_data': trigger_data,
            'start_time': datetime.now().isoformat(),
            'status': 'running',
            'completed_actions': [],
            'pending_approvals': []
        }
        
        self.active_executions[execution_id] = execution
        
        # Execute in background thread
        threading.Thread(
            target=self._execute_playbook_actions,
            args=(execution_id, playbook, trigger_data)
        ).start()
        
        return execution_id
    
    def _execute_playbook_actions(self, execution_id: str, playbook: Dict, trigger_data: Dict):
        """Execute playbook actions"""
        execution = self.active_executions[execution_id]
        
        try:
            for action in playbook['actions']:
                if action.get('requires_approval') and not self.is_approved(action, execution_id):
                    self.request_approval(action, execution_id)
                    # Wait for approval
                    while not self.is_approved(action, execution_id):
                        time.sleep(10)
                
                # Execute action
                result = self.execute_action(action, trigger_data)
                execution['completed_actions'].append({
                    'action': action['name'],
                    'result': result,
                    'timestamp': datetime.now().isoformat()
                })
            
            execution['status'] = 'completed'
            execution['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            execution['status'] = 'failed'
            execution['error'] = str(e)
            execution['end_time'] = datetime.now().isoformat()
```

## 🧪 Testing Requirements

Your platform must include:

### Integration Testing
- **End-to-end workflows** from alert to incident closure
- **Cross-component** communication and data flow
- **API functionality** and error handling
- **Dashboard updates** reflecting system changes
- **Performance testing** under load

### Scenario Testing
- **Security incident** simulation from detection to resolution
- **Threat hunting** with known attack patterns
- **Automated response** to different threat types
- **Dashboard usability** for different user roles
- **Integration failure** handling and recovery

### User Acceptance Testing
Create realistic scenarios including:
- SOC analyst daily workflow simulation
- Executive dashboard review scenarios
- Incident commander coordination testing
- Threat hunter investigation workflows
- System administrator maintenance tasks

## 📤 Submission Requirements

### Required Files
1. **Complete Platform** (all source code and configuration)
2. **Documentation Suite** (architecture, deployment, user guides)
3. **Demo Video** (15-minute platform walkthrough)
4. **Test Results** (integration and scenario test reports)
5. **Deployment Package** (Docker containers or installation scripts)

### README.md Must Include:
- **Platform architecture** and design decisions
- **Installation instructions** with prerequisites
- **Configuration guide** for different environments
- **User role definitions** and access controls
- **Integration capabilities** and extension points
- **Known limitations** and future roadmap

### Documentation Suite Must Include:
- **Architecture diagrams** showing component relationships
- **API documentation** with endpoint references
- **User guides** for each role (analyst, manager, executive)
- **Playbook examples** and customization guides
- **Troubleshooting guide** for common issues

## 📊 Grading Rubric (25 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|-------|
| **Incident Response Coordination** | 60% | 15 points |
| **Security Integration & Automation** | 20% | 5 points |
| **Professional Documentation** | 20% | 5 points |

### 5-Point Scale Criteria

**Incident Response Coordination (15 points)**
- **Excellent (15)**: Complete NIST IR lifecycle implementation, comprehensive evidence management, effective stakeholder notification, clear course concept integration, proper incident classification, reliable automation
- **Proficient (12)**: Good IR workflow, adequate evidence handling, functional notifications, basic course integration, reasonable classification
- **Developing (9)**: Basic IR functionality, simple evidence tracking, limited notifications, minimal integration, basic classification
- **Needs Improvement (6)**: Incomplete IR implementation, poor evidence handling, weak notifications, no clear integration
- **Inadequate (3)**: Minimal IR capabilities, major functionality gaps, broken workflows
- **No Submission (0)**: Missing or no attempt

**Security Integration & Automation (5 points)**
- **Excellent (5)**: Effective security automation, comprehensive notification system, reliable workflows, proper status tracking, good tool coordination
- **Proficient (4)**: Good automation capabilities, adequate notifications, functional workflows, basic tracking
- **Developing (3)**: Simple automation, limited notifications, basic workflows, minimal tracking
- **Needs Improvement (2)**: Poor automation quality, weak notifications, unreliable workflows
- **Inadequate (1)**: Minimal automation capabilities, major reliability issues
- **No Submission (0)**: Missing or no attempt

**Professional Documentation (5 points)**
- **Excellent (5)**: Comprehensive system architecture, excellent user guides, clear integration explanations, detailed deployment instructions, professional presentation
- **Proficient (4)**: Good documentation, adequate guides, reasonable explanations, basic deployment info
- **Developing (3)**: Basic documentation, limited guides, simple explanations, minimal deployment info
- **Needs Improvement (2)**: Poor documentation quality, inadequate guides, unclear explanations
- **Inadequate (1)**: Minimal documentation, unprofessional presentation, major gaps
- **No Submission (0)**: Missing or no attempt

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Optional Challenge

**Advanced Integration**: Implement real-time integration with one course security concept (e.g., automated PKI certificate validation during incidents, or MFA verification for incident access), with detailed documentation of the integration architecture.

## 💡 Tips for Success

1. **Start Early**: This is a comprehensive capstone project requiring significant time
2. **Plan Architecture**: Design the integration carefully before coding
3. **Focus on Integration**: The power is in how components work together
4. **User Experience**: Make dashboards intuitive and workflows efficient
5. **Document Everything**: Professional documentation is critical
6. **Test Thoroughly**: Integration issues are common in complex platforms
7. **Demo Preparation**: Practice your presentation - this showcases your expertise

## 📚 Resources

- NIST Cybersecurity Framework
- NIST SP 800-61r2: Computer Security Incident Handling Guide
- MITRE ATT&CK Framework
- SOAR Platform Best Practices
- Security Operations Center Design Guide

---

**Congratulations on completing CSCI 347! Build a focused capstone that demonstrates your incident response and security integration skills!** 🎓🔒