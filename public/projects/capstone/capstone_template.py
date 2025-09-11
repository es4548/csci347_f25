#!/usr/bin/env python3
"""
CSCI 347 Capstone Project Template

This template provides the foundational structure for implementing capstone
projects that integrate all course concepts. Students should choose one of
three options and build upon this foundation to create a comprehensive
cybersecurity platform.

Author: CSCI 347 Course Template
Date: Fall 2025
"""

import os
import json
import logging
import hashlib
import sqlite3
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod

# Import components from major projects
# Students should import their actual implementations
from project1_mfa_system import MFASystem  # Authentication integration
from project2_forensics_platform import ForensicPlatform  # Forensics integration
from project3_advanced_analysis import AdvancedForensicsToolkit  # Advanced analysis


class CapstoneOption(Enum):
    """Capstone project options"""
    SOC_PLATFORM = "soc_platform"
    FORENSICS_LAB = "forensics_lab"
    RESEARCH_PROJECT = "research_project"


class IntegrationLevel(Enum):
    """Level of integration with major projects"""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    RESEARCH = "research"


@dataclass
class ProjectIntegration:
    """Integration requirements and status for major projects"""
    project_name: str
    integration_level: IntegrationLevel
    required_components: List[str]
    implemented_components: List[str] = field(default_factory=list)
    integration_notes: str = ""
    
    @property
    def completion_percentage(self) -> float:
        if not self.required_components:
            return 100.0
        return len(self.implemented_components) / len(self.required_components) * 100.0


@dataclass
class InnovationContribution:
    """Innovation and research contribution tracking"""
    innovation_type: str
    description: str
    impact_assessment: str
    validation_method: str
    academic_potential: str
    industry_relevance: str
    implementation_status: str = "planned"


class CapstoneProjectBase(ABC):
    """
    Base class for all capstone project implementations
    
    This abstract base class defines the common interface and integration
    requirements that all capstone projects must implement.
    """
    
    def __init__(self, project_name: str, workspace_path: str, 
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize capstone project base
        
        Args:
            project_name: Name of the capstone project
            workspace_path: Path to project workspace
            config: Project configuration dictionary
        """
        self.project_name = project_name
        self.workspace_path = Path(workspace_path)
        self.config = config or {}
        
        # Create workspace structure
        self._setup_workspace()
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize integration tracking
        self._init_integration_tracking()
        
        # Initialize components
        self._init_components()
    
    def _setup_workspace(self):
        """Setup capstone workspace structure"""
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        
        # Create capstone-specific directories
        self.src_dir = self.workspace_path / "src"
        self.tests_dir = self.workspace_path / "tests"
        self.docs_dir = self.workspace_path / "docs"
        self.data_dir = self.workspace_path / "data"
        self.results_dir = self.workspace_path / "results"
        self.presentation_dir = self.workspace_path / "presentation"
        
        for directory in [self.src_dir, self.tests_dir, self.docs_dir,
                         self.data_dir, self.results_dir, self.presentation_dir]:
            directory.mkdir(exist_ok=True)
    
    def _setup_logging(self):
        """Setup comprehensive logging for capstone project"""
        log_file = self.workspace_path / f"{self.project_name}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(self.project_name)
        self.logger.info(f"Capstone project {self.project_name} initialized")
    
    def _init_integration_tracking(self):
        """Initialize integration tracking for major projects"""
        self.project_integrations = {
            "project1_mfa": ProjectIntegration(
                project_name="Multi-Factor Authentication System",
                integration_level=IntegrationLevel.INTERMEDIATE,
                required_components=[
                    "user_authentication",
                    "access_control",
                    "session_management",
                    "security_logging"
                ]
            ),
            "project2_forensics": ProjectIntegration(
                project_name="Digital Forensics Platform",
                integration_level=IntegrationLevel.INTERMEDIATE,
                required_components=[
                    "evidence_handling",
                    "chain_of_custody",
                    "investigation_workflows",
                    "forensic_reporting"
                ]
            ),
            "project3_advanced": ProjectIntegration(
                project_name="Advanced Analysis Toolkit",
                integration_level=IntegrationLevel.INTERMEDIATE,
                required_components=[
                    "memory_analysis",
                    "malware_detection",
                    "ml_integration",
                    "threat_intelligence"
                ]
            )
        }
        
        self.innovation_contributions = []
    
    @abstractmethod
    def _init_components(self):
        """Initialize project-specific components (implemented by subclasses)"""
        pass
    
    # ===== INTEGRATION METHODS =====
    
    def integrate_authentication_system(self) -> bool:
        """
        Integrate MFA system from Project 1
        
        Returns:
            Success status of integration
            
        TODO: Implement integration with your MFA system:
        - User registration and authentication
        - Role-based access control
        - Session management
        - Security event logging
        """
        try:
            # TODO: Students should integrate their actual MFA system
            # self.mfa_system = MFASystem(config=self.config.get('mfa', {}))
            
            # Placeholder integration
            self.logger.info("MFA system integration placeholder")
            
            # Mark components as implemented
            integration = self.project_integrations["project1_mfa"]
            integration.implemented_components = [
                "user_authentication",
                "access_control",
                "session_management",
                "security_logging"
            ]
            
            return True
            
        except Exception as e:
            self.logger.error(f"MFA integration failed: {e}")
            return False
    
    def integrate_forensics_platform(self) -> bool:
        """
        Integrate forensics platform from Project 2
        
        Returns:
            Success status of integration
            
        TODO: Implement integration with your forensics platform:
        - Evidence acquisition and storage
        - Chain of custody procedures
        - Investigation case management
        - Forensic analysis workflows
        """
        try:
            # TODO: Students should integrate their actual forensics platform
            # self.forensics_platform = ForensicPlatform(workspace_path=str(self.data_dir))
            
            # Placeholder integration
            self.logger.info("Forensics platform integration placeholder")
            
            # Mark components as implemented
            integration = self.project_integrations["project2_forensics"]
            integration.implemented_components = [
                "evidence_handling",
                "chain_of_custody",
                "investigation_workflows",
                "forensic_reporting"
            ]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Forensics integration failed: {e}")
            return False
    
    def integrate_advanced_analysis(self) -> bool:
        """
        Integrate advanced analysis toolkit from Project 3
        
        Returns:
            Success status of integration
            
        TODO: Implement integration with your advanced analysis toolkit:
        - Memory forensics capabilities
        - Malware detection and analysis
        - Machine learning integration
        - Threat intelligence correlation
        """
        try:
            # TODO: Students should integrate their actual advanced analysis toolkit
            # self.advanced_toolkit = AdvancedForensicsToolkit(
            #     workspace_path=str(self.data_dir),
            #     config=self.config.get('advanced', {})
            # )
            
            # Placeholder integration
            self.logger.info("Advanced analysis integration placeholder")
            
            # Mark components as implemented
            integration = self.project_integrations["project3_advanced"]
            integration.implemented_components = [
                "memory_analysis",
                "malware_detection",
                "ml_integration",
                "threat_intelligence"
            ]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Advanced analysis integration failed: {e}")
            return False
    
    # ===== INNOVATION AND RESEARCH =====
    
    def add_innovation_contribution(self, contribution: InnovationContribution):
        """Add an innovation contribution to the project"""
        self.innovation_contributions.append(contribution)
        self.logger.info(f"Added innovation: {contribution.innovation_type}")
    
    def validate_innovation_contribution(self, contribution_index: int) -> Dict[str, Any]:
        """
        Validate an innovation contribution with testing and evaluation
        
        Args:
            contribution_index: Index of contribution to validate
            
        Returns:
            Validation results dictionary
            
        TODO: Implement validation methodology:
        - Performance benchmarking against baselines
        - Accuracy testing with ground truth data
        - Usability evaluation with expert feedback
        - Security analysis and vulnerability assessment
        """
        if contribution_index >= len(self.innovation_contributions):
            return {"error": "Invalid contribution index"}
        
        contribution = self.innovation_contributions[contribution_index]
        
        # TODO: Implement actual validation methodology
        validation_results = {
            "contribution": contribution.innovation_type,
            "validation_status": "placeholder",
            "performance_metrics": {},
            "accuracy_results": {},
            "security_assessment": {},
            "expert_feedback": {},
            "recommendations": []
        }
        
        return validation_results
    
    # ===== ASSESSMENT AND REPORTING =====
    
    def generate_integration_report(self) -> Dict[str, Any]:
        """Generate comprehensive integration report"""
        report = {
            "project_name": self.project_name,
            "generation_timestamp": datetime.now().isoformat(),
            "overall_integration_status": self._calculate_overall_integration(),
            "project_integrations": {},
            "innovation_contributions": len(self.innovation_contributions),
            "recommendations": []
        }
        
        # Add detailed integration status for each major project
        for key, integration in self.project_integrations.items():
            report["project_integrations"][key] = {
                "name": integration.project_name,
                "integration_level": integration.integration_level.value,
                "completion_percentage": integration.completion_percentage,
                "required_components": integration.required_components,
                "implemented_components": integration.implemented_components,
                "missing_components": list(set(integration.required_components) - 
                                         set(integration.implemented_components)),
                "notes": integration.integration_notes
            }
        
        return report
    
    def _calculate_overall_integration(self) -> float:
        """Calculate overall integration percentage across all projects"""
        if not self.project_integrations:
            return 0.0
        
        total_percentage = sum(integration.completion_percentage 
                             for integration in self.project_integrations.values())
        return total_percentage / len(self.project_integrations)
    
    @abstractmethod
    def generate_capstone_report(self) -> str:
        """Generate comprehensive capstone project report (implemented by subclasses)"""
        pass
    
    def close(self):
        """Close capstone project and cleanup resources"""
        self.logger.info(f"Capstone project {self.project_name} completed")


class SOCPlatform(CapstoneProjectBase):
    """
    Option A: Integrated Cybersecurity Operations Center (SOC)
    
    Comprehensive security monitoring, detection, and response platform
    integrating preventive and reactive security measures.
    """
    
    def __init__(self, workspace_path: str, config: Optional[Dict[str, Any]] = None):
        super().__init__("SOC_Platform", workspace_path, config)
    
    def _init_components(self):
        """Initialize SOC-specific components"""
        self.logger.info("Initializing SOC Platform components")
        
        # Initialize core SOC components
        self._init_monitoring_dashboard()
        self._init_incident_response()
        self._init_threat_intelligence()
        self._init_siem_integration()
    
    def _init_monitoring_dashboard(self):
        """Initialize real-time security monitoring dashboard"""
        # TODO: Implement comprehensive monitoring dashboard
        # - Real-time event correlation
        # - Threat detection algorithms
        # - Alert management system
        # - Executive dashboards
        self.logger.info("Monitoring dashboard initialized")
    
    def _init_incident_response(self):
        """Initialize automated incident response workflows"""
        # TODO: Implement incident response automation
        # - Incident detection and classification
        # - Automated response playbooks
        # - Escalation procedures
        # - Integration with forensics platform
        self.logger.info("Incident response workflows initialized")
    
    def _init_threat_intelligence(self):
        """Initialize threat intelligence integration"""
        # TODO: Implement threat intelligence platform
        # - IOC feed integration
        # - Threat actor attribution
        # - TTPs mapping and correlation
        # - Automated threat hunting
        self.logger.info("Threat intelligence platform initialized")
    
    def _init_siem_integration(self):
        """Initialize SIEM integration and log management"""
        # TODO: Implement SIEM integration
        # - Log aggregation and parsing
        # - Event correlation rules
        # - Custom detection algorithms
        # - Compliance reporting
        self.logger.info("SIEM integration initialized")
    
    def process_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming security events through the SOC pipeline
        
        Args:
            event_data: Security event data dictionary
            
        Returns:
            Processing results and recommendations
            
        TODO: Implement comprehensive event processing:
        - Event normalization and enrichment
        - Threat intelligence correlation
        - Risk scoring and prioritization
        - Automated response triggering
        """
        processing_results = {
            "event_id": event_data.get("id", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "threat_level": "unknown",
            "confidence": 0.0,
            "enrichment_data": {},
            "recommended_actions": [],
            "automated_responses": []
        }
        
        # TODO: Implement actual event processing logic
        
        return processing_results
    
    def generate_capstone_report(self) -> str:
        """Generate SOC platform capstone report"""
        report_path = self.results_dir / "soc_platform_report.html"
        
        # TODO: Generate comprehensive SOC report
        # - Executive summary with security posture assessment
        # - Incident response effectiveness metrics
        # - Threat intelligence integration results
        # - Integration demonstration with all major projects
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SOC Platform Capstone Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .metric {{ background-color: #f0f8ff; padding: 10px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <h1>Cybersecurity Operations Center (SOC) Platform</h1>
            <h2>Capstone Project Report</h2>
            
            <div class="section">
                <h3>Executive Summary</h3>
                <p>Comprehensive SOC platform integrating security monitoring, 
                   incident response, and forensic investigation capabilities.</p>
                
                <div class="metric">
                    <strong>Integration Status:</strong> 
                    {self._calculate_overall_integration():.1f}% Complete
                </div>
                
                <div class="metric">
                    <strong>Innovation Contributions:</strong> 
                    {len(self.innovation_contributions)}
                </div>
            </div>
            
            <div class="section">
                <h3>Major Project Integrations</h3>
                {self._format_integration_status_html()}
            </div>
            
            <div class="section">
                <h3>SOC Capabilities</h3>
                <ul>
                    <li>Real-time security event monitoring and correlation</li>
                    <li>Automated incident response and forensic investigation</li>
                    <li>Threat intelligence integration and hunting</li>
                    <li>Comprehensive security reporting and compliance</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _format_integration_status_html(self) -> str:
        """Format integration status for HTML report"""
        html = ""
        for key, integration in self.project_integrations.items():
            completion = integration.completion_percentage
            status_color = "#d4edda" if completion == 100 else "#fff3cd" if completion > 50 else "#f8d7da"
            
            html += f"""
            <div style="background-color: {status_color}; padding: 10px; margin: 5px 0;">
                <strong>{integration.project_name}</strong><br>
                Completion: {completion:.1f}%<br>
                Components: {len(integration.implemented_components)}/{len(integration.required_components)}
            </div>
            """
        return html


class ForensicsLaboratory(CapstoneProjectBase):
    """
    Option B: Advanced Digital Forensics Laboratory
    
    Complete forensics investigation environment with educational components,
    advanced analysis capabilities, and research contributions.
    """
    
    def __init__(self, workspace_path: str, config: Optional[Dict[str, Any]] = None):
        super().__init__("Forensics_Laboratory", workspace_path, config)
    
    def _init_components(self):
        """Initialize forensics laboratory components"""
        self.logger.info("Initializing Forensics Laboratory components")
        
        # Initialize laboratory components
        self._init_evidence_processing()
        self._init_training_environment()
        self._init_research_platform()
        self._init_legal_compliance()
    
    def _init_evidence_processing(self):
        """Initialize multi-evidence processing pipeline"""
        # TODO: Implement comprehensive evidence processing
        # - Automated evidence intake and cataloging
        # - Cross-evidence timeline correlation
        # - Batch processing capabilities
        # - Quality assurance and validation
        self.logger.info("Evidence processing pipeline initialized")
    
    def _init_training_environment(self):
        """Initialize educational training environment"""
        # TODO: Implement training platform
        # - Interactive forensic challenges
        # - Skill assessment and tracking
        # - Virtual lab environments
        # - Certification preparation materials
        self.logger.info("Training environment initialized")
    
    def _init_research_platform(self):
        """Initialize research and development platform"""
        # TODO: Implement research capabilities
        # - Tool development and validation
        # - Academic documentation system
        # - Peer review workflows
        # - Open source contribution management
        self.logger.info("Research platform initialized")
    
    def _init_legal_compliance(self):
        """Initialize legal and compliance framework"""
        # TODO: Implement legal compliance
        # - Chain of custody automation
        # - Court admissibility validation
        # - Multi-jurisdiction compliance
        # - Expert witness preparation
        self.logger.info("Legal compliance framework initialized")
    
    def process_investigation_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a complete forensic investigation case
        
        Args:
            case_data: Investigation case information
            
        Returns:
            Investigation results and findings
            
        TODO: Implement comprehensive case processing:
        - Evidence acquisition and validation
        - Multi-platform analysis integration
        - Timeline reconstruction and correlation
        - Legal report generation
        """
        investigation_results = {
            "case_id": case_data.get("id", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "evidence_processed": 0,
            "artifacts_found": 0,
            "timeline_events": 0,
            "legal_compliance": False,
            "findings_summary": "",
            "recommendations": []
        }
        
        # TODO: Implement actual case processing logic
        
        return investigation_results
    
    def generate_capstone_report(self) -> str:
        """Generate forensics laboratory capstone report"""
        report_path = self.results_dir / "forensics_lab_report.html"
        
        # TODO: Generate comprehensive forensics lab report
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Digital Forensics Laboratory Capstone Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .capability {{ background-color: #f8f9fa; padding: 8px; margin: 3px 0; }}
            </style>
        </head>
        <body>
            <h1>Advanced Digital Forensics Laboratory</h1>
            <h2>Capstone Project Report</h2>
            
            <div class="section">
                <h3>Executive Summary</h3>
                <p>Comprehensive forensics laboratory integrating investigation, 
                   education, and research capabilities for digital forensics excellence.</p>
                
                <div class="capability">
                    <strong>Integration Status:</strong> 
                    {self._calculate_overall_integration():.1f}% Complete
                </div>
            </div>
            
            <div class="section">
                <h3>Laboratory Capabilities</h3>
                <div class="capability">Multi-Evidence Processing Pipeline</div>
                <div class="capability">Interactive Training Environment</div>
                <div class="capability">Research and Development Platform</div>
                <div class="capability">Legal Compliance Framework</div>
            </div>
            
            <div class="section">
                <h3>Research Contributions</h3>
                <p>Innovation count: {len(self.innovation_contributions)}</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return str(report_path)


class ResearchProject(CapstoneProjectBase):
    """
    Option C: Cybersecurity Research and Innovation Project
    
    Original research addressing current cybersecurity challenges with
    practical implementation and academic-quality documentation.
    """
    
    def __init__(self, workspace_path: str, research_topic: str, 
                 config: Optional[Dict[str, Any]] = None):
        self.research_topic = research_topic
        super().__init__(f"Research_{research_topic}", workspace_path, config)
    
    def _init_components(self):
        """Initialize research project components"""
        self.logger.info(f"Initializing Research Project: {self.research_topic}")
        
        # Initialize research components
        self._init_literature_review()
        self._init_experimental_platform()
        self._init_validation_framework()
        self._init_documentation_system()
    
    def _init_literature_review(self):
        """Initialize literature review and background research"""
        # TODO: Implement literature review system
        # - Academic paper database integration
        # - Citation management
        # - Gap analysis documentation
        # - Research question formulation
        self.logger.info("Literature review system initialized")
    
    def _init_experimental_platform(self):
        """Initialize experimental research platform"""
        # TODO: Implement experimental platform
        # - Hypothesis testing framework
        # - Data collection and analysis
        # - Statistical evaluation tools
        # - Reproducibility management
        self.logger.info("Experimental platform initialized")
    
    def _init_validation_framework(self):
        """Initialize research validation and peer review"""
        # TODO: Implement validation framework
        # - Experimental validation protocols
        # - Peer review management
        # - Result reproducibility testing
        # - Impact assessment tools
        self.logger.info("Validation framework initialized")
    
    def _init_documentation_system(self):
        """Initialize academic documentation system"""
        # TODO: Implement documentation system
        # - Academic paper generation
        # - Research methodology documentation
        # - Data and code documentation
        # - Presentation material generation
        self.logger.info("Documentation system initialized")
    
    def conduct_research_experiment(self, experiment_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Conduct a research experiment with proper methodology
        
        Args:
            experiment_config: Experiment configuration and parameters
            
        Returns:
            Experimental results and analysis
            
        TODO: Implement rigorous experimental methodology:
        - Hypothesis testing with statistical significance
        - Control group management and comparison
        - Data collection and quality assurance
        - Result analysis and interpretation
        """
        experiment_results = {
            "experiment_id": experiment_config.get("id", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "hypothesis": experiment_config.get("hypothesis", ""),
            "methodology": experiment_config.get("methodology", ""),
            "results": {},
            "statistical_analysis": {},
            "conclusions": "",
            "future_work": []
        }
        
        # TODO: Implement actual experimental methodology
        
        return experiment_results
    
    def generate_capstone_report(self) -> str:
        """Generate research project capstone report"""
        report_path = self.results_dir / "research_project_report.html"
        
        # TODO: Generate academic-quality research report
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cybersecurity Research Project Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .research-element {{ background-color: #f0f0f0; padding: 8px; margin: 3px 0; }}
            </style>
        </head>
        <body>
            <h1>Cybersecurity Research and Innovation Project</h1>
            <h2>Topic: {self.research_topic}</h2>
            
            <div class="section">
                <h3>Research Summary</h3>
                <p>Original research contribution addressing current gaps in 
                   cybersecurity knowledge and practice.</p>
                
                <div class="research-element">
                    <strong>Integration Status:</strong> 
                    {self._calculate_overall_integration():.1f}% Complete
                </div>
            </div>
            
            <div class="section">
                <h3>Research Components</h3>
                <div class="research-element">Literature Review and Gap Analysis</div>
                <div class="research-element">Experimental Research Platform</div>
                <div class="research-element">Validation and Peer Review Framework</div>
                <div class="research-element">Academic Documentation System</div>
            </div>
            
            <div class="section">
                <h3>Innovation Contributions</h3>
                <p>Total contributions: {len(self.innovation_contributions)}</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return str(report_path)


# ===== CAPSTONE PROJECT FACTORY =====

def create_capstone_project(option: CapstoneOption, workspace_path: str,
                           config: Optional[Dict[str, Any]] = None,
                           research_topic: Optional[str] = None) -> CapstoneProjectBase:
    """
    Factory function to create appropriate capstone project instance
    
    Args:
        option: Capstone project option to create
        workspace_path: Path to project workspace
        config: Project configuration dictionary
        research_topic: Research topic (required for research project)
        
    Returns:
        Appropriate capstone project instance
    """
    if option == CapstoneOption.SOC_PLATFORM:
        return SOCPlatform(workspace_path, config)
    elif option == CapstoneOption.FORENSICS_LAB:
        return ForensicsLaboratory(workspace_path, config)
    elif option == CapstoneOption.RESEARCH_PROJECT:
        if not research_topic:
            raise ValueError("Research topic required for research project option")
        return ResearchProject(workspace_path, research_topic, config)
    else:
        raise ValueError(f"Unknown capstone option: {option}")


# ===== EXAMPLE USAGE =====

def main():
    """
    Example usage demonstrating all three capstone options
    """
    print("CSCI 347 Capstone Project Template")
    print("=" * 50)
    
    workspace_base = Path("/tmp/capstone_workspace")
    
    # Example 1: SOC Platform
    print("\n--- SOC Platform Example ---")
    try:
        soc_project = create_capstone_project(
            CapstoneOption.SOC_PLATFORM,
            str(workspace_base / "soc_platform")
        )
        
        # Integrate major projects
        soc_project.integrate_authentication_system()
        soc_project.integrate_forensics_platform()
        soc_project.integrate_advanced_analysis()
        
        # Add innovation contribution
        innovation = InnovationContribution(
            innovation_type="Automated Threat Correlation",
            description="Novel ML-based threat correlation engine",
            impact_assessment="Reduces false positives by 40%",
            validation_method="Comparative analysis with baseline SIEM",
            academic_potential="Conference paper submission ready",
            industry_relevance="Direct applicability to SOC operations"
        )
        soc_project.add_innovation_contribution(innovation)
        
        # Generate reports
        integration_report = soc_project.generate_integration_report()
        print(f"SOC Integration Status: {integration_report['overall_integration_status']:.1f}%")
        
        capstone_report = soc_project.generate_capstone_report()
        print(f"SOC Capstone Report: {capstone_report}")
        
        soc_project.close()
        
    except Exception as e:
        print(f"SOC Platform example failed: {e}")
    
    # Example 2: Forensics Laboratory
    print("\n--- Forensics Laboratory Example ---")
    try:
        lab_project = create_capstone_project(
            CapstoneOption.FORENSICS_LAB,
            str(workspace_base / "forensics_lab")
        )
        
        # Integrate major projects
        lab_project.integrate_authentication_system()
        lab_project.integrate_forensics_platform()
        lab_project.integrate_advanced_analysis()
        
        # Generate report
        integration_report = lab_project.generate_integration_report()
        print(f"Lab Integration Status: {integration_report['overall_integration_status']:.1f}%")
        
        capstone_report = lab_project.generate_capstone_report()
        print(f"Lab Capstone Report: {capstone_report}")
        
        lab_project.close()
        
    except Exception as e:
        print(f"Forensics Laboratory example failed: {e}")
    
    # Example 3: Research Project
    print("\n--- Research Project Example ---")
    try:
        research_project = create_capstone_project(
            CapstoneOption.RESEARCH_PROJECT,
            str(workspace_base / "research_project"),
            research_topic="AI_Driven_Malware_Detection"
        )
        
        # Integrate major projects
        research_project.integrate_authentication_system()
        research_project.integrate_forensics_platform()
        research_project.integrate_advanced_analysis()
        
        # Add research innovation
        innovation = InnovationContribution(
            innovation_type="Novel ML Architecture",
            description="Transformer-based malware detection with explainability",
            impact_assessment="15% improvement over state-of-the-art",
            validation_method="10-fold cross-validation with public datasets",
            academic_potential="Top-tier conference submission ready",
            industry_relevance="Applicable to enterprise antivirus solutions"
        )
        research_project.add_innovation_contribution(innovation)
        
        # Generate reports
        integration_report = research_project.generate_integration_report()
        print(f"Research Integration Status: {integration_report['overall_integration_status']:.1f}%")
        
        capstone_report = research_project.generate_capstone_report()
        print(f"Research Capstone Report: {capstone_report}")
        
        research_project.close()
        
    except Exception as e:
        print(f"Research Project example failed: {e}")


if __name__ == "__main__":
    main()