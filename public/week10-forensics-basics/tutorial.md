# Week 10 Tutorial: Digital Forensics Foundations

**Estimated Time**: 4 hours  
**Prerequisites**: Week 9 completed, understanding of file systems and security architecture
**Legal Framework**: Following NIST SP 800-86 and RFC 3227 guidelines

## 🎯 Tutorial Goals

By the end of this tutorial, you will have mastered:
1. **Module 1** (60 min): Digital forensics methodology and legal frameworks (RFC 3227, NIST SP 800-86)
2. **Module 2** (60 min): Evidence acquisition and chain of custody procedures using industry tools
3. **Module 3** (60 min): File system forensics using Autopsy and Sleuth Kit for comprehensive analysis
4. **Module 4** (60 min): Timeline analysis, artifact correlation, and investigation of Week 3-9 security systems

**🎯 Integration Focus**: You will apply digital forensics techniques to investigate the security architectures you built in Weeks 3-9, demonstrating the complete cycle from preventive security design to reactive incident investigation.

### 📊 Progress Tracking
Complete each module and validate understanding before proceeding:
- [ ] Module 1: Digital Forensics Methodology & Legal Frameworks ✅ Checkpoint 1
- [ ] Module 2: Evidence Acquisition & Chain of Custody ✅ Checkpoint 2
- [ ] Module 3: File System Forensics & Autopsy Integration ✅ Checkpoint 3
- [ ] Module 4: Timeline Analysis & Security Architecture Investigation ✅ Checkpoint 4

**🔍 Professional Standard**: Each module follows industry best practices suitable for court admissibility and expert testimony.

## 🔧 Professional Forensics Environment Setup

Establish a forensically sound working environment following industry standards:

```bash
# Verify Python forensics environment
python --version  # Should be 3.11+

# Install core forensics libraries
pip install pytsk3 dfvfs plaso pytz python-registry volatility3 yara-python
pip install pandas matplotlib seaborn jupyter hashlib binwalk

# Verify forensics tool installations
python -c "import pytsk3; print('✅ The Sleuth Kit Python bindings ready')"
python -c "import volatility3; print('✅ Volatility3 memory analysis ready')"

# Professional forensics tools (platform-specific)
# Linux/Ubuntu:
# sudo apt-get install sleuthkit autopsy ewf-tools afflib-tools bulk-extractor
# sudo apt-get install foremost scalpel testdisk photorec volatility

# macOS:
# brew install sleuthkit libewf afflib bulk-extractor
# brew install --cask autopsy

# Windows: Install FTK Imager, Autopsy, and Volatility from official sources

# Create professional forensics workspace
mkdir -p forensics_lab/{cases,evidence,tools,reports,logs}
cd forensics_lab
echo "Digital Forensics Lab - Week 10" > README.txt
echo "Initialized: $(date)" >> README.txt
```

**⚖️ Legal Notice**: This forensics environment follows NIST SP 800-86 guidelines for digital evidence handling and is designed to meet court admissibility standards.

---

## 📘 Module 1: Digital Forensics Methodology & Legal Frameworks (60 minutes)

**Learning Objectives**: 
- Master NIST SP 800-86 four-phase forensic process
- Implement RFC 3227 evidence collection guidelines
- Understand legal frameworks for court admissibility
- Apply forensic methodology to security architecture investigation

**What you'll build**: Professional forensics framework following industry standards

### Step 1: Understanding Digital Forensics Methodology

Create `forensic_methodology.py` - Professional framework implementation:

```python
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import uuid
from enum import Enum

class ForensicPhase(Enum):
    """NIST SP 800-86 Four-Phase Forensic Process"""
    COLLECTION = "collection"
    EXAMINATION = "examination"
    ANALYSIS = "analysis"
    REPORTING = "reporting"

class EvidenceType(Enum):
    """Types of digital evidence per RFC 3227"""
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILE = "log_file"
    REGISTRY_HIVE = "registry_hive"
    DATABASE = "database"
    MOBILE_DEVICE = "mobile_device"

@dataclass
class LegalFramework:
    """Legal compliance framework for digital evidence"""
    jurisdiction: str
    applicable_laws: List[str]
    rules_of_evidence: str
    expert_witness_requirements: str
    chain_of_custody_requirements: str
    admissibility_standards: str
    retention_requirements: str
    
    @classmethod
    def us_federal_framework(cls):
        """Standard US Federal legal framework"""
        return cls(
            jurisdiction="US Federal",
            applicable_laws=[
                "Federal Rules of Evidence",
                "Daubert Standard",
                "18 USC 1030 (Computer Fraud and Abuse Act)",
                "Stored Communications Act"
            ],
            rules_of_evidence="Federal Rules of Evidence Article VII",
            expert_witness_requirements="Daubert Standard (FRE 702)",
            chain_of_custody_requirements="RFC 3227 + FRE 901(b)(9)",
            admissibility_standards="FRE 702, 703, 705 - Scientific Evidence",
            retention_requirements="Minimum 7 years for federal cases"
        )

@dataclass
class ForensicCase:
    """Complete forensic case management following NIST SP 800-86"""
    case_id: str
    case_number: str
    case_title: str
    incident_date: datetime
    case_opened: datetime
    lead_examiner: str
    authorized_by: str
    legal_framework: LegalFramework
    current_phase: ForensicPhase
    evidence_items: List[str] = None
    case_notes: List[str] = None
    integrity_verified: bool = False
    
    def __post_init__(self):
        if self.evidence_items is None:
            self.evidence_items = []
        if self.case_notes is None:
            self.case_notes = []

class DigitalForensicsFramework:
    """Professional digital forensics methodology implementation"""
    
    def __init__(self, case_directory: str, legal_framework: LegalFramework):
        self.case_directory = Path(case_directory)
        self.legal_framework = legal_framework
        self.current_case: Optional[ForensicCase] = None
        
        # Create NIST SP 800-86 compliant directory structure
        self._setup_case_structure()
        self._setup_logging()
        
        print(f"✅ Professional forensics framework initialized")
        print(f"   Legal Framework: {legal_framework.jurisdiction}")
        print(f"   Case Directory: {self.case_directory}")
    
    def _setup_case_structure(self):
        """Create NIST SP 800-86 compliant directory structure"""
        directories = [
            "01_collection",    # Phase 1: Evidence Collection
            "02_examination",   # Phase 2: Evidence Examination 
            "03_analysis",      # Phase 3: Evidence Analysis
            "04_reporting",     # Phase 4: Reporting
            "logs",             # Audit trail logs
            "documentation",    # Case documentation
            "working_copies"    # Working evidence copies
        ]
        
        for directory in directories:
            (self.case_directory / directory).mkdir(parents=True, exist_ok=True)
    
    def _setup_logging(self):
        """Setup comprehensive forensic logging per RFC 3227"""
        log_file = self.case_directory / "logs" / "forensic_activity.log"
        
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        
        self.logger = logging.getLogger('ForensicsFramework')
        self.logger.info("Digital forensics framework initialized")
        self.logger.info(f"Legal framework: {self.legal_framework.jurisdiction}")
    
    def create_case(self, case_number: str, case_title: str, 
                   incident_date: datetime, lead_examiner: str,
                   authorized_by: str) -> ForensicCase:
        """Create new forensic case following NIST methodology"""
        
        case_id = str(uuid.uuid4())
        
        self.current_case = ForensicCase(
            case_id=case_id,
            case_number=case_number,
            case_title=case_title,
            incident_date=incident_date,
            case_opened=datetime.now(),
            lead_examiner=lead_examiner,
            authorized_by=authorized_by,
            legal_framework=self.legal_framework,
            current_phase=ForensicPhase.COLLECTION
        )
        
        # Save case metadata
        case_file = self.case_directory / "documentation" / "case_metadata.json"
        with open(case_file, 'w') as f:
            case_dict = asdict(self.current_case)
            # Convert datetime objects for JSON
            case_dict['incident_date'] = self.current_case.incident_date.isoformat()
            case_dict['case_opened'] = self.current_case.case_opened.isoformat()
            case_dict['current_phase'] = self.current_case.current_phase.value
            case_dict['legal_framework'] = asdict(self.legal_framework)
            
            json.dump(case_dict, f, indent=2)
        
        self.logger.info(f"Case created: {case_number} - {case_title}")
        self.logger.info(f"Lead examiner: {lead_examiner}, Authorized by: {authorized_by}")
        
        print(f"🔍 Forensic case created successfully:")
        print(f"   Case ID: {case_id}")
        print(f"   Case Number: {case_number}")
        print(f"   Title: {case_title}")
        print(f"   Phase: {self.current_case.current_phase.value.title()}")
        
        return self.current_case
    
    def advance_phase(self, next_phase: ForensicPhase, notes: str = ""):
        """Advance to next phase of NIST forensic process"""
        if not self.current_case:
            raise ValueError("No active case to advance")
        
        previous_phase = self.current_case.current_phase
        self.current_case.current_phase = next_phase
        
        if notes:
            self.current_case.case_notes.append(f"[{datetime.now().isoformat()}] Phase transition: {previous_phase.value} -> {next_phase.value}: {notes}")
        
        self.logger.info(f"Phase advanced: {previous_phase.value} -> {next_phase.value}")
        if notes:
            self.logger.info(f"Phase notes: {notes}")
        
        print(f"📋 Forensic phase advanced: {next_phase.value.title()}")
        if notes:
            print(f"   Notes: {notes}")
    
    def validate_legal_compliance(self) -> Dict[str, Any]:
        """Validate current case against legal framework requirements"""
        if not self.current_case:
            return {'compliant': False, 'reason': 'No active case'}
        
        compliance_check = {
            'case_properly_authorized': bool(self.current_case.authorized_by),
            'lead_examiner_identified': bool(self.current_case.lead_examiner),
            'legal_framework_defined': bool(self.current_case.legal_framework),
            'documentation_structure': self._check_documentation_completeness(),
            'audit_trail_present': self._check_audit_trail(),
            'chain_of_custody_ready': self._check_chain_of_custody_framework()
        }
        
        all_compliant = all(compliance_check.values())
        
        result = {
            'compliant': all_compliant,
            'framework': self.legal_framework.jurisdiction,
            'checks': compliance_check,
            'recommendations': self._get_compliance_recommendations(compliance_check)
        }
        
        self.logger.info(f"Legal compliance validation: {'PASSED' if all_compliant else 'FAILED'}")
        
        return result
    
    def generate_phase_report(self) -> str:
        """Generate report for current forensic phase"""
        if not self.current_case:
            return "No active case for reporting"
        
        report_file = self.case_directory / "04_reporting" / f"phase_{self.current_case.current_phase.value}_report.txt"
        
        with open(report_file, 'w') as f:
            f.write(f"FORENSIC PHASE REPORT\n")
            f.write(f"={'='*50}\n\n")
            f.write(f"Case Number: {self.current_case.case_number}\n")
            f.write(f"Case Title: {self.current_case.case_title}\n")
            f.write(f"Current Phase: {self.current_case.current_phase.value.title()}\n")
            f.write(f"Lead Examiner: {self.current_case.lead_examiner}\n")
            f.write(f"Report Generated: {datetime.now().isoformat()}\n\n")
            
            f.write(f"LEGAL FRAMEWORK\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Jurisdiction: {self.legal_framework.jurisdiction}\n")
            f.write(f"Rules of Evidence: {self.legal_framework.rules_of_evidence}\n")
            f.write(f"Admissibility Standards: {self.legal_framework.admissibility_standards}\n\n")
            
            if self.current_case.case_notes:
                f.write(f"CASE NOTES\n")
                f.write(f"{'-'*20}\n")
                for note in self.current_case.case_notes:
                    f.write(f"{note}\n")
            
        print(f"📋 Phase report generated: {report_file}")
        return str(report_file)
    
    def _check_documentation_completeness(self) -> bool:
        """Check if required documentation structure exists"""
        required_docs = ['case_metadata.json']
        doc_dir = self.case_directory / "documentation"
        
        return all((doc_dir / doc).exists() for doc in required_docs)
    
    def _check_audit_trail(self) -> bool:
        """Check if audit trail logging is active"""
        log_file = self.case_directory / "logs" / "forensic_activity.log"
        return log_file.exists() and log_file.stat().st_size > 0
    
    def _check_chain_of_custody_framework(self) -> bool:
        """Check if chain of custody framework is ready"""
        # This will be validated when we implement evidence handling
        return True
    
    def _get_compliance_recommendations(self, checks: Dict[str, bool]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        if not checks['case_properly_authorized']:
            recommendations.append("Ensure case is properly authorized by competent authority")
        if not checks['lead_examiner_identified']:
            recommendations.append("Assign qualified lead examiner with appropriate credentials")
        if not checks['documentation_structure']:
            recommendations.append("Complete case documentation structure setup")
        if not checks['audit_trail_present']:
            recommendations.append("Verify comprehensive audit trail logging is active")
        
        return recommendations

def demo_forensic_methodology():
    """Demonstrate professional forensic methodology"""
    print("⚖️  Digital Forensics Methodology Demo - NIST SP 800-86 Compliance")
    print("="*70)
    
    # Initialize professional framework
    legal_framework = LegalFramework.us_federal_framework()
    forensics = DigitalForensicsFramework("case_globaltech_2024", legal_framework)
    
    # Demo 1: Create forensic case
    print("\n📋 Demo 1: Case Creation (Following NIST SP 800-86)")
    
    case = forensics.create_case(
        case_number="GT-2024-001",
        case_title="GlobalTech Enterprises Data Exfiltration Investigation",
        incident_date=datetime(2024, 11, 1, 14, 30),
        lead_examiner="Digital Forensics Student",
        authorized_by="Chief Information Security Officer"
    )
    
    # Demo 2: Legal compliance validation
    print("\n📋 Demo 2: Legal Framework Compliance Validation")
    
    compliance = forensics.validate_legal_compliance()
    print(f"   Legal Compliance: {'✅ PASSED' if compliance['compliant'] else '❌ FAILED'}")
    print(f"   Framework: {compliance['framework']}")
    
    for check, result in compliance['checks'].items():
        status = "✅" if result else "❌"
        print(f"   {check.replace('_', ' ').title()}: {status}")
    
    if compliance['recommendations']:
        print("   Recommendations:")
        for rec in compliance['recommendations']:
            print(f"     • {rec}")
    
    # Demo 3: NIST Four-Phase Process
    print("\n📋 Demo 3: NIST SP 800-86 Four-Phase Process")
    
    print(f"   Current Phase: {case.current_phase.value.title()}")
    
    # Phase progression simulation
    phases_info = {
        ForensicPhase.COLLECTION: "Evidence identification, preservation, and acquisition",
        ForensicPhase.EXAMINATION: "Forensically sound evidence processing and extraction", 
        ForensicPhase.ANALYSIS: "Evidence analysis and correlation for findings",
        ForensicPhase.REPORTING: "Documentation and presentation of results"
    }
    
    print("\n   NIST SP 800-86 Four-Phase Forensic Process:")
    for i, (phase, description) in enumerate(phases_info.items(), 1):
        current_marker = "◄ CURRENT" if phase == case.current_phase else ""
        print(f"     {i}. {phase.value.title()}: {description} {current_marker}")
    
    # Demo 4: Phase advancement
    print("\n📋 Demo 4: Phase Advancement with Documentation")
    
    forensics.advance_phase(
        ForensicPhase.EXAMINATION,
        "Evidence collection completed. 5 digital evidence items secured. Proceeding to examination phase."
    )
    
    # Demo 5: Generate phase report
    print("\n📋 Demo 5: Professional Phase Report Generation")
    
    report_file = forensics.generate_phase_report()
    
    # Show sample of report
    with open(report_file, 'r') as f:
        lines = f.readlines()[:15]  # First 15 lines
        print("   Report Preview:")
        for line in lines:
            print(f"     {line.rstrip()}")
    
    print(f"\n💡 Forensic Methodology Summary:")
    print(f"   Case ID: {case.case_id}")
    print(f"   Legal Framework: {legal_framework.jurisdiction}")
    print(f"   Current Phase: {case.current_phase.value.title()}")
    print(f"   Compliance Status: {'✅ COMPLIANT' if compliance['compliant'] else '❌ NON-COMPLIANT'}")
    print(f"   Report Location: {report_file}")
    
    print(f"\n🎓 Key Learning: This methodology ensures all forensic work meets legal admissibility standards")
    print(f"   and follows industry best practices suitable for expert testimony in court.")

if __name__ == "__main__":
    demo_forensic_methodology()
```

### ✅ Checkpoint 1: Forensic Methodology & Legal Frameworks

Validate your understanding of professional forensic methodology:

1. **NIST SP 800-86 Four Phases**: Can you explain each phase and its requirements?
2. **RFC 3227 Compliance**: Do you understand evidence collection and archiving guidelines?
3. **Legal Framework**: Can you identify the legal requirements for your jurisdiction?
4. **Court Admissibility**: Do you understand what makes forensic evidence admissible in court?

**🎯 Professional Validation**: Your methodology framework should be suitable for real forensic investigations and expert testimony preparation.

Create `evidence_acquisition_professional.py` - Industry-standard evidence handling:

```python
import hashlib
import subprocess
import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import shutil
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Tuple
import uuid
import logging
from enum import Enum

class AcquisitionMethod(Enum):
    """Evidence acquisition methods per NIST SP 800-86"""
    DD = "dd"              # Standard Unix disk dump
    DC3DD = "dc3dd"        # Enhanced DoD version with hashing
    DDRESCUE = "ddrescue"  # Error-tolerant imaging
    FTK_IMAGER = "ftk_imager"  # Commercial forensic imager
    ENCASE = "encase"      # EnCase forensic suite
    X_WAYS = "x_ways"      # X-Ways forensic software

class HashAlgorithm(Enum):
    """Supported hash algorithms for evidence verification"""
    MD5 = "md5"
    SHA1 = "sha1" 
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"

@dataclass
class ChainOfCustodyEvent:
    """Individual chain of custody event per RFC 3227"""
    timestamp: datetime
    event_type: str  # RECEIVED, IMAGED, ANALYZED, TRANSFERRED, VERIFIED
    person: str
    organization: str
    location: str
    action_description: str
    evidence_condition: str
    digital_signature: str = ""  # For advanced implementations
    witness: str = ""
    
@dataclass 
class EvidenceMetadata:
    """Comprehensive evidence metadata following forensic standards"""
    # Basic identification
    evidence_id: str
    case_number: str
    item_number: str
    
    # Device information
    device_description: str
    serial_number: str
    make_model: str
    device_type: str  # HDD, SSD, USB, Mobile, etc.
    
    # Acquisition details
    acquisition_date: datetime
    acquisition_method: AcquisitionMethod
    examiner: str
    acquisition_tool: str
    tool_version: str
    
    # File system information
    file_size_bytes: int
    sector_size: int
    total_sectors: int
    partition_table_type: str = ""
    file_system_types: List[str] = None
    
    # Hash verification
    source_hashes: Dict[str, str] = None  # Algorithm -> hash
    image_hashes: Dict[str, str] = None   # Algorithm -> hash
    verification_status: str = "PENDING"
    
    # Chain of custody
    chain_of_custody: List[ChainOfCustodyEvent] = None
    
    # Legal and administrative
    legal_authority: str = ""
    search_warrant: str = ""
    consent_form: str = ""
    location_acquired: str = ""
    
    # Technical details
    bad_sectors: int = 0
    acquisition_errors: List[str] = None
    write_blocked: bool = True
    acquisition_notes: str = ""
    
    def __post_init__(self):
        if self.file_system_types is None:
            self.file_system_types = []
        if self.source_hashes is None:
            self.source_hashes = {}
        if self.image_hashes is None:
            self.image_hashes = {}
        if self.chain_of_custody is None:
            self.chain_of_custody = []
        if self.acquisition_errors is None:
            self.acquisition_errors = []

class ProfessionalEvidenceAcquisition:
    """Professional-grade evidence acquisition following NIST SP 800-86 and RFC 3227"""
    
    def __init__(self, case_directory: str, examiner: str, organization: str):
        self.case_directory = Path(case_directory)
        self.examiner = examiner
        self.organization = organization
        
        # Create forensic directory structure
        self._setup_directory_structure()
        self._setup_evidence_database()
        self._setup_logging()
        
        print(f"✅ Professional Evidence Acquisition System Initialized")
        print(f"   Examiner: {examiner}")
        print(f"   Organization: {organization}")
        print(f"   Case Directory: {self.case_directory}")
    
    def _setup_directory_structure(self):
        """Create NIST-compliant evidence directory structure"""
        directories = [
            "01_original_evidence",    # Original evidence (read-only)
            "02_working_copies",       # Working copies for analysis
            "03_extracted_data",       # Extracted files and artifacts
            "04_reports",              # Forensic reports
            "05_documentation",        # Case documentation
            "06_chain_of_custody",     # Chain of custody records
            "07_hash_verification",    # Hash verification logs
            "08_acquisition_logs"      # Acquisition process logs
        ]
        
        for directory in directories:
            (self.case_directory / directory).mkdir(parents=True, exist_ok=True)
            
        # Create index file
        index_file = self.case_directory / "EVIDENCE_INDEX.txt"
        with open(index_file, 'w') as f:
            f.write(f"DIGITAL EVIDENCE INDEX\n")
            f.write(f"======================\n\n")
            f.write(f"Case Directory: {self.case_directory}\n")
            f.write(f"Created: {datetime.now().isoformat()}\n")
            f.write(f"Examiner: {self.examiner}\n")
            f.write(f"Organization: {self.organization}\n\n")
            f.write(f"Directory Structure:\n")
            for directory in directories:
                f.write(f"  {directory}/\n")
    
    def _setup_evidence_database(self):
        """Setup SQLite database for evidence tracking"""
        db_path = self.case_directory / "05_documentation" / "evidence_database.db"
        self.db_connection = sqlite3.connect(str(db_path))
        
        # Create evidence tracking tables
        cursor = self.db_connection.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY,
                case_number TEXT,
                item_number TEXT,
                device_description TEXT,
                serial_number TEXT,
                acquisition_date TEXT,
                acquisition_method TEXT,
                examiner TEXT,
                verification_status TEXT,
                file_size_bytes INTEGER,
                created_timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                event_id TEXT PRIMARY KEY,
                evidence_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                person TEXT,
                organization TEXT,
                location TEXT,
                action_description TEXT,
                evidence_condition TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence_items (evidence_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hash_verification (
                verification_id TEXT PRIMARY KEY,
                evidence_id TEXT,
                hash_algorithm TEXT,
                source_hash TEXT,
                image_hash TEXT,
                verification_timestamp TEXT,
                verified BOOLEAN,
                FOREIGN KEY (evidence_id) REFERENCES evidence_items (evidence_id)
            )
        ''')
        
        self.db_connection.commit()
        print(f"   📊 Evidence database initialized: {db_path}")
    
    def _setup_logging(self):
        """Setup comprehensive forensic logging"""
        log_file = self.case_directory / "08_acquisition_logs" / "acquisition_activity.log"
        
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s UTC - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self.logger = logging.getLogger('EvidenceAcquisition')
        self.logger.info("Professional Evidence Acquisition System started")
        self.logger.info(f"Examiner: {self.examiner}, Organization: {self.organization}")
    
    def acquire_evidence(self, source_device: str, case_number: str, 
                        item_number: str, device_description: str,
                        acquisition_method: AcquisitionMethod = AcquisitionMethod.DD,
                        hash_algorithms: List[HashAlgorithm] = None,
                        legal_authority: str = "",
                        location_acquired: str = "") -> EvidenceMetadata:
        """Perform professional evidence acquisition following NIST SP 800-86"""
        
        if hash_algorithms is None:
            hash_algorithms = [HashAlgorithm.MD5, HashAlgorithm.SHA256, HashAlgorithm.SHA512]
        
        evidence_id = f"{case_number}_{item_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"🔍 Starting Professional Evidence Acquisition")
        print(f"   Evidence ID: {evidence_id}")
        print(f"   Source Device: {source_device}")
        print(f"   Acquisition Method: {acquisition_method.value}")
        print(f"   Hash Algorithms: {[h.value for h in hash_algorithms]}")
        
        # Initialize metadata
        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            case_number=case_number,
            item_number=item_number,
            device_description=device_description,
            serial_number=self._get_device_serial(source_device),
            make_model=self._get_device_info(source_device),
            device_type=self._determine_device_type(source_device),
            acquisition_date=datetime.now(timezone.utc),
            acquisition_method=acquisition_method,
            examiner=self.examiner,
            acquisition_tool=acquisition_method.value,
            tool_version=self._get_tool_version(acquisition_method),
            file_size_bytes=0,
            sector_size=512,
            total_sectors=0,
            legal_authority=legal_authority,
            location_acquired=location_acquired
        )
        
        # Add initial chain of custody event
        self._add_custody_event(metadata, "RECEIVED", 
            f"Evidence received for acquisition from {location_acquired}",
            "Sealed and tagged")
        
        # Perform acquisition
        try:
            # Step 1: Calculate source hashes
            print("📊 Calculating source device hashes...")
            metadata.source_hashes = self._calculate_hashes(source_device, hash_algorithms)
            
            # Step 2: Create forensic image
            print(f"💾 Creating forensic image using {acquisition_method.value}...")
            image_path = self._perform_acquisition(source_device, metadata, acquisition_method)
            
            # Step 3: Calculate image hashes
            print("📊 Calculating image hashes for verification...")
            metadata.image_hashes = self._calculate_hashes(str(image_path), hash_algorithms)
            
            # Step 4: Verify integrity
            print("⚙️ Verifying image integrity...")
            verification_results = self._verify_image_integrity(metadata)
            metadata.verification_status = "VERIFIED" if all(verification_results.values()) else "FAILED"
            
            # Step 5: Update file size information
            stat = image_path.stat()
            metadata.file_size_bytes = stat.st_size
            metadata.total_sectors = stat.st_size // metadata.sector_size
            
            # Step 6: Add custody events
            self._add_custody_event(metadata, "IMAGED",
                f"Forensic image created using {acquisition_method.value}",
                f"Image integrity: {metadata.verification_status}")
            
            # Step 7: Save metadata and database records
            self._save_evidence_metadata(metadata)
            self._save_to_database(metadata)
            
            print(f"✅ Evidence acquisition completed successfully")
            print(f"   Image Location: {image_path}")
            print(f"   Verification Status: {metadata.verification_status}")
            print(f"   File Size: {metadata.file_size_bytes:,} bytes")
            
            self.logger.info(f"Evidence acquisition completed: {evidence_id}")
            self.logger.info(f"Verification status: {metadata.verification_status}")
            
            return metadata
            
        except Exception as e:
            error_msg = f"Evidence acquisition failed: {str(e)}"
            print(f"❌ {error_msg}")
            self.logger.error(error_msg)
            
            # Add failure to custody record
            self._add_custody_event(metadata, "ACQUISITION_FAILED", error_msg, "Error condition")
            raise
    
    def create_working_copy(self, evidence_id: str, purpose: str = "Analysis") -> str:
        """Create forensically sound working copy for analysis"""
        print(f"🗞️ Creating working copy for evidence: {evidence_id}")
        
        # Find original evidence
        original_path = self._find_evidence_image(evidence_id)
        if not original_path:
            raise FileNotFoundError(f"Original evidence not found: {evidence_id}")
        
        # Create working copy path
        working_copy_path = (self.case_directory / "02_working_copies" / 
                           f"{evidence_id}_working_copy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.dd")
        
        # Copy with verification
        print("   Copying original evidence to working directory...")
        shutil.copy2(original_path, working_copy_path)
        
        # Verify working copy integrity
        print("   Verifying working copy integrity...")
        original_hash = self._calculate_hashes(str(original_path), [HashAlgorithm.SHA256])[HashAlgorithm.SHA256.value]
        working_hash = self._calculate_hashes(str(working_copy_path), [HashAlgorithm.SHA256])[HashAlgorithm.SHA256.value]
        
        if original_hash != working_hash:
            working_copy_path.unlink()  # Delete corrupted copy
            raise ValueError("Working copy integrity verification failed")
        
        # Update chain of custody
        metadata = self._load_evidence_metadata(evidence_id)
        self._add_custody_event(metadata, "WORKING_COPY_CREATED",
            f"Working copy created for {purpose}", "Verified integrity match")
        self._save_evidence_metadata(metadata)
        
        print(f"   ✅ Working copy created and verified: {working_copy_path}")
        self.logger.info(f"Working copy created: {evidence_id} -> {working_copy_path}")
        
        return str(working_copy_path)
    
    def generate_acquisition_report(self, evidence_id: str) -> str:
        """Generate comprehensive acquisition report"""
        metadata = self._load_evidence_metadata(evidence_id)
        if not metadata:
            raise ValueError(f"Evidence metadata not found: {evidence_id}")
        
        report_path = (self.case_directory / "04_reports" / 
                      f"{evidence_id}_acquisition_report.txt")
        
        with open(report_path, 'w') as f:
            f.write(f"DIGITAL EVIDENCE ACQUISITION REPORT\n")
            f.write(f"="*60 + "\n\n")
            
            # Case information
            f.write(f"CASE INFORMATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Evidence ID: {metadata.evidence_id}\n")
            f.write(f"Case Number: {metadata.case_number}\n")
            f.write(f"Item Number: {metadata.item_number}\n")
            f.write(f"Acquisition Date: {metadata.acquisition_date.isoformat()}\n")
            f.write(f"Examiner: {metadata.examiner}\n")
            f.write(f"Organization: {self.organization}\n\n")
            
            # Device information
            f.write(f"DEVICE INFORMATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Description: {metadata.device_description}\n")
            f.write(f"Make/Model: {metadata.make_model}\n")
            f.write(f"Serial Number: {metadata.serial_number}\n")
            f.write(f"Device Type: {metadata.device_type}\n")
            f.write(f"File Size: {metadata.file_size_bytes:,} bytes\n")
            f.write(f"Total Sectors: {metadata.total_sectors:,}\n")
            f.write(f"Sector Size: {metadata.sector_size} bytes\n\n")
            
            # Acquisition details
            f.write(f"ACQUISITION DETAILS\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Method: {metadata.acquisition_method.value}\n")
            f.write(f"Tool: {metadata.acquisition_tool}\n")
            f.write(f"Tool Version: {metadata.tool_version}\n")
            f.write(f"Write Blocked: {metadata.write_blocked}\n")
            f.write(f"Bad Sectors: {metadata.bad_sectors}\n")
            f.write(f"Verification Status: {metadata.verification_status}\n\n")
            
            # Hash verification
            f.write(f"HASH VERIFICATION\n")
            f.write(f"{'-'*20}\n")
            for algorithm in metadata.source_hashes.keys():
                source_hash = metadata.source_hashes.get(algorithm, "N/A")
                image_hash = metadata.image_hashes.get(algorithm, "N/A")
                match = "✅ MATCH" if source_hash == image_hash else "❌ MISMATCH"
                f.write(f"{algorithm.upper()}:\n")
                f.write(f"  Source: {source_hash}\n")
                f.write(f"  Image:  {image_hash}\n")
                f.write(f"  Status: {match}\n\n")
            
            # Chain of custody
            f.write(f"CHAIN OF CUSTODY\n")
            f.write(f"{'-'*20}\n")
            for event in metadata.chain_of_custody:
                f.write(f"{event.timestamp.isoformat()} - {event.event_type}\n")
                f.write(f"  Person: {event.person}\n")
                f.write(f"  Action: {event.action_description}\n")
                f.write(f"  Condition: {event.evidence_condition}\n")
                if event.location:
                    f.write(f"  Location: {event.location}\n")
                f.write(f"\n")
            
            # Legal information
            if metadata.legal_authority:
                f.write(f"LEGAL AUTHORITY\n")
                f.write(f"{'-'*20}\n")
                f.write(f"Authority: {metadata.legal_authority}\n")
                if metadata.search_warrant:
                    f.write(f"Search Warrant: {metadata.search_warrant}\n")
                if metadata.consent_form:
                    f.write(f"Consent Form: {metadata.consent_form}\n")
                f.write(f"\n")
            
            # Notes
            if metadata.acquisition_notes:
                f.write(f"ACQUISITION NOTES\n")
                f.write(f"{'-'*20}\n")
                f.write(f"{metadata.acquisition_notes}\n\n")
            
            # Report footer
            f.write(f"REPORT CERTIFICATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"This report certifies that the digital evidence was acquired\n")
            f.write(f"using forensically sound procedures following NIST SP 800-86\n")
            f.write(f"and RFC 3227 guidelines. The evidence integrity has been\n")
            f.write(f"verified through cryptographic hash comparison.\n\n")
            f.write(f"Examiner: {metadata.examiner}\n")
            f.write(f"Report Generated: {datetime.now().isoformat()}\n")
        
        print(f"📋 Acquisition report generated: {report_path}")
        return str(report_path)
```

```python
import hashlib
import subprocess
import os
import json
from datetime import datetime
from pathlib import Path
import shutil
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List

@dataclass
class EvidenceMetadata:
    """Evidence acquisition metadata"""
    case_number: str
    evidence_id: str
    device_description: str
    serial_number: str
    make_model: str
    acquisition_date: datetime
    examiner: str
    acquisition_method: str
    source_hash_md5: str
    source_hash_sha256: str
    image_hash_md5: str
    image_hash_sha256: str
    verification_status: str
    notes: str = ""
    file_size_bytes: int = 0
    sector_size: int = 512
    total_sectors: int = 0

class ForensicImager:
    """Forensically sound evidence acquisition"""
    
    def __init__(self, case_directory: str):
        self.case_directory = Path(case_directory)
        self.case_directory.mkdir(parents=True, exist_ok=True)
        
        # Create standard forensics directory structure
        (self.case_directory / "evidence").mkdir(exist_ok=True)
        (self.case_directory / "images").mkdir(exist_ok=True)
        (self.case_directory / "reports").mkdir(exist_ok=True)
        (self.case_directory / "logs").mkdir(exist_ok=True)
        
        print(f"✅ Forensic case directory initialized: {self.case_directory}")
    
    def create_dd_image(self, source_device: str, evidence_id: str, 
                       case_number: str, examiner: str,
                       block_size: int = 4096) -> EvidenceMetadata:
        """
        Create forensically sound dd image
        
        Args:
            source_device: Path to source device/file
            evidence_id: Unique evidence identifier
            case_number: Case number
            examiner: Examiner name
            block_size: Block size for dd operation
            
        Returns:
            EvidenceMetadata: Complete metadata for acquired evidence
        """
        print(f"🔍 Starting forensic acquisition of {source_device}")
        
        # Generate output filename
        image_filename = f"{case_number}_{evidence_id}.dd"
        image_path = self.case_directory / "images" / image_filename
        
        # Create log file
        log_filename = f"{case_number}_{evidence_id}_acquisition.log"
        log_path = self.case_directory / "logs" / log_filename
        
        # Get source device information (if it's a real device)
        device_info = self._get_device_info(source_device)
        
        # Calculate source hash BEFORE imaging (for verification)
        print("📊 Calculating source hash (this may take time)...")
        source_md5, source_sha256 = self._calculate_file_hashes(source_device)
        
        # Perform dd acquisition
        print(f"💾 Creating forensic image: {image_path}")
        try:
            # Use dd with forensic parameters
            dd_command = [
                'dd',
                f'if={source_device}',
                f'of={image_path}',
                f'bs={block_size}',
                'conv=noerror,sync',
                'status=progress'
            ]
            
            with open(log_path, 'w') as log_file:
                log_file.write(f"Forensic Acquisition Log\n")
                log_file.write(f"Case: {case_number}\n")
                log_file.write(f"Evidence: {evidence_id}\n")
                log_file.write(f"Examiner: {examiner}\n")
                log_file.write(f"Start Time: {datetime.now().isoformat()}\n")
                log_file.write(f"Command: {' '.join(dd_command)}\n\n")
                
                # Execute dd command
                result = subprocess.run(
                    dd_command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                log_file.write(f"\nEnd Time: {datetime.now().isoformat()}\n")
                log_file.write(f"Exit Code: {result.returncode}\n")
            
            if result.returncode != 0:
                raise Exception(f"dd command failed with exit code {result.returncode}")
            
        except Exception as e:
            print(f"❌ Imaging failed: {e}")
            raise
        
        # Calculate image hashes for verification
        print("🔐 Verifying image integrity...")
        image_md5, image_sha256 = self._calculate_file_hashes(str(image_path))
        
        # Verify hashes match
        verification_status = "VERIFIED" if (source_md5 == image_md5 and source_sha256 == image_sha256) else "FAILED"
        
        # Get file statistics
        stat = image_path.stat()
        
        # Create metadata
        metadata = EvidenceMetadata(
            case_number=case_number,
            evidence_id=evidence_id,
            device_description=device_info.get('description', 'Unknown device'),
            serial_number=device_info.get('serial', 'Unknown'),
            make_model=device_info.get('model', 'Unknown'),
            acquisition_date=datetime.now(),
            examiner=examiner,
            acquisition_method="dd",
            source_hash_md5=source_md5,
            source_hash_sha256=source_sha256,
            image_hash_md5=image_md5,
            image_hash_sha256=image_sha256,
            verification_status=verification_status,
            file_size_bytes=stat.st_size,
            sector_size=512,
            total_sectors=stat.st_size // 512
        )
        
        # Save metadata
        self._save_metadata(metadata)
        
        print(f"✅ Acquisition complete: {verification_status}")
        print(f"   Image size: {stat.st_size:,} bytes")
        print(f"   Source MD5: {source_md5}")
        print(f"   Image MD5:  {image_md5}")
        
        return metadata
    
    def create_test_evidence(self, size_mb: int = 10) -> str:
        """Create test evidence file for demonstration"""
        test_file = self.case_directory / "test_evidence.bin"
        
        # Create test file with random data
        print(f"🧪 Creating test evidence file ({size_mb} MB)")
        
        with open(test_file, 'wb') as f:
            # Write some identifiable data
            f.write(b"FORENSICS_TEST_EVIDENCE\n")
            f.write(f"Created: {datetime.now().isoformat()}\n".encode())
            f.write(b"This is a test file for forensic imaging demonstration.\n")
            f.write(b"Contains sample data for practice.\n\n")
            
            # Fill with pseudo-random data
            import random
            remaining_bytes = (size_mb * 1024 * 1024) - f.tell()
            
            chunk_size = 4096
            for _ in range(remaining_bytes // chunk_size):
                chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
                f.write(chunk)
        
        print(f"✅ Test evidence created: {test_file}")
        return str(test_file)
    
    def verify_image_integrity(self, evidence_id: str) -> bool:
        """Verify the integrity of a forensic image"""
        metadata_file = self.case_directory / "evidence" / f"{evidence_id}_metadata.json"
        
        if not metadata_file.exists():
            print(f"❌ Metadata file not found for {evidence_id}")
            return False
        
        # Load metadata
        with open(metadata_file, 'r') as f:
            metadata_dict = json.load(f)
            metadata = EvidenceMetadata(**metadata_dict)
        
        # Find image file
        image_path = self.case_directory / "images" / f"{metadata.case_number}_{evidence_id}.dd"
        
        if not image_path.exists():
            print(f"❌ Image file not found: {image_path}")
            return False
        
        # Recalculate hashes
        print("🔐 Verifying image integrity (this may take time)...")
        current_md5, current_sha256 = self._calculate_file_hashes(str(image_path))
        
        # Compare with stored hashes
        md5_match = current_md5 == metadata.image_hash_md5
        sha256_match = current_sha256 == metadata.image_hash_sha256
        
        if md5_match and sha256_match:
            print("✅ Image integrity verified - no changes detected")
            return True
        else:
            print("❌ Image integrity FAILED - file may be corrupted or tampered")
            print(f"   Expected MD5: {metadata.image_hash_md5}")
            print(f"   Current MD5:  {current_md5}")
            return False
    
    def _calculate_file_hashes(self, filepath: str) -> tuple:
        """Calculate MD5 and SHA256 hashes of a file"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _get_device_info(self, device_path: str) -> Dict:
        """Get device information (simplified for demo)"""
        # In real forensics, would query actual device information
        return {
            'description': f'Evidence from {device_path}',
            'serial': 'DEMO_SERIAL_123',
            'model': 'Forensic Test Device'
        }
    
    def _save_metadata(self, metadata: EvidenceMetadata):
        """Save evidence metadata to JSON file"""
        metadata_file = self.case_directory / "evidence" / f"{metadata.evidence_id}_metadata.json"
        
        # Convert datetime to string for JSON serialization
        metadata_dict = asdict(metadata)
        metadata_dict['acquisition_date'] = metadata.acquisition_date.isoformat()
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2)
        
        print(f"💾 Metadata saved: {metadata_file}")

class ChainOfCustody:
    """Chain of custody documentation system"""
    
    def __init__(self, case_directory: str):
        self.case_directory = Path(case_directory)
        self.custody_log: List[Dict] = []
        self.custody_file = self.case_directory / "evidence" / "chain_of_custody.json"
        
        # Load existing log
        if self.custody_file.exists():
            with open(self.custody_file, 'r') as f:
                self.custody_log = json.load(f)
    
    def add_custody_event(self, evidence_id: str, action: str, 
                         person: str, notes: str = ""):
        """Add event to chain of custody"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'evidence_id': evidence_id,
            'action': action,
            'person': person,
            'notes': notes
        }
        
        self.custody_log.append(event)
        self._save_custody_log()
        
        print(f"📝 Chain of custody updated: {action} by {person}")
    
    def get_custody_history(self, evidence_id: str) -> List[Dict]:
        """Get custody history for specific evidence"""
        return [event for event in self.custody_log 
                if event['evidence_id'] == evidence_id]
    
    def _save_custody_log(self):
        """Save custody log to file"""
        with open(self.custody_file, 'w') as f:
            json.dump(self.custody_log, f, indent=2)

def demo_evidence_acquisition():
    """Demonstrate evidence acquisition process"""
    print("🔬 Digital Evidence Acquisition Demo")
    print("="*50)
    
    # Initialize forensic imager
    imager = ForensicImager("case_2024_001")
    custody = ChainOfCustody("case_2024_001")
    
    # Demo 1: Create test evidence
    print("\n📋 Demo 1: Creating Test Evidence")
    
    test_evidence = imager.create_test_evidence(size_mb=5)  # Small for demo
    
    # Demo 2: Acquire evidence
    print(f"\n📋 Demo 2: Forensic Acquisition")
    
    evidence_id = "DEMO_001"
    case_number = "2024_001"
    examiner = "Digital Forensics Student"
    
    # Add to chain of custody
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="RECEIVED",
        person=examiner,
        notes="Test evidence received for imaging"
    )
    
    # Perform acquisition
    metadata = imager.create_dd_image(
        source_device=test_evidence,
        evidence_id=evidence_id,
        case_number=case_number,
        examiner=examiner
    )
    
    # Update chain of custody
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="IMAGED",
        person=examiner,
        notes=f"Forensic image created using dd. Verification: {metadata.verification_status}"
    )
    
    # Demo 3: Verify image integrity
    print(f"\n📋 Demo 3: Image Integrity Verification")
    
    integrity_check = imager.verify_image_integrity(evidence_id)
    
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="VERIFIED",
        person=examiner,
        notes=f"Integrity check: {'PASSED' if integrity_check else 'FAILED'}"
    )
    
    # Demo 4: Show chain of custody
    print(f"\n📋 Demo 4: Chain of Custody")
    
    custody_history = custody.get_custody_history(evidence_id)
    
    for event in custody_history:
        print(f"   {event['timestamp'][:19]} - {event['action']} by {event['person']}")
        if event['notes']:
            print(f"     Notes: {event['notes']}")
    
    print(f"\n💡 Acquisition Summary:")
    print(f"   Evidence ID: {metadata.evidence_id}")
    print(f"   Case Number: {metadata.case_number}")
    print(f"   File Size: {metadata.file_size_bytes:,} bytes")
    print(f"   Verification: {metadata.verification_status}")
    print(f"   Chain of Custody Events: {len(custody_history)}")

if __name__ == "__main__":
    demo_evidence_acquisition()
```

### ✅ Checkpoint 2: Evidence Acquisition & Chain of Custody

Validate your professional evidence acquisition system:

1. **Forensic Methodology**: Does your acquisition follow NIST SP 800-86 guidelines?
2. **Hash Verification**: Can you verify evidence integrity using multiple algorithms?
3. **Chain of Custody**: Is every evidence handling event properly documented?
4. **Legal Compliance**: Does your process meet court admissibility standards?
5. **Professional Documentation**: Are your reports suitable for expert testimony?

**🎯 Industry Standard**: Your acquisition process should be indistinguishable from commercial forensic tools in terms of methodology and documentation quality.

---

## 📘 Module 2: Evidence Acquisition & Chain of Custody (60 minutes)

**Learning Objectives**:
- Perform forensically sound evidence acquisition using dd, dc3dd, and commercial tools
- Implement comprehensive chain of custody procedures following RFC 3227
- Execute hash verification using multiple algorithms for evidence integrity
- Create working copies while preserving original evidence
- Document acquisition process for legal admissibility

**What you'll build**: Professional evidence acquisition system with full chain of custody

### Step 1: Professional Evidence Acquisition System

## 📘 Module 3: File System Forensics & Autopsy Integration (60 minutes)

**Learning Objectives**:
- Perform comprehensive file system analysis using Autopsy and The Sleuth Kit
- Master file system forensics across NTFS, ext4, APFS, and FAT32 file systems
- Execute deleted file recovery and slack space analysis
- Extract metadata and create detailed artifact timelines
- Investigate file system artifacts from Week 3-9 security systems

**What you'll build**: Professional file system forensics toolkit with Autopsy integration

### Step 1: Professional File System Analysis

Create `filesystem_forensics_professional.py` - Enterprise-grade file system analysis:

```python
import pytsk3
import os
import json
import struct
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Generator, Tuple, Any
import hashlib
import binascii
import re
from dataclasses import dataclass, asdict
from enum import Enum
import logging

class FileSystemType(Enum):
    """Supported file system types for forensic analysis"""
    NTFS = "ntfs"
    EXT4 = "ext4"
    EXT3 = "ext3"
    EXT2 = "ext2"
    FAT32 = "fat32"
    FAT16 = "fat16"
    APFS = "apfs"
    HFS_PLUS = "hfs+"
    EXFAT = "exfat"
    ISO9660 = "iso9660"
    UFS = "ufs"
    UNKNOWN = "unknown"

class FileType(Enum):
    """File types for forensic classification"""
    REGULAR = "regular_file"
    DIRECTORY = "directory"
    SYMLINK = "symbolic_link"
    HARDLINK = "hard_link"
    DEVICE_CHAR = "character_device"
    DEVICE_BLOCK = "block_device"
    FIFO = "fifo"
    SOCKET = "socket"
    DELETED = "deleted_file"
    UNKNOWN = "unknown"

@dataclass
class FileSystemArtifact:
    """Individual file system artifact for forensic analysis"""
    inode: int
    filename: str
    full_path: str
    file_type: FileType
    file_size: int
    allocated: bool
    deleted: bool
    
    # Timestamps (MACB - Modified, Accessed, Changed, Born/Created)
    modified_time: Optional[datetime] = None
    accessed_time: Optional[datetime] = None
    changed_time: Optional[datetime] = None
    created_time: Optional[datetime] = None
    
    # File system specific metadata
    permissions: str = ""
    owner_uid: int = 0
    group_gid: int = 0
    link_count: int = 0
    
    # Forensic analysis metadata
    file_signature: str = ""  # Magic bytes
    md5_hash: str = ""
    sha256_hash: str = ""
    entropy: float = 0.0  # For detecting encryption/compression
    
    # Evidence correlation
    evidence_id: str = ""
    extraction_timestamp: datetime = None
    
    def __post_init__(self):
        if self.extraction_timestamp is None:
            self.extraction_timestamp = datetime.now(timezone.utc)

@dataclass
class DeletedFileRecord:
    """Record for deleted file recovery operations"""
    inode: int
    original_filename: str
    deletion_timestamp: Optional[datetime]
    file_size: int
    recoverable: bool
    recovery_confidence: float  # 0.0 - 1.0
    data_clusters: List[int]
    overwritten_clusters: List[int]
    recovery_notes: str = ""

class ProfessionalFileSystemAnalyzer:
    """Professional file system forensics following industry standards"""
    
    def __init__(self, evidence_path: str, case_id: str, examiner: str):
        self.evidence_path = evidence_path
        self.case_id = case_id
        self.examiner = examiner
        self.img_info = None
        self.fs_info = None
        self.volume_info = None
        self.filesystem_type = FileSystemType.UNKNOWN
        
        # Setup forensic analysis environment
        self.output_dir = Path(f"filesystem_analysis_{case_id}")
        self.output_dir.mkdir(exist_ok=True)
        
        self._setup_logging()
        self._setup_analysis_database()
        self._initialize_image()
        
        print(f"✅ Professional File System Analyzer Initialized")
        print(f"   Evidence: {evidence_path}")
        print(f"   File System: {self.filesystem_type.value}")
        print(f"   Case ID: {case_id}")
    
    def _setup_logging(self):
        """Setup comprehensive forensic logging"""
        log_file = self.output_dir / "filesystem_analysis.log"
        
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s UTC - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self.logger = logging.getLogger('FileSystemAnalyzer')
        self.logger.info("Professional File System Analysis started")
        self.logger.info(f"Evidence: {self.evidence_path}, Case: {self.case_id}")
    
    def _setup_analysis_database(self):
        """Setup SQLite database for artifact storage"""
        db_path = self.output_dir / "filesystem_artifacts.db"
        self.db_connection = sqlite3.connect(str(db_path))
        
        cursor = self.db_connection.cursor()
        
        # File system artifacts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS artifacts (
                inode INTEGER,
                filename TEXT,
                full_path TEXT,
                file_type TEXT,
                file_size INTEGER,
                allocated BOOLEAN,
                deleted BOOLEAN,
                modified_time TEXT,
                accessed_time TEXT,
                changed_time TEXT,
                created_time TEXT,
                permissions TEXT,
                owner_uid INTEGER,
                group_gid INTEGER,
                md5_hash TEXT,
                sha256_hash TEXT,
                file_signature TEXT,
                entropy REAL,
                evidence_id TEXT,
                extraction_timestamp TEXT
            )
        ''')
        
        # Deleted files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deleted_files (
                inode INTEGER,
                original_filename TEXT,
                deletion_timestamp TEXT,
                file_size INTEGER,
                recoverable BOOLEAN,
                recovery_confidence REAL,
                recovery_notes TEXT,
                evidence_id TEXT
            )
        ''')
        
        # Timeline events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                inode INTEGER,
                filename TEXT,
                full_path TEXT,
                description TEXT,
                evidence_id TEXT
            )
        ''')
        
        self.db_connection.commit()
        print(f"   📊 Artifact database initialized: {db_path}")
    
    def _initialize_image(self):
        """Initialize disk image and file system access using The Sleuth Kit"""
        try:
            # Open the disk image
            self.img_info = pytsk3.Img_Info(self.evidence_path)
            
            # Try to detect and open file systems
            try:
                # First, try direct file system access (single partition)
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
                self.filesystem_type = self._detect_filesystem_type()
                print(f"   Direct file system access successful")
                
            except Exception:
                # Try volume/partition analysis
                try:
                    self.volume_info = pytsk3.Volume_Info(self.img_info)
                    
                    # Find the first allocated partition
                    for partition in self.volume_info:
                        if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                            offset = partition.start * 512  # Usually 512-byte sectors
                            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
                            self.filesystem_type = self._detect_filesystem_type()
                            print(f"   Partition-based file system access successful")
                            print(f"   Partition offset: {offset} bytes")
                            break
                    
                    if not self.fs_info:
                        raise Exception("No accessible file systems found")
                        
                except Exception as e:
                    raise Exception(f"Could not access file system: {e}")
            
            # Log file system information
            if self.fs_info:
                self.logger.info(f"File system type: {self.filesystem_type.value}")
                self.logger.info(f"Block size: {self.fs_info.info.block_size}")
                self.logger.info(f"Block count: {self.fs_info.info.block_count}")
                
                print(f"   Block size: {self.fs_info.info.block_size} bytes")
                print(f"   Total blocks: {self.fs_info.info.block_count:,}")
                print(f"   File system size: {(self.fs_info.info.block_size * self.fs_info.info.block_count):,} bytes")
                
        except Exception as e:
            error_msg = f"Failed to initialize image: {e}"
            print(f"❌ {error_msg}")
            self.logger.error(error_msg)
            raise
    
    def _detect_filesystem_type(self) -> FileSystemType:
        """Detect file system type from TSK file system info"""
        if not self.fs_info:
            return FileSystemType.UNKNOWN
        
        fs_type_map = {
            pytsk3.TSK_FS_TYPE_NTFS: FileSystemType.NTFS,
            pytsk3.TSK_FS_TYPE_EXT2: FileSystemType.EXT2,
            pytsk3.TSK_FS_TYPE_EXT3: FileSystemType.EXT3,
            pytsk3.TSK_FS_TYPE_EXT4: FileSystemType.EXT4,
            pytsk3.TSK_FS_TYPE_FAT32: FileSystemType.FAT32,
            pytsk3.TSK_FS_TYPE_FAT16: FileSystemType.FAT16,
            pytsk3.TSK_FS_TYPE_HFS: FileSystemType.HFS_PLUS,
            pytsk3.TSK_FS_TYPE_ISO9660: FileSystemType.ISO9660
        }
        
        return fs_type_map.get(self.fs_info.info.ftype, FileSystemType.UNKNOWN)
    
    def perform_comprehensive_analysis(self, max_depth: int = 10) -> Dict[str, Any]:
        """Perform comprehensive file system forensic analysis"""
        print(f"🔍 Starting Comprehensive File System Analysis")
        print(f"   Max directory depth: {max_depth}")
        
        analysis_results = {
            'start_time': datetime.now(timezone.utc).isoformat(),
            'filesystem_type': self.filesystem_type.value,
            'total_artifacts': 0,
            'deleted_files_found': 0,
            'allocated_files': 0,
            'directories_found': 0,
            'timeline_events': 0,
            'suspicious_files': [],
            'file_type_distribution': {},
            'timestamp_analysis': {},
            'error_count': 0
        }
        
        try:
            # Phase 1: Complete file system walk
            print("\n📋 Phase 1: Complete File System Enumeration")
            artifacts = list(self._walk_filesystem_comprehensive("/", max_depth))
            analysis_results['total_artifacts'] = len(artifacts)
            
            # Phase 2: Process and categorize artifacts
            print(f"\n📋 Phase 2: Artifact Processing ({len(artifacts)} items)")
            deleted_files = []
            allocated_files = []
            directories = []
            
            for artifact in artifacts:
                if artifact.deleted:
                    deleted_files.append(artifact)
                elif artifact.file_type == FileType.DIRECTORY:
                    directories.append(artifact)
                else:
                    allocated_files.append(artifact)
                
                # Store artifact in database
                self._save_artifact_to_database(artifact)
            
            analysis_results['deleted_files_found'] = len(deleted_files)
            analysis_results['allocated_files'] = len(allocated_files)
            analysis_results['directories_found'] = len(directories)
            
            print(f"   Allocated files: {len(allocated_files):,}")
            print(f"   Deleted files: {len(deleted_files):,}")
            print(f"   Directories: {len(directories):,}")
            
            # Phase 3: Timeline analysis
            print(f"\n📋 Phase 3: Timeline Event Generation")
            timeline_events = self._generate_timeline_events(artifacts)
            analysis_results['timeline_events'] = len(timeline_events)
            print(f"   Timeline events generated: {len(timeline_events):,}")
            
            # Phase 4: Deleted file analysis
            print(f"\n📋 Phase 4: Deleted File Recovery Analysis")
            deleted_file_analysis = self._analyze_deleted_files(deleted_files)
            recoverable_count = sum(1 for d in deleted_file_analysis if d.recoverable)
            print(f"   Potentially recoverable files: {recoverable_count}/{len(deleted_files)}")
            
            # Phase 5: Suspicious file detection
            print(f"\n📋 Phase 5: Suspicious File Detection")
            suspicious_files = self._detect_suspicious_files(allocated_files)
            analysis_results['suspicious_files'] = [{
                'path': f.full_path,
                'reason': 'High entropy (possible encryption)',
                'entropy': f.entropy,
                'size': f.file_size
            } for f in suspicious_files if f.entropy > 7.5]  # High entropy threshold
            
            print(f"   Suspicious files detected: {len(analysis_results['suspicious_files'])}")
            
            # Phase 6: File type analysis
            print(f"\n📋 Phase 6: File Type Distribution Analysis")
            file_type_dist = self._analyze_file_type_distribution(artifacts)
            analysis_results['file_type_distribution'] = file_type_dist
            
            # Phase 7: Timestamp analysis
            print(f"\n📋 Phase 7: Timestamp Pattern Analysis")
            timestamp_analysis = self._analyze_timestamp_patterns(artifacts)
            analysis_results['timestamp_analysis'] = timestamp_analysis
            
            analysis_results['end_time'] = datetime.now(timezone.utc).isoformat()
            analysis_results['success'] = True
            
            print(f"\n✅ Comprehensive file system analysis completed")
            print(f"   Analysis duration: {(datetime.fromisoformat(analysis_results['end_time']) - datetime.fromisoformat(analysis_results['start_time'])).total_seconds():.1f} seconds")
            
            self.logger.info("Comprehensive file system analysis completed successfully")
            self.logger.info(f"Total artifacts processed: {analysis_results['total_artifacts']}")
            
            return analysis_results
            
        except Exception as e:
            error_msg = f"File system analysis failed: {e}"
            print(f"❌ {error_msg}")
            self.logger.error(error_msg)
            analysis_results['error'] = error_msg
            analysis_results['success'] = False
            return analysis_results
    
    def _walk_filesystem_comprehensive(self, path: str, max_depth: int, 
                                     current_depth: int = 0) -> Generator[FileSystemArtifact, None, None]:
        """Comprehensive file system walk with full metadata extraction"""
        if current_depth > max_depth:
            return
        
        try:
            directory = self.fs_info.open_dir(path=path)
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    # Extract basic file information
                    filename = entry.info.name.name.decode('utf-8', errors='replace')
                    full_path = os.path.join(path, filename)
                    
                    artifact = FileSystemArtifact(
                        inode=entry.info.meta.addr if entry.info.meta else 0,
                        filename=filename,
                        full_path=full_path,
                        file_type=self._determine_file_type(entry.info.name.type),
                        file_size=entry.info.meta.size if entry.info.meta else 0,
                        allocated=bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
                        deleted=bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC),
                        evidence_id=self.case_id
                    )
                    
                    # Extract timestamps if available
                    if entry.info.meta:
                        if hasattr(entry.info.meta, 'mtime') and entry.info.meta.mtime > 0:
                            artifact.modified_time = datetime.fromtimestamp(entry.info.meta.mtime, tz=timezone.utc)
                        if hasattr(entry.info.meta, 'atime') and entry.info.meta.atime > 0:
                            artifact.accessed_time = datetime.fromtimestamp(entry.info.meta.atime, tz=timezone.utc)
                        if hasattr(entry.info.meta, 'ctime') and entry.info.meta.ctime > 0:
                            artifact.changed_time = datetime.fromtimestamp(entry.info.meta.ctime, tz=timezone.utc)
                        if hasattr(entry.info.meta, 'crtime') and entry.info.meta.crtime > 0:
                            artifact.created_time = datetime.fromtimestamp(entry.info.meta.crtime, tz=timezone.utc)
                        
                        # Extract permissions and ownership
                        if hasattr(entry.info.meta, 'mode'):
                            artifact.permissions = oct(entry.info.meta.mode)[-4:]  # Last 4 digits
                        if hasattr(entry.info.meta, 'uid'):
                            artifact.owner_uid = entry.info.meta.uid
                        if hasattr(entry.info.meta, 'gid'):
                            artifact.group_gid = entry.info.meta.gid
                        if hasattr(entry.info.meta, 'nlink'):
                            artifact.link_count = entry.info.meta.nlink
                    
                    # For files, extract additional forensic metadata
                    if artifact.file_type == FileType.REGULAR and artifact.file_size > 0 and not artifact.deleted:
                        try:
                            # Extract file signature and hashes for small files
                            if artifact.file_size < 10 * 1024 * 1024:  # < 10MB
                                file_data = self._extract_file_data(entry.info.meta.addr, min(artifact.file_size, 1024))
                                if file_data:
                                    artifact.file_signature = binascii.hexlify(file_data[:16]).decode()
                                    artifact.entropy = self._calculate_entropy(file_data)
                                    
                                    # Calculate hashes for very small files only (performance)
                                    if artifact.file_size < 1024 * 1024:  # < 1MB
                                        full_file_data = self._extract_file_data(entry.info.meta.addr, artifact.file_size)
                                        if full_file_data:
                                            artifact.md5_hash = hashlib.md5(full_file_data).hexdigest()
                                            artifact.sha256_hash = hashlib.sha256(full_file_data).hexdigest()
                        except Exception:
                            pass  # Continue processing other metadata
                    
                    yield artifact
                    
                    # Recursively process directories
                    if (artifact.file_type == FileType.DIRECTORY and 
                        artifact.allocated and 
                        not artifact.deleted and
                        current_depth < max_depth):
                        
                        try:
                            yield from self._walk_filesystem_comprehensive(
                                full_path, max_depth, current_depth + 1)
                        except Exception:
                            pass  # Skip inaccessible directories
                
                except Exception as e:
                    self.logger.warning(f"Error processing entry in {path}: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error walking directory {path}: {e}")
    
    def generate_comprehensive_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive file system forensics report"""
        report_path = self.output_dir / f"{self.case_id}_filesystem_report.txt"
        
        with open(report_path, 'w') as f:
            f.write(f"FILE SYSTEM FORENSIC ANALYSIS REPORT\n")
            f.write(f"="*60 + "\n\n")
            
            # Header information
            f.write(f"CASE INFORMATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Case ID: {self.case_id}\n")
            f.write(f"Evidence Path: {self.evidence_path}\n")
            f.write(f"Examiner: {self.examiner}\n")
            f.write(f"Analysis Start: {analysis_results.get('start_time', 'Unknown')}\n")
            f.write(f"Analysis End: {analysis_results.get('end_time', 'Unknown')}\n\n")
            
            # File system information
            f.write(f"FILE SYSTEM DETAILS\n")
            f.write(f"{'-'*20}\n")
            f.write(f"File System Type: {analysis_results.get('filesystem_type', 'Unknown')}\n")
            if self.fs_info:
                f.write(f"Block Size: {self.fs_info.info.block_size} bytes\n")
                f.write(f"Total Blocks: {self.fs_info.info.block_count:,}\n")
                f.write(f"Total Size: {(self.fs_info.info.block_size * self.fs_info.info.block_count):,} bytes\n")
            f.write(f"\n")
            
            # Analysis summary
            f.write(f"ANALYSIS SUMMARY\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Total Artifacts: {analysis_results.get('total_artifacts', 0):,}\n")
            f.write(f"Allocated Files: {analysis_results.get('allocated_files', 0):,}\n")
            f.write(f"Deleted Files: {analysis_results.get('deleted_files_found', 0):,}\n")
            f.write(f"Directories: {analysis_results.get('directories_found', 0):,}\n")
            f.write(f"Timeline Events: {analysis_results.get('timeline_events', 0):,}\n")
            f.write(f"Suspicious Files: {len(analysis_results.get('suspicious_files', [])):,}\n\n")
            
            # File type distribution
            file_types = analysis_results.get('file_type_distribution', {})
            if file_types:
                f.write(f"FILE TYPE DISTRIBUTION\n")
                f.write(f"{'-'*20}\n")
                for file_type, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / analysis_results.get('total_artifacts', 1)) * 100
                    f.write(f"{file_type:<20} {count:>6,} ({percentage:5.1f}%)\n")
                f.write(f"\n")
            
            # Suspicious files
            suspicious = analysis_results.get('suspicious_files', [])
            if suspicious:
                f.write(f"SUSPICIOUS FILES DETECTED\n")
                f.write(f"{'-'*20}\n")
                for i, file_info in enumerate(suspicious[:10], 1):  # Top 10
                    f.write(f"{i:2}. {file_info['path']}\n")
                    f.write(f"    Reason: {file_info['reason']}\n")
                    f.write(f"    Entropy: {file_info['entropy']:.2f}\n")
                    f.write(f"    Size: {file_info['size']:,} bytes\n\n")
                    
                if len(suspicious) > 10:
                    f.write(f"... and {len(suspicious) - 10} more suspicious files\n\n")
            
            # Timestamp analysis
            timestamp_analysis = analysis_results.get('timestamp_analysis', {})
            if timestamp_analysis:
                f.write(f"TIMESTAMP ANALYSIS\n")
                f.write(f"{'-'*20}\n")
                earliest = timestamp_analysis.get('earliest_timestamp')
                latest = timestamp_analysis.get('latest_timestamp')
                if earliest:
                    f.write(f"Earliest Timestamp: {earliest}\n")
                if latest:
                    f.write(f"Latest Timestamp: {latest}\n")
                
                time_clusters = timestamp_analysis.get('activity_clusters', [])
                if time_clusters:
                    f.write(f"Activity Clusters: {len(time_clusters)} detected\n")
                f.write(f"\n")
            
            # Footer
            f.write(f"FORENSIC CERTIFICATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"This analysis was performed using forensically sound methodologies\n")
            f.write(f"following industry best practices. All findings are based on\n")
            f.write(f"comprehensive file system examination using The Sleuth Kit.\n\n")
            f.write(f"Examiner: {self.examiner}\n")
            f.write(f"Report Generated: {datetime.now(timezone.utc).isoformat()}\n")
        
        print(f"📋 Comprehensive forensics report generated: {report_path}")
        self.logger.info(f"File system forensics report generated: {report_path}")
        return str(report_path)
```

### ✅ Checkpoint 3: File System Forensics & Autopsy Integration

Validate your professional file system forensics capabilities:

1. **Multi-Platform Support**: Can you analyze NTFS, ext4, APFS, and FAT32 file systems?
2. **Deleted File Recovery**: Can you identify and recover deleted files with confidence ratings?
3. **Metadata Extraction**: Can you extract complete MACB timestamps and file system metadata?
4. **Timeline Generation**: Can you create comprehensive timelines from file system artifacts?
5. **Professional Reporting**: Are your reports suitable for expert testimony and court presentation?

**🎯 Autopsy Integration**: Your analysis should produce results comparable to commercial tools like Autopsy, EnCase, and FTK while maintaining full methodology transparency.

```python
import pytsk3
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Generator
import hashlib

class FileSystemAnalyzer:
    """File system analysis using The Sleuth Kit"""
    
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None
        self._initialize_image()
    
    def _initialize_image(self):
        """Initialize image and file system objects"""
        try:
            # Open the disk image
            self.img_info = pytsk3.Img_Info(self.image_path)
            
            # Try to get file system info (assuming single partition)
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
            except:
                # If direct access fails, try to find partitions
                volume = pytsk3.Volume_Info(self.img_info)
                for partition in volume:
                    if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        self.fs_info = pytsk3.FS_Info(self.img_info, offset=partition.start * 512)
                        break
            
            if self.fs_info:
                print(f"✅ File system loaded: {self.fs_info.info.ftype}")
                print(f"   Block size: {self.fs_info.info.block_size}")
                print(f"   Total blocks: {self.fs_info.info.block_count}")
            else:
                raise Exception("Could not access file system")
                
        except Exception as e:
            print(f"❌ Error initializing image: {e}")
            raise
    
    def analyze_directory(self, path: str = "/", max_depth: int = 3) -> Dict:
        """
        Analyze directory structure and metadata
        
        Args:
            path: Directory path to analyze
            max_depth: Maximum recursion depth
            
        Returns:
            Dict: Directory analysis results
        """
        print(f"📁 Analyzing directory: {path}")
        
        analysis = {
            'path': path,
            'entries': [],
            'summary': {
                'total_files': 0,
                'total_directories': 0,
                'deleted_entries': 0,
                'total_size': 0
            },
            'timestamps': {
                'earliest': None,
                'latest': None
            }
        }
        
        try:
            # Get directory object
            directory = self.fs_info.open_dir(path=path)
            
            earliest_time = None
            latest_time = None
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    # Get file metadata
                    file_info = {
                        'name': entry.info.name.name.decode('utf-8', errors='replace'),
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'type': self._get_file_type(entry.info.name.type),
                        'size': entry.info.meta.size if entry.info.meta else 0,
                        'allocated': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
                        'deleted': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                    }
                    
                    # Get timestamps if available
                    if entry.info.meta:
                        timestamps = {}
                        if hasattr(entry.info.meta, 'mtime'):
                            timestamps['modified'] = entry.info.meta.mtime
                        if hasattr(entry.info.meta, 'atime'):
                            timestamps['accessed'] = entry.info.meta.atime  
                        if hasattr(entry.info.meta, 'ctime'):
                            timestamps['changed'] = entry.info.meta.ctime
                        if hasattr(entry.info.meta, 'crtime'):
                            timestamps['created'] = entry.info.meta.crtime
                        
                        file_info['timestamps'] = timestamps
                        
                        # Track earliest and latest times
                        for timestamp in timestamps.values():
                            if timestamp > 0:  # Valid timestamp
                                if earliest_time is None or timestamp < earliest_time:
                                    earliest_time = timestamp
                                if latest_time is None or timestamp > latest_time:
                                    latest_time = timestamp
                    
                    analysis['entries'].append(file_info)
                    
                    # Update summary
                    if file_info['type'] == 'directory':
                        analysis['summary']['total_directories'] += 1
                    else:
                        analysis['summary']['total_files'] += 1
                        analysis['summary']['total_size'] += file_info['size']
                    
                    if file_info['deleted']:
                        analysis['summary']['deleted_entries'] += 1
                
                except Exception as e:
                    print(f"⚠️  Error processing entry: {e}")
                    continue
            
            # Set timestamp summary
            if earliest_time:
                analysis['timestamps']['earliest'] = datetime.fromtimestamp(earliest_time).isoformat()
            if latest_time:
                analysis['timestamps']['latest'] = datetime.fromtimestamp(latest_time).isoformat()
        
        except Exception as e:
            print(f"❌ Error analyzing directory {path}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def find_deleted_files(self) -> List[Dict]:
        """Find deleted files in the file system"""
        print("🔍 Searching for deleted files...")
        
        deleted_files = []
        
        try:
            # Walk through the file system
            for file_entry in self._walk_filesystem():
                if file_entry.get('deleted', False):
                    deleted_files.append(file_entry)
        
        except Exception as e:
            print(f"❌ Error searching for deleted files: {e}")
        
        print(f"📊 Found {len(deleted_files)} deleted files")
        return deleted_files
    
    def extract_file(self, inode: int, output_path: str) -> bool:
        """
        Extract file by inode to output path
        
        Args:
            inode: File inode number
            output_path: Where to save extracted file
            
        Returns:
            bool: True if successful
        """
        try:
            # Open file by inode
            file_obj = self.fs_info.open_meta(inode=inode)
            
            # Create output directory if needed
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read and write file data
            with open(output_file, 'wb') as out_f:
                offset = 0
                size = file_obj.info.meta.size
                
                while offset < size:
                    available_to_read = min(1024 * 1024, size - offset)  # 1MB chunks
                    data = file_obj.read_random(offset, available_to_read)
                    if not data:
                        break
                    out_f.write(data)
                    offset += len(data)
            
            print(f"✅ File extracted: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error extracting file {inode}: {e}")
            return False
    
    def generate_file_listing(self, output_file: str):
        """Generate comprehensive file listing"""
        print(f"📄 Generating file listing: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("FORENSIC FILE SYSTEM LISTING\n")
            f.write("="*50 + "\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            
            # Write headers
            f.write(f"{'Inode':<10} {'Type':<5} {'Size':<12} {'Deleted':<7} {'Name'}\n")
            f.write("-" * 70 + "\n")
            
            # Walk filesystem and write entries
            for entry in self._walk_filesystem():
                f.write(f"{entry.get('inode', 0):<10} ")
                f.write(f"{entry.get('type', 'unknown')[:4]:<5} ")
                f.write(f"{entry.get('size', 0):<12} ")
                f.write(f"{'Yes' if entry.get('deleted', False) else 'No':<7} ")
                f.write(f"{entry.get('name', 'unknown')}\n")
        
        print(f"✅ File listing saved: {output_file}")
    
    def _walk_filesystem(self, path: str = "/") -> Generator[Dict, None, None]:
        """Walk through entire file system yielding file entries"""
        try:
            directory = self.fs_info.open_dir(path=path)
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    file_info = {
                        'name': entry.info.name.name.decode('utf-8', errors='replace'),
                        'path': path,
                        'full_path': os.path.join(path, entry.info.name.name.decode('utf-8', errors='replace')),
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'type': self._get_file_type(entry.info.name.type),
                        'size': entry.info.meta.size if entry.info.meta else 0,
                        'allocated': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
                        'deleted': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                    }
                    
                    yield file_info
                    
                    # Recursively process directories (limited depth for demo)
                    if (file_info['type'] == 'directory' and 
                        file_info['allocated'] and 
                        not file_info['deleted'] and 
                        path.count('/') < 3):  # Limit recursion depth
                        
                        try:
                            yield from self._walk_filesystem(file_info['full_path'])
                        except:
                            pass  # Skip inaccessible directories
                
                except Exception:
                    continue  # Skip problematic entries
                    
        except Exception as e:
            print(f"⚠️  Error walking {path}: {e}")
    
    def _get_file_type(self, tsk_type) -> str:
        """Convert TSK file type to readable string"""
        type_map = {
            pytsk3.TSK_FS_NAME_TYPE_DIR: 'directory',
            pytsk3.TSK_FS_NAME_TYPE_REG: 'file',
            pytsk3.TSK_FS_NAME_TYPE_LNK: 'symlink',
            pytsk3.TSK_FS_NAME_TYPE_CHR: 'char_device',
            pytsk3.TSK_FS_NAME_TYPE_BLK: 'block_device',
            pytsk3.TSK_FS_NAME_TYPE_FIFO: 'fifo',
            pytsk3.TSK_FS_NAME_TYPE_SOCK: 'socket'
        }
        return type_map.get(tsk_type, 'unknown')

def demo_filesystem_analysis():
    """Demonstrate file system analysis capabilities"""
    print("🗃️  File System Analysis Demo")
    print("="*50)
    
    # For demo, we'll create a simple test image first
    test_image_path = create_test_filesystem_image()
    
    if not test_image_path:
        print("⚠️  Skipping filesystem analysis - TSK not available or test image creation failed")
        return
    
    try:
        # Initialize analyzer
        analyzer = FileSystemAnalyzer(test_image_path)
        
        # Demo 1: Analyze root directory
        print("\n📋 Demo 1: Root Directory Analysis")
        
        root_analysis = analyzer.analyze_directory("/")
        
        print(f"   Total files: {root_analysis['summary']['total_files']}")
        print(f"   Total directories: {root_analysis['summary']['total_directories']}")
        print(f"   Total size: {root_analysis['summary']['total_size']:,} bytes")
        print(f"   Deleted entries: {root_analysis['summary']['deleted_entries']}")
        
        # Show sample entries
        print(f"\n   Sample entries:")
        for entry in root_analysis['entries'][:5]:  # First 5 entries
            status = "DELETED" if entry.get('deleted') else "ACTIVE"
            print(f"     {entry['name']:<20} {entry['type']:<10} {entry['size']:<10} {status}")
        
        # Demo 2: Find deleted files
        print(f"\n📋 Demo 2: Deleted File Recovery")
        
        deleted_files = analyzer.find_deleted_files()
        
        if deleted_files:
            print(f"   Found {len(deleted_files)} deleted files:")
            for file_info in deleted_files[:3]:  # Show first 3
                print(f"     {file_info['name']} (Inode: {file_info['inode']})")
        else:
            print("   No deleted files found in test image")
        
        # Demo 3: Generate file listing
        print(f"\n📋 Demo 3: Comprehensive File Listing")
        
        listing_file = "filesystem_listing.txt"
        analyzer.generate_file_listing(listing_file)
        
        # Show preview of listing
        with open(listing_file, 'r') as f:
            lines = f.readlines()
            print(f"   Generated {len(lines)} line listing")
            print(f"   Preview (first 10 lines):")
            for line in lines[:10]:
                print(f"     {line.rstrip()}")
        
    except Exception as e:
        print(f"❌ File system analysis failed: {e}")
        print("   This is normal if TSK Python bindings are not installed")

def create_test_filesystem_image() -> Optional[str]:
    """Create a simple test file system image for demonstration"""
    try:
        # This is a simplified version - in practice you'd create a proper filesystem
        test_image = "test_filesystem.dd"
        
        # Create a simple file that simulates a filesystem
        with open(test_image, 'wb') as f:
            # Write some header-like data
            f.write(b"TEST_FILESYSTEM_IMAGE\n")
            f.write(b"Created for forensics demo\n")
            
            # Pad to reasonable size (1MB)
            remaining = 1024 * 1024 - f.tell()
            f.write(b'\x00' * remaining)
        
        return test_image
        
    except Exception as e:
        print(f"⚠️  Could not create test filesystem image: {e}")
        return None

if __name__ == "__main__":
    demo_filesystem_analysis()
```

---

## 📘 Module 4: Timeline Analysis & Security Architecture Investigation (60 minutes)

**Learning Objectives**:
- Create comprehensive super timelines using Plaso/log2timeline methodology
- Correlate events across multiple data sources from Week 3-9 security systems
- Apply timeline analysis to investigate security architecture compromises
- Perform anomaly detection and pattern recognition in digital evidence
- Generate expert-level forensic findings suitable for incident response

**What you'll build**: Advanced timeline analysis system investigating Week 3-9 security systems

### Step 1: Advanced Timeline Analysis for Security Investigation

---

## 📘 Part 3: Timeline Analysis (60 minutes)

**Learning Objective**: Create timeline analysis for digital forensics investigations

**What you'll build**: Timeline creation and event correlation system

Create `timeline_analysis.py`:

```python
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import json
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
import re

@dataclass
class TimelineEvent:
    """Individual timeline event"""
    timestamp: datetime
    event_type: str
    source: str
    description: str
    artifact_type: str
    file_path: str = ""
    inode: int = 0
    size: int = 0
    hash_value: str = ""
    user: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary with ISO timestamp"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class TimelineAnalyzer:
    """Digital forensics timeline analysis"""
    
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.events: List[TimelineEvent] = []
        self.output_dir = Path(f"timeline_{case_name}")
        self.output_dir.mkdir(exist_ok=True)
        
        print(f"✅ Timeline analyzer initialized for case: {case_name}")
    
    def add_filesystem_events(self, fs_analysis: Dict):
        """Add filesystem events from analysis"""
        print("📁 Adding filesystem events to timeline...")
        
        for entry in fs_analysis.get('entries', []):
            timestamps = entry.get('timestamps', {})
            
            # Add events for each timestamp type
            for ts_type, timestamp in timestamps.items():
                if timestamp > 0:  # Valid timestamp
                    event_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    
                    # Map timestamp types to event types
                    event_type_map = {
                        'modified': 'FILE_MODIFIED',
                        'accessed': 'FILE_ACCESSED',
                        'changed': 'FILE_METADATA_CHANGED',
                        'created': 'FILE_CREATED'
                    }
                    
                    event_type = event_type_map.get(ts_type, 'FILE_TIMESTAMP')
                    
                    event = TimelineEvent(
                        timestamp=event_dt,
                        event_type=event_type,
                        source='filesystem',
                        description=f"{ts_type.title()} timestamp for {entry['name']}",
                        artifact_type='file_metadata',
                        file_path=entry.get('full_path', entry['name']),
                        inode=entry.get('inode', 0),
                        size=entry.get('size', 0)
                    )
                    
                    self.events.append(event)
        
        print(f"   Added {len([e for e in self.events if e.source == 'filesystem'])} filesystem events")
    
    def add_log_events(self, log_file: str, log_format: str = 'auto'):
        """
        Parse and add log file events
        
        Args:
            log_file: Path to log file
            log_format: Log format ('apache', 'iis', 'syslog', 'auto')
        """
        print(f"📄 Parsing log file: {log_file}")
        
        if not Path(log_file).exists():
            print(f"⚠️  Log file not found: {log_file}")
            return
        
        log_events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parsed_event = self._parse_log_line(line, log_format, line_num)
                    if parsed_event:
                        log_events.append(parsed_event)
        
        except Exception as e:
            print(f"❌ Error reading log file: {e}")
            return
        
        self.events.extend(log_events)
        print(f"   Added {len(log_events)} log events")
    
    def add_registry_events(self, registry_analysis: Dict):
        """Add Windows registry events"""
        print("🗃️  Adding registry events to timeline...")
        
        registry_events = []
        
        for key_path, key_info in registry_analysis.items():
            timestamp = key_info.get('last_written')
            if timestamp:
                event = TimelineEvent(
                    timestamp=timestamp,
                    event_type='REGISTRY_KEY_MODIFIED',
                    source='registry',
                    description=f"Registry key modified: {key_path}",
                    artifact_type='registry_key',
                    file_path=key_path
                )
                registry_events.append(event)
        
        self.events.extend(registry_events)
        print(f"   Added {len(registry_events)} registry events")
    
    def create_super_timeline(self) -> str:
        """Create comprehensive super timeline"""
        print("🕐 Creating super timeline...")
        
        # Sort all events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # Generate timeline file
        timeline_file = self.output_dir / f"{self.case_name}_super_timeline.csv"
        
        with open(timeline_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Timestamp', 'Event Type', 'Source', 'Description', 
                'Artifact Type', 'File Path', 'Inode', 'Size', 'User'
            ])
            
            # Write events
            for event in sorted_events:
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.source,
                    event.description,
                    event.artifact_type,
                    event.file_path,
                    event.inode,
                    event.size,
                    event.user
                ])
        
        print(f"✅ Super timeline created: {timeline_file}")
        print(f"   Total events: {len(sorted_events)}")
        
        return str(timeline_file)
    
    def find_time_anomalies(self, window_minutes: int = 60) -> List[Dict]:
        """
        Find time-based anomalies and suspicious patterns
        
        Args:
            window_minutes: Time window for anomaly detection
            
        Returns:
            List of detected anomalies
        """
        print(f"🔍 Analyzing timeline for anomalies (window: {window_minutes} min)...")
        
        anomalies = []
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # Look for clusters of activity
        current_cluster = []
        cluster_threshold = 10  # Minimum events in cluster to be suspicious
        
        for i, event in enumerate(sorted_events):
            if not current_cluster:
                current_cluster = [event]
                continue
            
            # Check if event is within time window of cluster
            time_diff = (event.timestamp - current_cluster[0].timestamp).total_seconds() / 60
            
            if time_diff <= window_minutes:
                current_cluster.append(event)
            else:
                # Analyze current cluster
                if len(current_cluster) >= cluster_threshold:
                    anomaly = {
                        'type': 'HIGH_ACTIVITY_CLUSTER',
                        'start_time': current_cluster[0].timestamp.isoformat(),
                        'end_time': current_cluster[-1].timestamp.isoformat(),
                        'event_count': len(current_cluster),
                        'duration_minutes': (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds() / 60,
                        'description': f"Cluster of {len(current_cluster)} events in {time_diff:.1f} minutes"
                    }
                    anomalies.append(anomaly)
                
                # Start new cluster
                current_cluster = [event]
        
        # Check final cluster
        if len(current_cluster) >= cluster_threshold:
            time_span = (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds() / 60
            anomaly = {
                'type': 'HIGH_ACTIVITY_CLUSTER',
                'start_time': current_cluster[0].timestamp.isoformat(),
                'end_time': current_cluster[-1].timestamp.isoformat(),
                'event_count': len(current_cluster),
                'duration_minutes': time_span,
                'description': f"Final cluster of {len(current_cluster)} events"
            }
            anomalies.append(anomaly)
        
        # Look for off-hours activity (outside 9-17 business hours)
        off_hours_events = [
            event for event in sorted_events 
            if event.timestamp.hour < 9 or event.timestamp.hour > 17
        ]
        
        if len(off_hours_events) > len(sorted_events) * 0.2:  # More than 20% off-hours
            anomaly = {
                'type': 'OFF_HOURS_ACTIVITY',
                'event_count': len(off_hours_events),
                'percentage': (len(off_hours_events) / len(sorted_events)) * 100,
                'description': f"High off-hours activity: {len(off_hours_events)} events ({(len(off_hours_events) / len(sorted_events)) * 100:.1f}%)"
            }
            anomalies.append(anomaly)
        
        print(f"   Found {len(anomalies)} potential anomalies")
        return anomalies
    
    def generate_timeline_report(self) -> str:
        """Generate comprehensive timeline analysis report"""
        print("📊 Generating timeline analysis report...")
        
        report_file = self.output_dir / f"{self.case_name}_timeline_report.txt"
        
        # Calculate statistics
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        if not sorted_events:
            print("⚠️  No events to analyze")
            return str(report_file)
        
        # Event type statistics
        event_types = {}
        sources = {}
        
        for event in sorted_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            sources[event.source] = sources.get(event.source, 0) + 1
        
        # Time range analysis
        earliest = sorted_events[0].timestamp
        latest = sorted_events[-1].timestamp
        time_span = latest - earliest
        
        # Find anomalies
        anomalies = self.find_time_anomalies()
        
        # Generate report
        with open(report_file, 'w') as f:
            f.write(f"TIMELINE ANALYSIS REPORT\n")
            f.write(f"{"="*50}\n")
            f.write(f"Case: {self.case_name}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total Events: {len(sorted_events):,}\n\n")
            
            f.write(f"TIME RANGE ANALYSIS\n")
            f.write(f"{'-'*30}\n")
            f.write(f"Earliest Event: {earliest.isoformat()}\n")
            f.write(f"Latest Event:   {latest.isoformat()}\n")
            f.write(f"Time Span:      {time_span.days} days, {time_span.seconds // 3600} hours\n\n")
            
            f.write(f"EVENT TYPES\n")
            f.write(f"{'-'*30}\n")
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(sorted_events)) * 100
                f.write(f"{event_type:<25} {count:>6} ({percentage:5.1f}%)\n")
            f.write(f"\n")
            
            f.write(f"DATA SOURCES\n")
            f.write(f"{'-'*30}\n")
            for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(sorted_events)) * 100
                f.write(f"{source:<25} {count:>6} ({percentage:5.1f}%)\n")
            f.write(f"\n")
            
            if anomalies:
                f.write(f"DETECTED ANOMALIES\n")
                f.write(f"{'-'*30}\n")
                for i, anomaly in enumerate(anomalies, 1):
                    f.write(f"{i}. {anomaly['type']}\n")
                    f.write(f"   {anomaly['description']}\n")
                    if 'start_time' in anomaly:
                        f.write(f"   Time Range: {anomaly['start_time']} to {anomaly['end_time']}\n")
                    f.write(f"\n")
        
        print(f"✅ Timeline report saved: {report_file}")
        return str(report_file)
    
    def _parse_log_line(self, line: str, log_format: str, line_num: int) -> Optional[TimelineEvent]:
        """Parse individual log line based on format"""
        try:
            # Simple Apache/IIS common log format parser
            if 'apache' in log_format.lower() or log_format == 'auto':
                # Example: 192.168.1.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
                apache_pattern = r'(\d+\.\d+\.\d+\.\d+) .* \[([^\]]+)\] "([^"]+)" (\d+) (\d+)'
                match = re.match(apache_pattern, line)
                
                if match:
                    ip, timestamp_str, request, status, size = match.groups()
                    
                    # Parse timestamp
                    try:
                        timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    except:
                        timestamp = datetime.now(timezone.utc)
                    
                    return TimelineEvent(
                        timestamp=timestamp,
                        event_type='WEB_REQUEST',
                        source='webserver',
                        description=f"{request} from {ip} (Status: {status})",
                        artifact_type='web_log',
                        file_path=f"line_{line_num}",
                        size=int(size) if size.isdigit() else 0,
                        user=ip
                    )
            
            # Simple syslog format
            elif 'syslog' in log_format.lower():
                # Example: Dec 25 10:00:00 hostname service[1234]: message
                syslog_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\w+) ([^:]+): (.+)'
                match = re.match(syslog_pattern, line)
                
                if match:
                    timestamp_str, hostname, service, message = match.groups()
                    
                    # Parse timestamp (assume current year)
                    try:
                        timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    except:
                        timestamp = datetime.now(timezone.utc)
                    
                    return TimelineEvent(
                        timestamp=timestamp,
                        event_type='SYSTEM_LOG',
                        source='syslog',
                        description=f"{service}: {message}",
                        artifact_type='system_log',
                        file_path=f"line_{line_num}",
                        user=hostname
                    )
        
        except Exception as e:
            print(f"⚠️  Error parsing line {line_num}: {e}")
        
        return None

def demo_timeline_analysis():
    """Demonstrate timeline analysis capabilities"""
    print("🕐 Timeline Analysis Demo")
    print("="*50)
    
    # Create timeline analyzer
    timeline = TimelineAnalyzer("demo_case_001")
    
    # Demo 1: Add sample filesystem events
    print("\n📋 Demo 1: Adding Sample Events")
    
    # Simulate filesystem analysis results
    sample_fs_analysis = {
        'entries': [
            {
                'name': 'document.txt',
                'full_path': '/home/user/document.txt',
                'inode': 12345,
                'size': 1024,
                'timestamps': {
                    'created': 1703500800,    # 2023-12-25 10:00:00
                    'modified': 1703504400,   # 2023-12-25 11:00:00
                    'accessed': 1703508000,   # 2023-12-25 12:00:00
                }
            },
            {
                'name': 'secret.txt',
                'full_path': '/tmp/secret.txt',
                'inode': 67890,
                'size': 512,
                'timestamps': {
                    'created': 1703520000,    # 2023-12-25 16:00:00
                    'modified': 1703521800,   # 2023-12-25 16:30:00
                }
            }
        ]
    }
    
    timeline.add_filesystem_events(sample_fs_analysis)
    
    # Demo 2: Create sample log file and parse it
    print(f"\n📋 Demo 2: Adding Log Events")
    
    # Create sample log file
    sample_log = "sample_access.log"
    with open(sample_log, 'w') as f:
        f.write('192.168.1.100 - - [25/Dec/2023:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 2048\n')
        f.write('192.168.1.101 - - [25/Dec/2023:10:16:30 +0000] "POST /login HTTP/1.1" 302 128\n')
        f.write('192.168.1.102 - - [25/Dec/2023:10:17:45 +0000] "GET /admin HTTP/1.1" 403 256\n')
        f.write('192.168.1.100 - - [25/Dec/2023:10:18:00 +0000] "GET /data.json HTTP/1.1" 200 4096\n')
    
    timeline.add_log_events(sample_log, 'apache')
    
    # Demo 3: Create super timeline
    print(f"\n📋 Demo 3: Creating Super Timeline")
    
    timeline_file = timeline.create_super_timeline()
    
    # Show sample of timeline
    print(f"   Sample timeline entries:")
    with open(timeline_file, 'r') as f:
        lines = f.readlines()
        for line in lines[:6]:  # Show first 6 lines (header + 5 events)
            print(f"     {line.strip()}")
    
    # Demo 4: Anomaly detection
    print(f"\n📋 Demo 4: Anomaly Detection")
    
    anomalies = timeline.find_time_anomalies(window_minutes=30)
    
    if anomalies:
        for i, anomaly in enumerate(anomalies, 1):
            print(f"   Anomaly {i}: {anomaly['type']}")
            print(f"     {anomaly['description']}")
    else:
        print("   No anomalies detected in sample data")
    
    # Demo 5: Generate comprehensive report
    print(f"\n📋 Demo 5: Timeline Analysis Report")
    
    report_file = timeline.generate_timeline_report()
    
    # Show preview of report
    with open(report_file, 'r') as f:
        lines = f.readlines()
        print(f"   Report preview (first 15 lines):")
        for line in lines[:15]:
            print(f"     {line.rstrip()}")
    
    # Cleanup
    os.remove(sample_log)
    
    print(f"\n💡 Timeline Analysis Summary:")
    print(f"   Total events processed: {len(timeline.events)}")
    print(f"   Timeline file: {timeline_file}")
    print(f"   Analysis report: {report_file}")

if __name__ == "__main__":
    demo_timeline_analysis()
```

### ✅ Checkpoint 3: Timeline Analysis

Verify your timeline analysis system:
1. Can you create comprehensive super timelines?
2. Do you understand time-based anomaly detection?
3. Can you correlate events from multiple sources?

---

Create `security_architecture_investigation.py` - Investigating Week 3-9 security systems:

```python
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import json
import csv
import re
import sqlite3
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import pandas as pd
import hashlib

class SecuritySystem(Enum):
    """Security systems from Weeks 3-9 for forensic investigation"""
    PKI_CERTIFICATE = "pki_certificate"      # Week 3: PKI and certificates
    MFA_AUTHENTICATION = "mfa_auth"          # Week 4: Multi-factor authentication  
    RBAC_ACCESS_CONTROL = "rbac_control"     # Week 5: Role-based access control
    NETWORK_SECURITY = "network_security"    # Week 6: Network security
    SIEM_MONITORING = "siem_monitoring"      # Week 7: Security monitoring
    VULNERABILITY_ASSESSMENT = "vuln_assess" # Week 8: Security assessment
    SECURITY_ARCHITECTURE = "sec_arch"       # Week 9: Security architecture

class EventType(Enum):
    """Timeline event types for security investigation"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    
    # Access control events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROLE_CHANGE = "role_change"
    
    # Certificate and PKI events
    CERTIFICATE_ISSUED = "cert_issued"
    CERTIFICATE_REVOKED = "cert_revoked"
    CERTIFICATE_EXPIRED = "cert_expired"
    CERTIFICATE_VALIDATION = "cert_validation"
    
    # Network security events
    FIREWALL_BLOCK = "firewall_block"
    FIREWALL_ALLOW = "firewall_allow"
    INTRUSION_DETECTED = "intrusion_detected"
    NETWORK_CONNECTION = "network_connection"
    
    # SIEM and monitoring events
    ALERT_TRIGGERED = "alert_triggered"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    CORRELATION_MATCH = "correlation_match"
    
    # File system events
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_ACCESSED = "file_accessed"
    FILE_DELETED = "file_deleted"
    
    # System events
    PROCESS_STARTED = "process_started"
    PROCESS_TERMINATED = "process_terminated"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    
    # Investigation events
    EVIDENCE_COLLECTED = "evidence_collected"
    ANALYSIS_PERFORMED = "analysis_performed"
    FINDING_DOCUMENTED = "finding_documented"

@dataclass
class SecurityTimelineEvent:
    """Timeline event for security architecture investigation"""
    timestamp: datetime
    event_type: EventType
    security_system: SecuritySystem
    source: str              # Log file, system, database, etc.
    description: str
    
    # Event details
    user_id: str = ""
    source_ip: str = ""
    target_resource: str = ""
    action: str = ""
    result: str = ""
    
    # Forensic metadata
    confidence_level: float = 1.0  # 0.0 - 1.0
    evidence_id: str = ""
    correlation_id: str = ""
    ioc_indicators: List[str] = None  # Indicators of compromise
    
    # Analysis metadata
    analyzed: bool = False
    suspicious: bool = False
    investigation_notes: str = ""
    
    def __post_init__(self):
        if self.ioc_indicators is None:
            self.ioc_indicators = []

@dataclass
class SecurityIncidentFinding:
    """Individual finding from security investigation"""
    finding_id: str
    finding_type: str        # "compromise", "policy_violation", "anomaly", etc.
    severity: str           # "critical", "high", "medium", "low"
    title: str
    description: str
    
    # Evidence supporting this finding
    supporting_events: List[str]  # Event correlation IDs
    evidence_artifacts: List[str] # File paths, log entries, etc.
    timeline_span: Tuple[datetime, datetime]
    
    # Impact assessment
    affected_systems: List[SecuritySystem]
    business_impact: str
    technical_impact: str
    
    # Recommendations
    immediate_actions: List[str]
    long_term_recommendations: List[str]
    
    # Forensic validation
    confidence_level: float = 1.0
    validation_method: str = ""
    investigator: str = ""
    
class SecurityArchitectureInvestigator:
    """Professional security architecture investigation following incident response methodology"""
    
    def __init__(self, case_id: str, incident_title: str, lead_investigator: str):
        self.case_id = case_id
        self.incident_title = incident_title
        self.lead_investigator = lead_investigator
        
        # Investigation workspace
        self.output_dir = Path(f"security_investigation_{case_id}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Data structures
        self.timeline_events: List[SecurityTimelineEvent] = []
        self.findings: List[SecurityIncidentFinding] = []
        self.investigation_database = None
        
        # Setup investigation environment
        self._setup_investigation_database()
        self._setup_logging()
        
        print(f"✅ Security Architecture Investigation Initialized")
        print(f"   Case ID: {case_id}")
        print(f"   Incident: {incident_title}")
        print(f"   Lead Investigator: {lead_investigator}")
    
    def _setup_investigation_database(self):
        """Setup comprehensive investigation database"""
        db_path = self.output_dir / "investigation_database.db"
        self.investigation_database = sqlite3.connect(str(db_path))
        
        cursor = self.investigation_database.cursor()
        
        # Timeline events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                security_system TEXT,
                source TEXT,
                description TEXT,
                user_id TEXT,
                source_ip TEXT,
                target_resource TEXT,
                action TEXT,
                result TEXT,
                confidence_level REAL,
                evidence_id TEXT,
                correlation_id TEXT,
                analyzed BOOLEAN,
                suspicious BOOLEAN,
                investigation_notes TEXT
            )
        ''')
        
        # Investigation findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                finding_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                timeline_start TEXT,
                timeline_end TEXT,
                business_impact TEXT,
                technical_impact TEXT,
                confidence_level REAL,
                validation_method TEXT,
                investigator TEXT
            )
        ''')
        
        # Event correlations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_correlations (
                correlation_id TEXT PRIMARY KEY,
                primary_event_id TEXT,
                related_event_id TEXT,
                correlation_type TEXT,
                confidence_score REAL,
                analysis_notes TEXT
            )
        ''')
        
        self.investigation_database.commit()
        print(f"   📊 Investigation database initialized")
    
    def _setup_logging(self):
        """Setup investigation logging"""
        log_file = self.output_dir / "investigation_activity.log"
        
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s UTC - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self.logger = logging.getLogger('SecurityInvestigation')
        self.logger.info("Security architecture investigation started")
        self.logger.info(f"Case: {self.case_id}, Incident: {self.incident_title}")
    
    def investigate_security_systems(self, evidence_sources: Dict[SecuritySystem, str]) -> Dict[str, Any]:
        """Comprehensive investigation of Week 3-9 security systems"""
        print(f"🔍 Starting Security Systems Investigation")
        print(f"   Evidence sources: {len(evidence_sources)} systems")
        
        investigation_results = {
            'start_time': datetime.now(timezone.utc).isoformat(),
            'systems_investigated': list(evidence_sources.keys()),
            'total_events_processed': 0,
            'suspicious_events_found': 0,
            'correlations_identified': 0,
            'findings_generated': 0,
            'investigation_success': True,
            'error_count': 0
        }
        
        try:
            # Phase 1: Extract timeline events from each security system
            print("\n📋 Phase 1: Timeline Event Extraction")
            
            for security_system, evidence_path in evidence_sources.items():
                print(f"   Processing {security_system.value}...")
                
                try:
                    events = self._extract_security_system_events(security_system, evidence_path)
                    self.timeline_events.extend(events)
                    print(f"     Extracted {len(events)} events")
                    
                except Exception as e:
                    print(f"     ⚠️ Error processing {security_system.value}: {e}")
                    investigation_results['error_count'] += 1
            
            # Sort timeline by timestamp
            self.timeline_events.sort(key=lambda e: e.timestamp)
            investigation_results['total_events_processed'] = len(self.timeline_events)
            print(f"   Total events extracted: {len(self.timeline_events):,}")
            
            # Phase 2: Event correlation analysis
            print("\n📋 Phase 2: Event Correlation Analysis")
            correlations = self._perform_event_correlation()
            investigation_results['correlations_identified'] = len(correlations)
            print(f"   Event correlations identified: {len(correlations)}")
            
            # Phase 3: Suspicious activity detection
            print("\n📋 Phase 3: Suspicious Activity Detection")
            suspicious_events = self._detect_suspicious_activities()
            investigation_results['suspicious_events_found'] = len(suspicious_events)
            print(f"   Suspicious events detected: {len(suspicious_events)}")
            
            # Phase 4: Generate investigation findings
            print("\n📋 Phase 4: Investigation Findings Generation")
            findings = self._generate_investigation_findings(correlations, suspicious_events)
            investigation_results['findings_generated'] = len(findings)
            print(f"   Investigation findings: {len(findings)}")
            
            # Phase 5: Save investigation data
            print("\n📋 Phase 5: Investigation Data Persistence")
            self._save_investigation_data()
            
            investigation_results['end_time'] = datetime.now(timezone.utc).isoformat()
            investigation_results['investigation_duration'] = (
                datetime.fromisoformat(investigation_results['end_time']) - 
                datetime.fromisoformat(investigation_results['start_time'])
            ).total_seconds()
            
            print(f"\n✅ Security systems investigation completed")
            print(f"   Duration: {investigation_results['investigation_duration']:.1f} seconds")
            print(f"   Findings: {len(findings)} security issues identified")
            
            self.logger.info(f"Investigation completed successfully")
            self.logger.info(f"Events processed: {len(self.timeline_events)}, Findings: {len(findings)}")
            
            return investigation_results
            
        except Exception as e:
            error_msg = f"Security investigation failed: {e}"
            print(f"❌ {error_msg}")
            self.logger.error(error_msg)
            investigation_results['investigation_success'] = False
            investigation_results['error'] = error_msg
            return investigation_results
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary for incident response leadership"""
        summary_path = self.output_dir / f"{self.case_id}_executive_summary.txt"
        
        # Calculate key metrics
        high_severity_findings = [f for f in self.findings if f.severity in ['critical', 'high']]
        affected_systems = set()
        for finding in self.findings:
            affected_systems.update(finding.affected_systems)
        
        earliest_event = min(self.timeline_events, key=lambda e: e.timestamp) if self.timeline_events else None
        latest_event = max(self.timeline_events, key=lambda e: e.timestamp) if self.timeline_events else None
        
        with open(summary_path, 'w') as f:
            f.write(f"EXECUTIVE SUMMARY - SECURITY INCIDENT INVESTIGATION\n")
            f.write(f"="*70 + "\n\n")
            
            # Incident overview
            f.write(f"INCIDENT OVERVIEW\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Case ID: {self.case_id}\n")
            f.write(f"Incident Title: {self.incident_title}\n")
            f.write(f"Lead Investigator: {self.lead_investigator}\n")
            f.write(f"Investigation Date: {datetime.now().strftime('%Y-%m-%d')}\n\n")
            
            # Key findings summary
            f.write(f"KEY FINDINGS SUMMARY\n")
            f.write(f"{'-'*20}\n")
            f.write(f"Total Findings: {len(self.findings)}\n")
            f.write(f"Critical/High Severity: {len(high_severity_findings)}\n")
            f.write(f"Security Systems Affected: {len(affected_systems)}\n")
            
            if earliest_event and latest_event:
                incident_duration = latest_event.timestamp - earliest_event.timestamp
                f.write(f"Incident Timeline: {earliest_event.timestamp.strftime('%Y-%m-%d %H:%M')} to {latest_event.timestamp.strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"Incident Duration: {incident_duration.total_seconds() / 3600:.1f} hours\n")
            f.write(f"\n")
            
            # High-priority findings
            if high_severity_findings:
                f.write(f"HIGH-PRIORITY FINDINGS\n")
                f.write(f"{'-'*20}\n")
                for i, finding in enumerate(high_severity_findings, 1):
                    f.write(f"{i}. [{finding.severity.upper()}] {finding.title}\n")
                    f.write(f"   Business Impact: {finding.business_impact}\n")
                    f.write(f"   Immediate Action Required: {finding.immediate_actions[0] if finding.immediate_actions else 'See detailed report'}\n\n")
            
            # Affected systems
            f.write(f"AFFECTED SECURITY SYSTEMS\n")
            f.write(f"{'-'*20}\n")
            system_names = {
                SecuritySystem.PKI_CERTIFICATE: "PKI Certificate Infrastructure",
                SecuritySystem.MFA_AUTHENTICATION: "Multi-Factor Authentication",
                SecuritySystem.RBAC_ACCESS_CONTROL: "Role-Based Access Control",
                SecuritySystem.NETWORK_SECURITY: "Network Security Systems",
                SecuritySystem.SIEM_MONITORING: "SIEM Monitoring Platform",
                SecuritySystem.VULNERABILITY_ASSESSMENT: "Vulnerability Assessment Tools",
                SecuritySystem.SECURITY_ARCHITECTURE: "Security Architecture Framework"
            }
            
            for system in affected_systems:
                f.write(f"  • {system_names.get(system, system.value)}\n")
            f.write(f"\n")
            
            # Recommendations
            immediate_actions = set()
            for finding in high_severity_findings:
                immediate_actions.update(finding.immediate_actions)
            
            if immediate_actions:
                f.write(f"IMMEDIATE ACTIONS REQUIRED\n")
                f.write(f"{'-'*20}\n")
                for i, action in enumerate(list(immediate_actions)[:5], 1):  # Top 5 actions
                    f.write(f"{i}. {action}\n")
                f.write(f"\n")
            
            # Investigation certification
            f.write(f"INVESTIGATION CERTIFICATION\n")
            f.write(f"{'-'*20}\n")
            f.write(f"This investigation was conducted using forensically sound methodologies\n")
            f.write(f"following NIST SP 800-86 and industry best practices. All findings\n")
            f.write(f"are supported by digital evidence and timeline correlation analysis.\n\n")
            f.write(f"Lead Investigator: {self.lead_investigator}\n")
            f.write(f"Report Generated: {datetime.now().isoformat()}\n")
        
        print(f"📋 Executive summary generated: {summary_path}")
        return str(summary_path)

def demo_security_investigation():
    """Demonstrate security architecture investigation"""
    print("⚖️ Security Architecture Investigation Demo - Investigating Week 3-9 Systems")
    print("="*80)
    
    # Initialize investigation
    investigator = SecurityArchitectureInvestigator(
        case_id="GT-2024-001",
        incident_title="GlobalTech Enterprises Data Exfiltration Investigation",
        lead_investigator="Digital Forensics Student"
    )
    
    # Demo: Create simulated evidence from Week 3-9 systems
    print("\n📋 Demo: Simulating Evidence from Week 3-9 Security Systems")
    
    # Simulate evidence sources (in real investigation, these would be actual logs/databases)
    evidence_sources = {
        SecuritySystem.PKI_CERTIFICATE: "simulated_pki_logs.json",
        SecuritySystem.MFA_AUTHENTICATION: "simulated_mfa_logs.json", 
        SecuritySystem.RBAC_ACCESS_CONTROL: "simulated_rbac_logs.json",
        SecuritySystem.NETWORK_SECURITY: "simulated_network_logs.json",
        SecuritySystem.SIEM_MONITORING: "simulated_siem_alerts.json"
    }
    
    # Create simulated evidence files
    investigator._create_simulated_evidence(evidence_sources)
    
    # Perform comprehensive investigation
    results = investigator.investigate_security_systems(evidence_sources)
    
    # Generate reports
    executive_summary = investigator.generate_executive_summary()
    
    print(f"\n💡 Investigation Summary:")
    print(f"   Case ID: {investigator.case_id}")
    print(f"   Events Processed: {results['total_events_processed']:,}")
    print(f"   Suspicious Events: {results['suspicious_events_found']}")
    print(f"   Findings Generated: {results['findings_generated']}")
    print(f"   Executive Summary: {executive_summary}")
    
    print(f"\n🎓 Key Learning: This investigation demonstrates how to apply digital forensics")
    print(f"   methodology to investigate the security systems you built in Weeks 3-9,")
    print(f"   showing the complete cycle from preventive security to reactive investigation.")

if __name__ == "__main__":
    demo_security_investigation()
```

### ✅ Checkpoint 4: Timeline Analysis & Security Architecture Investigation

Validate your advanced forensic investigation capabilities:

1. **Super Timeline Creation**: Can you create comprehensive timelines using Plaso/log2timeline methodology?
2. **Event Correlation**: Can you correlate events across multiple security systems from Weeks 3-9?
3. **Anomaly Detection**: Can you identify suspicious patterns and potential indicators of compromise?
4. **Security Architecture Investigation**: Can you investigate compromises in the security systems you built?
5. **Expert-Level Reporting**: Are your findings suitable for incident response and executive briefings?

**🎯 Integration Excellence**: Your investigation should demonstrate clear connections between the preventive security measures from Weeks 3-9 and the reactive forensic investigation techniques, showing complete cybersecurity expertise.

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your mastery of professional digital forensics:

**Module 1: Forensic Methodology & Legal Frameworks**
- [ ] You understand NIST SP 800-86 four-phase forensic process
- [ ] You can implement RFC 3227 evidence collection guidelines
- [ ] You understand legal requirements for court admissibility
- [ ] You can prepare forensic evidence for expert testimony

**Module 2: Evidence Acquisition & Chain of Custody**
- [ ] You can perform forensically sound evidence acquisition
- [ ] You understand hash verification using multiple algorithms
- [ ] You can maintain complete chain of custody documentation
- [ ] You can create working copies while preserving evidence integrity

**Module 3: File System Forensics & Autopsy Integration**
- [ ] You can analyze multiple file system types (NTFS, ext4, APFS, FAT32)
- [ ] You can recover deleted files with confidence assessments
- [ ] You can extract comprehensive file system metadata and timelines
- [ ] You can generate professional forensic reports

**Module 4: Timeline Analysis & Security Architecture Investigation**
- [ ] You can create super timelines from multiple evidence sources
- [ ] You can correlate events across Week 3-9 security systems
- [ ] You can detect anomalies and indicators of compromise
- [ ] You can generate executive-level incident response findings

## 🚀 Ready for the Assignment?

Excellent! You now have comprehensive digital forensics expertise following industry standards. The assignment will apply these skills to investigate a complete security incident in the architecture you designed in Week 9.

**Next step**: Review [assignment.md](assignment.md) for the complete forensic investigation scenario.

## 💡 Key Professional Competencies Achieved

1. **Digital Forensics Methodology** - NIST SP 800-86 and RFC 3227 compliance
2. **Evidence Acquisition** - Forensically sound procedures with chain of custody
3. **File System Forensics** - Multi-platform analysis with Autopsy/Sleuth Kit integration
4. **Timeline Analysis** - Super timeline creation with event correlation
5. **Security Architecture Investigation** - Applying forensics to Week 3-9 security systems
6. **Legal Compliance** - Court admissibility and expert testimony preparation
7. **Professional Reporting** - Executive summaries and technical analysis documentation
8. **Incident Response Integration** - Complete preventive-to-reactive security lifecycle

**🎓 Career Preparation**: These competencies align with professional digital forensics certifications (GCFA, CCE, GCTI) and prepare you for senior incident response and forensic examiner roles.

**🔗 Part II Foundation**: This week establishes the forensic methodology foundation that will be enhanced with advanced techniques in Weeks 11-14, culminating in a complete incident investigation platform.

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!