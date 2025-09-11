#!/usr/bin/env python3
"""
Digital Forensics Investigation Platform Template

This template provides the foundational structure for implementing a comprehensive
digital forensics platform. Students should build upon this foundation to create
a production-ready forensic investigation system.

Author: CSCI 347 Course Template
Date: Fall 2025
"""

import os
import hashlib
import json
import sqlite3
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import logging

# Forensic libraries (students need to install these)
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False
    print("Warning: pytsk3 not installed. File system analysis will be limited.")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not installed. File type detection will be limited.")


class EvidenceType(Enum):
    """Types of digital evidence supported by the platform"""
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    MOBILE_IMAGE = "mobile_image"
    LOG_FILES = "log_files"
    CLOUD_DATA = "cloud_data"


class FileSystemType(Enum):
    """Supported file system types"""
    NTFS = "ntfs"
    FAT32 = "fat32"
    EXT4 = "ext4"
    HFS_PLUS = "hfs+"
    APFS = "apfs"
    UNKNOWN = "unknown"


class AnalysisStatus(Enum):
    """Status of analysis tasks"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ChainOfCustodyEntry:
    """Chain of custody record for evidence tracking"""
    timestamp: datetime
    investigator: str
    action: str
    location: str
    notes: Optional[str] = None
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'investigator': self.investigator,
            'action': self.action,
            'location': self.location,
            'notes': self.notes,
            'hash_before': self.hash_before,
            'hash_after': self.hash_after
        }


@dataclass
class Evidence:
    """Digital evidence container with metadata and chain of custody"""
    evidence_id: str
    case_id: str
    file_path: str
    evidence_type: EvidenceType
    original_hash: str
    current_hash: str
    file_size: int
    acquired_date: datetime
    acquired_by: str
    description: str
    chain_of_custody: List[ChainOfCustodyEntry] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_custody_entry(self, investigator: str, action: str, location: str, 
                         notes: Optional[str] = None):
        """Add a new entry to the chain of custody"""
        entry = ChainOfCustodyEntry(
            timestamp=datetime.now(timezone.utc),
            investigator=investigator,
            action=action,
            location=location,
            notes=notes,
            hash_before=self.current_hash,
            hash_after=self._calculate_current_hash()
        )
        self.chain_of_custody.append(entry)
        self.current_hash = entry.hash_after

    def _calculate_current_hash(self) -> str:
        """Calculate current hash of the evidence file"""
        if not os.path.exists(self.file_path):
            return "FILE_NOT_FOUND"
        
        sha256_hash = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def verify_integrity(self) -> bool:
        """Verify evidence integrity by comparing hashes"""
        current = self._calculate_current_hash()
        return current == self.current_hash


@dataclass
class Case:
    """Forensic investigation case container"""
    case_id: str
    case_name: str
    investigator: str
    created_date: datetime
    description: str
    status: str = "active"
    evidence_list: List[Evidence] = field(default_factory=list)
    notes: str = ""
    tags: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence):
        """Add evidence to the case"""
        self.evidence_list.append(evidence)
        evidence.add_custody_entry(
            investigator=self.investigator,
            action="Added to case",
            location="Evidence database",
            notes=f"Added to case {self.case_id}"
        )


@dataclass
class TimelineEvent:
    """Timeline event for forensic analysis"""
    timestamp: datetime
    source: str
    event_type: str
    description: str
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0  # 0.0 to 1.0 confidence score

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'description': self.description,
            'file_path': self.file_path,
            'metadata': self.metadata,
            'confidence': self.confidence
        }


@dataclass
class AnalysisResult:
    """Result of forensic analysis operation"""
    analysis_id: str
    evidence_id: str
    analysis_type: str
    status: AnalysisStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    results: Dict[str, Any] = field(default_factory=dict)
    timeline_events: List[TimelineEvent] = field(default_factory=list)
    artifacts_found: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ForensicPlatform:
    """
    Core Digital Forensics Platform
    
    This class provides the foundational structure for implementing
    a comprehensive digital forensics investigation platform.
    """

    def __init__(self, workspace_path: str):
        """
        Initialize the forensic platform
        
        Args:
            workspace_path: Path to the forensic workspace directory
        """
        self.workspace_path = Path(workspace_path)
        self.workspace_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize directories
        self.evidence_dir = self.workspace_path / "evidence"
        self.cases_dir = self.workspace_path / "cases"
        self.reports_dir = self.workspace_path / "reports"
        self.temp_dir = self.workspace_path / "temp"
        
        for directory in [self.evidence_dir, self.cases_dir, self.reports_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Initialize file type detection
        self._init_file_detection()
    
    def _setup_logging(self):
        """Setup forensic logging system"""
        log_file = self.workspace_path / "forensic_platform.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Forensic platform initialized")
    
    def _init_database(self):
        """Initialize SQLite database for case and evidence management"""
        db_path = self.workspace_path / "forensic_platform.db"
        self.db_connection = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create tables
        self._create_tables()
        
    def _create_tables(self):
        """Create database tables for forensic data"""
        cursor = self.db_connection.cursor()
        
        # Cases table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                case_name TEXT NOT NULL,
                investigator TEXT NOT NULL,
                created_date TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'active',
                notes TEXT,
                tags TEXT
            )
        """)
        
        # Evidence table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT,
                file_path TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                file_size INTEGER,
                acquired_date TEXT NOT NULL,
                acquired_by TEXT NOT NULL,
                description TEXT,
                metadata TEXT,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        
        # Chain of custody table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT,
                timestamp TEXT NOT NULL,
                investigator TEXT NOT NULL,
                action TEXT NOT NULL,
                location TEXT NOT NULL,
                notes TEXT,
                hash_before TEXT,
                hash_after TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
            )
        """)
        
        # Timeline events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                metadata TEXT,
                confidence REAL DEFAULT 1.0,
                FOREIGN KEY (case_id) REFERENCES cases (case_id)
            )
        """)
        
        # Analysis results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                analysis_id TEXT PRIMARY KEY,
                evidence_id TEXT,
                analysis_type TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                results TEXT,
                artifacts_found TEXT,
                errors TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
            )
        """)
        
        self.db_connection.commit()
    
    def _init_file_detection(self):
        """Initialize file type detection system"""
        if MAGIC_AVAILABLE:
            self.magic = magic.Magic()
        else:
            self.magic = None
            self.logger.warning("File type detection limited - python-magic not available")
    
    # ===== CASE MANAGEMENT =====
    
    def create_case(self, case_name: str, investigator: str, description: str) -> Case:
        """
        Create a new forensic investigation case
        
        Args:
            case_name: Name of the investigation case
            investigator: Lead investigator name
            description: Case description
            
        Returns:
            Case object
            
        TODO: Implement the following:
        - Generate unique case ID
        - Create case directory structure
        - Initialize case database entries
        - Setup case-specific logging
        - Create initial case report template
        """
        import uuid
        case_id = str(uuid.uuid4())[:8]
        
        case = Case(
            case_id=case_id,
            case_name=case_name,
            investigator=investigator,
            created_date=datetime.now(timezone.utc),
            description=description
        )
        
        # Create case directory
        case_dir = self.cases_dir / case_id
        case_dir.mkdir(exist_ok=True)
        
        # Save to database
        self._save_case_to_db(case)
        
        self.logger.info(f"Created case {case_id}: {case_name}")
        return case
    
    def _save_case_to_db(self, case: Case):
        """Save case to database"""
        cursor = self.db_connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cases 
            (case_id, case_name, investigator, created_date, description, status, notes, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case.case_id,
            case.case_name,
            case.investigator,
            case.created_date.isoformat(),
            case.description,
            case.status,
            case.notes,
            json.dumps(case.tags)
        ))
        self.db_connection.commit()
    
    # ===== EVIDENCE ACQUISITION =====
    
    def acquire_evidence(self, source_path: str, evidence_type: EvidenceType, 
                        case_id: str, investigator: str, description: str) -> Evidence:
        """
        Acquire and process digital evidence
        
        Args:
            source_path: Path to source evidence file
            evidence_type: Type of evidence being acquired
            case_id: Associated case ID
            investigator: Investigator acquiring evidence
            description: Evidence description
            
        Returns:
            Evidence object
            
        TODO: Implement the following:
        - Create forensic copy/image
        - Calculate and verify hashes
        - Extract basic metadata
        - Initialize chain of custody
        - Store evidence in secure location
        - Update case with new evidence
        """
        import uuid
        evidence_id = str(uuid.uuid4())[:8]
        
        # Copy evidence to secure location
        evidence_path = self.evidence_dir / f"{evidence_id}_{os.path.basename(source_path)}"
        
        # TODO: Implement forensic copying with verification
        # For now, simple copy (students should implement proper forensic copy)
        import shutil
        shutil.copy2(source_path, evidence_path)
        
        # Calculate hash
        original_hash = self._calculate_file_hash(evidence_path)
        
        # Get file size
        file_size = os.path.getsize(evidence_path)
        
        evidence = Evidence(
            evidence_id=evidence_id,
            case_id=case_id,
            file_path=str(evidence_path),
            evidence_type=evidence_type,
            original_hash=original_hash,
            current_hash=original_hash,
            file_size=file_size,
            acquired_date=datetime.now(timezone.utc),
            acquired_by=investigator,
            description=description
        )
        
        # Initialize chain of custody
        evidence.add_custody_entry(
            investigator=investigator,
            action="Initial acquisition",
            location=str(evidence_path),
            notes=f"Acquired from {source_path}"
        )
        
        # Save to database
        self._save_evidence_to_db(evidence)
        
        self.logger.info(f"Acquired evidence {evidence_id}: {description}")
        return evidence
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _save_evidence_to_db(self, evidence: Evidence):
        """Save evidence to database"""
        cursor = self.db_connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO evidence 
            (evidence_id, case_id, file_path, evidence_type, original_hash, 
             current_hash, file_size, acquired_date, acquired_by, description, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            evidence.evidence_id,
            evidence.case_id,
            evidence.file_path,
            evidence.evidence_type.value,
            evidence.original_hash,
            evidence.current_hash,
            evidence.file_size,
            evidence.acquired_date.isoformat(),
            evidence.acquired_by,
            evidence.description,
            json.dumps(evidence.metadata)
        ))
        
        # Save chain of custody
        for entry in evidence.chain_of_custody:
            cursor.execute("""
                INSERT INTO chain_of_custody 
                (evidence_id, timestamp, investigator, action, location, notes, 
                 hash_before, hash_after)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.evidence_id,
                entry.timestamp.isoformat(),
                entry.investigator,
                entry.action,
                entry.location,
                entry.notes,
                entry.hash_before,
                entry.hash_after
            ))
        
        self.db_connection.commit()
    
    # ===== FILE SYSTEM ANALYSIS =====
    
    def analyze_file_system(self, evidence: Evidence) -> AnalysisResult:
        """
        Analyze file system structure and extract artifacts
        
        Args:
            evidence: Evidence object to analyze
            
        Returns:
            AnalysisResult with file system analysis
            
        TODO: Implement the following:
        - Detect file system type
        - Extract file system metadata
        - Identify deleted files
        - Extract file system timeline
        - Analyze file system structures
        - Generate comprehensive artifact list
        """
        import uuid
        analysis_id = str(uuid.uuid4())[:8]
        
        result = AnalysisResult(
            analysis_id=analysis_id,
            evidence_id=evidence.evidence_id,
            analysis_type="file_system_analysis",
            status=AnalysisStatus.IN_PROGRESS,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            if not TSK_AVAILABLE:
                raise Exception("pytsk3 not available for file system analysis")
            
            # TODO: Implement TSK-based file system analysis
            # This is a placeholder - students should implement full analysis
            
            # Open the image
            img = pytsk3.Img_Info(evidence.file_path)
            
            # Get file system info
            fs = pytsk3.FS_Info(img)
            
            result.results['file_system_type'] = str(fs.info.ftype)
            result.results['block_size'] = fs.info.block_size
            result.results['block_count'] = fs.info.block_count
            
            # TODO: Implement recursive file enumeration
            # TODO: Extract deleted files
            # TODO: Create file system timeline
            # TODO: Extract metadata
            
            result.status = AnalysisStatus.COMPLETED
            result.end_time = datetime.now(timezone.utc)
            
        except Exception as e:
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            result.end_time = datetime.now(timezone.utc)
            self.logger.error(f"File system analysis failed: {e}")
        
        # Save analysis results
        self._save_analysis_result(result)
        
        return result
    
    def extract_timeline(self, evidence: Evidence, start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None) -> List[TimelineEvent]:
        """
        Extract timeline events from evidence
        
        Args:
            evidence: Evidence to analyze
            start_date: Optional start date filter
            end_date: Optional end date filter
            
        Returns:
            List of timeline events
            
        TODO: Implement the following:
        - File system timeline (MAC times)
        - Registry timeline (Windows)
        - Log file timeline
        - Browser history timeline
        - Email timeline
        - Application-specific timelines
        """
        timeline_events = []
        
        # TODO: Implement timeline extraction
        # This is a placeholder - students should implement comprehensive timeline
        
        # Example: Basic file system MAC times
        if TSK_AVAILABLE:
            try:
                img = pytsk3.Img_Info(evidence.file_path)
                fs = pytsk3.FS_Info(img)
                
                # TODO: Walk file system and extract timestamps
                # TODO: Correlate events from multiple sources
                # TODO: Apply date filters
                
                # Placeholder event
                event = TimelineEvent(
                    timestamp=datetime.now(timezone.utc),
                    source="file_system",
                    event_type="file_created",
                    description="Example timeline event",
                    confidence=0.8
                )
                timeline_events.append(event)
                
            except Exception as e:
                self.logger.error(f"Timeline extraction failed: {e}")
        
        return timeline_events
    
    # ===== ARTIFACT ANALYSIS =====
    
    def analyze_web_artifacts(self, evidence: Evidence) -> Dict[str, Any]:
        """
        Analyze web browser artifacts
        
        Args:
            evidence: Evidence to analyze
            
        Returns:
            Dictionary containing web artifacts
            
        TODO: Implement the following:
        - Browser history extraction
        - Cache analysis
        - Cookie parsing
        - Download history
        - Bookmark analysis
        - Session storage analysis
        """
        artifacts = {
            'browser_history': [],
            'downloads': [],
            'cookies': [],
            'cache_files': [],
            'bookmarks': []
        }
        
        # TODO: Implement browser artifact extraction
        # Look for common browser database files
        # Parse SQLite databases for Chrome, Firefox, Edge, Safari
        # Extract and correlate web artifacts
        
        self.logger.info("Web artifact analysis completed")
        return artifacts
    
    def analyze_email_artifacts(self, evidence: Evidence) -> Dict[str, Any]:
        """
        Analyze email artifacts
        
        Args:
            evidence: Evidence to analyze
            
        Returns:
            Dictionary containing email artifacts
            
        TODO: Implement the following:
        - PST/OST file parsing
        - MBOX file analysis
        - EML file extraction
        - Email header analysis
        - Attachment extraction
        - Email timeline creation
        """
        artifacts = {
            'emails': [],
            'attachments': [],
            'contacts': [],
            'calendars': []
        }
        
        # TODO: Implement email artifact extraction
        # Parse various email formats
        # Extract metadata and attachments
        # Build email communication timeline
        
        self.logger.info("Email artifact analysis completed")
        return artifacts
    
    # ===== REPORTING =====
    
    def generate_case_report(self, case_id: str, template: str = "standard") -> str:
        """
        Generate comprehensive forensic report for a case
        
        Args:
            case_id: Case ID to generate report for
            template: Report template to use
            
        Returns:
            Path to generated report file
            
        TODO: Implement the following:
        - Load case and evidence data
        - Generate executive summary
        - Include chain of custody documentation
        - Add technical analysis details
        - Include timeline visualizations
        - Export to PDF format
        """
        report_path = self.reports_dir / f"case_{case_id}_report.html"
        
        # TODO: Implement comprehensive report generation
        # Load case data from database
        # Create professional forensic report
        # Include all required sections for legal admissibility
        
        # Placeholder report
        with open(report_path, 'w') as f:
            f.write(f"""
            <html>
            <head><title>Forensic Report - Case {case_id}</title></head>
            <body>
                <h1>Digital Forensics Investigation Report</h1>
                <h2>Case ID: {case_id}</h2>
                <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
                
                <h2>Executive Summary</h2>
                <p>TODO: Implement comprehensive report generation</p>
                
                <h2>Chain of Custody</h2>
                <p>TODO: Include chain of custody documentation</p>
                
                <h2>Technical Analysis</h2>
                <p>TODO: Include detailed technical findings</p>
                
                <h2>Timeline Analysis</h2>
                <p>TODO: Include timeline visualizations</p>
                
                <h2>Conclusions</h2>
                <p>TODO: Include investigative conclusions</p>
            </body>
            </html>
            """)
        
        self.logger.info(f"Generated case report: {report_path}")
        return str(report_path)
    
    def _save_analysis_result(self, result: AnalysisResult):
        """Save analysis result to database"""
        cursor = self.db_connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO analysis_results 
            (analysis_id, evidence_id, analysis_type, status, start_time, 
             end_time, results, artifacts_found, errors)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.analysis_id,
            result.evidence_id,
            result.analysis_type,
            result.status.value,
            result.start_time.isoformat(),
            result.end_time.isoformat() if result.end_time else None,
            json.dumps(result.results),
            json.dumps(result.artifacts_found),
            json.dumps(result.errors)
        ))
        self.db_connection.commit()
    
    # ===== UTILITY METHODS =====
    
    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """Verify the integrity of evidence by hash comparison"""
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT file_path, original_hash FROM evidence WHERE evidence_id = ?", (evidence_id,))
        row = cursor.fetchone()
        
        if not row:
            return False
        
        file_path, original_hash = row
        current_hash = self._calculate_file_hash(Path(file_path))
        
        return current_hash == original_hash
    
    def list_cases(self) -> List[Dict[str, Any]]:
        """List all cases in the database"""
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT * FROM cases")
        columns = [desc[0] for desc in cursor.description]
        cases = []
        
        for row in cursor.fetchall():
            case_dict = dict(zip(columns, row))
            case_dict['tags'] = json.loads(case_dict.get('tags', '[]'))
            cases.append(case_dict)
        
        return cases
    
    def close(self):
        """Close database connections and cleanup resources"""
        if hasattr(self, 'db_connection'):
            self.db_connection.close()
        self.logger.info("Forensic platform shut down")


# ===== EXAMPLE USAGE =====

def main():
    """
    Example usage of the forensic platform
    This demonstrates basic workflows for forensic investigation
    """
    print("Digital Forensics Investigation Platform")
    print("=" * 50)
    
    # Initialize platform
    platform = ForensicPlatform("/tmp/forensic_workspace")
    
    try:
        # Create a new case
        case = platform.create_case(
            case_name="Sample Investigation",
            investigator="Detective Smith",
            description="Sample forensic investigation for demonstration"
        )
        
        print(f"Created case: {case.case_id} - {case.case_name}")
        
        # TODO: In real usage, acquire evidence from actual sources
        # For demonstration, create a sample file
        sample_file = Path("/tmp/sample_evidence.txt")
        sample_file.write_text("This is sample evidence content for forensic analysis.")
        
        # Acquire evidence
        evidence = platform.acquire_evidence(
            source_path=str(sample_file),
            evidence_type=EvidenceType.LOG_FILES,
            case_id=case.case_id,
            investigator="Detective Smith",
            description="Sample text file evidence"
        )
        
        print(f"Acquired evidence: {evidence.evidence_id}")
        print(f"Evidence hash: {evidence.original_hash}")
        
        # Verify evidence integrity
        integrity_ok = platform.verify_evidence_integrity(evidence.evidence_id)
        print(f"Evidence integrity verified: {integrity_ok}")
        
        # Analyze file system (will fail without proper disk image)
        # result = platform.analyze_file_system(evidence)
        # print(f"Analysis result: {result.status}")
        
        # Extract timeline
        timeline = platform.extract_timeline(evidence)
        print(f"Timeline events found: {len(timeline)}")
        
        # Generate report
        report_path = platform.generate_case_report(case.case_id)
        print(f"Generated report: {report_path}")
        
        # List all cases
        cases = platform.list_cases()
        print(f"Total cases in database: {len(cases)}")
        
        # Cleanup sample file
        sample_file.unlink()
        
    finally:
        platform.close()


if __name__ == "__main__":
    main()