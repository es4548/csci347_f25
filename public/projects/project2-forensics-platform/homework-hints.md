# Project 2 Homework Hints: Digital Forensics Investigation Platform

## Time Breakdown (2 weeks, ~35-45 hours total)

### Week 1 (22 hours)
- **Day 1-2 (8 hours)**: Project setup, evidence acquisition module, hash verification
- **Day 3-4 (8 hours)**: File system analysis core, TSK integration
- **Day 5-7 (6 hours)**: Chain of custody implementation, basic case management

### Week 2 (18-23 hours)
- **Day 8-10 (10 hours)**: Timeline analysis, artifact extraction, automation
- **Day 11-12 (6 hours)**: Reporting system, web interface
- **Day 13-14 (7 hours)**: Testing with evidence files, documentation, demo prep

## Step-by-Step Implementation Guide

### Phase 1: Project Setup and Evidence Acquisition (8 hours)

#### 1.1 Environment Setup (2 hours)
```bash
# Create forensic platform structure
mkdir -p project2-forensics-platform/{src/{acquisition,analysis,case_management,reporting,timeline,api,web,utils},tests,tools,templates,sample_data}
cd project2-forensics-platform

# Set up virtual environment
python -m venv venv
source venv/bin/activate

# Install forensic dependencies
pip install fastapi uvicorn[standard] sqlalchemy psycopg2-binary
pip install pytsk3 python-magic yara-python hashlib
pip install plotly jinja2 reportlab pillow
pip install pytest pytest-cov black pylint mypy

# Install Sleuth Kit (system dependency)
# Ubuntu/Debian: sudo apt-get install sleuthkit
# macOS: brew install sleuthkit
# Windows: Download from sleuthkit.org

# Create requirements.txt
pip freeze > requirements.txt
```

#### 1.2 Database Schema for Forensic Cases (3 hours)
```python
# src/models/forensic_database.py
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text, LargeBinary, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid

DATABASE_URL = "postgresql://user:password@localhost/forensics_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number = Column(String(50), unique=True, nullable=False)
    case_name = Column(String(200), nullable=False)
    description = Column(Text)
    investigator_id = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="open")  # open, closed, archived
    priority = Column(String(10), default="medium")  # low, medium, high, critical
    case_type = Column(String(50))  # criminal, civil, internal, incident_response

    # Legal and compliance fields
    court_case_number = Column(String(100))
    legal_hold = Column(Boolean, default=False)
    retention_date = Column(DateTime)

class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), nullable=False)
    evidence_number = Column(String(50), nullable=False)
    evidence_type = Column(String(50), nullable=False)  # disk, mobile, network, memory
    description = Column(Text)

    # File and storage information
    original_filename = Column(String(500))
    file_path = Column(String(1000))
    file_size = Column(Integer)

    # Hash values for integrity
    md5_hash = Column(String(32))
    sha1_hash = Column(String(40))
    sha256_hash = Column(String(64))

    # Acquisition metadata
    acquired_by = Column(String(100), nullable=False)
    acquired_date = Column(DateTime, default=datetime.utcnow)
    acquisition_method = Column(String(100))
    imaging_tool = Column(String(100))
    write_blocker_used = Column(Boolean, default=False)

    # Chain of custody
    custody_log = Column(JSONB)  # JSON array of custody events

    # Analysis status
    processing_status = Column(String(20), default="pending")  # pending, processing, completed, error
    analysis_started = Column(DateTime)
    analysis_completed = Column(DateTime)

class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(UUID(as_uuid=True), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(100), nullable=False)  # acquired, transferred, analyzed, stored
    investigator = Column(String(100), nullable=False)
    location = Column(String(200))
    notes = Column(Text)
    digital_signature = Column(String(500))  # Cryptographic signature
    hash_verification = Column(Boolean, default=False)

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(UUID(as_uuid=True), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(50), nullable=False)  # file_access, file_modify, file_create, file_delete
    source_type = Column(String(50))  # filesystem, registry, log, network
    file_path = Column(String(1000))
    description = Column(Text)
    inode = Column(Integer)
    size = Column(Integer)
    metadata = Column(JSONB)  # Additional event metadata

class AnalysisArtifact(Base):
    __tablename__ = "analysis_artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = Column(UUID(as_uuid=True), nullable=False)
    artifact_type = Column(String(50), nullable=False)  # browser_history, email, registry_key, etc.
    artifact_name = Column(String(200))
    file_path = Column(String(1000))
    extraction_method = Column(String(100))
    extracted_data = Column(JSONB)
    relevance_score = Column(Float, default=0.0)
    tags = Column(String(500))  # Comma-separated tags
    notes = Column(Text)
    extracted_at = Column(DateTime, default=datetime.utcnow)
```

#### 1.3 Evidence Acquisition Engine (3 hours)
```python
# src/acquisition/evidence_acquirer.py
import hashlib
import os
import shutil
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import magic
import json

class EvidenceAcquirer:
    def __init__(self, case_id: str, investigator: str):
        self.case_id = case_id
        self.investigator = investigator
        self.supported_formats = ['dd', 'raw', 'e01', 'aff']

    def create_forensic_image(self, source_device: str, output_path: str,
                            image_format: str = 'dd') -> Tuple[bool, Dict[str, Any]]:
        """Create forensic image of source device"""

        if image_format not in self.supported_formats:
            return False, {"error": f"Unsupported format: {image_format}"}

        # Generate output filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{output_path}/evidence_{timestamp}.{image_format}"

        try:
            if image_format == 'dd':
                return self._create_dd_image(source_device, output_file)
            elif image_format == 'e01':
                return self._create_e01_image(source_device, output_file)
            else:
                return False, {"error": f"Format {image_format} not implemented"}

        except Exception as e:
            return False, {"error": f"Imaging failed: {str(e)}"}

    def _create_dd_image(self, source: str, output: str) -> Tuple[bool, Dict[str, Any]]:
        """Create bit-for-bit dd image"""

        # Calculate block size for optimal performance
        block_size = 64 * 1024  # 64KB blocks

        start_time = datetime.now()

        try:
            # Use dd command for imaging (in production, use proper forensic tools)
            cmd = [
                'dd',
                f'if={source}',
                f'of={output}',
                f'bs={block_size}',
                'conv=noerror,sync',
                'status=progress'
            ]

            # Execute dd command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            end_time = datetime.now()

            # Calculate hashes for integrity verification
            hashes = self._calculate_file_hashes(output)

            # Get file size
            file_size = os.path.getsize(output)

            metadata = {
                "acquisition_method": "dd_imaging",
                "source_device": source,
                "output_file": output,
                "file_size": file_size,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                "block_size": block_size,
                "dd_output": result.stderr,  # dd writes progress to stderr
                **hashes
            }

            return True, metadata

        except subprocess.CalledProcessError as e:
            return False, {
                "error": f"dd command failed: {e}",
                "stdout": e.stdout,
                "stderr": e.stderr
            }

    def _create_e01_image(self, source: str, output: str) -> Tuple[bool, Dict[str, Any]]:
        """Create Expert Witness Format (E01) image using ewfacquire"""

        try:
            # In production, use ewfacquire from libewf
            # For demo, simulate E01 creation
            cmd = [
                'ewfacquire',
                '-t', output,
                '-C', self.case_id,
                '-D', f'Evidence acquired by {self.investigator}',
                '-E', self.investigator,
                '-N', f'Forensic evidence',
                '-c', 'best',  # Best compression
                '-f', 'encase6',  # EnCase 6 format
                '-S', '650MB',  # Segment size
                source
            ]

            start_time = datetime.now()
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            end_time = datetime.now()

            # Calculate hashes
            hashes = self._calculate_file_hashes(f"{output}.E01")

            metadata = {
                "acquisition_method": "ewf_e01",
                "source_device": source,
                "output_file": f"{output}.E01",
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                **hashes
            }

            return True, metadata

        except subprocess.CalledProcessError as e:
            # Fallback: create a mock E01 by copying and renaming
            return self._create_mock_e01(source, output)

    def _create_mock_e01(self, source: str, output: str) -> Tuple[bool, Dict[str, Any]]:
        """Create mock E01 for demonstration purposes"""

        start_time = datetime.now()

        # Copy file and rename to .E01 extension
        output_e01 = f"{output}.E01"
        shutil.copy2(source, output_e01)

        end_time = datetime.now()

        # Calculate hashes
        hashes = self._calculate_file_hashes(output_e01)

        metadata = {
            "acquisition_method": "mock_e01",
            "source_device": source,
            "output_file": output_e01,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "note": "Mock E01 format for demonstration",
            **hashes
        }

        return True, metadata

    def _calculate_file_hashes(self, filepath: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes"""

        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(65536), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

        return {
            "md5_hash": md5_hash.hexdigest(),
            "sha1_hash": sha1_hash.hexdigest(),
            "sha256_hash": sha256_hash.hexdigest()
        }

    def verify_image_integrity(self, image_path: str, expected_hashes: Dict[str, str]) -> bool:
        """Verify image integrity against expected hashes"""

        current_hashes = self._calculate_file_hashes(image_path)

        for hash_type in ['md5_hash', 'sha1_hash', 'sha256_hash']:
            if hash_type in expected_hashes:
                if current_hashes[hash_type] != expected_hashes[hash_type]:
                    return False

        return True

    def acquire_live_memory(self, output_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Acquire live memory dump (simulation)"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{output_path}/memory_dump_{timestamp}.mem"

        try:
            # In production, use tools like DumpIt, Belkasoft RAM Capturer, or volatility
            # For demo, create mock memory dump
            with open(output_file, 'wb') as f:
                # Create 1MB mock memory dump
                f.write(b'MEMORY_DUMP_SIMULATION' + b'\x00' * (1024*1024 - 22))

            hashes = self._calculate_file_hashes(output_file)

            metadata = {
                "acquisition_method": "live_memory_dump",
                "output_file": output_file,
                "file_size": os.path.getsize(output_file),
                "acquisition_time": datetime.now().isoformat(),
                "note": "Simulated memory dump for demonstration",
                **hashes
            }

            return True, metadata

        except Exception as e:
            return False, {"error": f"Memory acquisition failed: {str(e)}"}

    def acquire_network_capture(self, interface: str, duration_seconds: int,
                              output_path: str) -> Tuple[bool, Dict[str, Any]]:
        """Acquire network traffic capture"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{output_path}/network_capture_{timestamp}.pcap"

        try:
            # Use tcpdump for network capture
            cmd = [
                'tcpdump',
                '-i', interface,
                '-s', '0',  # Capture full packets
                '-w', output_file,
                '-G', str(duration_seconds),  # Rotate every N seconds
                '-W', '1'  # Only keep 1 file
            ]

            start_time = datetime.now()
            result = subprocess.run(cmd, timeout=duration_seconds + 5,
                                  capture_output=True, text=True)
            end_time = datetime.now()

            if os.path.exists(output_file):
                hashes = self._calculate_file_hashes(output_file)

                metadata = {
                    "acquisition_method": "network_capture",
                    "interface": interface,
                    "output_file": output_file,
                    "file_size": os.path.getsize(output_file),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "duration_seconds": duration_seconds,
                    **hashes
                }

                return True, metadata
            else:
                return False, {"error": "Network capture file not created"}

        except subprocess.TimeoutExpired:
            # Expected timeout after capture duration
            if os.path.exists(output_file):
                hashes = self._calculate_file_hashes(output_file)
                metadata = {
                    "acquisition_method": "network_capture",
                    "interface": interface,
                    "output_file": output_file,
                    "file_size": os.path.getsize(output_file),
                    "duration_seconds": duration_seconds,
                    **hashes
                }
                return True, metadata
            else:
                return False, {"error": "Network capture timed out without creating file"}

        except Exception as e:
            return False, {"error": f"Network capture failed: {str(e)}"}
```

### Phase 2: File System Analysis Core (8 hours)

#### 2.1 TSK Integration and File System Parser (5 hours)
```python
# src/analysis/filesystem_analyzer.py
import pytsk3
import pyewf
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Generator
import json

class FileSystemAnalyzer:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None
        self._initialize_image()

    def _initialize_image(self):
        """Initialize image and file system objects"""
        try:
            # Determine image type and open appropriately
            if self.image_path.lower().endswith('.e01'):
                # Handle E01 images with pyewf
                ewf_handle = pyewf.handle()
                ewf_handle.open([self.image_path])
                self.img_info = EWFImgInfo(ewf_handle)
            else:
                # Handle raw/dd images
                self.img_info = pytsk3.Img_Info(self.image_path)

            # Try to get partition table
            try:
                self.volume_info = pytsk3.Volume_Info(self.img_info)
                self.partitions = []

                for partition in self.volume_info:
                    if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        try:
                            fs_info = pytsk3.FS_Info(self.img_info, offset=partition.start * self.volume_info.info.block_size)
                            self.partitions.append({
                                'offset': partition.start * self.volume_info.info.block_size,
                                'size': partition.len * self.volume_info.info.block_size,
                                'description': partition.desc.decode('utf-8', errors='ignore'),
                                'fs_info': fs_info,
                                'fs_type': self._get_fs_type(fs_info)
                            })
                        except Exception as e:
                            print(f"Could not open file system for partition {partition.start}: {e}")

            except Exception as e:
                # No partition table, try to open as single file system
                try:
                    self.fs_info = pytsk3.FS_Info(self.img_info)
                    self.partitions = [{
                        'offset': 0,
                        'size': self.img_info.get_size(),
                        'description': 'Single file system',
                        'fs_info': self.fs_info,
                        'fs_type': self._get_fs_type(self.fs_info)
                    }]
                except Exception as e2:
                    raise Exception(f"Could not open image as file system: {e2}")

        except Exception as e:
            raise Exception(f"Failed to initialize image {self.image_path}: {e}")

    def _get_fs_type(self, fs_info) -> str:
        """Determine file system type"""
        fs_type_mapping = {
            pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
            pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
            pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
            pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
            pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
            pytsk3.TSK_FS_TYPE_EXT2: "ext2",
            pytsk3.TSK_FS_TYPE_EXT3: "ext3",
            pytsk3.TSK_FS_TYPE_EXT4: "ext4",
            pytsk3.TSK_FS_TYPE_HFS: "HFS",
            pytsk3.TSK_FS_TYPE_APFS: "APFS"
        }
        return fs_type_mapping.get(fs_info.info.ftype, f"Unknown ({fs_info.info.ftype})")

    def analyze_all_partitions(self) -> List[Dict[str, Any]]:
        """Analyze all partitions in the image"""
        results = []

        for i, partition in enumerate(self.partitions):
            print(f"Analyzing partition {i}: {partition['description']}")

            partition_analysis = {
                'partition_number': i,
                'offset': partition['offset'],
                'size': partition['size'],
                'description': partition['description'],
                'fs_type': partition['fs_type'],
                'file_count': 0,
                'directory_count': 0,
                'deleted_files': 0,
                'timeline_events': []
            }

            try:
                fs_info = partition['fs_info']

                # Walk the file system
                file_count, dir_count, deleted_count, timeline = self._walk_filesystem(fs_info)

                partition_analysis.update({
                    'file_count': file_count,
                    'directory_count': dir_count,
                    'deleted_files': deleted_count,
                    'timeline_events': timeline[:1000]  # Limit to first 1000 events
                })

            except Exception as e:
                partition_analysis['error'] = str(e)

            results.append(partition_analysis)

        return results

    def _walk_filesystem(self, fs_info, path: str = "/") -> tuple:
        """Walk file system and collect metadata"""
        file_count = 0
        dir_count = 0
        deleted_count = 0
        timeline_events = []

        try:
            directory = fs_info.open_dir(path=path)

            for entry in directory:
                # Skip . and .. entries
                if entry.info.name.name in [b'.', b'..']:
                    continue

                try:
                    filename = entry.info.name.name.decode('utf-8', errors='ignore')
                    full_path = f"{path}/{filename}" if path != "/" else f"/{filename}"

                    # Get file metadata
                    if entry.info.meta:
                        file_info = {
                            'inode': entry.info.meta.addr,
                            'filename': filename,
                            'full_path': full_path,
                            'size': entry.info.meta.size,
                            'allocated': entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC,
                            'type': 'directory' if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR else 'file'
                        }

                        # Extract timestamps
                        timestamps = {}
                        if hasattr(entry.info.meta, 'atime'):
                            timestamps['accessed'] = datetime.fromtimestamp(entry.info.meta.atime)
                        if hasattr(entry.info.meta, 'mtime'):
                            timestamps['modified'] = datetime.fromtimestamp(entry.info.meta.mtime)
                        if hasattr(entry.info.meta, 'ctime'):
                            timestamps['changed'] = datetime.fromtimestamp(entry.info.meta.ctime)
                        if hasattr(entry.info.meta, 'crtime'):
                            timestamps['created'] = datetime.fromtimestamp(entry.info.meta.crtime)

                        file_info['timestamps'] = timestamps

                        # Create timeline events
                        for event_type, timestamp in timestamps.items():
                            timeline_events.append({
                                'timestamp': timestamp.isoformat(),
                                'event_type': f"file_{event_type}",
                                'file_path': full_path,
                                'inode': entry.info.meta.addr,
                                'size': entry.info.meta.size,
                                'allocated': file_info['allocated']
                            })

                        # Count files and directories
                        if file_info['type'] == 'directory':
                            dir_count += 1
                            # Recursively analyze subdirectories (with depth limit)
                            if full_path.count('/') < 10:  # Limit recursion depth
                                sub_files, sub_dirs, sub_deleted, sub_timeline = self._walk_filesystem(
                                    fs_info, full_path
                                )
                                file_count += sub_files
                                dir_count += sub_dirs
                                deleted_count += sub_deleted
                                timeline_events.extend(sub_timeline)
                        else:
                            file_count += 1

                        # Check if file is deleted
                        if not file_info['allocated']:
                            deleted_count += 1

                except Exception as e:
                    # Skip files that can't be processed
                    continue

        except Exception as e:
            print(f"Error walking filesystem at {path}: {e}")

        return file_count, dir_count, deleted_count, timeline_events

    def extract_deleted_files(self, output_dir: str) -> List[Dict[str, Any]]:
        """Extract deleted files from all partitions"""
        recovered_files = []

        for i, partition in enumerate(self.partitions):
            fs_info = partition['fs_info']
            partition_output = os.path.join(output_dir, f"partition_{i}_deleted")
            os.makedirs(partition_output, exist_ok=True)

            try:
                recovered = self._recover_deleted_files(fs_info, partition_output)
                recovered_files.extend(recovered)
            except Exception as e:
                print(f"Error recovering deleted files from partition {i}: {e}")

        return recovered_files

    def _recover_deleted_files(self, fs_info, output_dir: str) -> List[Dict[str, Any]]:
        """Recover deleted files from a file system"""
        recovered = []

        try:
            # Walk unallocated inodes
            for inode_num in range(fs_info.info.first_inum, fs_info.info.last_inum):
                try:
                    file_obj = fs_info.open_meta(inode=inode_num)

                    # Check if file is deleted (unallocated)
                    if file_obj.info.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                        # Try to get file name
                        filename = f"deleted_inode_{inode_num}"

                        # Try to read file content
                        if file_obj.info.size > 0 and file_obj.info.size < 10*1024*1024:  # Limit to 10MB
                            try:
                                output_path = os.path.join(output_dir, filename)

                                with open(output_path, 'wb') as output_file:
                                    data = file_obj.read_random(0, file_obj.info.size)
                                    output_file.write(data)

                                recovered_info = {
                                    'inode': inode_num,
                                    'original_size': file_obj.info.size,
                                    'recovered_path': output_path,
                                    'recovery_time': datetime.now().isoformat(),
                                    'md5_hash': self._calculate_md5(output_path)
                                }

                                recovered.append(recovered_info)

                            except Exception as e:
                                # File content not recoverable
                                continue

                except Exception as e:
                    # Inode not accessible
                    continue

        except Exception as e:
            print(f"Error during deleted file recovery: {e}")

        return recovered

    def _calculate_md5(self, filepath: str) -> str:
        """Calculate MD5 hash of a file"""
        import hashlib

        md5_hash = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def create_super_timeline(self) -> List[Dict[str, Any]]:
        """Create super timeline from all file system events"""
        all_events = []

        for partition in self.partitions:
            try:
                fs_info = partition['fs_info']
                _, _, _, timeline_events = self._walk_filesystem(fs_info)

                # Add partition context to events
                for event in timeline_events:
                    event['partition'] = partition['description']
                    event['fs_type'] = partition['fs_type']
                    all_events.append(event)

            except Exception as e:
                print(f"Error creating timeline for partition: {e}")

        # Sort events by timestamp
        all_events.sort(key=lambda x: x['timestamp'])

        return all_events

    def search_files(self, pattern: str, search_content: bool = False) -> List[Dict[str, Any]]:
        """Search for files by name pattern or content"""
        results = []

        for partition in self.partitions:
            try:
                fs_info = partition['fs_info']
                partition_results = self._search_in_partition(fs_info, pattern, search_content)
                results.extend(partition_results)
            except Exception as e:
                print(f"Error searching in partition: {e}")

        return results

    def _search_in_partition(self, fs_info, pattern: str, search_content: bool) -> List[Dict[str, Any]]:
        """Search for files in a specific partition"""
        import re
        results = []
        pattern_regex = re.compile(pattern, re.IGNORECASE)

        # Implementation would recursively search file names and optionally content
        # This is a simplified version
        return results

# Helper class for E01 images
class EWFImgInfo:
    """Wrapper for pyewf handle to work with pytsk3"""

    def __init__(self, ewf_handle):
        self.ewf_handle = ewf_handle

    def read(self, offset, size):
        self.ewf_handle.seek(offset)
        return self.ewf_handle.read(size)

    def get_size(self):
        return self.ewf_handle.get_media_size()
```

#### 2.2 Artifact Extraction Engine (3 hours)
```python
# src/analysis/artifact_extractor.py
import os
import re
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

class ForensicArtifactExtractor:
    def __init__(self, filesystem_analyzer):
        self.fs_analyzer = filesystem_analyzer
        self.artifacts = []

    def extract_all_artifacts(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all supported artifacts"""

        artifact_results = {
            'browser_history': self.extract_browser_artifacts(),
            'email_artifacts': self.extract_email_artifacts(),
            'registry_artifacts': self.extract_registry_artifacts(),
            'log_files': self.extract_log_artifacts(),
            'document_metadata': self.extract_document_metadata(),
            'user_accounts': self.extract_user_account_info(),
            'installed_programs': self.extract_installed_programs(),
            'network_artifacts': self.extract_network_artifacts()
        }

        return artifact_results

    def extract_browser_artifacts(self) -> List[Dict[str, Any]]:
        """Extract browser history, cookies, downloads"""
        artifacts = []

        # Common browser paths
        browser_paths = [
            # Chrome/Chromium
            r"/Users/*/Library/Application Support/Google/Chrome/Default/History",
            r"/home/*/.config/google-chrome/Default/History",
            r"/Documents and Settings/*/Local Settings/Application Data/Google/Chrome/User Data/Default/History",

            # Firefox
            r"/Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite",
            r"/home/*/.mozilla/firefox/*/places.sqlite",
            r"/Documents and Settings/*/Application Data/Mozilla/Firefox/Profiles/*/places.sqlite",

            # Safari
            r"/Users/*/Library/Safari/History.db",

            # Edge
            r"/Users/*/Library/Application Support/Microsoft Edge/Default/History",
        ]

        for partition in self.fs_analyzer.partitions:
            try:
                fs_info = partition['fs_info']
                artifacts.extend(self._extract_chrome_history(fs_info))
                artifacts.extend(self._extract_firefox_history(fs_info))
                artifacts.extend(self._extract_safari_history(fs_info))
            except Exception as e:
                print(f"Error extracting browser artifacts: {e}")

        return artifacts

    def _extract_chrome_history(self, fs_info) -> List[Dict[str, Any]]:
        """Extract Chrome browser history"""
        artifacts = []

        # Search for Chrome History database
        history_files = self._find_files_by_pattern(fs_info, r".*/History$")

        for history_file in history_files:
            try:
                # Extract History database and analyze
                temp_path = self._extract_file_to_temp(fs_info, history_file['inode'])

                if temp_path:
                    browser_data = self._parse_chrome_history_db(temp_path)

                    artifacts.append({
                        'artifact_type': 'chrome_history',
                        'source_file': history_file['path'],
                        'extraction_time': datetime.now().isoformat(),
                        'entries_count': len(browser_data),
                        'data': browser_data[:100]  # Limit to first 100 entries
                    })

                    # Clean up temp file
                    os.remove(temp_path)

            except Exception as e:
                print(f"Error parsing Chrome history: {e}")

        return artifacts

    def _parse_chrome_history_db(self, db_path: str) -> List[Dict[str, Any]]:
        """Parse Chrome History SQLite database"""
        history_entries = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Query URLs table
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time, typed_count
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """)

            for row in cursor.fetchall():
                # Chrome stores time as microseconds since 1601-01-01
                visit_time = self._chrome_time_to_datetime(row[3]) if row[3] else None

                history_entries.append({
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2],
                    'last_visit_time': visit_time.isoformat() if visit_time else None,
                    'typed_count': row[4]
                })

            conn.close()

        except Exception as e:
            print(f"Error parsing Chrome history database: {e}")

        return history_entries

    def _chrome_time_to_datetime(self, chrome_time: int) -> datetime:
        """Convert Chrome timestamp to datetime"""
        # Chrome time is microseconds since 1601-01-01
        epoch_start = datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=chrome_time)
        return epoch_start + delta

    def extract_email_artifacts(self) -> List[Dict[str, Any]]:
        """Extract email artifacts (PST, MBOX, etc.)"""
        artifacts = []

        email_patterns = [
            r".*\.pst$",  # Outlook PST files
            r".*\.ost$",  # Outlook OST files
            r".*\.mbox$", # MBOX files
            r".*\.eml$",  # Individual email files
        ]

        for partition in self.fs_analyzer.partitions:
            try:
                fs_info = partition['fs_info']

                for pattern in email_patterns:
                    email_files = self._find_files_by_pattern(fs_info, pattern)

                    for email_file in email_files:
                        artifacts.append({
                            'artifact_type': 'email_file',
                            'file_type': email_file['path'].split('.')[-1].upper(),
                            'source_file': email_file['path'],
                            'file_size': email_file['size'],
                            'extraction_time': datetime.now().isoformat(),
                            'metadata': self._extract_email_metadata(fs_info, email_file)
                        })

            except Exception as e:
                print(f"Error extracting email artifacts: {e}")

        return artifacts

    def extract_registry_artifacts(self) -> List[Dict[str, Any]]:
        """Extract Windows Registry artifacts"""
        artifacts = []

        registry_files = [
            r"/Windows/System32/config/SYSTEM",
            r"/Windows/System32/config/SOFTWARE",
            r"/Windows/System32/config/SAM",
            r"/Windows/System32/config/SECURITY",
            r"/Documents and Settings/*/NTUSER.DAT",
            r"/Users/*/NTUSER.DAT"
        ]

        for partition in self.fs_analyzer.partitions:
            if partition['fs_type'] == 'NTFS':  # Windows systems
                try:
                    fs_info = partition['fs_info']

                    for reg_pattern in registry_files:
                        reg_files = self._find_files_by_pattern(fs_info, reg_pattern)

                        for reg_file in reg_files:
                            artifacts.append({
                                'artifact_type': 'registry_hive',
                                'hive_type': self._identify_registry_hive(reg_file['path']),
                                'source_file': reg_file['path'],
                                'file_size': reg_file['size'],
                                'extraction_time': datetime.now().isoformat(),
                                'key_analysis': self._analyze_registry_keys(fs_info, reg_file)
                            })

                except Exception as e:
                    print(f"Error extracting registry artifacts: {e}")

        return artifacts

    def _identify_registry_hive(self, path: str) -> str:
        """Identify the type of registry hive"""
        hive_map = {
            'SYSTEM': 'System Configuration',
            'SOFTWARE': 'Installed Software',
            'SAM': 'Security Account Manager',
            'SECURITY': 'Security Settings',
            'NTUSER.DAT': 'User Profile'
        }

        filename = os.path.basename(path).upper()
        return hive_map.get(filename, 'Unknown Registry Hive')

    def extract_document_metadata(self) -> List[Dict[str, Any]]:
        """Extract metadata from documents (Office, PDF, etc.)"""
        artifacts = []

        document_patterns = [
            r".*\.docx?$",
            r".*\.xlsx?$",
            r".*\.pptx?$",
            r".*\.pdf$",
            r".*\.rtf$"
        ]

        for partition in self.fs_analyzer.partitions:
            try:
                fs_info = partition['fs_info']

                for pattern in document_patterns:
                    doc_files = self._find_files_by_pattern(fs_info, pattern)

                    for doc_file in doc_files[:50]:  # Limit to first 50 documents
                        metadata = self._extract_document_meta(fs_info, doc_file)

                        if metadata:
                            artifacts.append({
                                'artifact_type': 'document_metadata',
                                'document_type': doc_file['path'].split('.')[-1].upper(),
                                'source_file': doc_file['path'],
                                'file_size': doc_file['size'],
                                'extraction_time': datetime.now().isoformat(),
                                'metadata': metadata
                            })

            except Exception as e:
                print(f"Error extracting document metadata: {e}")

        return artifacts

    def _extract_document_meta(self, fs_info, doc_file: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract metadata from a document file"""
        try:
            # Extract file to temporary location
            temp_path = self._extract_file_to_temp(fs_info, doc_file['inode'])

            if not temp_path:
                return None

            metadata = {}
            file_ext = doc_file['path'].split('.')[-1].lower()

            if file_ext in ['docx', 'xlsx', 'pptx']:
                # Office documents are ZIP files with XML metadata
                metadata = self._extract_office_metadata(temp_path)
            elif file_ext == 'pdf':
                metadata = self._extract_pdf_metadata(temp_path)

            # Clean up
            os.remove(temp_path)
            return metadata

        except Exception as e:
            print(f"Error extracting metadata from {doc_file['path']}: {e}")
            return None

    def _extract_office_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from Office documents"""
        import zipfile
        metadata = {}

        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Read core properties
                if 'docProps/core.xml' in zip_file.namelist():
                    core_xml = zip_file.read('docProps/core.xml')
                    root = ET.fromstring(core_xml)

                    # Extract common metadata
                    metadata.update({
                        'title': self._get_xml_text(root, './/dc:title'),
                        'creator': self._get_xml_text(root, './/dc:creator'),
                        'created': self._get_xml_text(root, './/dcterms:created'),
                        'modified': self._get_xml_text(root, './/dcterms:modified'),
                        'last_modified_by': self._get_xml_text(root, './/cp:lastModifiedBy'),
                        'revision': self._get_xml_text(root, './/cp:revision')
                    })

        except Exception as e:
            print(f"Error extracting Office metadata: {e}")

        return metadata

    def _get_xml_text(self, root, xpath: str) -> Optional[str]:
        """Get text from XML element using xpath"""
        try:
            element = root.find(xpath, {
                'dc': 'http://purl.org/dc/elements/1.1/',
                'dcterms': 'http://purl.org/dc/terms/',
                'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
            })
            return element.text if element is not None else None
        except:
            return None

    def _find_files_by_pattern(self, fs_info, pattern: str) -> List[Dict[str, Any]]:
        """Find files matching a regex pattern"""
        matching_files = []
        pattern_regex = re.compile(pattern, re.IGNORECASE)

        # This is a simplified implementation
        # In a full implementation, you would recursively walk the file system
        # and match file paths against the pattern

        return matching_files

    def _extract_file_to_temp(self, fs_info, inode: int) -> Optional[str]:
        """Extract a file to temporary location for analysis"""
        import tempfile

        try:
            file_obj = fs_info.open_meta(inode=inode)

            if file_obj.info.size > 100*1024*1024:  # Skip files > 100MB
                return None

            # Create temporary file
            temp_fd, temp_path = tempfile.mkstemp()

            with os.fdopen(temp_fd, 'wb') as temp_file:
                # Read file content in chunks
                offset = 0
                chunk_size = 64*1024

                while offset < file_obj.info.size:
                    remaining = file_obj.info.size - offset
                    read_size = min(chunk_size, remaining)

                    data = file_obj.read_random(offset, read_size)
                    temp_file.write(data)
                    offset += read_size

            return temp_path

        except Exception as e:
            print(f"Error extracting file inode {inode}: {e}")
            return None

    # Additional artifact extraction methods would be implemented here
    def extract_log_artifacts(self) -> List[Dict[str, Any]]:
        """Extract system and application logs"""
        return []

    def extract_user_account_info(self) -> List[Dict[str, Any]]:
        """Extract user account information"""
        return []

    def extract_installed_programs(self) -> List[Dict[str, Any]]:
        """Extract installed program information"""
        return []

    def extract_network_artifacts(self) -> List[Dict[str, Any]]:
        """Extract network-related artifacts"""
        return []

    def _analyze_registry_keys(self, fs_info, reg_file: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze important registry keys"""
        return {}

    def _extract_email_metadata(self, fs_info, email_file: Dict[str, Any]) -> Dict[str, Any]:
        """Extract email file metadata"""
        return {}
```

### Phase 3: Chain of Custody and Case Management (6 hours)

#### 3.1 Chain of Custody Implementation (3 hours)
```python
# src/case_management/chain_of_custody.py
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class ChainOfCustodyManager:
    def __init__(self, db_session):
        self.db = db_session
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Load or generate RSA keys for digital signatures"""
        try:
            # In production, load from secure key storage
            # For demo, generate temporary keys
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            print(f"Error loading/generating keys: {e}")

    def create_custody_entry(self, evidence_id: str, action: str,
                           investigator: str, location: str,
                           notes: str = "") -> str:
        """Create new chain of custody entry"""

        timestamp = datetime.utcnow()

        # Create custody record
        custody_data = {
            "evidence_id": evidence_id,
            "timestamp": timestamp.isoformat(),
            "action": action,
            "investigator": investigator,
            "location": location,
            "notes": notes,
            "hash_verification": False  # Will be updated if hash verification performed
        }

        # Create digital signature
        signature = self._create_digital_signature(custody_data)
        custody_data["digital_signature"] = signature

        # Store in database
        from src.models.forensic_database import ChainOfCustody

        custody_entry = ChainOfCustody(
            evidence_id=evidence_id,
            timestamp=timestamp,
            action=action,
            investigator=investigator,
            location=location,
            notes=notes,
            digital_signature=signature
        )

        self.db.add(custody_entry)
        self.db.commit()

        return str(custody_entry.id)

    def verify_evidence_integrity(self, evidence_id: str,
                                current_hash: str) -> bool:
        """Verify evidence integrity against chain of custody"""

        from src.models.forensic_database import EvidenceItem, ChainOfCustody

        # Get evidence record
        evidence = self.db.query(EvidenceItem).filter(
            EvidenceItem.id == evidence_id
        ).first()

        if not evidence:
            return False

        # Compare against original hash
        original_hashes = [
            evidence.md5_hash,
            evidence.sha1_hash,
            evidence.sha256_hash
        ]

        if current_hash in original_hashes:
            # Update custody record to indicate successful verification
            latest_entry = self.db.query(ChainOfCustody).filter(
                ChainOfCustody.evidence_id == evidence_id
            ).order_by(ChainOfCustody.timestamp.desc()).first()

            if latest_entry:
                latest_entry.hash_verification = True
                self.db.commit()

            return True

        return False

    def _create_digital_signature(self, data: Dict[str, Any]) -> str:
        """Create digital signature for custody data"""

        try:
            # Create canonical string representation
            data_string = json.dumps(data, sort_keys=True)

            # Sign the data
            signature = self.private_key.sign(
                data_string.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Return base64-encoded signature
            import base64
            return base64.b64encode(signature).decode('utf-8')

        except Exception as e:
            print(f"Error creating digital signature: {e}")
            return ""

    def verify_custody_signature(self, custody_id: str) -> bool:
        """Verify digital signature of custody entry"""

        from src.models.forensic_database import ChainOfCustody

        custody_entry = self.db.query(ChainOfCustody).filter(
            ChainOfCustody.id == custody_id
        ).first()

        if not custody_entry:
            return False

        try:
            # Reconstruct data for verification
            data = {
                "evidence_id": str(custody_entry.evidence_id),
                "timestamp": custody_entry.timestamp.isoformat(),
                "action": custody_entry.action,
                "investigator": custody_entry.investigator,
                "location": custody_entry.location or "",
                "notes": custody_entry.notes or "",
                "hash_verification": custody_entry.hash_verification
            }

            data_string = json.dumps(data, sort_keys=True)

            # Verify signature
            import base64
            signature = base64.b64decode(custody_entry.digital_signature)

            self.public_key.verify(
                signature,
                data_string.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def get_custody_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Get complete chain of custody for evidence"""

        from src.models.forensic_database import ChainOfCustody

        custody_entries = self.db.query(ChainOfCustody).filter(
            ChainOfCustody.evidence_id == evidence_id
        ).order_by(ChainOfCustody.timestamp.asc()).all()

        chain = []
        for entry in custody_entries:
            chain.append({
                "id": str(entry.id),
                "timestamp": entry.timestamp.isoformat(),
                "action": entry.action,
                "investigator": entry.investigator,
                "location": entry.location,
                "notes": entry.notes,
                "hash_verified": entry.hash_verification,
                "signature_valid": self.verify_custody_signature(str(entry.id))
            })

        return chain

    def transfer_evidence(self, evidence_id: str, from_investigator: str,
                         to_investigator: str, location: str,
                         notes: str = "") -> bool:
        """Transfer evidence between investigators"""

        try:
            # Create transfer-out entry
            self.create_custody_entry(
                evidence_id=evidence_id,
                action="transferred_out",
                investigator=from_investigator,
                location=location,
                notes=f"Transferred to {to_investigator}. {notes}"
            )

            # Create transfer-in entry
            self.create_custody_entry(
                evidence_id=evidence_id,
                action="transferred_in",
                investigator=to_investigator,
                location=location,
                notes=f"Received from {from_investigator}. {notes}"
            )

            return True

        except Exception as e:
            print(f"Error transferring evidence: {e}")
            return False

    def generate_custody_form(self, evidence_id: str) -> Dict[str, Any]:
        """Generate official chain of custody form"""

        from src.models.forensic_database import EvidenceItem

        # Get evidence details
        evidence = self.db.query(EvidenceItem).filter(
            EvidenceItem.id == evidence_id
        ).first()

        if not evidence:
            return {}

        # Get custody chain
        custody_chain = self.get_custody_chain(evidence_id)

        # Generate form data
        form_data = {
            "evidence_information": {
                "evidence_number": evidence.evidence_number,
                "case_id": str(evidence.case_id),
                "description": evidence.description,
                "evidence_type": evidence.evidence_type,
                "file_size": evidence.file_size,
                "acquisition_date": evidence.acquired_date.isoformat(),
                "acquired_by": evidence.acquired_by,
                "md5_hash": evidence.md5_hash,
                "sha1_hash": evidence.sha1_hash,
                "sha256_hash": evidence.sha256_hash
            },
            "custody_chain": custody_chain,
            "form_generated": datetime.utcnow().isoformat(),
            "total_custody_events": len(custody_chain),
            "all_signatures_valid": all(entry["signature_valid"] for entry in custody_chain)
        }

        return form_data
```

#### 3.2 Case Management System (3 hours)
```python
# src/case_management/case_manager.py
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
import uuid

class ForensicCaseManager:
    def __init__(self, db_session: Session):
        self.db = db_session

    def create_case(self, case_name: str, investigator_id: str,
                   description: str = "", case_type: str = "incident_response",
                   priority: str = "medium") -> str:
        """Create new forensic case"""

        from src.models.forensic_database import ForensicCase

        # Generate case number
        case_number = self._generate_case_number()

        new_case = ForensicCase(
            case_number=case_number,
            case_name=case_name,
            description=description,
            investigator_id=investigator_id,
            case_type=case_type,
            priority=priority
        )

        self.db.add(new_case)
        self.db.commit()

        return str(new_case.id)

    def _generate_case_number(self) -> str:
        """Generate unique case number"""
        timestamp = datetime.now().strftime("%Y%m%d")
        sequence = self._get_daily_case_sequence()
        return f"CASE-{timestamp}-{sequence:03d}"

    def _get_daily_case_sequence(self) -> int:
        """Get next sequence number for today"""
        from src.models.forensic_database import ForensicCase

        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        count = self.db.query(ForensicCase).filter(
            ForensicCase.created_at >= today_start,
            ForensicCase.created_at < today_end
        ).count()

        return count + 1

    def add_evidence_to_case(self, case_id: str, evidence_data: Dict[str, Any]) -> str:
        """Add evidence item to case"""

        from src.models.forensic_database import EvidenceItem

        evidence = EvidenceItem(
            case_id=case_id,
            evidence_number=self._generate_evidence_number(case_id),
            evidence_type=evidence_data.get('evidence_type', 'unknown'),
            description=evidence_data.get('description', ''),
            original_filename=evidence_data.get('original_filename'),
            file_path=evidence_data.get('file_path'),
            file_size=evidence_data.get('file_size', 0),
            md5_hash=evidence_data.get('md5_hash'),
            sha1_hash=evidence_data.get('sha1_hash'),
            sha256_hash=evidence_data.get('sha256_hash'),
            acquired_by=evidence_data.get('acquired_by'),
            acquisition_method=evidence_data.get('acquisition_method'),
            imaging_tool=evidence_data.get('imaging_tool'),
            write_blocker_used=evidence_data.get('write_blocker_used', False)
        )

        self.db.add(evidence)
        self.db.commit()

        return str(evidence.id)

    def _generate_evidence_number(self, case_id: str) -> str:
        """Generate evidence number for case"""
        from src.models.forensic_database import EvidenceItem

        count = self.db.query(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).count()

        return f"EVD-{count + 1:03d}"

    def get_case_summary(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive case summary"""

        from src.models.forensic_database import ForensicCase, EvidenceItem, TimelineEvent

        case = self.db.query(ForensicCase).filter(
            ForensicCase.id == case_id
        ).first()

        if not case:
            return None

        # Get evidence items
        evidence_items = self.db.query(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).all()

        # Get timeline events count
        timeline_count = self.db.query(TimelineEvent).join(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).count()

        # Calculate processing statistics
        processing_stats = self._calculate_processing_stats(evidence_items)

        summary = {
            "case_info": {
                "id": str(case.id),
                "case_number": case.case_number,
                "case_name": case.case_name,
                "description": case.description,
                "investigator": case.investigator_id,
                "created_at": case.created_at.isoformat(),
                "status": case.status,
                "priority": case.priority,
                "case_type": case.case_type
            },
            "evidence_summary": {
                "total_items": len(evidence_items),
                "total_size_bytes": sum(e.file_size or 0 for e in evidence_items),
                "evidence_types": list(set(e.evidence_type for e in evidence_items)),
                "processing_status": processing_stats
            },
            "analysis_summary": {
                "timeline_events": timeline_count,
                "analysis_progress": self._calculate_analysis_progress(evidence_items)
            }
        }

        return summary

    def _calculate_processing_stats(self, evidence_items: List) -> Dict[str, int]:
        """Calculate evidence processing statistics"""
        stats = {
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "error": 0
        }

        for item in evidence_items:
            status = item.processing_status or "pending"
            stats[status] = stats.get(status, 0) + 1

        return stats

    def _calculate_analysis_progress(self, evidence_items: List) -> float:
        """Calculate overall analysis progress percentage"""
        if not evidence_items:
            return 0.0

        completed = sum(1 for item in evidence_items if item.processing_status == "completed")
        return (completed / len(evidence_items)) * 100

    def update_case_status(self, case_id: str, status: str, notes: str = "") -> bool:
        """Update case status"""

        from src.models.forensic_database import ForensicCase

        case = self.db.query(ForensicCase).filter(
            ForensicCase.id == case_id
        ).first()

        if not case:
            return False

        case.status = status
        if notes:
            # In a full implementation, you would have a case notes/activity log table
            case.description += f"\n[{datetime.now().isoformat()}] Status changed to {status}: {notes}"

        self.db.commit()
        return True

    def get_case_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Get timeline of all events for a case"""

        from src.models.forensic_database import EvidenceItem, TimelineEvent

        # Get all timeline events for evidence in this case
        timeline_events = self.db.query(TimelineEvent).join(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).order_by(TimelineEvent.timestamp.asc()).all()

        timeline = []
        for event in timeline_events:
            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "source_type": event.source_type,
                "file_path": event.file_path,
                "description": event.description,
                "evidence_id": str(event.evidence_id),
                "inode": event.inode,
                "size": event.size
            })

        return timeline

    def generate_case_report(self, case_id: str) -> Dict[str, Any]:
        """Generate comprehensive case report"""

        case_summary = self.get_case_summary(case_id)
        if not case_summary:
            return {}

        # Get detailed evidence information
        evidence_details = self._get_evidence_details(case_id)

        # Get analysis results
        analysis_results = self._get_analysis_results(case_id)

        # Get timeline
        timeline = self.get_case_timeline(case_id)

        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_type": "comprehensive_case_report",
                "case_id": case_id
            },
            "case_summary": case_summary,
            "evidence_details": evidence_details,
            "analysis_results": analysis_results,
            "timeline_summary": {
                "total_events": len(timeline),
                "date_range": self._get_timeline_date_range(timeline),
                "event_types": self._get_event_type_summary(timeline)
            },
            "recommendations": self._generate_recommendations(case_summary, analysis_results)
        }

        return report

    def _get_evidence_details(self, case_id: str) -> List[Dict[str, Any]]:
        """Get detailed evidence information"""
        from src.models.forensic_database import EvidenceItem

        evidence_items = self.db.query(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).all()

        details = []
        for item in evidence_items:
            details.append({
                "evidence_number": item.evidence_number,
                "evidence_type": item.evidence_type,
                "description": item.description,
                "file_size": item.file_size,
                "acquisition_method": item.acquisition_method,
                "acquired_by": item.acquired_by,
                "acquired_date": item.acquired_date.isoformat() if item.acquired_date else None,
                "processing_status": item.processing_status,
                "integrity_hashes": {
                    "md5": item.md5_hash,
                    "sha1": item.sha1_hash,
                    "sha256": item.sha256_hash
                }
            })

        return details

    def _get_analysis_results(self, case_id: str) -> Dict[str, Any]:
        """Get analysis results summary"""
        from src.models.forensic_database import AnalysisArtifact, EvidenceItem

        artifacts = self.db.query(AnalysisArtifact).join(EvidenceItem).filter(
            EvidenceItem.case_id == case_id
        ).all()

        results = {
            "total_artifacts": len(artifacts),
            "artifact_types": {},
            "high_relevance_artifacts": []
        }

        # Categorize artifacts
        for artifact in artifacts:
            artifact_type = artifact.artifact_type
            if artifact_type not in results["artifact_types"]:
                results["artifact_types"][artifact_type] = 0
            results["artifact_types"][artifact_type] += 1

            # High relevance artifacts (score > 0.7)
            if artifact.relevance_score and artifact.relevance_score > 0.7:
                results["high_relevance_artifacts"].append({
                    "type": artifact_type,
                    "name": artifact.artifact_name,
                    "relevance_score": artifact.relevance_score,
                    "notes": artifact.notes
                })

        return results

    def _get_timeline_date_range(self, timeline: List[Dict[str, Any]]) -> Dict[str, str]:
        """Get date range of timeline events"""
        if not timeline:
            return {"start": None, "end": None}

        dates = [event["timestamp"] for event in timeline]
        return {
            "start": min(dates),
            "end": max(dates)
        }

    def _get_event_type_summary(self, timeline: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get summary of event types in timeline"""
        event_types = {}
        for event in timeline:
            event_type = event["event_type"]
            event_types[event_type] = event_types.get(event_type, 0) + 1

        return event_types

    def _generate_recommendations(self, case_summary: Dict[str, Any],
                                analysis_results: Dict[str, Any]) -> List[str]:
        """Generate investigation recommendations"""
        recommendations = []

        # Check processing completion
        progress = case_summary["analysis_summary"]["analysis_progress"]
        if progress < 100:
            recommendations.append(f"Complete evidence processing ({progress:.1f}% complete)")

        # Check for high-relevance artifacts
        high_rel_count = len(analysis_results.get("high_relevance_artifacts", []))
        if high_rel_count > 0:
            recommendations.append(f"Review {high_rel_count} high-relevance artifacts for further investigation")

        # Check evidence types
        evidence_types = case_summary["evidence_summary"]["evidence_types"]
        if "memory" in evidence_types:
            recommendations.append("Perform memory analysis for volatile artifacts")

        if "network" in evidence_types:
            recommendations.append("Analyze network traffic for communication patterns")

        return recommendations
```

## Common Issues and Solutions

### Issue 1: "TSK library not found"
**Problem**: pytsk3 installation fails or TSK not found.
**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install sleuthkit libtsk-dev python3-dev

# macOS
brew install sleuthkit
export TSK_HOME=/usr/local

# Then reinstall pytsk3
pip uninstall pytsk3
pip install pytsk3
```

### Issue 2: "Cannot open E01 images"
**Problem**: pyewf not available or E01 support missing.
**Solution**:
```bash
# Install libewf
sudo apt-get install libewf-dev  # Ubuntu/Debian
brew install libewf  # macOS

pip install pyewf
```

### Issue 3: Large evidence files cause memory issues
**Problem**: Running out of memory when processing large images.
**Solution**:
```python
# Process files in chunks
def process_large_file(file_obj, chunk_size=64*1024):
    offset = 0
    while offset < file_obj.info.size:
        chunk = file_obj.read_random(offset, chunk_size)
        # Process chunk
        offset += chunk_size
```

### Issue 4: Hash verification fails
**Problem**: Hash mismatches during integrity checks.
**Solution**:
```python
# Implement robust hash verification
def verify_with_multiple_algorithms(file_path, expected_hashes):
    calculated = calculate_all_hashes(file_path)

    for hash_type, expected in expected_hashes.items():
        if calculated[hash_type] != expected:
            print(f"{hash_type} mismatch: expected {expected}, got {calculated[hash_type]}")
            return False

    return True
```

## Pro Tips

1. **Evidence Integrity**: Always verify hashes at every step of processing.

2. **Performance Optimization**: Use memory mapping for large files:
```python
import mmap

def process_large_file_efficiently(filepath):
    with open(filepath, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # Process memory-mapped file
            pass
```

3. **Chain of Custody**: Log every action with timestamps and digital signatures.

4. **Database Indexing**: Create proper indexes for timeline queries:
```sql
CREATE INDEX idx_timeline_timestamp ON timeline_events(timestamp);
CREATE INDEX idx_timeline_evidence ON timeline_events(evidence_id);
```

5. **Error Handling**: Gracefully handle corrupted evidence:
```python
try:
    fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
except Exception as e:
    log_error(f"Cannot open file system: {e}")
    # Continue with other partitions
```

6. **Legal Compliance**: Always follow forensic best practices and maintain detailed documentation for court admissibility.