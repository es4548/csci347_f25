# 🛠️ Technical Setup & Troubleshooting Guide

**Course**: CSCI 347 - Network Security and Digital Forensics  
**Purpose**: Complete technical setup guide with troubleshooting for all course tools

---

## 📋 Table of Contents

1. [Essential Tools Overview](#essential-tools-overview)
2. [Week-by-Week Setup Requirements](#week-by-week-setup-requirements)
3. [Common Setup Issues & Solutions](#common-setup-issues--solutions)
4. [Alternative Tool Options](#alternative-tool-options)
5. [Virtual Environment Setup](#virtual-environment-setup)
6. [Mobile Device Alternatives](#mobile-device-alternatives)
7. [Performance Optimization](#performance-optimization)
8. [Getting Help](#getting-help)

---

## 🔧 Essential Tools Overview

### Core Development Environment

**Required for all weeks:**
- Python 3.9+ (3.11 recommended)
- Git and GitHub account
- Code editor (VS Code recommended)
- Terminal/Command Line access

### Specialized Tools by Week

**Weeks 1-9 (Security Architecture):**
- OpenSSL (certificate management)
- Docker (optional but recommended)
- Wireshark (network analysis)
- Nmap (network scanning)

**Weeks 10-14 (Digital Forensics):**
- Autopsy/Sleuth Kit (disk forensics)
- Volatility3 (memory forensics)
- YARA (malware detection)
- ADB (Android debugging - optional)
- libimobiledevice (iOS analysis - optional)

---

## 📅 Week-by-Week Setup Requirements

### Week 1-2: Cryptography Basics
```bash
# Install required Python packages
pip install cryptography pycryptodome hashlib

# Verify installation
python -c "from cryptography.fernet import Fernet; print('Crypto ready!')"
```

**Common Issues:**
- **Error: "No module named cryptography"**
  - Solution: `pip install --upgrade pip && pip install cryptography`
- **Permission denied errors**
  - Solution: Use virtual environment (see below)

### Week 3: PKI Setup
```bash
# Install OpenSSL (if not present)
# macOS
brew install openssl

# Ubuntu/Debian
sudo apt-get install openssl

# Windows
# Download from https://www.openssl.org/source/ or use Git Bash

# Verify OpenSSL
openssl version
```

**Alternative if OpenSSL unavailable:**
```python
# Use Python's cryptography library instead
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
# Full PKI implementation possible with Python only
```

### Week 6-7: Network Security Tools
```bash
# Wireshark Installation
# macOS
brew install --cask wireshark

# Ubuntu/Debian  
sudo apt-get install wireshark

# Windows
# Download from https://www.wireshark.org/download.html

# Nmap Installation
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get install nmap

# Windows
# Download from https://nmap.org/download.html
```

**Alternative for restricted environments:**
```python
# Use Python's scapy for packet analysis
pip install scapy
# Provides similar functionality without admin rights
```

### Week 10-11: Basic Forensics Tools

**Autopsy Installation:**
```bash
# Download from https://www.autopsy.com/download/
# Alternative: Use Docker container
docker pull sleuthkit/autopsy
docker run -p 9999:9999 sleuthkit/autopsy
```

**If Autopsy is too resource-intensive:**
```python
# Use Python-based alternatives
pip install pytsk3 pyewf
# Lightweight forensic analysis in Python
```

### Week 12: Memory Forensics (Volatility)

**Volatility3 Setup:**
```bash
# Clone Volatility3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

# Install requirements
pip install -r requirements.txt

# Test installation
python vol.py -h
```

**Common Volatility Issues:**

1. **"No module named yara"**
```bash
# Install YARA Python bindings
pip install yara-python
```

2. **Memory dump too large**
```bash
# Use smaller sample dumps for learning
wget https://github.com/volatilityfoundation/volatility3/raw/stable/test_data/sample.mem
# 256MB sample instead of multi-GB production dumps
```

3. **Profile detection fails**
```python
# Manually specify profile
python vol.py -f memory.dump --profile=Win10x64 pslist
```

### Week 13: Mobile Forensics

**Android (ADB) Setup:**
```bash
# Download Android SDK Platform Tools
# https://developer.android.com/studio/releases/platform-tools

# Add to PATH
export PATH=$PATH:/path/to/platform-tools

# Enable Developer Mode on Android device (optional)
# Settings → About → Tap "Build Number" 7 times

# Test connection (if device available)
adb devices
```

**Alternative for students without Android devices:**
```bash
# Use Android emulator
# Install Android Studio (free)
# Create virtual device for testing
# OR use provided forensic images
```

**iOS Analysis (Optional):**
```bash
# macOS only
brew install libimobiledevice

# Alternative: Use provided iOS backup samples
# No physical device required
```

---

## 🔧 Common Setup Issues & Solutions

### Issue 1: Permission Denied Errors

**Problem:** Can't install packages globally
```bash
pip install package_name
# ERROR: Permission denied
```

**Solution:** Use virtual environment
```bash
# Create virtual environment
python -m venv csci347_env

# Activate it
# Windows
csci347_env\Scripts\activate
# macOS/Linux  
source csci347_env/bin/activate

# Now install freely
pip install -r requirements.txt
```

### Issue 2: Tool Version Conflicts

**Problem:** Different tools require different Python versions

**Solution:** Use pyenv for version management
```bash
# Install pyenv
curl https://pyenv.run | bash

# Install multiple Python versions
pyenv install 3.9.16
pyenv install 3.11.5

# Set version for project
pyenv local 3.11.5
```

### Issue 3: Insufficient System Resources

**Problem:** Forensic tools consuming too much RAM/CPU

**Solutions:**

1. **Use cloud resources (free tier):**
```bash
# Google Colab for memory forensics
# Upload notebook with Volatility pre-installed
# 12GB RAM free tier
```

2. **Optimize local usage:**
```python
# Process large files in chunks
def process_large_dump(filename, chunk_size=1024*1024):
    with open(filename, 'rb') as f:
        while chunk := f.read(chunk_size):
            # Process chunk
            analyze_chunk(chunk)
```

3. **Use lightweight alternatives:**
```python
# Instead of full Autopsy GUI
# Use command-line tools
fls image.dd  # List files
icat image.dd 128 > recovered_file  # Recover specific file
```

### Issue 4: Network Restrictions

**Problem:** Corporate/university firewall blocking tools

**Solutions:**

1. **Use offline packages:**
```bash
# Download packages on unrestricted network
pip download -r requirements.txt -d ./offline_packages

# Install offline
pip install --no-index --find-links ./offline_packages -r requirements.txt
```

2. **Request academic exceptions:**
- Contact IT for educational tool whitelist
- Use VPN with instructor approval
- Work in designated lab environment

---

## 🔄 Alternative Tool Options

### Free Alternatives to Commercial Tools

| Commercial Tool | Free Alternative | Usage |
|----------------|------------------|--------|
| EnCase | Autopsy | Disk forensics |
| FTK | CAINE Linux | Forensic analysis |
| X-Ways | SIFT Workstation | Complete forensics |
| Cellebrite | ADB + Python | Mobile forensics |
| IDA Pro | Ghidra | Reverse engineering |

### Browser-Based Alternatives (No Installation)

1. **CyberChef** - Crypto and encoding operations
   - https://gchq.github.io/CyberChef/
   
2. **Hybrid Analysis** - Malware analysis
   - https://www.hybrid-analysis.com/

3. **VirusTotal** - File analysis
   - https://www.virustotal.com/

4. **Regex101** - Regular expression testing
   - https://regex101.com/

---

## 📱 Mobile Device Alternatives

### No Physical Device? No Problem!

**Option 1: Emulators**
```bash
# Android Studio Emulator (free)
# - Full Android OS
# - Root access available
# - Forensic analysis possible

# iOS Simulator (macOS only)
# - Limited forensic capability
# - Good for app analysis
```

**Option 2: Sample Data Sets**
```python
# Pre-extracted mobile forensic data
# Available in course resources
mobile_data = {
    'sms_database': 'samples/android_sms.db',
    'whatsapp_backup': 'samples/whatsapp_backup.crypt',
    'ios_backup': 'samples/iphone_backup.tar'
}
```

**Option 3: Cloud-Based Analysis**
```python
# Use provided API endpoints
import requests

# Analyze mobile backup without local processing
response = requests.post('https://api.course.forensics/analyze',
                        files={'backup': open('backup.ab', 'rb')})
results = response.json()
```

---

## ⚡ Performance Optimization

### Memory-Efficient Forensics

```python
# Instead of loading entire file
def efficient_file_search(filepath, pattern):
    """Search large files without loading into memory"""
    import mmap
    import re
    
    with open(filepath, 'r+b') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
            for match in re.finditer(pattern.encode(), mmapped_file):
                yield match.start(), match.group()

# Use generators for large datasets
def process_logs(log_file):
    with open(log_file) as f:
        for line in f:  # Generator, not list
            if 'ERROR' in line:
                yield parse_log_line(line)
```

### Parallel Processing

```python
# Speed up analysis with multiprocessing
from multiprocessing import Pool
import hashlib

def calculate_hash(filepath):
    """Calculate file hash"""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return filepath, hasher.hexdigest()

# Process multiple files in parallel
with Pool() as pool:
    results = pool.map(calculate_hash, file_list)
```

---

## 🆘 Getting Help

### Immediate Support

1. **Course Discord/Slack Channel**
   - Real-time help from classmates and TAs
   - Tool-specific channels (#volatility-help, #mobile-forensics)

2. **Office Hours**
   - Virtual troubleshooting sessions
   - Screen sharing for complex issues

3. **Documentation**
   - Course wiki with common solutions
   - Video tutorials for complex setups

### Self-Help Resources

```bash
# Built-in help for most tools
volatility3 -h
autopsy --help
adb help

# Python package documentation
python -m pydoc cryptography
```

### Fallback Options

If you absolutely cannot get a tool working:

1. **Partner with classmate** for tool-specific portions
2. **Use provided analysis outputs** to continue with assignments
3. **Focus on methodology** and document what you would do
4. **Schedule 1-on-1 help session** with instructor/TA

---

## 📝 Setup Verification Script

Save this as `verify_setup.py` and run to check your environment:

```python
#!/usr/bin/env python3
"""
CSCI 347 Setup Verification Script
Checks all required tools and reports status
"""

import sys
import subprocess
import importlib
from pathlib import Path

def check_python_version():
    """Verify Python version 3.9+"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 9:
        print("✅ Python version: {}.{}.{}".format(*version[:3]))
        return True
    else:
        print("❌ Python 3.9+ required (found {}.{}.{})".format(*version[:3]))
        return False

def check_python_package(package_name):
    """Check if Python package is installed"""
    try:
        importlib.import_module(package_name)
        print(f"✅ {package_name} installed")
        return True
    except ImportError:
        print(f"❌ {package_name} not installed - run: pip install {package_name}")
        return False

def check_command_line_tool(tool_name, version_flag="--version"):
    """Check if command-line tool is available"""
    try:
        result = subprocess.run([tool_name, version_flag], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            print(f"✅ {tool_name} installed")
            return True
    except (FileNotFoundError, subprocess.SubprocessError):
        print(f"⚠️  {tool_name} not found (optional)")
        return False

def main():
    print("=" * 50)
    print("CSCI 347 Environment Verification")
    print("=" * 50)
    
    all_good = True
    
    # Check Python version
    print("\n📍 Checking Python...")
    all_good &= check_python_version()
    
    # Check essential Python packages
    print("\n📍 Checking Python packages...")
    essential_packages = [
        'cryptography',
        'hashlib',
        'json',
        'sqlite3',
        'socket',
        'threading'
    ]
    
    for package in essential_packages:
        if package in ['hashlib', 'json', 'sqlite3', 'socket', 'threading']:
            # Built-in packages
            check_python_package(package)
        else:
            all_good &= check_python_package(package)
    
    # Check optional but recommended packages
    print("\n📍 Checking optional packages...")
    optional_packages = [
        'numpy',
        'pandas',
        'requests',
        'scapy'
    ]
    
    for package in optional_packages:
        check_python_package(package)
    
    # Check command-line tools
    print("\n📍 Checking command-line tools...")
    tools = [
        ('git', '--version'),
        ('openssl', 'version'),
        ('python3', '--version'),
        ('pip', '--version'),
        ('docker', '--version'),
    ]
    
    for tool, flag in tools:
        check_command_line_tool(tool, flag)
    
    # Check for course directory
    print("\n📍 Checking course structure...")
    course_dir = Path.cwd()
    if (course_dir / "week01-crypto-basics").exists():
        print("✅ Course directory structure found")
    else:
        print("⚠️  Not in course directory")
    
    # Final report
    print("\n" + "=" * 50)
    if all_good:
        print("✅ Essential setup complete! You're ready to start.")
        print("Note: Some optional tools may not be installed.")
        print("Install them as needed for specific weeks.")
    else:
        print("❌ Some essential components missing.")
        print("Please install missing components before starting.")
    print("=" * 50)
    
    return 0 if all_good else 1

if __name__ == "__main__":
    sys.exit(main())
```

---

## 💡 Pro Tips

1. **Start setup early** - Don't wait until assignment deadline
2. **Use version control** - Commit working configurations
3. **Document your setup** - Note what worked for future reference
4. **Help others** - Share solutions in course forum
5. **Keep backups** - Save configuration files and scripts

---

**Remember**: Technical issues are part of the learning process in cybersecurity. Problem-solving these setups is valuable experience for your career!