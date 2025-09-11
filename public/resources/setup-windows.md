# 🪟 Windows Setup Guide - CSCI 347

**Course**: CSCI 347 - Network Security and Digital Forensics  
**Platform**: Windows 10/11  
**Time needed**: 20-30 minutes

---

## 🎯 Quick Start Checklist

- [ ] Install Python 3.11+ with PATH enabled
- [ ] Install Git for Windows
- [ ] Clone course repository
- [ ] Set up virtual environment
- [ ] Install required Python packages
- [ ] Install VirtualBox or alternative
- [ ] Verify setup

---

## 📋 System Requirements

**Minimum requirements:**
- Windows 10 (version 1903 or later) or Windows 11
- 8GB RAM (16GB recommended for forensics work)
- 100GB free disk space
- Administrator access for software installation
- Internet connection for downloads

**Recommended:**
- 64-bit processor with virtualization support (VT-x/AMD-V)
- SSD storage for better VM performance
- Windows Defender or compatible antivirus (some may flag security tools)

---

## 🐍 Step 1: Install Python

### Option A: Official Python.org (Recommended)

1. **Download Python**:
   - Go to [python.org/downloads](https://python.org/downloads)
   - Click "Download Python 3.11.x" (latest 3.11 version)

2. **Install Python**:
   - Run the installer **as Administrator**
   - ⚠️ **CRITICAL**: Check "Add Python to PATH" at the bottom
   - Check "Install for all users"
   - Click "Install Now"

3. **Verify Installation**:
   ```cmd
   # Open new Command Prompt or PowerShell
   python --version
   # Should show: Python 3.11.x
   
   pip --version
   # Should show pip version
   ```

### Option B: Microsoft Store (Alternative)

```powershell
# Search for "Python 3.11" in Microsoft Store and install
# This automatically handles PATH configuration
```

### Troubleshooting Python Installation

**❌ "python is not recognized as an internal or external command"**
- Restart Command Prompt/PowerShell after installation
- Manually add Python to PATH:
  - Search "Environment Variables" in Start Menu
  - Edit system environment variables
  - Add `C:\Users\YourName\AppData\Local\Programs\Python\Python311\` to PATH
  - Add `C:\Users\YourName\AppData\Local\Programs\Python\Python311\Scripts\` to PATH

**❌ "Access is denied" during installation**
- Right-click installer and "Run as Administrator"
- Disable antivirus temporarily during installation

---

## 🔧 Step 2: Install Git for Windows

1. **Download Git**:
   - Go to [git-scm.com/download/win](https://git-scm.com/download/win)
   - Download the 64-bit standalone installer

2. **Install Git**:
   - Run installer as Administrator
   - **Important settings during installation**:
     - Default editor: Use your preferred editor (Notepad++ or VS Code)
     - PATH environment: "Git from the command line and also from 3rd-party software"
     - HTTPS transport backend: "Use the native Windows Secure Channel library"
     - Line ending conversions: "Checkout Windows-style, commit Unix-style line endings"
     - Terminal emulator: "Use Windows' default console window"

3. **Verify Git Installation**:
   ```cmd
   git --version
   # Should show: git version 2.x.x
   ```

---

## 📚 Step 3: Set Up Course Repository

1. **Configure Git**:
   ```cmd
   git config --global user.name "FirstName LastName - CSCI347_f25"
   git config --global user.email "your.email@university.edu"
   ```

2. **Fork and Clone Repository**:
   ```cmd
   # 1. Go to GitHub and fork: https://github.com/DEmcla/csci347_f25
   # 2. Clone YOUR fork (replace YourUsername)
   git clone https://github.com/YourUsername/csci347_f25.git
   cd csci347_f25
   
   # 3. Add upstream remote
   git remote add upstream https://github.com/DEmcla/csci347_f25.git
   ```

---

## 🏠 Step 4: Create Python Virtual Environment

1. **Create Virtual Environment**:
   ```cmd
   # Navigate to course directory
   cd csci347_f25
   
   # Create virtual environment
   python -m venv venv
   ```

2. **Activate Virtual Environment**:
   ```cmd
   # Windows Command Prompt
   venv\Scripts\activate
   
   # Windows PowerShell (if above doesn't work)
   venv\Scripts\Activate.ps1
   ```

3. **Verify Activation**:
   ```cmd
   # You should see (venv) at the start of your prompt
   # Check Python location
   where python
   # Should point to: ...\csci347_f25\venv\Scripts\python.exe
   ```

### PowerShell Execution Policy Fix

If you get execution policy errors in PowerShell:
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try activating again
venv\Scripts\Activate.ps1
```

---

## 📦 Step 5: Install Python Packages

1. **Upgrade pip**:
   ```cmd
   # Make sure virtual environment is activated (you should see (venv))
   python -m pip install --upgrade pip
   ```

2. **Install Required Packages**:
   ```cmd
   pip install cryptography pyOpenSSL requests scapy pytest
   pip install pycryptodome hashlib-compat volatility3
   ```

3. **Handle Common Installation Issues**:

   **❌ "Microsoft Visual C++ 14.0 is required"**
   
   **Why this happens:** The `cryptography` package contains C/C++ code for performance-critical cryptographic operations. Windows needs a C++ compiler to build these components, unlike Linux/macOS which have compilers built-in.
   
   ```cmd
   # Solution 1: Use pre-compiled wheels (RECOMMENDED - no compiler needed!)
   pip install --only-binary=all cryptography
   
   # Solution 2: Install build tools (only if Solution 1 doesn't work)
   # Download "Microsoft C++ Build Tools" from Microsoft (~1GB)
   # https://visualstudio.microsoft.com/visual-cpp-build-tools/
   # OR install Visual Studio Community (full IDE, ~10GB)
   ```
   
   **Note:** Most students won't need the C++ tools - modern pip usually downloads pre-compiled versions automatically. You'll only need this if you see the error message.

   **❌ Package installation timeouts**
   ```cmd
   # Use longer timeout
   pip install --timeout 1000 package_name
   
   # Or use different index
   pip install --index-url https://pypi.python.org/simple/ package_name
   ```

---

## 💻 Step 6: Install Virtualization Software

### Option A: VirtualBox (Most Compatible)

1. **Download VirtualBox**:
   - Go to [virtualbox.org/wiki/Downloads](https://virtualbox.org/wiki/Downloads)
   - Download "Windows hosts" version

2. **Pre-installation Requirements**:
   ```cmd
   # Check if virtualization is enabled
   systeminfo | find "Hyper-V"
   # If Hyper-V is enabled, you may need to disable it
   ```

3. **Disable Hyper-V (if needed)**:
   ```cmd
   # Run as Administrator
   dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All
   # Restart computer
   ```

4. **Install VirtualBox**:
   - Run installer as Administrator
   - Install with default settings
   - Restart if prompted

5. **Enable Virtualization in BIOS** (if VMs won't start):
   - Restart computer
   - Enter BIOS/UEFI setup (usually F2, F12, or Del during boot)
   - Look for "Virtualization Technology" or "VT-x" setting
   - Enable it
   - Save and exit

### Option B: VMware Workstation Player (Alternative)

```cmd
# Free for personal/educational use
# Download from: https://www.vmware.com/products/workstation-player.html
# Better performance on some Windows 11 systems
```

### Option C: Windows Subsystem for Linux (WSL2) - Limited

```cmd
# For basic Linux forensics work only
# Not suitable for full VM labs
wsl --install Ubuntu
```

---

## ✅ Step 7: Verify Complete Setup

1. **Run Verification Script**:
   ```cmd
   # Ensure virtual environment is activated
   venv\Scripts\activate
   
   # Run verification
   python week01-crypto-basics\verify-environment.py
   ```

2. **Expected Output**:
   ```
   ✅ Python 3.11+ found
   ✅ Virtual environment active
   ✅ Required packages installed
   ✅ Git configured
   ✅ VirtualBox/VMware available
   ✅ Ready to start CSCI 347!
   ```

3. **Create Assignment Directory**:
   ```cmd
   mkdir assignments\CSCI347_f25_FirstName_LastName\week01
   git add assignments\
   git commit -m "Set up assignment directory structure"
   git push origin main
   ```

---

## 🔧 Windows-Specific Tools

### Additional Security Tools

```cmd
# Windows Sysinternals Suite (useful for forensics)
# Download from: https://docs.microsoft.com/en-us/sysinternals/

# Windows Event Viewer (built-in)
eventvwr.msc

# Windows Registry Editor (be careful!)
regedit

# Resource Monitor
resmon

# Network tools (built-in)
netstat -an
ipconfig /all
nslookup
```

### PowerShell for Security Analysis

```powershell
# PowerShell security commands
Get-Process | Sort-Object CPU -Descending
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
Get-EventLog -LogName Security -Newest 10
Get-WmiObject -Class Win32_Process
```

---

## 🚨 Common Windows Issues & Solutions

### Issue 1: Antivirus Blocking Tools

**Problem**: Windows Defender or antivirus flagging security tools
```cmd
# Solution: Add exclusions for course directory
# Windows Security → Virus & threat protection → Exclusions
# Add folder: C:\path\to\csci347_f25
```

### Issue 2: Windows Update Interference

**Problem**: Windows updates breaking Python/VirtualBox
```cmd
# Solution: Defer updates during course
# Settings → Update & Security → Advanced options
# Pause updates for up to 35 days
```

### Issue 3: Corporate/School Network Restrictions

**Problem**: Firewall blocking downloads or tools
```cmd
# Solution 1: Use mobile hotspot for initial setup
# Solution 2: Download packages offline
pip download -r requirements.txt -d offline_packages
pip install --no-index --find-links offline_packages -r requirements.txt

# Solution 3: Use university lab computers
```

### Issue 4: Storage Space Issues

**Problem**: Not enough space for VMs and forensic images
```cmd
# Solution 1: Use external drive
# Move VMs to external storage
# Update VirtualBox VM location

# Solution 2: Clean up Windows
cleanmgr /sagerun:1

# Solution 3: Use cloud storage for large files
# OneDrive, Google Drive for course materials
```

### Issue 5: Performance Issues

**Problem**: Slow VM performance
```cmd
# Solution 1: Increase VM RAM allocation
# Give VMs at least 2GB RAM, 4GB if possible

# Solution 2: Disable Windows visual effects
# System Properties → Performance → Adjust for best performance

# Solution 3: Close unnecessary programs
# Use Task Manager to end resource-heavy processes

# Solution 4: Use SSD storage
# Move VMs to SSD if available
```

---

## 🔍 Testing Your Setup

### Week 1 Crypto Test

```cmd
# Activate environment
venv\Scripts\activate

# Test cryptography
python -c "from cryptography.fernet import Fernet; print('Crypto working!')"

# Test file operations
python -c "import hashlib; print('Hashing working!')"
```

### Network Tools Test

```cmd
# Test network connectivity
ping google.com

# Test DNS resolution
nslookup github.com

# Check Python networking
python -c "import socket; print('Network working!')"
```

### Git Integration Test

```cmd
# Test Git operations
git status
git remote -v

# Test GitHub connectivity
git ls-remote origin
```

---

## 💡 Windows Pro Tips

1. **Use Windows Terminal** instead of Command Prompt for better experience
2. **Install Windows Package Manager (winget)** for easier tool installation
3. **Use Windows PowerToys** for advanced utilities
4. **Set up WSL2** as backup Linux environment
5. **Create system restore point** before major tool installations
6. **Use Windows Sandbox** for testing suspicious files safely

---

## 🆘 Getting Help

### Windows-Specific Support

1. **Check Windows Event Viewer** for system errors
2. **Use Windows Troubleshooters** for common issues
3. **Microsoft Community Forums** for Windows-specific problems
4. **Course Discord/Slack** #windows-help channel

### Professional Resources

- **Microsoft Security Response Center (MSRC)** for security updates
- **Windows Sysinternals** documentation and tools
- **PowerShell Gallery** for security scripts
- **Windows Server communities** for advanced networking

---

## 🔄 Weekly Activation Reminder

Each time you start working on course materials:

```cmd
# 1. Open Command Prompt or PowerShell
# 2. Navigate to course directory
cd C:\path\to\csci347_f25

# 3. Activate virtual environment
venv\Scripts\activate

# 4. Verify activation (should see (venv) in prompt)
python --version
pip list

# 5. Start working on assignments
```

**Save this as a batch file** (`start_csci347.bat`) for quick activation:
```batch
@echo off
cd /d "C:\path\to\your\csci347_f25"
call venv\Scripts\activate.bat
cmd /k
```

---

**Next Steps**: Once your Windows environment is set up, you're ready for Week 1 cryptography tutorials!