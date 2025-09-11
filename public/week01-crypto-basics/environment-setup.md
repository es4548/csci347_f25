# Course Environment Setup

**Time needed: 15-20 minutes**

**Need the quick version?** See [Setup Checklist](../quick-reference/setup-checklist.md) (2 minutes)

---

## 🚀 Choose Your Operating System

For detailed, OS-specific setup instructions, select your platform:

### 📱 **Platform-Specific Setup Guides**

| Operating System | Setup Guide | Time | Difficulty |
|------------------|-------------|------|------------|
| 🪟 **Windows 10/11** | [Windows Setup Guide](../resources/setup-windows.md) | 20-30 min | ⭐⭐⭐ |
| 🍎 **macOS** (Intel & Apple Silicon) | [macOS Setup Guide](../resources/setup-macos.md) | 15-25 min | ⭐⭐ |
| 🐧 **Linux** (Ubuntu, Fedora, etc.) | [Linux Setup Guide](../resources/setup-linux.md) | 10-20 min | ⭐ |

**💡 Recommendation**: Use the OS-specific guides above for the best experience. They include troubleshooting for common platform issues and optimized tool selections.

---

## ⚡ Quick Universal Setup (All Platforms)

If you prefer a condensed version, here are the universal steps:

### System Requirements

**Minimum requirements:**
- 8GB RAM (16GB recommended)
- 100GB free disk space 
- Python 3.11 or higher
- Git
- Virtualization software (VirtualBox, UTM, etc.)

### Step 1: Install Python & Git

#### Windows
1. **Python**: Download from [python.org](https://python.org) - **Check "Add Python to PATH"**
2. **Git**: Download from [git-scm.com](https://git-scm.com)

#### macOS  
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python@3.11 git
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-pip python3.11-venv git
```

### Step 2: Set Up Course Repository

```bash
# 1. Fork the course repository on GitHub
# Go to: https://github.com/DEmcla/csci347_f25 and click "Fork"

# 2. Clone YOUR fork (replace YourUsername)
git clone https://github.com/YourUsername/csci347_f25.git
cd csci347_f25

# 3. Configure Git for the course
git config user.name "Your Name - CSCI347_f25"
git config user.email "your.email@example.com"

# 4. Add the original repo to get updates
git remote add upstream https://github.com/DEmcla/csci347_f25.git
```

### Step 3: Create Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install required packages
pip install --upgrade pip
pip install cryptography pyOpenSSL volatility3 scapy requests pytest
```

### Step 4: Install Virtualization Software

**For Intel/AMD processors:**
- Download [VirtualBox](https://virtualbox.org) and install

**For Apple Silicon (M1/M2/M3) Macs:**
- Download [UTM](https://mac.getutm.app/) instead (VirtualBox won't work)

**For Linux:**
- Install VirtualBox: `sudo apt install virtualbox` (Ubuntu/Debian)
- Or use KVM/QEMU for better performance

### Step 5: Verify Setup

```bash
python week01-crypto-basics/verify-environment.py
```

**Expected output:**
```
✅ Python 3.11+ found
✅ Virtual environment active  
✅ Required packages installed
✅ Git configured
✅ Ready to start!
```

### Step 6: Create Your Assignment Folder

```bash
# Create your personal assignment directory (use your actual name)
mkdir -p assignments/CSCI347_f25_FirstName_LastName/week01

# Commit the structure
git add assignments/
git commit -m "Set up assignment directory structure"
git push origin main
```

---

## ⚠️ Having Issues?

**For comprehensive troubleshooting and OS-specific solutions:**

- 🪟 **Windows Issues**: See [Windows Setup Guide](../resources/setup-windows.md#common-windows-issues--solutions)
- 🍎 **macOS Issues**: See [macOS Setup Guide](../resources/setup-macos.md#common-macos-issues--solutions)  
- 🐧 **Linux Issues**: See [Linux Setup Guide](../resources/setup-linux.md#common-linux-issues--solutions)
- 📖 **General Help**: Check [Full Troubleshooting Guide](../resources/troubleshooting.md)

### Quick Fixes

**Python not found?**
- Windows: Try `python` instead of `python3`
- Make sure Python was added to PATH during installation

**Permission errors?**
- Don't use `sudo` with pip in virtual environments
- Recreate the virtual environment if needed

**Need help?**
- Post questions in Canvas discussions
- Create GitHub issue for technical problems

## Next Steps

Once your environment is set up, you're ready to start the Week 1 tutorial and assignment!