# 🍎 macOS Setup Guide - CSCI 347

**Course**: CSCI 347 - Network Security and Digital Forensics  
**Platform**: macOS (Intel & Apple Silicon)  
**Time needed**: 15-25 minutes

---

## 🎯 Quick Start Checklist

- [ ] Install Homebrew package manager
- [ ] Install Python 3.11+ via Homebrew
- [ ] Install Git (if not already present)
- [ ] Clone course repository
- [ ] Set up virtual environment
- [ ] Install required Python packages
- [ ] Install virtualization software
- [ ] Verify setup

---

## 📋 System Requirements

**Minimum requirements:**
- macOS Monterey (12.0) or later
- 8GB RAM (16GB recommended for forensics work)
- 100GB free disk space
- Admin access for software installation
- Internet connection for downloads

**Architecture Support:**
- **Intel Macs**: Full compatibility with all tools
- **Apple Silicon (M1/M2/M3)**: Some tools require Rosetta 2

---

## 🍺 Step 1: Install Homebrew

Homebrew is the essential package manager for macOS that makes installing development tools much easier.

1. **Install Homebrew**:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Add Homebrew to PATH**:
   ```bash
   # For Intel Macs
   echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc
   
   # For Apple Silicon Macs
   echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
   
   # Reload shell configuration
   source ~/.zshrc
   ```

3. **Verify Homebrew**:
   ```bash
   brew --version
   # Should show: Homebrew x.x.x
   ```

### Alternative: Manual Installation

If you prefer not to use Homebrew, you can install Python directly from python.org, but Homebrew is strongly recommended for easier package management.

---

## 🐍 Step 2: Install Python

1. **Install Python via Homebrew**:
   ```bash
   # Install latest Python 3.11
   brew install python@3.11
   
   # Link it to make it default
   brew link python@3.11
   ```

2. **Verify Python Installation**:
   ```bash
   python3 --version
   # Should show: Python 3.11.x
   
   pip3 --version
   # Should show pip version
   ```

3. **Create Python3 Alias** (optional but recommended):
   ```bash
   echo 'alias python="python3"' >> ~/.zshrc
   echo 'alias pip="pip3"' >> ~/.zshrc
   source ~/.zshrc
   ```

### Troubleshooting Python on macOS

**❌ "python3: command not found" after installation**
```bash
# Check if Homebrew Python is in PATH
echo $PATH | grep brew

# Manually add to PATH if needed
export PATH="/opt/homebrew/bin:$PATH"  # Apple Silicon
export PATH="/usr/local/bin:$PATH"     # Intel Mac
```

**❌ Multiple Python versions causing conflicts**
```bash
# Use pyenv for version management
brew install pyenv
echo 'eval "$(pyenv init -)"' >> ~/.zshrc
source ~/.zshrc

# Install and use specific Python version
pyenv install 3.11.5
pyenv global 3.11.5
```

---

## 🔧 Step 3: Install Git

Git is usually pre-installed on macOS, but we'll ensure you have the latest version.

1. **Check if Git is installed**:
   ```bash
   git --version
   # If version is 2.30+, you're good to go
   ```

2. **Install/Update Git via Homebrew**:
   ```bash
   brew install git
   ```

3. **Install Xcode Command Line Tools** (if needed):
   ```bash
   xcode-select --install
   # This provides additional development tools
   ```

---

## 📚 Step 4: Set Up Course Repository

1. **Configure Git**:
   ```bash
   git config --global user.name "FirstName LastName - CSCI347_f25"
   git config --global user.email "your.email@university.edu"
   ```

2. **Fork and Clone Repository**:
   ```bash
   # 1. Go to GitHub and fork: https://github.com/DEmcla/csci347_f25
   # 2. Clone YOUR fork (replace YourUsername)
   git clone https://github.com/YourUsername/csci347_f25.git
   cd csci347_f25
   
   # 3. Add upstream remote
   git remote add upstream https://github.com/DEmcla/csci347_f25.git
   ```

---

## 🏠 Step 5: Create Python Virtual Environment

1. **Create Virtual Environment**:
   ```bash
   # Navigate to course directory
   cd csci347_f25
   
   # Create virtual environment
   python3 -m venv venv
   ```

2. **Activate Virtual Environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Verify Activation**:
   ```bash
   # You should see (venv) at the start of your prompt
   which python
   # Should point to: .../csci347_f25/venv/bin/python
   
   python --version
   # Should show Python 3.11.x from virtual environment
   ```

4. **Make Activation Easy**:
   ```bash
   # Create an alias for quick activation
   echo 'alias activate347="cd ~/path/to/csci347_f25 && source venv/bin/activate"' >> ~/.zshrc
   source ~/.zshrc
   ```

---

## 📦 Step 6: Install Python Packages

1. **Upgrade pip**:
   ```bash
   # Make sure virtual environment is activated
   python -m pip install --upgrade pip
   ```

2. **Install Required Packages**:
   ```bash
   pip install cryptography pyOpenSSL requests scapy pytest
   pip install pycryptodome volatility3 yara-python
   ```

3. **Handle macOS-Specific Issues**:

   **❌ Cryptography compilation errors**
   ```bash
   # Install required development tools
   brew install openssl libffi
   
   # Set environment variables for compilation
   export LDFLAGS="-L$(brew --prefix openssl)/lib"
   export CPPFLAGS="-I$(brew --prefix openssl)/include"
   
   # Install with proper linking
   pip install --upgrade pip setuptools wheel
   pip install cryptography
   ```

   **❌ "xcrun: error: invalid active developer path"**
   ```bash
   # Reinstall Xcode command line tools
   sudo xcode-select --reset
   xcode-select --install
   ```

   **❌ Apple Silicon compatibility issues**
   ```bash
   # Some packages may need Rosetta 2
   softwareupdate --install-rosetta --agree-to-license
   
   # Use x86_64 Python if needed for specific packages
   arch -x86_64 pip install problem_package
   ```

---

## 💻 Step 7: Install Virtualization Software

### For Intel Macs: VirtualBox

```bash
# Install VirtualBox via Homebrew
brew install --cask virtualbox

# Install VirtualBox Extension Pack
brew install --cask virtualbox-extension-pack
```

### For Apple Silicon Macs: UTM

```bash
# VirtualBox doesn't work on Apple Silicon
# Use UTM instead
brew install --cask utm

# Alternative: VMware Fusion (free for personal use)
brew install --cask vmware-fusion
```

### Enable Virtualization (if needed)

```bash
# Check if virtualization is supported
sysctl -n machdep.cpu.features | grep VMX  # Intel only

# For Apple Silicon, virtualization is always enabled
# No BIOS settings needed
```

---

## 🛠️ Step 8: Install Additional Security Tools

### Homebrew Security Tools

```bash
# Network analysis tools
brew install nmap wireshark

# Cryptographic tools
brew install openssl gnupg

# Forensics and analysis tools
brew install sleuthkit autopsy

# Text processing and analysis
brew install ripgrep fd bat

# Network utilities
brew install netcat socat curl wget
```

### Optional Development Tools

```bash
# Code editors
brew install --cask visual-studio-code
brew install --cask sublime-text

# Terminal enhancements
brew install iterm2 oh-my-zsh
brew install htop tree jq

# Docker for containerized environments
brew install --cask docker
```

---

## ✅ Step 9: Verify Complete Setup

1. **Run Verification Script**:
   ```bash
   # Ensure virtual environment is activated
   source venv/bin/activate
   
   # Run verification
   python week01-crypto-basics/verify-environment.py
   ```

2. **Expected Output**:
   ```
   ✅ Python 3.11+ found
   ✅ Virtual environment active
   ✅ Required packages installed
   ✅ Git configured
   ✅ Virtualization software available
   ✅ Ready to start CSCI 347!
   ```

3. **Create Assignment Directory**:
   ```bash
   mkdir -p assignments/CSCI347_f25_FirstName_LastName/week01
   git add assignments/
   git commit -m "Set up assignment directory structure"
   git push origin main
   ```

---

## 🔧 macOS-Specific Tools & Features

### Built-in Security Tools

```bash
# Network utilities
netstat -an
lsof -i
dscacheutil -q host

# System information
system_profiler SPSoftwareDataType
system_profiler SPHardwareDataType

# Process monitoring
ps aux | grep process_name
top -o cpu

# Log analysis
log show --predicate 'process == "kernel"' --last 1h
console  # GUI log viewer

# Keychain management
security find-internet-password -s github.com
security dump-keychain
```

### Terminal Configuration

```bash
# Enhanced shell setup
echo 'export CLICOLOR=1' >> ~/.zshrc
echo 'export LSCOLORS=ExFxBxDxCxegedabagacad' >> ~/.zshrc

# Useful aliases for security work
cat >> ~/.zshrc << 'EOF'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias h='history'
alias c='clear'
alias ..='cd ..'
alias ...='cd ../..'
alias ports='lsof -i -P -n | grep LISTEN'
alias myip='curl ipinfo.io/ip'
EOF

source ~/.zshrc
```

### File System Security

```bash
# Check file permissions
ls -la@e filename  # Shows extended attributes and ACLs

# Set proper permissions for course files
find . -type f -name "*.py" -exec chmod 644 {} \;
find . -type d -exec chmod 755 {} \;

# Check for quarantine attributes (downloaded files)
xattr -l filename
xattr -d com.apple.quarantine filename  # Remove quarantine
```

---

## 🚨 Common macOS Issues & Solutions

### Issue 1: Gatekeeper Blocking Security Tools

**Problem**: macOS preventing execution of security tools
```bash
# Solution: Allow specific applications
sudo xattr -r -d com.apple.quarantine /path/to/application

# Or temporarily disable Gatekeeper (not recommended)
sudo spctl --master-disable
# Re-enable after installation
sudo spctl --master-enable
```

### Issue 2: SIP (System Integrity Protection) Conflicts

**Problem**: SIP preventing low-level access
```bash
# Check SIP status
csrutil status

# If you need to disable SIP (advanced users only):
# 1. Restart in Recovery Mode (Cmd+R during boot)
# 2. Open Terminal in Recovery Mode
# 3. csrutil disable
# 4. Restart normally
# 5. Re-enable after testing: csrutil enable
```

### Issue 3: Python SSL Certificate Issues

**Problem**: SSL certificate verification failures
```bash
# Update certificates
/Applications/Python\ 3.11/Install\ Certificates.command

# Or install certificates via Homebrew
brew install ca-certificates
```

### Issue 4: Virtualization Performance on Apple Silicon

**Problem**: x86 VMs running slowly on Apple Silicon
```bash
# Solution 1: Use ARM-based VMs when possible
# Download ARM versions of Linux distributions

# Solution 2: Optimize UTM settings
# Increase allocated RAM and CPU cores
# Enable hardware acceleration in UTM settings

# Solution 3: Use Docker containers instead of full VMs
docker run -it ubuntu:latest /bin/bash
```

### Issue 5: Homebrew Permission Issues

**Problem**: Permission denied errors with Homebrew
```bash
# Fix Homebrew permissions
sudo chown -R $(whoami) $(brew --prefix)/*

# Or reinstall Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

## 🔍 Testing Your macOS Setup

### Crypto and Networking Test

```bash
# Activate environment
source venv/bin/activate

# Test cryptography
python -c "from cryptography.fernet import Fernet; print('Crypto working!')"

# Test networking
python -c "import socket; s=socket.socket(); s.connect(('google.com', 80)); print('Network working!'); s.close()"

# Test SSL
python -c "import ssl, socket; print('SSL working!')"
```

### System Tools Test

```bash
# Test system information gathering
system_profiler SPHardwareDataType | grep "Model Name"

# Test network analysis
netstat -rn | head -5

# Test process monitoring
ps aux | head -5

# Test file system
ls -la@e . | head -3
```

### Virtualization Test

```bash
# Test VirtualBox (Intel Macs)
vboxmanage --version

# Test UTM (Apple Silicon)
open -a UTM --args --version 2>/dev/null || echo "UTM not installed"

# Test Docker
docker --version
```

---

## 🍎 macOS Pro Tips

### Performance Optimization

```bash
# Free up memory
sudo purge

# Monitor system performance
Activity\ Monitor.app  # GUI
htop                   # Terminal

# Clean up Homebrew
brew cleanup --prune=all

# Update all packages
brew update && brew upgrade
```

### Security Enhancements

```bash
# Enable FileVault (disk encryption)
sudo fdesetup enable

# Check firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Enable stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Show hidden files in Finder
defaults write com.apple.finder AppleShowAllFiles YES
killall Finder
```

### Development Environment

```bash
# Install oh-my-zsh for better terminal experience
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# Useful plugins for security work
echo 'plugins=(git python pip virtualenv brew)' >> ~/.zshrc

# Set up code signing for development
codesign --verify --verbose /usr/bin/python3
```

---

## 📱 Integration with iOS (Optional)

### iOS Forensics Preparation

```bash
# Install iOS forensics tools
brew install libimobiledevice
brew install ideviceinstaller

# Test iOS device connection
idevice_id -l  # List connected devices
ideviceinfo    # Show device information

# iTunes backup analysis tools
pip install biplist plistlib
```

---

## 🔄 Daily Workflow Script

Create a startup script for easy daily activation:

```bash
# Create activation script
cat > ~/start_csci347.sh << 'EOF'
#!/bin/bash
echo "🔐 Starting CSCI 347 Environment..."
cd ~/path/to/csci347_f25
source venv/bin/activate
echo "✅ Virtual environment activated"
echo "📁 Current directory: $(pwd)"
echo "🐍 Python version: $(python --version)"
echo "📦 Packages installed: $(pip list | wc -l) packages"
echo ""
echo "Ready for Network Security and Digital Forensics work! 🛡️"
EOF

chmod +x ~/start_csci347.sh

# Use it
~/start_csci347.sh
```

### Spotlight Integration

```bash
# Make script searchable in Spotlight
mkdir -p ~/Scripts
mv ~/start_csci347.sh ~/Scripts/
echo 'export PATH="$HOME/Scripts:$PATH"' >> ~/.zshrc
```

---

## 🆘 Getting Help

### macOS-Specific Support

1. **Console.app** for system log analysis
2. **Activity Monitor** for performance troubleshooting
3. **Apple Developer Forums** for development issues
4. **Homebrew GitHub Issues** for package problems

### Professional Resources

- **MacAdmins Slack** for enterprise Mac management
- **Der Flounder** blog for Mac security insights
- **Objective-See** for Mac security tools
- **Patrick Wardle** presentations and tools

---

**Next Steps**: Your macOS environment is ready for CSCI 347. Start with Week 1 cryptography basics!