# 🐧 Linux Setup Guide - CSCI 347

**Course**: CSCI 347 - Network Security and Digital Forensics  
**Platform**: Linux (Ubuntu, Debian, Fedora, CentOS, Arch)  
**Time needed**: 10-20 minutes

---

## 🎯 Quick Start Checklist

- [ ] Update system packages
- [ ] Install Python 3.11+ and development tools
- [ ] Install Git
- [ ] Clone course repository
- [ ] Set up virtual environment
- [ ] Install required Python packages
- [ ] Install virtualization software
- [ ] Install security tools
- [ ] Verify setup

---

## 📋 System Requirements

**Minimum requirements:**
- Modern Linux distribution (Ubuntu 20.04+, Debian 10+, Fedora 35+, etc.)
- 8GB RAM (16GB recommended for forensics work)
- 100GB free disk space
- Sudo access for package installation
- Internet connection for downloads

**Recommended distributions for security work:**
- **Ubuntu/Debian**: Largest package ecosystem, best documentation
- **Kali Linux**: Pre-installed security tools (may be overkill for course)
- **Fedora**: Latest packages and technologies
- **CentOS/RHEL**: Enterprise environment simulation

---

## 🔄 Step 1: Update System

### Ubuntu/Debian
```bash
sudo apt update && sudo apt upgrade -y
```

### Fedora
```bash
sudo dnf update -y
```

### CentOS/RHEL 8+
```bash
sudo dnf update -y
# For CentOS 7 or RHEL 7, use: sudo yum update -y
```

### Arch Linux
```bash
sudo pacman -Syu
```

---

## 🐍 Step 2: Install Python and Development Tools

### Ubuntu/Debian
```bash
# Install Python 3.11 and essential tools
sudo apt install -y python3.11 python3.11-pip python3.11-venv python3.11-dev
sudo apt install -y build-essential libssl-dev libffi-dev git curl wget

# Make python3.11 default (optional)
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
```

### Fedora
```bash
# Install Python and development tools
sudo dnf install -y python3.11 python3-pip python3-virtualenv python3-devel
sudo dnf install -y gcc gcc-c++ make openssl-devel libffi-devel git curl wget
sudo dnf groupinstall -y "Development Tools"
```

### CentOS/RHEL 8+
```bash
# Enable EPEL and PowerTools repositories
sudo dnf install -y epel-release
sudo dnf config-manager --enable powertools

# Install Python 3.11 (may need to compile from source on older versions)
sudo dnf install -y python39 python39-pip python39-devel
sudo dnf install -y gcc gcc-c++ make openssl-devel libffi-devel git curl wget
```

### Arch Linux
```bash
# Install Python and development tools
sudo pacman -S python python-pip python-virtualenv base-devel git curl wget
sudo pacman -S openssl libffi
```

### Verify Python Installation
```bash
python3 --version
# Should show Python 3.11.x or 3.9+ minimum

pip3 --version
# Should show pip version
```

---

## 🔧 Step 3: Install Git (if not already installed)

```bash
# Git is usually installed, but let's ensure it's updated
# Ubuntu/Debian
sudo apt install -y git

# Fedora
sudo dnf install -y git

# CentOS/RHEL
sudo dnf install -y git

# Arch
sudo pacman -S git
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
   # Should show Python 3.x from virtual environment
   ```

4. **Make Activation Convenient**:
   ```bash
   # Add alias to ~/.bashrc or ~/.zshrc
   echo 'alias activate347="cd ~/path/to/csci347_f25 && source venv/bin/activate"' >> ~/.bashrc
   source ~/.bashrc
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
   pip install pandas numpy matplotlib  # For data analysis
   ```

3. **Handle Common Linux Issues**:

   **❌ Cryptography compilation errors**
   ```bash
   # Install development headers
   # Ubuntu/Debian
   sudo apt install -y libssl-dev libffi-dev python3-dev
   
   # Fedora
   sudo dnf install -y openssl-devel libffi-devel python3-devel
   
   # Then reinstall
   pip install --upgrade cryptography
   ```

   **❌ Scapy requiring root privileges**
   ```bash
   # Grant capabilities to Python binary (alternative to running as root)
   sudo setcap cap_net_raw=eip $(which python)
   
   # Or install libpcap development headers
   sudo apt install -y libpcap-dev  # Ubuntu/Debian
   sudo dnf install -y libpcap-devel  # Fedora
   ```

   **❌ "Failed building wheel" errors**
   ```bash
   # Install wheel and setuptools
   pip install --upgrade pip setuptools wheel
   
   # Install with no binary if needed
   pip install --no-binary=cryptography cryptography
   ```

---

## 💻 Step 7: Install Virtualization Software

### Option A: VirtualBox (Most Compatible)

#### Ubuntu/Debian
```bash
# Method 1: Official repository
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
echo "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
sudo apt update
sudo apt install -y virtualbox-7.0

# Method 2: Ubuntu repository (older version)
sudo apt install -y virtualbox virtualbox-ext-pack
```

#### Fedora
```bash
# Add VirtualBox repository
sudo dnf config-manager --add-repo https://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo
sudo dnf install -y VirtualBox-7.0

# Or use RPM Fusion
sudo dnf install -y https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install -y VirtualBox
```

#### Arch Linux
```bash
sudo pacman -S virtualbox virtualbox-host-modules-arch
sudo modprobe vboxdrv
```

### Option B: KVM/QEMU (Linux Native)

```bash
# Ubuntu/Debian
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager

# Fedora
sudo dnf install -y @virtualization

# Add user to libvirt group
sudo usermod -a -G libvirt $(whoami)

# Start libvirt service
sudo systemctl enable --now libvirtd
```

### Option C: VMware Workstation (Commercial)

```bash
# Download VMware Workstation Pro from official site
# Install with:
sudo bash VMware-Workstation-*.bundle
```

### Enable Virtualization

```bash
# Check if virtualization is supported
egrep -c '(vmx|svm)' /proc/cpuinfo
# Should return a number > 0

# Check if KVM modules are loaded
lsmod | grep kvm

# Load VirtualBox modules (if using VirtualBox)
sudo modprobe vboxdrv
sudo usermod -a -G vboxusers $(whoami)
```

---

## 🛠️ Step 8: Install Security Tools

### Network Analysis Tools
```bash
# Ubuntu/Debian
sudo apt install -y nmap wireshark-qt netcat-openbsd tcpdump

# Fedora
sudo dnf install -y nmap wireshark-qt netcat tcpdump

# Arch
sudo pacman -S nmap wireshark-qt gnu-netcat tcpdump
```

### Forensics Tools
```bash
# Ubuntu/Debian
sudo apt install -y sleuthkit autopsy testdisk foremost binwalk

# Fedora
sudo dnf install -y sleuthkit testdisk foremost binwalk

# Install Autopsy manually (latest version)
wget https://github.com/sleuthkit/autopsy/releases/latest/download/autopsy-*.zip
```

### Cryptographic Tools
```bash
# Most distributions
sudo apt install -y openssl gnupg  # Ubuntu/Debian
sudo dnf install -y openssl gnupg2  # Fedora
sudo pacman -S openssl gnupg  # Arch
```

### Text Processing and Analysis
```bash
# Modern alternatives to classic tools
# Ubuntu/Debian
sudo apt install -y ripgrep fd-find bat exa

# Fedora
sudo dnf install -y ripgrep fd-find bat exa

# Arch
sudo pacman -S ripgrep fd bat exa
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
   ✅ Security tools installed
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

## 🔧 Linux-Specific Tools & Features

### System Information Gathering
```bash
# Hardware information
lscpu                    # CPU information
lsmem                    # Memory information
lsblk                    # Block devices
lspci                    # PCI devices
lsusb                    # USB devices

# System monitoring
htop                     # Interactive process viewer
iotop                    # I/O monitoring
nethogs                  # Network usage by process
ss -tulpn               # Network connections
```

### Security Monitoring
```bash
# Log analysis
journalctl -f           # Follow system logs
tail -f /var/log/auth.log  # Authentication logs
last                    # Recent logins
w                       # Current users

# File integrity
find / -perm -4000 -type f 2>/dev/null  # SUID files
find / -perm -2000 -type f 2>/dev/null  # SGID files

# Network security
netstat -tulpn          # Open ports
iptables -L             # Firewall rules
ss -s                   # Socket statistics
```

### File System Analysis
```bash
# Disk usage and analysis
df -h                   # Disk space usage
du -sh */              # Directory sizes
lsof                    # Open files
fuser -v /path/to/file  # Processes using file

# File attributes and permissions
stat filename           # Detailed file information
getfacl filename        # Access control lists
lsattr filename         # Extended attributes
```

---

## 🚨 Common Linux Issues & Solutions

### Issue 1: Permission Denied for Network Tools

**Problem**: Scapy, Nmap, etc. require root privileges
```bash
# Solution 1: Grant capabilities (preferred)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service=eip $(which nmap)

# Solution 2: Use sudo for specific commands
sudo python script_using_raw_sockets.py

# Solution 3: Add user to specific groups
sudo usermod -a -G wireshark $(whoami)  # For Wireshark
```

### Issue 2: Missing Development Headers

**Problem**: Package compilation fails
```bash
# Ubuntu/Debian - install development packages
sudo apt install -y python3-dev libssl-dev libffi-dev libpcap-dev

# Fedora - install development packages
sudo dnf install -y python3-devel openssl-devel libffi-devel libpcap-devel

# Generic solution - install build essentials
sudo apt install -y build-essential  # Ubuntu/Debian
sudo dnf groupinstall -y "Development Tools"  # Fedora
```

### Issue 3: Virtualization Not Working

**Problem**: VMs won't start or run slowly
```bash
# Check virtualization support
egrep -c '(vmx|svm)' /proc/cpuinfo

# Enable virtualization in BIOS if needed
# Restart computer and enter BIOS setup

# For KVM
sudo systemctl enable --now libvirtd
sudo usermod -a -G libvirt $(whoami)

# For VirtualBox
sudo /sbin/vboxconfig
sudo modprobe vboxdrv
```

### Issue 4: Firewall Blocking Connections

**Problem**: iptables/firewalld blocking network tools
```bash
# Check firewall status
sudo iptables -L                    # iptables
sudo firewall-cmd --state          # firewalld (Fedora/CentOS)
sudo ufw status                     # ufw (Ubuntu)

# Temporary disable for testing (re-enable after!)
sudo iptables -F                    # Flush iptables rules
sudo systemctl stop firewalld      # Stop firewalld
sudo ufw disable                    # Disable ufw

# Better: Allow specific ports/protocols
sudo firewall-cmd --add-port=80/tcp --permanent
sudo firewall-cmd --reload
```

### Issue 5: SELinux/AppArmor Restrictions

**Problem**: Security frameworks blocking tool execution
```bash
# Check SELinux status
sestatus                           # CentOS/Fedora

# Temporary disable SELinux (for testing only)
sudo setenforce 0

# Check AppArmor status
sudo aa-status                     # Ubuntu

# Disable specific AppArmor profile
sudo aa-disable /path/to/profile
```

---

## 🔍 Testing Your Linux Setup

### Crypto and Networking Test
```bash
# Activate environment
source venv/bin/activate

# Test cryptography
python -c "from cryptography.fernet import Fernet; print('Crypto working!')"

# Test networking with elevated privileges
sudo python -c "from scapy.all import *; print('Scapy working!')"

# Test SSL connections
python -c "import ssl, socket; print('SSL working!')"
```

### System Tools Test
```bash
# Test system information gathering
lscpu | head -5
df -h | head -5

# Test network analysis
netstat -rn | head -5
ss -tulpn | head -5

# Test process monitoring
ps aux | head -5
```

### Security Tools Test
```bash
# Test network scanning (be ethical!)
nmap -V

# Test packet capture (requires root)
sudo tcpdump -D

# Test Wireshark
wireshark --version
```

---

## 🐧 Linux Distribution Specific Tips

### Ubuntu/Debian Specific

```bash
# Enable universe/multiverse repositories
sudo add-apt-repository universe
sudo add-apt-repository multiverse
sudo apt update

# Install snap packages
sudo snap install code    # VS Code
sudo snap install discord # Communication

# PPA for latest security tools
sudo add-apt-repository ppa:mozillateam/ppa
```

### Fedora Specific

```bash
# Enable RPM Fusion repositories
sudo dnf install -y https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm

# Install multimedia codecs
sudo dnf groupupdate multimedia --setop="install_weak_deps=False" --exclude=PackageKit-gstreamer-plugin

# Flatpak applications
flatpak install flathub org.wireshark.Wireshark
```

### Arch Linux Specific

```bash
# Install AUR helper
git clone https://aur.archlinux.org/yay.git
cd yay
makepkg -si

# Install from AUR
yay -S autopsy-bin
yay -S volatility3

# Keep system updated
sudo pacman -Syu
```

### CentOS/RHEL Specific

```bash
# Enable EPEL repository
sudo dnf install -y epel-release

# For development tools
sudo dnf groupinstall -y "Development Tools"

# Install from source when packages unavailable
wget https://source-url.tar.gz
tar -xzf package.tar.gz
cd package
./configure && make && sudo make install
```

---

## 🔄 Daily Workflow Script

Create a comprehensive startup script:

```bash
# Create the script
cat > ~/start_csci347.sh << 'EOF'
#!/bin/bash

echo "🛡️  Starting CSCI 347 Linux Environment..."

# Check if running as root (shouldn't be)
if [ "$EUID" -eq 0 ]; then
    echo "❌ Don't run this script as root!"
    exit 1
fi

# Navigate to course directory
COURSE_DIR="$HOME/csci347_f25"
if [ ! -d "$COURSE_DIR" ]; then
    echo "❌ Course directory not found: $COURSE_DIR"
    echo "Please clone the repository first"
    exit 1
fi

cd "$COURSE_DIR"

# Activate virtual environment
if [ ! -f "venv/bin/activate" ]; then
    echo "❌ Virtual environment not found. Creating it..."
    python3 -m venv venv
fi

source venv/bin/activate

# System status
echo "✅ Virtual environment activated"
echo "📁 Current directory: $(pwd)"
echo "🐍 Python version: $(python --version)"
echo "📦 Packages installed: $(pip list | wc -l) packages"
echo "💻 System: $(uname -sr)"
echo "🔧 Git status: $(git status --porcelain | wc -l) modified files"
echo ""

# Check for system updates (optional)
if command -v apt &> /dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
    if [ $UPDATES -gt 1 ]; then
        echo "📦 $((UPDATES-1)) system updates available (run 'sudo apt upgrade')"
    fi
fi

echo "Ready for Network Security and Digital Forensics work! 🔐"

# Start a new shell with the environment
exec $SHELL
EOF

# Make executable
chmod +x ~/start_csci347.sh

# Create desktop shortcut (for GUI environments)
cat > ~/Desktop/CSCI347.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=CSCI 347 Environment
Comment=Start CSCI 347 development environment
Exec=gnome-terminal -- bash -c "~/start_csci347.sh"
Icon=utilities-terminal
Terminal=false
StartupNotify=true
EOF

chmod +x ~/Desktop/CSCI347.desktop
```

---

## 🆘 Getting Help

### Linux-Specific Resources

1. **Man pages**: `man command_name` for detailed documentation
2. **Info pages**: `info command_name` for additional information
3. **Distribution forums**: Ubuntu Forums, Fedora Discussion, Arch Wiki
4. **Stack Overflow**: Tagged with your specific distribution

### Log Files for Troubleshooting

```bash
# System logs
journalctl -xe           # Recent system logs
dmesg | tail            # Kernel messages
/var/log/syslog         # System messages (Ubuntu/Debian)
/var/log/messages       # System messages (Fedora/CentOS)

# Package installation logs
/var/log/apt/history.log      # Ubuntu/Debian
/var/log/dnf.log             # Fedora
```

### Professional Linux Security Resources

- **Linux Security Wiki**: Documentation and best practices
- **CIS Benchmarks**: Security configuration guidelines
- **NIST Cybersecurity Framework**: Federal security standards
- **Red Hat Security Guide**: Enterprise Linux security

---

**Next Steps**: Your Linux environment is optimized for CSCI 347. The combination of native tools and Python packages gives you powerful capabilities for network security and digital forensics work!