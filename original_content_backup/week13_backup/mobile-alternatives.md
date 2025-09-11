# 📱 Mobile Forensics Without Physical Devices

**Course**: CSCI 347 - Week 13 Mobile Forensics  
**Purpose**: Complete mobile forensics learning without physical Android/iOS devices

---

## 🎯 Overview

Not everyone has access to spare mobile devices for forensic analysis. This guide provides complete alternatives using emulators, sample data, and cloud resources to achieve all Week 13 learning objectives.

---

## 📲 Option 1: Android Emulator (Recommended)

### Setup Android Studio Emulator (Free)

**Time Required**: 30 minutes  
**Disk Space**: 10GB  
**RAM Required**: 8GB minimum

#### Step 1: Install Android Studio
```bash
# Download from https://developer.android.com/studio
# Choose your OS version
# Run installer with default options
```

#### Step 2: Create Virtual Device
```bash
# In Android Studio:
1. Tools → AVD Manager
2. Create Virtual Device
3. Choose: Pixel 4 (or any device)
4. System Image: Android 11 (API 30)
5. Name: ForensicsDevice
6. Advanced: Enable root access
```

#### Step 3: Configure for Forensics
```bash
# Enable Developer Options in emulator
1. Settings → About → Build Number (tap 7 times)
2. Settings → Developer Options → Enable
3. Enable USB Debugging
4. Enable Root Access

# Connect with ADB
adb devices
# Should show: emulator-5554 device

# Get root access
adb root
adb shell
# Should show: root@generic_x86:/#
```

### Forensic Analysis on Emulator

#### Extract Data
```python
import subprocess
import os
from pathlib import Path

class EmulatorForensics:
    def __init__(self):
        self.device_id = "emulator-5554"
        self.output_dir = Path("emulator_forensics")
        self.output_dir.mkdir(exist_ok=True)
    
    def extract_sms_database(self):
        """Extract SMS database from emulator"""
        # Pull SMS database
        cmd = [
            "adb", "-s", self.device_id, "pull",
            "/data/data/com.android.providers.telephony/databases/mmssms.db",
            str(self.output_dir / "mmssms.db")
        ]
        subprocess.run(cmd)
        print(f"SMS database extracted to {self.output_dir}/mmssms.db")
    
    def extract_contacts(self):
        """Extract contacts database"""
        cmd = [
            "adb", "-s", self.device_id, "pull",
            "/data/data/com.android.providers.contacts/databases/contacts2.db",
            str(self.output_dir / "contacts2.db")
        ]
        subprocess.run(cmd)
        print(f"Contacts extracted to {self.output_dir}/contacts2.db")
    
    def extract_call_logs(self):
        """Extract call log database"""
        # Call logs are in contacts2.db
        print("Call logs included in contacts2.db")
    
    def create_test_data(self):
        """Generate test data in emulator"""
        
        # Send test SMS
        subprocess.run([
            "adb", "shell", "am", "start", "-a", "android.intent.action.SENDTO",
            "-d", "sms:5551234567", "--es", "sms_body", "Test forensic message"
        ])
        
        # Add test contact
        subprocess.run([
            "adb", "shell", "am", "start", "-a", "android.intent.action.INSERT",
            "-t", "vnd.android.cursor.dir/contact",
            "-e", "name", "John Doe",
            "-e", "phone", "5551234567"
        ])
        
        print("Test data created in emulator")
    
    def full_extraction(self):
        """Perform complete forensic extraction"""
        print("Starting emulator forensic extraction...")
        
        # Create test data first
        self.create_test_data()
        
        # Extract databases
        self.extract_sms_database()
        self.extract_contacts()
        
        # Extract installed apps
        result = subprocess.run(
            ["adb", "shell", "pm", "list", "packages"],
            capture_output=True, text=True
        )
        
        with open(self.output_dir / "installed_apps.txt", "w") as f:
            f.write(result.stdout)
        
        print(f"Extraction complete! Check {self.output_dir} folder")

# Usage
forensics = EmulatorForensics()
forensics.full_extraction()
```

---

## 💾 Option 2: Pre-Provided Sample Data

### Download Course Sample Data

We provide sanitized mobile forensic datasets for analysis without needing devices:

#### Available Datasets
```python
# sample_datasets.py
MOBILE_DATASETS = {
    "android_sample_1": {
        "description": "Samsung Galaxy S10 - Corporate breach investigation",
        "contains": ["SMS", "Contacts", "WhatsApp", "Browser History", "Photos"],
        "size": "250MB",
        "download": "course_resources/android_sample_1.zip"
    },
    "ios_backup_1": {
        "description": "iPhone 12 - Data exfiltration case",
        "contains": ["iMessage", "Call Logs", "Safari", "Photos", "Apps"],
        "size": "500MB",
        "download": "course_resources/ios_backup_1.zip"
    },
    "mixed_device_case": {
        "description": "Multi-device investigation scenario",
        "contains": ["Android + iOS data", "Cloud sync data", "Cross-platform messages"],
        "size": "750MB",
        "download": "course_resources/mixed_case.zip"
    }
}
```

### Working with Sample Data

#### Analyze Android Sample
```python
import sqlite3
import json
from datetime import datetime

class SampleDataAnalysis:
    def __init__(self, sample_path):
        self.sample_path = Path(sample_path)
    
    def analyze_sms(self):
        """Analyze SMS from sample database"""
        db_path = self.sample_path / "data" / "mmssms.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all SMS messages
        cursor.execute("""
            SELECT address, body, date, type 
            FROM sms 
            ORDER BY date DESC
        """)
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                "number": row[0],
                "content": row[1],
                "timestamp": datetime.fromtimestamp(row[2]/1000).isoformat(),
                "type": "sent" if row[3] == 2 else "received"
            })
        
        conn.close()
        return messages
    
    def analyze_whatsapp(self):
        """Analyze WhatsApp from sample"""
        wa_db = self.sample_path / "data" / "whatsapp" / "msgstore.db"
        
        if not wa_db.exists():
            # Use decrypted sample
            wa_db = self.sample_path / "data" / "whatsapp_decrypted.db"
        
        conn = sqlite3.connect(wa_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT key_remote_jid, data, timestamp, key_from_me 
            FROM messages 
            WHERE data IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                "chat": row[0],
                "message": row[1],
                "timestamp": datetime.fromtimestamp(row[2]/1000).isoformat(),
                "sent": bool(row[3])
            })
        
        conn.close()
        return messages
    
    def generate_timeline(self):
        """Create forensic timeline from all sources"""
        timeline = []
        
        # Add SMS events
        for sms in self.analyze_sms():
            timeline.append({
                "time": sms["timestamp"],
                "source": "SMS",
                "event": f"SMS {sms['type']}: {sms['content'][:50]}..."
            })
        
        # Add WhatsApp events
        for wa in self.analyze_whatsapp():
            timeline.append({
                "time": wa["timestamp"],
                "source": "WhatsApp",
                "event": f"Message in {wa['chat']}: {wa['message'][:50]}..."
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["time"])
        
        return timeline

# Usage with sample data
analyzer = SampleDataAnalysis("samples/android_sample_1")
sms_messages = analyzer.analyze_sms()
timeline = analyzer.generate_timeline()

print(f"Found {len(sms_messages)} SMS messages")
print(f"Generated timeline with {len(timeline)} events")
```

---

## ☁️ Option 3: Cloud-Based Analysis

### Use Google Colab (Free)

Google Colab provides free cloud computing for mobile forensics analysis:

#### Setup Colab Notebook
```python
# mobile_forensics_colab.ipynb

# Cell 1: Environment Setup
!pip install python-adb
!pip install androguard
!pip install iphone_backup_decrypt

# Cell 2: Download Sample Data
!wget https://course.example.com/samples/android_sample.zip
!unzip android_sample.zip

# Cell 3: Analysis Functions
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

def analyze_mobile_data(data_path):
    """Complete mobile forensics analysis in cloud"""
    # Your analysis code here
    pass

# Cell 4: Visualization
def visualize_communications(data):
    """Create timeline and relationship graphs"""
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Timeline plot
    plt.figure(figsize=(12, 6))
    plt.scatter(df['timestamp'], df['source'])
    plt.title('Communication Timeline')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
```

**Colab Advantages**:
- No local installation required
- 12GB RAM, 100GB disk space
- GPU available if needed
- Share notebooks with instructor
- Persistent storage in Google Drive

---

## 📦 Option 4: Docker Containers

### Mobile Forensics Docker Environment

```dockerfile
# Dockerfile
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    android-tools-adb \
    sqlite3 \
    git

# Install Python packages
RUN pip3 install \
    androguard \
    python-adb \
    frida \
    objection

# Copy analysis scripts
COPY mobile_forensics/ /forensics/

WORKDIR /forensics

CMD ["/bin/bash"]
```

#### Run Container
```bash
# Build container
docker build -t mobile-forensics .

# Run with sample data mounted
docker run -it \
    -v $(pwd)/samples:/forensics/samples \
    -v $(pwd)/output:/forensics/output \
    mobile-forensics

# Inside container, run analysis
python3 analyze_mobile.py --input /forensics/samples/android_sample
```

---

## 🎮 Option 5: Interactive Simulations

### Web-Based Mobile Forensics Simulator

Access our custom web-based simulator that mimics real mobile forensics:

```javascript
// Available at: https://course.example.com/mobile-simulator

// Features:
- Virtual Android device interface
- Simulated data extraction process
- Interactive database analysis
- Timeline reconstruction tools
- Report generation

// No installation required
// Works in any modern browser
// Includes guided tutorials
```

### Simulator Exercises

1. **SMS Analysis Challenge**
   - Extract messages from virtual device
   - Identify deleted messages
   - Reconstruct conversation threads

2. **App Data Investigation**
   - Analyze WhatsApp backup
   - Decrypt Signal database
   - Extract Instagram messages

3. **Timeline Correlation**
   - Combine multiple data sources
   - Identify patterns
   - Generate forensic timeline

---

## 📊 Comparison of Alternatives

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **Emulator** | Full Android experience, Root access | Resource intensive, Setup time | Complete learning |
| **Sample Data** | No setup, Real case data | Limited interaction | Quick analysis practice |
| **Cloud (Colab)** | No local resources, Shareable | Internet required | Collaboration |
| **Docker** | Consistent environment, Portable | Docker knowledge needed | Advanced users |
| **Simulator** | Browser-based, Guided | Limited features | Beginners |

---

## 🎯 Learning Objectives Achievement

Regardless of method chosen, you will achieve all Week 13 objectives:

### ✅ Can Do With Alternatives
- Mobile device data extraction *(using samples or emulator)*
- SMS/MMS analysis *(all methods)*
- Application data forensics *(samples provide real data)*
- Timeline reconstruction *(identical to physical devices)*
- Mobile malware analysis *(samples include malware)*
- Report generation *(same process)*
- Legal considerations *(theoretical, no difference)*

### ⚠️ Limitations
- Physical acquisition *(but logical is sufficient for course)*
- Hardware-specific exploits *(covered theoretically)*
- Latest device models *(samples cover common scenarios)*

---

## 💻 Assignment Modifications

If using alternatives, note in your submission:

```markdown
## Assignment Submission Note

**Analysis Method Used**: Android Emulator / Sample Data / Cloud Analysis
**Reason**: No access to physical test device
**Data Source**: [Specify emulator version or sample dataset used]

All learning objectives have been met using the alternative method.
Analysis results are equivalent to physical device forensics.
```

---

## 🛠️ Troubleshooting

### Common Issues with Alternatives

#### Emulator Won't Start
```bash
# Increase RAM allocation
emulator -avd ForensicsDevice -memory 2048

# Use software rendering
emulator -avd ForensicsDevice -gpu swiftshader_indirect
```

#### Sample Data Corrupted
```python
# Verify integrity
import hashlib

def verify_sample(filepath, expected_hash):
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash

# Check provided hashes
if not verify_sample('sample.zip', 'abc123...'):
    print("Re-download sample data")
```

#### Colab Session Timeout
```python
# Keep session alive
import time
from IPython.display import display, Javascript

def keep_alive():
    while True:
        time.sleep(60)
        display(Javascript(''))

# Run in background thread
import threading
thread = threading.Thread(target=keep_alive)
thread.daemon = True
thread.start()
```

---

## 📚 Additional Resources

### Video Tutorials
- "Android Emulator Forensics" - Course YouTube
- "Analyzing iOS Backups Without iPhone" - Tutorial
- "Mobile Forensics in the Cloud" - Workshop recording

### Practice Datasets
- NIST Mobile Forensics Dataset
- Digital Corpora Phone Images
- ForGe Mobile Samples

### Online Tools
- SQLite Browser (web version)
- Online PLIST viewer
- Hex editor online

---

## ✅ Validation Checklist

Before submitting your assignment, ensure:

- [ ] All required data types analyzed (SMS, Calls, Apps)
- [ ] Timeline successfully reconstructed
- [ ] Evidence properly documented
- [ ] Chain of custody maintained (even for samples)
- [ ] Report includes methodology description
- [ ] Screenshots/outputs included as proof
- [ ] Alternative method clearly stated

---

## 🎓 Final Note

Using alternatives does not diminish your learning or grades. The forensic methodology, analysis techniques, and critical thinking skills are identical whether using physical devices or alternatives. Focus on the process, not the device!

**Remember**: Many professional forensic investigators work primarily with provided images and samples rather than physical devices. You're learning real-world applicable skills!