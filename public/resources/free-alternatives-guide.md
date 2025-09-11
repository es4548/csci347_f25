# 📚 Free Resource Alternatives Guide

**Course**: CSCI 347 - Network Security and Digital Forensics  
**Purpose**: Free alternatives to paid/restricted resources

---

## 🔓 ISO Standard Free Alternatives

### ISO/IEC 27037 → Free Alternative Resources

**Original**: ISO/IEC 27037:2012 - Guidelines for identification, collection, acquisition and preservation of digital evidence  
**Cost**: $200+ from ISO  
**Free Alternatives**:

#### Option 1: SWGDE Guidelines (Scientific Working Group on Digital Evidence)
- **URL**: https://www.swgde.org/documents
- **Specific Documents**:
  - SWGDE Best Practices for Computer Forensic Acquisitions
  - SWGDE Best Practices for Mobile Device Forensics
  - SWGDE Best Practices for Digital Evidence Collection
- **Coverage**: 100% of ISO 27037 concepts with US legal focus

#### Option 2: NIST Special Publications (Free)
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
  - https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
- **NIST SP 800-101**: Guidelines on Mobile Device Forensics
  - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf
- **Coverage**: Comprehensive forensics methodology equivalent to ISO standards

#### Option 3: ACPO Good Practice Guide
- **Document**: Association of Chief Police Officers - Digital Evidence Guide
- **URL**: https://www.digital-detective.net/digital-forensics-documents/ACPO_Good_Practice_Guide_for_Digital_Evidence_v5.pdf
- **Coverage**: UK/European perspective, very similar to ISO 27037

#### Option 4: RFC 3227 (Already Free)
- **Title**: Guidelines for Evidence Collection and Archiving
- **URL**: https://www.ietf.org/rfc/rfc3227.txt
- **Coverage**: Network forensics and evidence handling

### Comparison Table

| ISO 27037 Topic | Free Alternative | Source |
|-----------------|------------------|---------|
| Evidence Identification | SWGDE Section 2.1 | SWGDE Best Practices |
| Collection Methods | NIST SP 800-86 Ch. 3 | NIST |
| Chain of Custody | RFC 3227 Section 3 | IETF |
| Acquisition Procedures | ACPO Principle 2 | ACPO Guide |
| Preservation Techniques | SWGDE Section 4 | SWGDE |
| Documentation Requirements | NIST SP 800-86 Ch. 4 | NIST |

---

## 📖 Academic Paper Alternatives

### Instead of Paywalled Journals

#### Option 1: ArXiv (Computer Science)
- **URL**: https://arxiv.org/list/cs.CR/recent
- **Content**: Cryptography and Security preprints
- **Quality**: Pre-publication research, cutting-edge

#### Option 2: Google Scholar
- **URL**: https://scholar.google.com
- **Tip**: Click "PDF" links for free versions
- **Filter**: Past year for recent research

#### Option 3: Semantic Scholar
- **URL**: https://www.semanticscholar.org
- **Feature**: AI-powered paper recommendations
- **Benefit**: Often finds free versions

#### Option 4: University Repositories
- **MIT DSpace**: https://dspace.mit.edu
- **Stanford Digital Repository**: https://purl.stanford.edu
- **CMU Research Showcase**: https://kilthub.cmu.edu

#### Option 5: Conference Proceedings (Often Free)
- **USENIX Security**: https://www.usenix.org/conferences/byname/108
- **IEEE Security & Privacy**: Many papers freely available
- **ACM Digital Library**: Open access papers marked

---

## 🛠️ Commercial Tool Alternatives

### Forensics Software

| Commercial Tool | Cost | Free Alternative | Download Link |
|-----------------|------|------------------|---------------|
| EnCase Forensic | $3,000+ | **Autopsy** | https://www.autopsy.com |
| FTK (Forensic Toolkit) | $4,000+ | **CAINE Linux** | https://www.caine-live.net |
| X-Ways Forensics | $1,000+ | **SIFT Workstation** | https://www.sans.org/tools/sift-workstation |
| Magnet AXIOM | $3,000+ | **DEFT Linux** | http://www.deftlinux.net |
| Cellebrite UFED | $15,000+ | **Android Debug Bridge** | https://developer.android.com |

### Memory Forensics

| Commercial Tool | Free Alternative | Features |
|-----------------|------------------|----------|
| Volexity Volcano | **Volatility 3** | Full memory analysis |
| Rekall (discontinued) | **Volatility 3** | Better maintained |
| Mandiant Redline | **Volatility + YARA** | Memory + IOC scanning |

### Network Analysis

| Commercial Tool | Free Alternative | Use Case |
|-----------------|------------------|----------|
| NetworkMiner Pro | **NetworkMiner Free** | Packet analysis |
| Omnipeek | **Wireshark** | Protocol analysis |
| NetWitness | **Security Onion** | NSM platform |
| SolarWinds | **ntopng** | Flow analysis |

### Mobile Forensics

| Commercial Tool | Free Alternative | Platform |
|-----------------|------------------|----------|
| Cellebrite | **ADB + Python** | Android |
| Oxygen Detective | **Andriller** | Android |
| XRY | **libimobiledevice** | iOS |
| BlackBag BlackLight | **iOS Backup Tools** | iOS |

---

## 📚 Textbook Alternatives

### Instead of Expensive Textbooks

#### Digital Forensics
- **"Digital Forensics with Open Source Tools"** - Altheide & Carvey
  - Often available through university library
  - Older edition free: https://www.sciencedirect.com/book/9781597495868

#### Cryptography
- **"Crypto101"** - Laurens Van Houtven
  - Completely free: https://www.crypto101.io
  - Modern, practical approach

#### Network Security
- **"Security Engineering"** - Ross Anderson
  - Free online: https://www.cl.cam.ac.uk/~rja14/book.html
  - Comprehensive security text

#### Incident Response
- **"Applied Incident Response"** - Steve Anson
  - Preview chapters often available
  - SANS Reading Room alternatives: https://www.sans.org/white-papers

---

## 🎓 MOOC Alternatives

### Free Course Materials

#### Coursera (Audit Option)
- **"Introduction to Cyber Security"** - NYU
- **"Digital Forensics"** - University of Maryland
- **Note**: Audit for free, pay only for certificate

#### edX (Free Audit)
- **"Cybersecurity Fundamentals"** - RITx
- **"Computer Forensics"** - RochesterX

#### YouTube University
- **Professor Messer**: Security+ complete course
- **13Cubed**: Digital forensics tutorials
- **IppSec**: Practical security demonstrations

#### Open Courseware
- **MIT OpenCourseWare**: 6.858 Computer Systems Security
- **Stanford Online**: CS155 Computer and Network Security

---

## 🔬 Lab Environment Alternatives

### Instead of Expensive Lab Setup

#### Option 1: Cloud Labs (Free Tier)
```yaml
Google Cloud Platform:
  - 90-day trial: $300 credit
  - Always Free: f1-micro instance
  
AWS Free Tier:
  - 12 months: t2.micro instance
  - 750 hours/month
  
Azure Free Account:
  - $200 credit first 30 days
  - 12 months free services
```

#### Option 2: Virtual Labs
```yaml
VirtualBox: Free virtualization
  - Run multiple VMs
  - Snapshot capability
  - Network simulation

SANS Cyber Ranges: Free exercises
  - https://www.sans.org/ranges

TryHackMe: Free rooms
  - Forensics challenges
  - Browser-based labs
```

#### Option 3: Docker Containers
```bash
# Forensics Lab in Docker
docker pull remnux/remnux-distro
docker run -it --rm remnux/remnux-distro

# Security Tools Suite
docker pull kalilinux/kali-rolling
docker run -it kalilinux/kali-rolling

# Minimal resource usage compared to full VMs
```

---

## 💾 Sample Data Sources

### Free Forensic Images & Datasets

#### Disk Images
- **Digital Corpora**: https://digitalcorpora.org/corpora/disk-images
- **CFReDS**: https://cfreds.nist.gov
- **ForGe**: https://github.com/hannuvisti/forge

#### Memory Dumps
- **Volatility Samples**: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
- **Memory Analysis**: https://www.memoryanalysis.net/amf

#### Network Captures
- **Wireshark Samples**: https://wiki.wireshark.org/SampleCaptures
- **Netresec PCAP**: https://www.netresec.com/index.ashx?page=PcapFiles
- **PacketTotal**: https://packettotal.com/app/search

#### Mobile Forensics
- **Android Dumps**: https://github.com/AndroidDumps
- **iOS Backup Samples**: Available in course resources
- **NIST Mobile Data**: https://www.nist.gov/itl/ssd/software-quality-group

#### Malware Samples (Handle with Care!)
- **VirusTotal**: https://www.virustotal.com (Analysis only)
- **Hybrid Analysis**: https://www.hybrid-analysis.com
- **ANY.RUN**: https://app.any.run (Interactive sandbox)

---

## 🌐 Open Source Intelligence (OSINT)

### Free OSINT Tools for Investigations

#### Domain/IP Investigation
- **Shodan.io**: Free tier available
- **Censys.io**: Academic accounts free
- **VirusTotal**: Free API with limits
- **AbuseIPDB**: Free tier

#### Social Media Analysis
- **TweetDeck**: Twitter analysis
- **Social Searcher**: Multi-platform search
- **Have I Been Pwned**: Breach data

#### Metadata Analysis
- **ExifTool**: Image metadata
- **FOCA**: Document metadata
- **Metagoofil**: Metadata harvesting

---

## 📝 Documentation Templates

### Free Templates for Professional Documentation

#### Forensic Reports
- **SANS DFIR Templates**: https://www.sans.org/score/dfir-templates
- **NIST Templates**: Available with SP 800-86

#### Chain of Custody
- **SWGDE Templates**: https://www.swgde.org/documents
- **Court-tested forms**: Public domain

#### Expert Witness
- **Federal Court Templates**: https://www.uscourts.gov
- **State templates**: Usually public domain

---

## 🔄 Update Schedule

This guide is maintained regularly. Check for updates:
- **ISO alternatives**: Quarterly review
- **Tool alternatives**: Monthly updates
- **Academic resources**: Semester updates
- **Sample data**: As available

---

## 💡 Contribution

Found a great free alternative? Submit a pull request:
1. Fork the course repository
2. Add to this guide
3. Include verification that resource is legally free
4. Submit PR with description

---

## ⚖️ Legal Note

All resources listed here are:
- ✅ Legally free to access
- ✅ Appropriate for educational use
- ✅ Not requiring institutional subscriptions
- ✅ Available globally (unless noted)

When in doubt about legality, use official sources only.

---

## 🆘 Can't Find a Free Alternative?

Contact course instructor for:
- Institutional access codes
- Educational licenses
- Special arrangements
- Alternative assignments

Remember: Financial constraints should never prevent learning. We'll find a solution!