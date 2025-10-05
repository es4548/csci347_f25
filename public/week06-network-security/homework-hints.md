# Week 6 Homework Hints: Network Security Analysis

## 🎯 Quick Start Guide (5 hours total)

### Time Breakdown
- **Traffic Analysis with Provided PCAPs**: 2 hours
- **Firewall Rules Creation**: 1.5 hours
- **IDS Signatures Writing**: 1.5 hours

## 📋 Step-by-Step Implementation

### Step 1: Understanding Network Security Analysis (30 minutes)

**Assignment Focus:**
- **Analyze provided packet captures** (not live capture)
- **Create firewall rules** in iptables format
- **Write IDS signatures** in Snort format
- **Document attack signatures** found in traffic

**Key Concepts:**
- **Traffic Analysis**: Examine packet captures for threats
- **Firewall Rules**: Block/allow traffic based on patterns
- **IDS Signatures**: Detect known attack patterns
- **Attack Documentation**: Record findings and evidence

### Step 2: Environment Setup (15 minutes)

```bash
pip install scapy pandas matplotlib

mkdir week06-network-analysis
cd week06-network-analysis
mkdir screenshots

touch network_analysis.py
touch firewall_rules.txt
touch ids_rules.txt
touch analysis_report.md
```

### Step 3: Packet Capture Analysis (90 minutes)

**Assignment Requirement**: Analyze provided packet captures

```python
# network_analysis.py
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
from datetime import datetime
import json

class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.findings = {
            'normal_traffic': [],
            'anomalous_behavior': [],
            'security_violations': [],
            'attack_signatures': []
        }

    def load_pcap(self):
        """Load packet capture file"""
        print(f"📄 Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"✅ Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"❌ Error loading PCAP: {e}")
            return False

    def analyze_traffic_patterns(self):
        """Identify normal vs anomalous traffic patterns"""
        print("\n🔍 Analyzing Traffic Patterns...")

        # Basic statistics
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        dst_ports = Counter()
        packet_sizes = []

        for packet in self.packets:
            # Protocol analysis
            if packet.haslayer(IP):
                protocols[packet[IP].proto] += 1
                src_ips[packet[IP].src] += 1
                dst_ips[packet[IP].dst] += 1
                packet_sizes.append(len(packet))

            # Port analysis
            if packet.haslayer(TCP):
                dst_ports[packet[TCP].dport] += 1
            elif packet.haslayer(UDP):
                dst_ports[packet[UDP].dport] += 1

        # Identify normal patterns
        normal_patterns = {
            'common_protocols': protocols.most_common(3),
            'typical_ports': [p for p, c in dst_ports.most_common(10) if p in [80, 443, 53, 22]],
            'average_packet_size': sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        }

        self.findings['normal_traffic'].append({
            'description': 'Baseline traffic patterns',
            'patterns': normal_patterns
        })

        # Detect anomalies
        self.detect_anomalies(src_ips, dst_ports, packet_sizes)

    def detect_anomalies(self, src_ips, dst_ports, packet_sizes):
        """Detect anomalous behavior patterns"""

        # Anomaly 1: Unusual source IP activity
        for ip, count in src_ips.most_common(5):
            if count > len(self.packets) * 0.1:  # More than 10% of traffic
                self.findings['anomalous_behavior'].append({
                    'type': 'high_volume_source',
                    'details': f"IP {ip} generated {count} packets ({count/len(self.packets)*100:.1f}% of traffic)",
                    'evidence': f"Source IP: {ip}, Packet count: {count}"
                })

        # Anomaly 2: Port scanning indicators
        port_scan_ips = {}
        for packet in self.packets:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport

                if src_ip not in port_scan_ips:
                    port_scan_ips[src_ip] = set()
                port_scan_ips[src_ip].add(dst_port)

        for ip, ports in port_scan_ips.items():
            if len(ports) > 10:  # Contacted many different ports
                self.findings['anomalous_behavior'].append({
                    'type': 'potential_port_scan',
                    'details': f"IP {ip} contacted {len(ports)} different ports",
                    'evidence': f"Ports: {sorted(list(ports))[:20]}"  # Show first 20
                })

        # Anomaly 3: Unusual packet sizes
        large_packets = [size for size in packet_sizes if size > 1400]
        if large_packets:
            self.findings['anomalous_behavior'].append({
                'type': 'large_packets',
                'details': f"Found {len(large_packets)} packets > 1400 bytes",
                'evidence': f"Sizes: {large_packets[:10]}"  # Show first 10
            })

    def detect_security_violations(self):
        """Find security violations and attack patterns"""
        print("\n🛡️ Detecting Security Violations...")

        for packet in self.packets:
            # Check for suspicious payloads
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # SQL Injection patterns
                sql_patterns = ['union select', 'or 1=1', 'drop table', '; --', "' or '1'='1"]
                for pattern in sql_patterns:
                    if pattern.lower() in payload.lower():
                        self.findings['security_violations'].append({
                            'type': 'sql_injection_attempt',
                            'packet_info': self.get_packet_info(packet),
                            'pattern': pattern,
                            'payload_sample': payload[:100]
                        })

                # XSS patterns
                xss_patterns = ['<script>', 'javascript:', 'alert(', 'document.cookie']
                for pattern in xss_patterns:
                    if pattern.lower() in payload.lower():
                        self.findings['security_violations'].append({
                            'type': 'xss_attempt',
                            'packet_info': self.get_packet_info(packet),
                            'pattern': pattern,
                            'payload_sample': payload[:100]
                        })

                # Directory traversal
                if '../' in payload or '..\\' in payload:
                    self.findings['security_violations'].append({
                        'type': 'directory_traversal',
                        'packet_info': self.get_packet_info(packet),
                        'payload_sample': payload[:100]
                    })

            # Check for brute force indicators
            if packet.haslayer(TCP) and packet.haslayer(IP):
                # SSH brute force (port 22)
                if packet[TCP].dport == 22:
                    self.findings['security_violations'].append({
                        'type': 'ssh_connection_attempt',
                        'packet_info': self.get_packet_info(packet),
                        'note': 'Potential brute force if multiple failures from same IP'
                    })

                # HTTP login attempts
                if packet[TCP].dport in [80, 443] and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'login' in payload.lower() or 'password' in payload.lower():
                        self.findings['security_violations'].append({
                            'type': 'http_login_attempt',
                            'packet_info': self.get_packet_info(packet),
                            'payload_sample': payload[:100]
                        })

    def get_packet_info(self, packet):
        """Extract key information from packet"""
        info = {'timestamp': packet.time}

        if packet.haslayer(IP):
            info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto
            })

        if packet.haslayer(TCP):
            info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'flags': packet[TCP].flags
            })
        elif packet.haslayer(UDP):
            info.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })

        return info

    def document_attack_signatures(self):
        """Document identified attack signatures"""
        print("\n📋 Documenting Attack Signatures...")

        # Group findings by attack type
        attack_types = defaultdict(list)

        for violation in self.findings['security_violations']:
            attack_types[violation['type']].append(violation)

        for attack_type, instances in attack_types.items():
            signature = {
                'attack_type': attack_type,
                'instances_found': len(instances),
                'signature_pattern': self.create_signature_pattern(attack_type, instances),
                'severity': self.assess_severity(attack_type, len(instances)),
                'recommendations': self.get_recommendations(attack_type)
            }

            self.findings['attack_signatures'].append(signature)

    def create_signature_pattern(self, attack_type, instances):
        """Create detection pattern for attack type"""
        patterns = {
            'sql_injection_attempt': 'content: contains "union select", "or 1=1", "drop table"',
            'xss_attempt': 'content: contains "<script>", "javascript:", "alert("',
            'directory_traversal': 'content: contains "../", "..\\"',
            'ssh_connection_attempt': 'dst_port: 22; flags: S',
            'http_login_attempt': 'dst_port: 80,443; content: contains "login", "password"'
        }
        return patterns.get(attack_type, 'Pattern analysis needed')

    def assess_severity(self, attack_type, instance_count):
        """Assess severity based on attack type and frequency"""
        severity_map = {
            'sql_injection_attempt': 'HIGH',
            'xss_attempt': 'MEDIUM',
            'directory_traversal': 'HIGH',
            'ssh_connection_attempt': 'MEDIUM' if instance_count < 10 else 'HIGH',
            'http_login_attempt': 'LOW' if instance_count < 5 else 'MEDIUM'
        }
        return severity_map.get(attack_type, 'MEDIUM')

    def get_recommendations(self, attack_type):
        """Get security recommendations for attack type"""
        recommendations = {
            'sql_injection_attempt': [
                'Implement input validation and parameterized queries',
                'Deploy web application firewall (WAF)',
                'Regular security code reviews'
            ],
            'xss_attempt': [
                'Implement output encoding',
                'Content Security Policy (CSP)',
                'Input validation'
            ],
            'directory_traversal': [
                'Input validation and sanitization',
                'Access controls and file permissions',
                'Chroot jail for web applications'
            ],
            'ssh_connection_attempt': [
                'Implement fail2ban',
                'Use key-based authentication',
                'Change default SSH port'
            ],
            'http_login_attempt': [
                'Implement account lockout policies',
                'Multi-factor authentication',
                'Rate limiting'
            ]
        }
        return recommendations.get(attack_type, ['Review and update security policies'])

    def generate_visualizations(self):
        """Create traffic analysis visualizations"""
        print("\n📈 Generating Visualizations...")

        # Extract data for visualization
        timestamps = [packet.time for packet in self.packets]
        protocols = []
        packet_sizes = []

        for packet in self.packets:
            packet_sizes.append(len(packet))
            if packet.haslayer(IP):
                protocols.append(packet[IP].proto)

        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))

        # 1. Traffic timeline
        ax1.plot(timestamps, packet_sizes, 'b.', alpha=0.6)
        ax1.set_title('Packet Size Over Time')
        ax1.set_xlabel('Timestamp')
        ax1.set_ylabel('Packet Size (bytes)')

        # 2. Protocol distribution
        protocol_counts = Counter(protocols)
        ax2.pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%')
        ax2.set_title('Protocol Distribution')

        # 3. Packet size histogram
        ax3.hist(packet_sizes, bins=50, alpha=0.7)
        ax3.set_title('Packet Size Distribution')
        ax3.set_xlabel('Packet Size (bytes)')
        ax3.set_ylabel('Frequency')

        # 4. Top destination ports
        dst_ports = []
        for packet in self.packets:
            if packet.haslayer(TCP):
                dst_ports.append(packet[TCP].dport)
            elif packet.haslayer(UDP):
                dst_ports.append(packet[UDP].dport)

        port_counts = Counter(dst_ports).most_common(10)
        if port_counts:
            ports, counts = zip(*port_counts)
            ax4.bar(range(len(ports)), counts)
            ax4.set_title('Top Destination Ports')
            ax4.set_xlabel('Port')
            ax4.set_ylabel('Packet Count')
            ax4.set_xticks(range(len(ports)))
            ax4.set_xticklabels(ports, rotation=45)

        plt.tight_layout()
        plt.savefig('screenshots/traffic_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()

        print("📊 Visualization saved to screenshots/traffic_analysis.png")

    def save_analysis_report(self):
        """Save detailed analysis report"""
        print("\n💾 Saving Analysis Report...")

        with open('analysis_report.md', 'w') as f:
            f.write("# Network Security Analysis Report\n\n")
            f.write(f"**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**PCAP File**: {self.pcap_file}\n")
            f.write(f"**Total Packets**: {len(self.packets)}\n\n")

            # Normal traffic patterns
            f.write("## Normal Traffic Patterns\n\n")
            for pattern in self.findings['normal_traffic']:
                f.write(f"- **{pattern['description']}**\n")
                f.write(f"  - Common protocols: {pattern['patterns']['common_protocols']}\n")
                f.write(f"  - Typical ports: {pattern['patterns']['typical_ports']}\n")
                f.write(f"  - Average packet size: {pattern['patterns']['average_packet_size']:.1f} bytes\n\n")

            # Anomalous behavior
            f.write("## Anomalous Behavior\n\n")
            for anomaly in self.findings['anomalous_behavior']:
                f.write(f"- **{anomaly['type']}**: {anomaly['details']}\n")
                f.write(f"  - Evidence: {anomaly['evidence']}\n\n")

            # Security violations
            f.write("## Security Violations\n\n")
            for violation in self.findings['security_violations']:
                f.write(f"- **{violation['type']}**\n")
                if 'packet_info' in violation:
                    info = violation['packet_info']
                    f.write(f"  - Source: {info.get('src_ip', 'unknown')}\n")
                    f.write(f"  - Destination: {info.get('dst_ip', 'unknown')}\n")
                    f.write(f"  - Port: {info.get('dst_port', 'unknown')}\n")
                if 'payload_sample' in violation:
                    f.write(f"  - Payload sample: `{violation['payload_sample']}`\n")
                f.write("\n")

            # Attack signatures
            f.write("## Attack Signatures\n\n")
            for signature in self.findings['attack_signatures']:
                f.write(f"### {signature['attack_type']}\n")
                f.write(f"- **Instances found**: {signature['instances_found']}\n")
                f.write(f"- **Severity**: {signature['severity']}\n")
                f.write(f"- **Detection pattern**: {signature['signature_pattern']}\n")
                f.write("- **Recommendations**:\n")
                for rec in signature['recommendations']:
                    f.write(f"  - {rec}\n")
                f.write("\n")

        print("✅ Analysis report saved to analysis_report.md")

def main():
    # Example usage with provided PCAP file
    pcap_file = "sample_traffic.pcap"  # Replace with actual provided file

    analyzer = PacketAnalyzer(pcap_file)

    if analyzer.load_pcap():
        analyzer.analyze_traffic_patterns()
        analyzer.detect_security_violations()
        analyzer.document_attack_signatures()
        analyzer.generate_visualizations()
        analyzer.save_analysis_report()

        print("\n✅ Analysis complete! Check the following files:")
        print("   - analysis_report.md: Detailed findings")
        print("   - screenshots/traffic_analysis.png: Visualizations")

if __name__ == "__main__":
    main()
```

### Step 4: Firewall Rules Creation (45 minutes)

**Assignment Requirement**: Create firewall rules in iptables format

```python
# Create firewall_rules.txt based on analysis findings

def generate_firewall_rules(analysis_findings):
    """Generate iptables firewall rules based on traffic analysis"""

    rules = []

    # Basic default policies
    rules.append("# Default firewall policies")
    rules.append("iptables -P INPUT DROP")
    rules.append("iptables -P FORWARD DROP")
    rules.append("iptables -P OUTPUT ACCEPT")
    rules.append("")

    # Allow loopback traffic
    rules.append("# Allow loopback traffic")
    rules.append("iptables -A INPUT -i lo -j ACCEPT")
    rules.append("iptables -A OUTPUT -o lo -j ACCEPT")
    rules.append("")

    # Allow established connections
    rules.append("# Allow established and related connections")
    rules.append("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    rules.append("")

    # Allow legitimate services
    rules.append("# Allow legitimate services")
    rules.append("iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min -j ACCEPT")  # SSH with rate limiting
    rules.append("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")   # HTTP
    rules.append("iptables -A INPUT -p tcp --dport 443 -j ACCEPT")  # HTTPS
    rules.append("iptables -A INPUT -p udp --dport 53 -j ACCEPT")   # DNS
    rules.append("")

    # Block common attack patterns based on analysis
    rules.append("# Block common attack patterns")

    # Block port scanning attempts
    rules.append("# Block port scanning")
    rules.append("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
    rules.append("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
    rules.append("iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP")
    rules.append("iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP")
    rules.append("")

    # Rate limiting for brute force protection
    rules.append("# Brute force protection")
    rules.append("iptables -A INPUT -p tcp --dport 22 -m recent --name ssh_attack --set")
    rules.append("iptables -A INPUT -p tcp --dport 22 -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 4 -j DROP")
    rules.append("")

    # Block suspicious IP addresses (example from analysis)
    if 'anomalous_behavior' in analysis_findings:
        rules.append("# Block suspicious IP addresses identified in analysis")
        for anomaly in analysis_findings['anomalous_behavior']:
            if anomaly['type'] == 'high_volume_source':
                # Extract IP from evidence string
                ip = anomaly['evidence'].split(':')[1].split(',')[0].strip()
                rules.append(f"iptables -A INPUT -s {ip} -j DROP")
        rules.append("")

    # Log suspicious activity
    rules.append("# Log suspicious activity")
    rules.append("iptables -A INPUT -p tcp --dport 1337 -j LOG --log-prefix 'BACKDOOR_ATTEMPT: '")
    rules.append("iptables -A INPUT -p tcp --dport 4444 -j LOG --log-prefix 'BACKDOOR_ATTEMPT: '")
    rules.append("iptables -A INPUT -p tcp --dport 31337 -j LOG --log-prefix 'BACKDOOR_ATTEMPT: '")
    rules.append("")

    # Block common backdoor ports
    rules.append("# Block common backdoor ports")
    backdoor_ports = [1337, 4444, 5555, 31337, 12345]
    for port in backdoor_ports:
        rules.append(f"iptables -A INPUT -p tcp --dport {port} -j DROP")
        rules.append(f"iptables -A INPUT -p udp --dport {port} -j DROP")
    rules.append("")

    # DDoS protection
    rules.append("# DDoS protection")
    rules.append("iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT")
    rules.append("iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT")
    rules.append("")

    # Log and drop everything else
    rules.append("# Log and drop everything else")
    rules.append("iptables -A INPUT -j LOG --log-prefix 'DROPPED: '")
    rules.append("iptables -A INPUT -j DROP")

    return rules

# Save firewall rules to file
def save_firewall_rules():
    """Generate and save firewall rules based on common threats"""
    # Simulate analysis findings for rule generation
    mock_findings = {
        'anomalous_behavior': [
            {
                'type': 'high_volume_source',
                'evidence': 'Source IP: 192.168.1.100, Packet count: 5000'
            }
        ]
    }

    rules = generate_firewall_rules(mock_findings)

    with open('firewall_rules.txt', 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Network Security Firewall Rules\n")
        f.write("# Generated based on traffic analysis findings\n\n")

        for rule in rules:
            f.write(rule + '\n')

    print("✅ Firewall rules saved to firewall_rules.txt")

if __name__ == "__main__":
    save_firewall_rules()
```

### Step 5: IDS Signatures Creation (45 minutes)

**Assignment Requirement**: Write Snort-compatible rules

```python
# Create ids_rules.txt with Snort-compatible signatures

def generate_ids_signatures():
    """Generate Snort-compatible IDS rules based on common attacks"""

    signatures = []

    # Header comment
    signatures.append("# Network Security IDS Rules")
    signatures.append("# Snort-compatible signatures for common attacks")
    signatures.append("# Generated based on traffic analysis findings")
    signatures.append("")

    # Port scan detection
    signatures.append("# Port scan detection")
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"Possible TCP port scan"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"TCP SYN flood"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1002; rev:1;)')
    signatures.append("")

    # SQL injection detection
    signatures.append("# SQL injection detection")
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"SQL injection attempt - UNION SELECT"; content:"union"; nocase; content:"select"; nocase; distance:0; within:20; sid:2001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"SQL injection attempt - OR 1=1"; content:"or"; nocase; content:"1=1"; nocase; distance:0; within:10; sid:2002; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"SQL injection attempt - DROP TABLE"; content:"drop"; nocase; content:"table"; nocase; distance:0; within:15; sid:2003; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 443 (msg:"HTTPS SQL injection attempt"; content:"union"; nocase; content:"select"; nocase; distance:0; within:20; sid:2004; rev:1;)')
    signatures.append("")

    # Brute force detection
    signatures.append("# Brute force attack detection")
    signatures.append('alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force attempt"; content:"SSH"; threshold:type both, track by_src, count 5, seconds 300; sid:3001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 21 (msg:"FTP brute force attempt"; content:"USER"; threshold:type both, track by_src, count 10, seconds 300; sid:3002; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"HTTP login brute force"; content:"login"; nocase; threshold:type both, track by_src, count 10, seconds 300; sid:3003; rev:1;)')
    signatures.append("")

    # Data exfiltration detection
    signatures.append("# Data exfiltration detection")
    signatures.append('alert tcp $HOME_NET any -> !$HOME_NET any (msg:"Large outbound data transfer"; dsize:>1000; threshold:type both, track by_src, count 100, seconds 60; sid:4001; rev:1;)')
    signatures.append('alert tcp $HOME_NET any -> !$HOME_NET 443 (msg:"Suspicious HTTPS upload"; flow:to_server; dsize:>500; threshold:type both, track by_src, count 50, seconds 300; sid:4002; rev:1;)')
    signatures.append("")

    # Web application attacks
    signatures.append("# Web application attacks")
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"XSS attempt - script tag"; content:"<script"; nocase; sid:5001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"XSS attempt - javascript"; content:"javascript:"; nocase; sid:5002; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"Directory traversal attempt"; content:"../"; sid:5003; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 80 (msg:"Command injection attempt"; content:"|3B|"; content:"cat"; distance:0; within:10; sid:5004; rev:1;)')
    signatures.append("")

    # Backdoor and malware detection
    signatures.append("# Backdoor and malware detection")
    signatures.append('alert tcp any any -> $HOME_NET 1337 (msg:"Backdoor connection attempt - port 1337"; sid:6001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 4444 (msg:"Backdoor connection attempt - port 4444"; sid:6002; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET 31337 (msg:"Backdoor connection attempt - port 31337"; sid:6003; rev:1;)')
    signatures.append('alert tcp any any -> any 6667 (msg:"IRC connection - possible botnet"; content:"NICK"; sid:6004; rev:1;)')
    signatures.append("")

    # Network reconnaissance
    signatures.append("# Network reconnaissance")
    signatures.append('alert icmp any any -> $HOME_NET any (msg:"ICMP ping sweep"; itype:8; threshold:type both, track by_src, count 10, seconds 10; sid:7001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"TCP null scan"; flags:0; sid:7002; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"TCP FIN scan"; flags:F; sid:7003; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"TCP Xmas scan"; flags:FPU; sid:7004; rev:1;)')
    signatures.append("")

    # DNS attacks
    signatures.append("# DNS attacks")
    signatures.append('alert udp any any -> $HOME_NET 53 (msg:"DNS zone transfer attempt"; content:"|00 00 FC|"; offset:2; depth:3; sid:8001; rev:1;)')
    signatures.append('alert udp any any -> any 53 (msg:"DNS amplification attack"; content:"|01 00 00 01|"; offset:2; depth:4; dsize:>512; sid:8002; rev:1;)')
    signatures.append("")

    # Custom rules based on analysis findings
    signatures.append("# Custom rules based on traffic analysis")
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"Suspicious packet size"; dsize:>1400; sid:9001; rev:1;)')
    signatures.append('alert tcp any any -> $HOME_NET any (msg:"High frequency connections"; threshold:type both, track by_src, count 100, seconds 60; sid:9002; rev:1;)')

    return signatures

def save_ids_rules():
    """Generate and save IDS signatures"""
    signatures = generate_ids_signatures()

    with open('ids_rules.txt', 'w') as f:
        for sig in signatures:
            f.write(sig + '\n')

    print("✅ IDS signatures saved to ids_rules.txt")

    # Also create a summary of rule categories
    with open('ids_rules_summary.md', 'w') as f:
        f.write("# IDS Rules Summary\n\n")
        f.write("## Rule Categories\n\n")
        f.write("1. **Port Scan Detection (SID 1000s)**\n")
        f.write("   - TCP port scans\n")
        f.write("   - SYN flood attacks\n\n")
        f.write("2. **SQL Injection Detection (SID 2000s)**\n")
        f.write("   - UNION SELECT attempts\n")
        f.write("   - OR 1=1 patterns\n")
        f.write("   - DROP TABLE commands\n\n")
        f.write("3. **Brute Force Detection (SID 3000s)**\n")
        f.write("   - SSH login attempts\n")
        f.write("   - FTP login attempts\n")
        f.write("   - HTTP login attempts\n\n")
        f.write("4. **Data Exfiltration Detection (SID 4000s)**\n")
        f.write("   - Large outbound transfers\n")
        f.write("   - Suspicious uploads\n\n")
        f.write("5. **Web Application Attacks (SID 5000s)**\n")
        f.write("   - XSS attempts\n")
        f.write("   - Directory traversal\n")
        f.write("   - Command injection\n\n")
        f.write("6. **Backdoor Detection (SID 6000s)**\n")
        f.write("   - Common backdoor ports\n")
        f.write("   - IRC connections\n\n")
        f.write("7. **Network Reconnaissance (SID 7000s)**\n")
        f.write("   - Port scanning techniques\n")
        f.write("   - ICMP sweeps\n\n")
        f.write("8. **DNS Attacks (SID 8000s)**\n")
        f.write("   - Zone transfer attempts\n")
        f.write("   - DNS amplification\n\n")
        f.write("9. **Custom Rules (SID 9000s)**\n")
        f.write("   - Analysis-based detections\n")
        f.write("   - Environment-specific rules\n\n")

    print("✅ IDS rules summary saved to ids_rules_summary.md")

if __name__ == "__main__":
    save_ids_rules()
```

## 🐛 Common Issues & Solutions

### Issue: Scapy installation problems
**Solution**: Install with `pip install scapy` or use virtual environment

### Issue: PCAP file not found
**Solution**: Check that provided PCAP files are in correct directory

### Issue: Unicode decode errors in payload analysis
**Solution**: Use `errors='ignore'` when decoding packet payloads

### Issue: Empty visualizations
**Solution**: Verify PCAP has packets and contains the expected traffic

## ✅ Testing Workflow (Assignment Requirements)

```bash
# 1. Analyze provided packet capture
python network_analysis.py  # Uses sample_traffic.pcap

# 2. Generate firewall rules
python -c "
from Step4_code import save_firewall_rules
save_firewall_rules()
"

# 3. Generate IDS signatures
python -c "
from Step5_code import save_ids_rules
save_ids_rules()
"

# 4. Check generated files
ls -la *.txt *.md screenshots/

# 5. Review outputs
cat firewall_rules.txt
cat ids_rules.txt
cat analysis_report.md
```

## 📁 Expected File Structure (Assignment Requirements)
```
week06-network-analysis/
├── network_analysis.py          # Traffic analysis script
├── firewall_rules.txt           # Your firewall configuration
├── ids_rules.txt                # IDS detection rules
├── analysis_report.md           # Findings and recommendations
├── screenshots/
│   └── traffic_analysis.png     # Evidence of detected attacks
├── sample_traffic.pcap          # Provided PCAP file
└── ids_rules_summary.md         # Rule documentation
```

## 🎯 Grading Focus Areas (from assignment)

1. **Traffic Analysis (10 points)**: Identify normal/anomalous patterns, security violations, attack signatures
2. **Firewall Rules (8 points)**: Block attacks, allow legitimate traffic, defense in depth, logging
3. **IDS Signatures (7 points)**: Detect port scans, SQL injection, brute force, data exfiltration

## 💡 Pro Tips

1. **Focus on Provided PCAPs**: Don't try to capture live traffic
2. **Use Assignment Tools**: Wireshark for GUI analysis, Python scapy for automation
3. **Document Everything**: Screenshots and detailed reports are required
4. **Test Rules Logically**: Verify firewall/IDS rules make sense for detected attacks
5. **Follow Formats**: Use iptables syntax for firewall, Snort format for IDS

## 🔍 Key Security Concepts (Assignment Learning Objectives)

### Network Security Analysis:
- **TCP/IP Security**: Understanding protocol vulnerabilities
- **Attack Pattern Recognition**: Common signatures and indicators
- **Defense in Depth**: Multiple layers of protection
- **Threat Intelligence**: Using analysis to improve defenses

### Assignment Focus Areas:
- **Port Scans**: Reconnaissance patterns in traffic
- **SQL Injection**: Web application attack detection
- **Brute Force**: Authentication attack patterns
- **Data Exfiltration**: Unusual outbound traffic patterns

## 🚀 Extension Ideas (Optional)

- Integrate with Wireshark for GUI analysis
- Add geolocation analysis of IP addresses
- Create custom scapy functions for specific attacks
- Build correlation rules between different attack types

## ⏱️ Time Management

- **Analyze PCAPs first**: Understanding traffic is foundation
- **Start with obvious attacks**: SQL injection, port scans are easy to spot
- **Write rules incrementally**: Test firewall/IDS rules as you go
- **Document as you go**: Don't leave report writing until the end

## 🔧 Debugging Helpers

**Load and inspect PCAP:**
```python
from scapy.all import *
packets = rdpcap("sample_traffic.pcap")
print(f"Loaded {len(packets)} packets")
packets[0].show()  # Show first packet details
```

**Check for specific protocols:**
```python
tcp_packets = [p for p in packets if p.haslayer(TCP)]
http_packets = [p for p in packets if p.haslayer(TCP) and p[TCP].dport == 80]
print(f"TCP: {len(tcp_packets)}, HTTP: {len(http_packets)}")
```

**Search packet payloads:**
```python
for packet in packets:
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if 'union select' in payload.lower():
            print(f"SQL injection found: {payload[:100]}")
```

## 📊 Sample Analysis Report Structure

```markdown
# Network Security Analysis Report

## Executive Summary
Brief overview of findings and major threats identified.

## Normal Traffic Patterns
- Protocol distribution
- Common ports and services
- Typical packet sizes and timing

## Anomalous Behavior
- Unusual traffic volumes
- Port scanning activity
- Suspicious connection patterns

## Security Violations
- SQL injection attempts with evidence
- Brute force attacks with source IPs
- Data exfiltration indicators

## Attack Signatures
- Documented patterns for each attack type
- Severity assessments
- Recommended countermeasures

## Firewall Recommendations
- Specific iptables rules to block detected attacks
- Allow rules for legitimate traffic
- Logging requirements

## IDS Signatures
- Snort rules for each attack type
- Detection thresholds and tuning
- False positive considerations
```

Remember: This assignment focuses on understanding real network threats through traffic analysis, not building monitoring infrastructure!