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
        #Load packet capture file
        print(f" Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            return False

    def analyze_traffic_patterns(self):
     #Identify normal abnormal traffic patterns
        print("Analyzing Traffic Patterns...")

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
        #Detect anomalous behavior patterns

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
        print("Detecting Security Violations...")

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
        #Extract key information from packet
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
        #Document identified attack signatures
        print("Documenting Attack Signatures...")

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
        #Create detection pattern for attack type
        patterns = {
            'sql_injection_attempt': 'content: contains "union select", "or 1=1", "drop table"',
            'xss_attempt': 'content: contains "<script>", "javascript:", "alert("',
            'directory_traversal': 'content: contains "../", "..\\"',
            'ssh_connection_attempt': 'dst_port: 22; flags: S',
            'http_login_attempt': 'dst_port: 80,443; content: contains "login", "password"'
        }
        return patterns.get(attack_type, 'Pattern analysis needed')

    def assess_severity(self, attack_type, instance_count):
        #Assess severity based on attack type and frequency
        severity_map = {
            'sql_injection_attempt': 'HIGH',
            'xss_attempt': 'MEDIUM',
            'directory_traversal': 'HIGH',
            'ssh_connection_attempt': 'MEDIUM' if instance_count < 10 else 'HIGH',
            'http_login_attempt': 'LOW' if instance_count < 5 else 'MEDIUM'
        }
        return severity_map.get(attack_type, 'MEDIUM')

    def get_recommendations(self, attack_type):
        #Get security recommendations for attack type
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
        #Create traffic analysis visualizations
        print("Generating Visualizations...")

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

        print("Visualization saved to screenshots/traffic_analysis.png")

    def save_analysis_report(self):
        #Save detailed analysis report
        print("Saving Analysis Report...")

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

        print("Analysis report saved to analysis_report.md")

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

        print("\n Analysis complete! Check the following files:")
        print("   - analysis_report.md: Detailed findings")
        print("   - screenshots/traffic_analysis.png: Visualizations")

if __name__ == "__main__":
    main()