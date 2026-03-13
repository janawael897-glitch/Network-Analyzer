#!/usr/bin/env python3
"""
Network Traffic Analyzer for Threat Detection
Main entry point for the threat detection system
"""

import sys
import logging
from scapy.all import *
from collections import defaultdict, Counter
import time
import json
import numpy as np
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from network packets"""
    
    def __init__(self):
        self.features = []
    
    def extract_packet_features(self, packet):
        """Extract comprehensive features from a single packet"""
        features = {
            'timestamp': time.time(),
            'packet_length': len(packet)
        }
        
        # IP Layer features
        if IP in packet:
            features.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'ttl': packet[IP].ttl,
                'protocol': packet[IP].proto,
                'ip_flags': packet[IP].flags,
                'frag_offset': packet[IP].frag
            })
        
        # TCP Layer features
        if TCP in packet:
            features.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'tcp_flags': str(packet[TCP].flags),
                'window_size': packet[TCP].window,
                'seq_num': packet[TCP].seq,
                'ack_num': packet[TCP].ack
            })
            
        # UDP Layer features
        elif UDP in packet:
            features.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport,
                'udp_length': packet[UDP].len
            })
        
        # ICMP Layer features
        elif ICMP in packet:
            features.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code
            })
        
        # DNS Layer features
        if DNS in packet:
            features.update({
                'dns_query': packet[DNS].qd.qname.decode() if packet[DNS].qd else None,
                'dns_qr': packet[DNS].qr  # 0 for query, 1 for response
            })
        
        # Payload analysis
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            features.update({
                'payload_length': len(payload),
                'payload_entropy': self.calculate_entropy(payload)
            })
        
        return features
    
    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def extract_flow_features(self, packets):
        """Extract flow-level features from multiple packets"""
        if not packets:
            return {}
        
        flow_features = {
            'total_packets': len(packets),
            'total_bytes': sum(len(p) for p in packets),
            'duration': packets[-1].time - packets[0].time if len(packets) > 1 else 0,
            'avg_packet_size': np.mean([len(p) for p in packets]),
            'std_packet_size': np.std([len(p) for p in packets])
        }
        
        # Calculate inter-arrival times
        if len(packets) > 1:
            inter_arrival_times = [
                packets[i].time - packets[i-1].time 
                for i in range(1, len(packets))
            ]
            flow_features['avg_iat'] = np.mean(inter_arrival_times)
            flow_features['std_iat'] = np.std(inter_arrival_times)
        
        return flow_features


class PortScanDetector:
    """Detect port scanning activities"""
    
    def __init__(self, threshold=20, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.scan_attempts = defaultdict(list)
    
    def analyze(self, src_ip, dst_port, timestamp):
        """Analyze for port scan patterns"""
        # Track destination ports accessed by source IP
        self.scan_attempts[src_ip].append((dst_port, timestamp))
        
        # Clean old entries
        current_time = timestamp
        self.scan_attempts[src_ip] = [
            (port, ts) for port, ts in self.scan_attempts[src_ip]
            if current_time - ts <= self.time_window
        ]
        
        # Check threshold
        unique_ports = len(set(port for port, _ in self.scan_attempts[src_ip]))
        
        if unique_ports > self.threshold:
            return {
                'detected': True,
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source': src_ip,
                'ports_scanned': unique_ports,
                'message': f'Port scan detected from {src_ip}: {unique_ports} unique ports in {self.time_window}s'
            }
        
        return {'detected': False}


class DDoSDetector:
    """Detect DDoS attack patterns"""
    
    def __init__(self, syn_threshold=100, packet_threshold=1000, time_window=10):
        self.syn_threshold = syn_threshold
        self.packet_threshold = packet_threshold
        self.time_window = time_window
        self.syn_packets = defaultdict(list)
        self.packet_counts = defaultdict(list)
    
    def analyze_syn_flood(self, src_ip, tcp_flags, timestamp):
        """Detect SYN flood attacks"""
        if 'S' in str(tcp_flags) and 'A' not in str(tcp_flags):
            self.syn_packets[src_ip].append(timestamp)
            
            # Clean old entries
            current_time = timestamp
            self.syn_packets[src_ip] = [
                ts for ts in self.syn_packets[src_ip]
                if current_time - ts <= self.time_window
            ]
            
            # Check threshold
            if len(self.syn_packets[src_ip]) > self.syn_threshold:
                return {
                    'detected': True,
                    'type': 'SYN_FLOOD',
                    'severity': 'CRITICAL',
                    'source': src_ip,
                    'syn_count': len(self.syn_packets[src_ip]),
                    'message': f'SYN flood detected from {src_ip}: {len(self.syn_packets[src_ip])} SYN packets in {self.time_window}s'
                }
        
        return {'detected': False}
    
    def analyze_packet_flood(self, src_ip, timestamp):
        """Detect general packet flooding"""
        self.packet_counts[src_ip].append(timestamp)
        
        # Clean old entries
        current_time = timestamp
        self.packet_counts[src_ip] = [
            ts for ts in self.packet_counts[src_ip]
            if current_time - ts <= self.time_window
        ]
        
        # Check threshold
        if len(self.packet_counts[src_ip]) > self.packet_threshold:
            return {
                'detected': True,
                'type': 'PACKET_FLOOD',
                'severity': 'HIGH',
                'source': src_ip,
                'packet_count': len(self.packet_counts[src_ip]),
                'message': f'Packet flood detected from {src_ip}: {len(self.packet_counts[src_ip])} packets in {self.time_window}s'
            }
        
        return {'detected': False}


class DNSAnomalyDetector:
    """Detect DNS-based anomalies including DGA"""
    
    def __init__(self, entropy_threshold=3.5):
        self.entropy_threshold = entropy_threshold
        self.dns_queries = defaultdict(list)
    
    def analyze_dga(self, domain, src_ip):
        """Detect Domain Generation Algorithm (DGA) patterns"""
        if not domain:
            return {'detected': False}
        
        # Calculate domain entropy
        domain_str = domain.decode() if isinstance(domain, bytes) else domain
        domain_entropy = self.calculate_domain_entropy(domain_str)
        
        # High entropy suggests DGA
        if domain_entropy > self.entropy_threshold:
            return {
                'detected': True,
                'type': 'DGA_DOMAIN',
                'severity': 'HIGH',
                'source': src_ip,
                'domain': domain_str,
                'entropy': domain_entropy,
                'message': f'Potential DGA domain detected: {domain_str} (entropy: {domain_entropy:.2f})'
            }
        
        return {'detected': False}
    
    @staticmethod
    def calculate_domain_entropy(domain):
        """Calculate entropy of domain name"""
        if not domain:
            return 0.0
        
        # Remove TLD for better analysis
        domain_parts = domain.rstrip('.').split('.')
        if len(domain_parts) > 1:
            domain = domain_parts[-2]  # Get second-level domain
        
        # Calculate character frequency
        char_freq = Counter(domain.lower())
        domain_len = len(domain)
        
        entropy = 0.0
        for count in char_freq.values():
            p = count / domain_len
            entropy += -p * np.log2(p)
        
        return entropy


class AbnormalPacketDetector:
    """Detect abnormal packet characteristics"""
    
    def __init__(self):
        self.packet_size_stats = {'mean': 500, 'std': 200}  # Initialize with defaults
    
    def analyze_packet_size(self, packet_len):
        """Detect abnormally sized packets"""
        # Very small packets (could be probes)
        if packet_len < 20:
            return {
                'detected': True,
                'type': 'ABNORMAL_SIZE',
                'severity': 'MEDIUM',
                'packet_size': packet_len,
                'message': f'Abnormally small packet detected: {packet_len} bytes'
            }
        
        # Very large packets (could be fragmentation attack)
        if packet_len > 9000:
            return {
                'detected': True,
                'type': 'ABNORMAL_SIZE',
                'severity': 'MEDIUM',
                'packet_size': packet_len,
                'message': f'Abnormally large packet detected: {packet_len} bytes'
            }
        
        return {'detected': False}
    
    def analyze_malformed_packet(self, packet):
        """Detect malformed packets"""
        try:
            if IP in packet:
                # Check for invalid IP header
                if packet[IP].version not in [4, 6]:
                    return {
                        'detected': True,
                        'type': 'MALFORMED_PACKET',
                        'severity': 'HIGH',
                        'message': f'Invalid IP version: {packet[IP].version}'
                    }
                
                # Check for invalid TTL
                if packet[IP].ttl == 0 or packet[IP].ttl > 255:
                    return {
                        'detected': True,
                        'type': 'MALFORMED_PACKET',
                        'severity': 'MEDIUM',
                        'message': f'Invalid TTL value: {packet[IP].ttl}'
                    }
            
            if TCP in packet:
                # Check for invalid flag combinations
                flags = str(packet[TCP].flags)
                if 'F' in flags and 'S' in flags:  # FIN and SYN together
                    return {
                        'detected': True,
                        'type': 'MALFORMED_PACKET',
                        'severity': 'HIGH',
                        'message': f'Invalid TCP flags: {flags}'
                    }
        
        except Exception as e:
            logger.error(f"Error analyzing malformed packet: {e}")
        
        return {'detected': False}


class AlertSystem:
    """Handle and log security alerts"""
    
    def __init__(self, output_file='alerts.json'):
        self.output_file = output_file
        self.alerts = []
    
    def add_alert(self, alert_data, packet_features):
        """Add new alert to the system"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_data.get('type'),
            'severity': alert_data.get('severity'),
            'message': alert_data.get('message'),
            'source_ip': packet_features.get('src_ip'),
            'destination_ip': packet_features.get('dst_ip'),
            'additional_info': {k: v for k, v in alert_data.items() 
                              if k not in ['type', 'severity', 'message', 'detected']}
        }
        
        self.alerts.append(alert)
        logger.warning(f"ALERT: {alert['alert_type']} - {alert['message']}")
        
        # Save to file
        self.save_alerts()
    
    def save_alerts(self):
        """Save alerts to JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.alerts, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving alerts: {e}")
    
    def get_alert_summary(self):
        """Get summary of alerts"""
        if not self.alerts:
            return "No alerts detected"
        
        alert_types = Counter(alert['alert_type'] for alert in self.alerts)
        severity_counts = Counter(alert['severity'] for alert in self.alerts)
        
        summary = f"\n{'='*60}\n"
        summary += "ALERT SUMMARY\n"
        summary += f"{'='*60}\n"
        summary += f"Total Alerts: {len(self.alerts)}\n\n"
        summary += "By Type:\n"
        for alert_type, count in alert_types.most_common():
            summary += f"  {alert_type}: {count}\n"
        summary += "\nBy Severity:\n"
        for severity, count in severity_counts.most_common():
            summary += f"  {severity}: {count}\n"
        summary += f"{'='*60}\n"
        
        return summary


class NetworkThreatAnalyzer:
    """Main threat analyzer integrating all detection modules"""
    
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.feature_extractor = FeatureExtractor()
        self.port_scan_detector = PortScanDetector()
        self.ddos_detector = DDoSDetector()
        self.dns_detector = DNSAnomalyDetector()
        self.packet_detector = AbnormalPacketDetector()
        self.alert_system = AlertSystem()
        
        self.packet_count = 0
        self.start_time = time.time()
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        # Extract features
        features = self.feature_extractor.extract_packet_features(packet)
        
        # Run all detectors
        alerts = []
        
        # Port scan detection
        if features.get('dst_port'):
            alert = self.port_scan_detector.analyze(
                features.get('src_ip'),
                features.get('dst_port'),
                features.get('timestamp')
            )
            if alert.get('detected'):
                alerts.append(alert)
        
        # DDoS detection
        if features.get('tcp_flags'):
            alert = self.ddos_detector.analyze_syn_flood(
                features.get('src_ip'),
                features.get('tcp_flags'),
                features.get('timestamp')
            )
            if alert.get('detected'):
                alerts.append(alert)
        
        # Packet flood detection
        if features.get('src_ip'):
            alert = self.ddos_detector.analyze_packet_flood(
                features.get('src_ip'),
                features.get('timestamp')
            )
            if alert.get('detected'):
                alerts.append(alert)
        
        # DNS DGA detection
        if features.get('dns_query'):
            alert = self.dns_detector.analyze_dga(
                features.get('dns_query'),
                features.get('src_ip')
            )
            if alert.get('detected'):
                alerts.append(alert)
        
        # Abnormal packet detection
        alert = self.packet_detector.analyze_packet_size(features.get('packet_length'))
        if alert.get('detected'):
            alerts.append(alert)
        
        alert = self.packet_detector.analyze_malformed_packet(packet)
        if alert.get('detected'):
            alerts.append(alert)
        
        # Process alerts
        for alert in alerts:
            self.alert_system.add_alert(alert, features)
        
        # Log progress every 1000 packets
        if self.packet_count % 1000 == 0:
            elapsed = time.time() - self.start_time
            rate = self.packet_count / elapsed
            logger.info(f"Processed {self.packet_count} packets ({rate:.2f} packets/sec)")
    
    def start_live_capture(self, packet_count=0):
        """Start live packet capture"""
        logger.info(f"Starting live capture on interface {self.interface}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            sniff(iface=self.interface, prn=self.packet_callback, count=packet_count, store=0)
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Error during capture: {e}")
        finally:
            self.print_summary()
    
    def analyze_pcap(self, pcap_file):
        """Analyze existing PCAP file"""
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"Loaded {len(packets)} packets from {pcap_file}")
            
            for packet in packets:
                self.packet_callback(packet)
            
            self.print_summary()
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP: {e}")
    
    def print_summary(self):
        """Print analysis summary"""
        elapsed = time.time() - self.start_time
        
        logger.info("\n" + "="*60)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*60)
        logger.info(f"Total packets processed: {self.packet_count}")
        logger.info(f"Total time: {elapsed:.2f} seconds")
        logger.info(f"Average rate: {self.packet_count/elapsed:.2f} packets/sec")
        logger.info(self.alert_system.get_alert_summary())


def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   Network Traffic Analyzer for Threat Detection          ║
    ║   Version 1.0                                            ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Live capture: python network_analyzer.py live [interface]")
        print("  PCAP analysis: python network_analyzer.py pcap <file.pcap>")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    analyzer = NetworkThreatAnalyzer()
    
    if mode == 'live':
        interface = sys.argv[2] if len(sys.argv) > 2 else 'eth0'
        analyzer.interface = interface
        analyzer.start_live_capture()
    
    elif mode == 'pcap':
        if len(sys.argv) < 3:
            print("Error: Please specify PCAP file")
            sys.exit(1)
        pcap_file = sys.argv[2]
        analyzer.analyze_pcap(pcap_file)
    
    else:
        print(f"Error: Unknown mode '{mode}'")
        print("Use 'live' or 'pcap'")
        sys.exit(1)


if __name__ == '__main__':
    main()