import re
import logging
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
from django.utils import timezone
from .models import SystemSettings
from ml.anomaly_detector import AnomalyDetector

logger = logging.getLogger('core')

class ThreatDetector:
    """
    A class that detects threats in network packets
    using signature-based and anomaly-based detection.
    """
    
    def __init__(self):
        """Initialize the ThreatDetector with detection rules."""
        # Common ports used in attacks
        self.suspicious_ports = {
            22: 'SSH',
            23: 'Telnet',
            445: 'SMB',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            4444: 'Metasploit',
            5900: 'VNC'
        }
        
        # Regex patterns for signature-based detection
        self.signatures = {
            'sql_injection': re.compile(r'(?i)(select\s+.*from|union\s+select|insert\s+into|update\s+.*set|delete\s+from)', re.IGNORECASE),
            'xss': re.compile(r'(?i)(<script>|<img[^>]+onerror=|javascript:)', re.IGNORECASE),
            'command_injection': re.compile(r'(?i)(;.*\s*rm\s|;\s*bash|;\s*sh\s|\|\s*bash)', re.IGNORECASE),
            'path_traversal': re.compile(r'(?i)(\.\.\/|\.\.\\|\.\./|\.\.\\\.\./)', re.IGNORECASE),
            'file_inclusion': re.compile(r'(?i)(php://|file://|data://|expect://|zip://)', re.IGNORECASE),
        }
        
        # Initialize anomaly detector
        try:
            self.anomaly_detector = AnomalyDetector()
        except ImportError:
            logger.warning("AnomalyDetector could not be imported. Machine learning detection disabled.")
            self.anomaly_detector = None
            
        # Load whitelisted IPs and domains
        self.whitelisted_ips = set()
        self.whitelisted_domains = set()
        
        whitelist_ips = SystemSettings.get('whitelisted_ips', '')
        if whitelist_ips:
            self.whitelisted_ips = set(whitelist_ips.split(','))
            
        whitelist_domains = SystemSettings.get('whitelisted_domains', '')
        if whitelist_domains:
            self.whitelisted_domains = set(whitelist_domains.split(','))
    
    def detect_threats(self, packet, db_packet=None):
        """
        Analyze a packet for potential threats.
        
        Args:
            packet: Scapy packet object
            db_packet: Packet database object (optional)
            
        Returns:
            List of detected threats as (threat_type, severity, description) tuples
        """
        threats = []
        
        # Skip packets with whitelisted IPs
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if src_ip in self.whitelisted_ips or dst_ip in self.whitelisted_ips:
                return threats
        
        # Run signature-based detection
        signature_threats = self._signature_detection(packet)
        threats.extend(signature_threats)
        
        # Run port scan detection
        port_scan_threats = self._detect_port_scan(packet)
        threats.extend(port_scan_threats)
        
        # Run DOS attack detection
        dos_threats = self._detect_dos_attack(packet)
        threats.extend(dos_threats)
        
        # Run anomaly-based detection if available
        if self.anomaly_detector and db_packet:
            anomaly_threats = self._anomaly_detection(packet, db_packet)
            threats.extend(anomaly_threats)
        
        return threats
    
    def _signature_detection(self, packet):
        """
        Perform signature-based detection.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            List of detected threats
        """
        threats = []
        
        # Check for known attack patterns in packet payload
        if Raw in packet:
            payload = bytes(packet[Raw]).decode('utf-8', 'ignore')
            
            for threat_type, pattern in self.signatures.items():
                if pattern.search(payload):
                    if threat_type == 'sql_injection':
                        threats.append((
                            'SQL Injection Attempt',
                            'high',
                            'Detected potential SQL injection pattern in HTTP request.'
                        ))
                    elif threat_type == 'xss':
                        threats.append((
                            'Cross-Site Scripting (XSS) Attempt',
                            'high',
                            'Detected potential XSS attack pattern in HTTP request.'
                        ))
                    elif threat_type == 'command_injection':
                        threats.append((
                            'Command Injection Attempt',
                            'critical',
                            'Detected potential command injection pattern in request.'
                        ))
                    elif threat_type == 'path_traversal':
                        threats.append((
                            'Path Traversal Attempt',
                            'high',
                            'Detected potential directory traversal pattern in request.'
                        ))
                    elif threat_type == 'file_inclusion':
                        threats.append((
                            'File Inclusion Attempt',
                            'high',
                            'Detected potential remote/local file inclusion pattern in request.'
                        ))
        
        # Check for suspicious port access
        if TCP in packet and IP in packet:
            dst_port = packet[TCP].dport
            if dst_port in self.suspicious_ports:
                service = self.suspicious_ports[dst_port]
                threats.append((
                    f'Suspicious {service} Access',
                    'medium',
                    f'Detected access to {service} service (port {dst_port}).'
                ))
        
        # Check for ICMP flood
        if ICMP in packet:
            threats.append((
                'ICMP Packet',
                'low',
                'ICMP packet detected, potential ping sweep or reconnaissance.'
            ))
        
        return threats
    
    def _detect_port_scan(self, packet):
        """
        Detect potential port scanning activity.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            List of detected threats
        """
        threats = []
        
        # Check for SYN scan
        if TCP in packet and IP in packet:
            if packet[TCP].flags == 2:  # SYN flag
                # In a real implementation, you'd track multiple SYN packets to different ports
                # from the same source IP to accurately detect port scans
                threats.append((
                    'Potential Port Scan',
                    'medium',
                    'Detected SYN packet that may be part of a port scan.'
                ))
                
        return threats
    
    def _detect_dos_attack(self, packet):
        """
        Detect potential Denial of Service (DOS) attacks.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            List of detected threats
        """
        threats = []
        
        # In a real implementation, you'd track packet rates over time
        # to detect abnormal traffic volumes indicating DOS attacks
        
        # Check for SYN flood (simplified)
        if TCP in packet and IP in packet and packet[TCP].flags == 2:  # SYN flag
            # In reality, you'd count SYN packets over time to detect a flood
            pass
            
        return threats
    
    def _anomaly_detection(self, packet, db_packet):
        """
        Perform anomaly-based detection using machine learning.
        
        Args:
            packet: Scapy packet object
            db_packet: Packet database object
            
        Returns:
            List of detected threats
        """
        threats = []
        
        try:
            # Extract features for anomaly detection
            features = self._extract_packet_features(packet, db_packet)
            
            # Detect anomalies using the ML model
            is_anomaly, confidence, anomaly_type = self.anomaly_detector.detect(features)
            
            if is_anomaly and confidence > 0.8:
                severity = 'high' if confidence > 0.95 else 'medium'
                threats.append((
                    f'ML-Detected Anomaly: {anomaly_type}',
                    severity,
                    f'Machine learning model detected suspicious traffic pattern with {confidence:.2f} confidence.'
                ))
                
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            
        return threats
    
    def _extract_packet_features(self, packet, db_packet):
        """
        Extract features from packet for machine learning analysis.
        
        Args:
            packet: Scapy packet object
            db_packet: Packet database object
            
        Returns:
            Dictionary of packet features
        """
        features = {
            'protocol': db_packet.protocol,
            'packet_length': db_packet.packet_length,
            'src_port': db_packet.source_port,
            'dst_port': db_packet.destination_port,
            'flags': db_packet.flags
        }
        
        # Add TCP-specific features
        if TCP in packet:
            features['tcp_window_size'] = packet[TCP].window
            features['tcp_flags'] = packet[TCP].flags
        
        return features 