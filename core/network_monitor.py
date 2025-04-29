import threading
import time
from datetime import datetime
import ipaddress
import logging
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw
from django.utils import timezone
from django.db import transaction
from .models import NetworkScan, Packet, Threat, Alert, SystemSettings
from .threat_detector import ThreatDetector

logger = logging.getLogger('core')

class NetworkMonitor:
    """
    A class that monitors network traffic using Scapy,
    analyzes packets, and detects threats in real-time.
    """
    
    def __init__(self, scan_id=None, interface=None, filter_str=None, count=0, timeout=None):
        """
        Initialize the NetworkMonitor.
        
        Args:
            scan_id: UUID of the NetworkScan object
            interface: Network interface to capture packets from
            filter_str: BPF filter string
            count: Number of packets to capture (0 for infinite)
            timeout: Stop sniffing after timeout seconds
        """
        self.scan_id = scan_id
        self.interface = interface or SystemSettings.get('default_interface', 'eth0')
        self.filter_str = filter_str
        self.count = count
        self.timeout = timeout
        self.stop_event = threading.Event()
        self.capture_thread = None
        self.packet_count = 0
        self.threat_detector = ThreatDetector()
        self.excluded_ips = set()
        
        # Load excluded IPs from system settings
        excluded_str = SystemSettings.get('excluded_ips', '')
        if excluded_str:
            self.excluded_ips = set(excluded_str.split(','))
    
    def start_capture(self):
        """Start packet capture in a separate thread."""
        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("Packet capture is already running")
            return False
        
        # Update scan status to running
        if self.scan_id:
            try:
                scan = NetworkScan.objects.get(id=self.scan_id)
                scan.status = 'running'
                scan.save()
                logger.info(f"Started network scan: {scan.name}")
            except NetworkScan.DoesNotExist:
                logger.error(f"NetworkScan with ID {self.scan_id} does not exist")
                return False
        
        self.stop_event.clear()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop the packet capture thread."""
        self.stop_event.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
            
        # Update scan status to completed
        if self.scan_id:
            try:
                scan = NetworkScan.objects.get(id=self.scan_id)
                scan.status = 'completed'
                scan.end_time = timezone.now()
                scan.save()
                logger.info(f"Completed network scan: {scan.name}")
            except NetworkScan.DoesNotExist:
                logger.error(f"NetworkScan with ID {self.scan_id} does not exist")
        
        return True
    
    def _packet_callback(self, packet):
        """
        Process each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        self.packet_count += 1
        
        # Skip processing if stop event is set
        if self.stop_event.is_set():
            return
        
        # Process the packet
        try:
            self._process_packet(packet)
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def _process_packet(self, packet):
        """
        Process a captured packet, store it in DB, and check for threats.
        
        Args:
            packet: Scapy packet object
        """
        # Skip if no scan_id is provided (monitoring only mode)
        if not self.scan_id:
            return
        
        # Extract packet information
        timestamp = datetime.now()
        protocol = "UNKNOWN"
        src_ip = dst_ip = "0.0.0.0"
        src_port = dst_port = None
        flags = None
        payload = None
        packet_length = len(packet)
        
        # Extract IP information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Skip excluded IPs
            if src_ip in self.excluded_ips or dst_ip in self.excluded_ips:
                return
            
            # TCP packet
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = self._get_tcp_flags(packet[TCP])
                if Raw in packet:
                    payload = bytes(packet[Raw])
            
            # UDP packet
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if Raw in packet:
                    payload = bytes(packet[Raw])
            
            # ICMP packet
            elif ICMP in packet:
                protocol = "ICMP"
                if Raw in packet:
                    payload = bytes(packet[Raw])
        
        # Save packet to database
        try:
            with transaction.atomic():
                db_packet = Packet.objects.create(
                    scan_id=self.scan_id,
                    timestamp=timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=protocol,
                    source_port=src_port,
                    destination_port=dst_port,
                    payload=payload,
                    packet_length=packet_length,
                    flags=flags
                )
                
                # Run threat detection on the packet
                threats = self.threat_detector.detect_threats(packet, db_packet)
                
                # Save detected threats
                for threat_type, severity, description in threats:
                    threat = Threat.objects.create(
                        scan_id=self.scan_id,
                        timestamp=timestamp,
                        threat_type=threat_type,
                        severity=severity,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        description=description,
                        status='new'
                    )
                    threat.related_packets.add(db_packet)
                    
                    # Generate alert for high and critical threats
                    if severity in ('high', 'critical'):
                        Alert.objects.create(
                            title=f"{severity.upper()} Threat: {threat_type}",
                            message=f"Detected {threat_type} from {src_ip} to {dst_ip}. {description}",
                            severity='critical' if severity == 'critical' else 'error',
                            related_threat=threat
                        )
        
        except Exception as e:
            logger.error(f"Error saving packet to database: {str(e)}")
    
    def _capture_packets(self):
        """Capture packets using Scapy's sniff function."""
        try:
            logger.info(f"Starting packet capture on {self.interface}")
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._packet_callback,
                count=self.count,
                timeout=self.timeout,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            
            # Update scan status to failed
            if self.scan_id:
                try:
                    scan = NetworkScan.objects.get(id=self.scan_id)
                    scan.status = 'failed'
                    scan.end_time = timezone.now()
                    scan.save()
                except NetworkScan.DoesNotExist:
                    pass
    
    @staticmethod
    def _get_tcp_flags(tcp_packet):
        """
        Extract and format TCP flags from a TCP packet.
        
        Args:
            tcp_packet: Scapy TCP packet
            
        Returns:
            String representation of TCP flags
        """
        flags = []
        if tcp_packet.flags & 0x01:  # FIN
            flags.append('FIN')
        if tcp_packet.flags & 0x02:  # SYN
            flags.append('SYN')
        if tcp_packet.flags & 0x04:  # RST
            flags.append('RST')
        if tcp_packet.flags & 0x08:  # PSH
            flags.append('PSH')
        if tcp_packet.flags & 0x10:  # ACK
            flags.append('ACK')
        if tcp_packet.flags & 0x20:  # URG
            flags.append('URG')
        if tcp_packet.flags & 0x40:  # ECE
            flags.append('ECE')
        if tcp_packet.flags & 0x80:  # CWR
            flags.append('CWR')
        
        return ','.join(flags)
    
    def get_stats(self):
        """Return statistics about the packet capture."""
        return {
            'packet_count': self.packet_count,
            'is_running': self.capture_thread is not None and self.capture_thread.is_alive(),
            'interface': self.interface,
            'filter': self.filter_str
        } 