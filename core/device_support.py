import platform
import subprocess
import socket
import re
import logging
import json
import os
from enum import Enum
from django.conf import settings

logger = logging.getLogger('core')

class DeviceType(Enum):
    """Enum for supported device types."""
    WINDOWS_WORKSTATION = 'windows_workstation'
    WINDOWS_SERVER = 'windows_server'
    LINUX_SERVER = 'linux_server'
    LINUX_WORKSTATION = 'linux_workstation'
    MAC_WORKSTATION = 'mac_workstation'
    CISCO_ROUTER = 'cisco_router'
    CISCO_SWITCH = 'cisco_switch'
    JUNIPER_ROUTER = 'juniper_router'
    FORTINET_FIREWALL = 'fortinet_firewall'
    PALO_ALTO_FIREWALL = 'palo_alto_firewall'
    CLOUD_AWS_INSTANCE = 'cloud_aws_instance'
    CLOUD_AZURE_INSTANCE = 'cloud_azure_instance'
    CLOUD_GCP_INSTANCE = 'cloud_gcp_instance'
    IOT_DEVICE = 'iot_device'
    ANDROID_DEVICE = 'android_device'
    IOS_DEVICE = 'ios_device'
    EMBEDDED_SYSTEM = 'embedded_system'
    INDUSTRIAL_CONTROL = 'industrial_control'
    SCADA_SYSTEM = 'scada_system'
    UNKNOWN = 'unknown'

class DeviceSupport:
    """
    Provides detection, compatibility, and monitoring capabilities for various device types.
    Enables the system to work with multiple platforms and devices seamlessly.
    """
    
    def __init__(self):
        """Initialize the device support system."""
        self.device_profiles = {}
        self.device_fingerprints = {}
        self.network_device_mappings = {}
        self.os_compatibility = {}
        
        # Load device profiles
        self._load_device_profiles()
        
        # Load network device mappings
        self._load_network_device_mappings()
        
        # Initialize OS compatibility map
        self._init_os_compatibility()
    
    def _load_device_profiles(self):
        """Load device profiles from configuration files."""
        try:
            profiles_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'device_profiles.json')
            if os.path.exists(profiles_path):
                with open(profiles_path, 'r') as f:
                    self.device_profiles = json.load(f)
            else:
                # Create default profiles if file doesn't exist
                self._create_default_profiles()
                
            # Load device fingerprints
            fingerprints_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'device_fingerprints.json')
            if os.path.exists(fingerprints_path):
                with open(fingerprints_path, 'r') as f:
                    self.device_fingerprints = json.load(f)
            else:
                # Create default fingerprints if file doesn't exist
                self._create_default_fingerprints()
                
        except Exception as e:
            logger.error(f"Error loading device profiles: {str(e)}")
            # Create default profiles in case of error
            self._create_default_profiles()
    
    def _load_network_device_mappings(self):
        """Load network device mappings from configuration files."""
        try:
            mappings_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'network_device_mappings.json')
            if os.path.exists(mappings_path):
                with open(mappings_path, 'r') as f:
                    self.network_device_mappings = json.load(f)
            else:
                # Create default mappings if file doesn't exist
                self._create_default_mappings()
                
        except Exception as e:
            logger.error(f"Error loading network device mappings: {str(e)}")
            # Create default mappings in case of error
            self._create_default_mappings()
    
    def _create_default_profiles(self):
        """Create default device profiles."""
        self.device_profiles = {
            DeviceType.WINDOWS_WORKSTATION.value: {
                'name': 'Windows Workstation',
                'scanning_protocols': ['WMI', 'SMB', 'RPC'],
                'monitoring_protocols': ['WinRM', 'SNMP', 'SYSLOG'],
                'authentication_methods': ['NTLM', 'Kerberos', 'Local'],
                'vulnerability_scanners': ['Windows-specific', 'General'],
                'log_paths': ['System', 'Security', 'Application'],
                'default_ports': [445, 135, 139, 3389],
                'supported_analysis': ['memory', 'registry', 'event_logs', 'processes']
            },
            DeviceType.LINUX_SERVER.value: {
                'name': 'Linux Server',
                'scanning_protocols': ['SSH', 'SNMP', 'SYSLOG'],
                'monitoring_protocols': ['SSH', 'SNMP', 'SYSLOG'],
                'authentication_methods': ['SSH Key', 'Password', 'LDAP'],
                'vulnerability_scanners': ['Linux-specific', 'General'],
                'log_paths': ['/var/log'],
                'default_ports': [22, 161, 514, 80, 443],
                'supported_analysis': ['memory', 'logs', 'processes', 'filesystem']
            },
            DeviceType.CISCO_ROUTER.value: {
                'name': 'Cisco Router',
                'scanning_protocols': ['SNMP', 'SSH', 'TELNET'],
                'monitoring_protocols': ['SNMP', 'SYSLOG', 'NetFlow', 'SPAN'],
                'authentication_methods': ['TACACS+', 'RADIUS', 'Local'],
                'vulnerability_scanners': ['Network-specific'],
                'log_paths': ['Internal Logging Buffer', 'SYSLOG'],
                'default_ports': [22, 23, 161, 514, 443],
                'supported_analysis': ['config', 'traffic', 'acl', 'routing']
            },
            DeviceType.CLOUD_AWS_INSTANCE.value: {
                'name': 'AWS EC2 Instance',
                'scanning_protocols': ['SSH', 'AWS API', 'HTTP/HTTPS'],
                'monitoring_protocols': ['CloudWatch', 'VPC Flow Logs', 'AWS API'],
                'authentication_methods': ['IAM', 'SSH Key'],
                'vulnerability_scanners': ['Cloud-specific', 'OS-specific'],
                'log_paths': ['CloudTrail', 'CloudWatch Logs', 'S3 Buckets'],
                'default_ports': [22, 80, 443],
                'supported_analysis': ['apis', 'configuration', 'logs', 'network']
            },
            DeviceType.ANDROID_DEVICE.value: {
                'name': 'Android Device',
                'scanning_protocols': ['ADB', 'HTTP/HTTPS'],
                'monitoring_protocols': ['ADB', 'Agent-based'],
                'authentication_methods': ['Android Keystore', 'Password', 'Biometric'],
                'vulnerability_scanners': ['Mobile-specific'],
                'log_paths': ['/data/log', '/sdcard/log'],
                'default_ports': [5555, 80, 443],
                'supported_analysis': ['apps', 'network', 'permissions', 'system']
            },
            DeviceType.INDUSTRIAL_CONTROL.value: {
                'name': 'Industrial Control System',
                'scanning_protocols': ['Modbus', 'DNP3', 'Ethernet/IP', 'SNMP'],
                'monitoring_protocols': ['SNMP', 'Modbus TCP', 'OPC UA'],
                'authentication_methods': ['Local', 'Proprietary'],
                'vulnerability_scanners': ['ICS-specific'],
                'log_paths': ['Proprietary'],
                'default_ports': [502, 44818, 161, 20000],
                'supported_analysis': ['protocols', 'signals', 'commands', 'limited']
            }
        }
        
        # Save device profiles to file
        try:
            os.makedirs(os.path.join(settings.BASE_DIR, 'core', 'data'), exist_ok=True)
            profiles_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'device_profiles.json')
            with open(profiles_path, 'w') as f:
                json.dump(self.device_profiles, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving device profiles: {str(e)}")
    
    def _create_default_fingerprints(self):
        """Create default device fingerprints for identification."""
        self.device_fingerprints = {
            DeviceType.WINDOWS_WORKSTATION.value: {
                'os_pattern': r'windows (10|11|[0-9]+)',
                'ttl_range': [64, 128],
                'tcp_window_size': [64240, 65535],
                'open_ports': [135, 139, 445, 3389],
                'mac_prefix': ['00:0C:29', '00:50:56', '00:15:5D']
            },
            DeviceType.LINUX_SERVER.value: {
                'os_pattern': r'linux|ubuntu|centos|debian|rhel|fedora',
                'ttl_range': [32, 64],
                'tcp_window_size': [5840, 29200, 32120],
                'open_ports': [22, 80, 443],
                'mac_prefix': ['00:0C:29', '00:50:56', '00:15:5D']
            },
            DeviceType.CISCO_ROUTER.value: {
                'os_pattern': r'cisco ios',
                'ttl_range': [255, 255],
                'tcp_window_size': [4128, 8192],
                'open_ports': [22, 23, 80, 443],
                'mac_prefix': ['00:00:0C', '00:17:5A', '00:18:BA', '00:1A:A1']
            },
            DeviceType.IOT_DEVICE.value: {
                'os_pattern': r'rtos|embedded|esp|arduino',
                'ttl_range': [32, 255],
                'tcp_window_size': [512, 2048, 8192],
                'open_ports': [80, 8080, 5683],
                'mac_prefix': ['B8:27:EB', 'DC:A6:32', 'EC:FA:BC', '00:1E:42']
            }
        }
        
        # Save device fingerprints to file
        try:
            os.makedirs(os.path.join(settings.BASE_DIR, 'core', 'data'), exist_ok=True)
            fingerprints_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'device_fingerprints.json')
            with open(fingerprints_path, 'w') as f:
                json.dump(self.device_fingerprints, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving device fingerprints: {str(e)}")
    
    def _create_default_mappings(self):
        """Create default network device mappings."""
        self.network_device_mappings = {
            # MAC address prefixes for various vendors
            'mac_prefix': {
                '00:00:0C': 'Cisco',
                '00:01:42': 'Cisco',
                '00:1A:A1': 'Cisco',
                '00:40:96': 'Cisco',
                '00:06:7C': 'Cisco',
                '00:E0:F9': 'Cisco',
                'C8:F9:F9': 'Cisco',
                
                '10:0E:7E': 'Juniper',
                '28:C0:DA': 'Juniper',
                'F4:B5:2F': 'Juniper',
                
                '08:5B:0E': 'Fortinet',
                '00:09:0F': 'Fortinet',
                
                '00:1B:17': 'Palo Alto',
                
                'B8:27:EB': 'Raspberry Pi',
                'DC:A6:32': 'Raspberry Pi',
                
                '7C:BB:8A': 'Apple',
                'F4:5C:89': 'Apple',
                '00:CD:FE': 'Apple',
                
                '00:50:56': 'VMware',
                '00:0C:29': 'VMware',
                '00:15:5D': 'Microsoft Hyper-V'
            },
            
            # Common ports to device type mapping
            'port_signature': {
                22: {
                    'protocol': 'SSH',
                    'description': 'SSH Remote Access',
                    'risk_level': 'medium'
                },
                23: {
                    'protocol': 'Telnet',
                    'description': 'Telnet Remote Access (Insecure)',
                    'risk_level': 'high'
                },
                25: {
                    'protocol': 'SMTP',
                    'description': 'Mail Transfer Protocol',
                    'risk_level': 'medium'
                },
                80: {
                    'protocol': 'HTTP',
                    'description': 'Web Server (Unencrypted)',
                    'risk_level': 'medium'
                },
                443: {
                    'protocol': 'HTTPS',
                    'description': 'Secure Web Server',
                    'risk_level': 'low'
                },
                502: {
                    'protocol': 'Modbus',
                    'description': 'Industrial Control Protocol',
                    'risk_level': 'high'
                },
                3389: {
                    'protocol': 'RDP',
                    'description': 'Remote Desktop Protocol',
                    'risk_level': 'high'
                },
                5060: {
                    'protocol': 'SIP',
                    'description': 'Voice over IP',
                    'risk_level': 'medium'
                }
            }
        }
        
        # Save network device mappings to file
        try:
            os.makedirs(os.path.join(settings.BASE_DIR, 'core', 'data'), exist_ok=True)
            mappings_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'network_device_mappings.json')
            with open(mappings_path, 'w') as f:
                json.dump(self.network_device_mappings, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving network device mappings: {str(e)}")
    
    def _init_os_compatibility(self):
        """Initialize OS compatibility mapping."""
        self.os_compatibility = {
            'windows': {
                'supported_versions': ['7', '8', '8.1', '10', '11', 'Server 2016', 'Server 2019', 'Server 2022'],
                'packet_capture': ['WinPcap', 'Npcap', 'RawCap'],
                'process_inspection': ['WMI', 'PowerShell', 'Process Explorer'],
                'monitoring_methods': ['WMI', 'ETW', 'Windows Event Log', 'SNMP', 'Sysmon']
            },
            'linux': {
                'supported_versions': ['Ubuntu 18.04+', 'CentOS 7+', 'Debian 10+', 'RHEL 7+', 'Fedora 30+', 'Amazon Linux 2'],
                'packet_capture': ['libpcap', 'tcpdump', 'AF_PACKET'],
                'process_inspection': ['ps', '/proc', 'strace'],
                'monitoring_methods': ['syslog', 'auditd', 'systemd-journald', 'SNMP']
            },
            'macos': {
                'supported_versions': ['Monterey', 'Ventura', 'Sonoma'],
                'packet_capture': ['libpcap', 'tcpdump', 'BPF'],
                'process_inspection': ['ps', 'Activity Monitor', 'dtrace'],
                'monitoring_methods': ['syslog', 'OpenBSM', 'TCC.db', 'EndpointSecurity']
            },
            'android': {
                'supported_versions': ['10', '11', '12', '13', '14'],
                'packet_capture': ['VPN Service', 'tcpdump (rooted)'],
                'process_inspection': ['ps (rooted)', 'Android Debug Bridge'],
                'monitoring_methods': ['logcat', 'Event Logs', 'Android Agent']
            },
            'ios': {
                'supported_versions': ['14', '15', '16', '17'],
                'packet_capture': ['Network Extension', 'Remote Virtual Interface'],
                'process_inspection': ['Limited (via agent)'],
                'monitoring_methods': ['System Log', 'Mobile Device Management', 'iOS Agent']
            },
            'network_devices': {
                'supported_vendors': ['Cisco', 'Juniper', 'Fortinet', 'Palo Alto', 'Arista', 'HPE/Aruba'],
                'access_methods': ['SNMP', 'SSH', 'API', 'NETCONF', 'RESTCONF'],
                'monitoring_methods': ['SNMP', 'Syslog', 'NetFlow', 'IPFIX', 'SPAN/TAP']
            },
            'iot_devices': {
                'supported_types': ['IP Cameras', 'Smart Home', 'Industrial IoT', 'Medical IoT'],
                'access_methods': ['MQTT', 'COAP', 'HTTP/REST', 'Custom Protocols'],
                'monitoring_methods': ['Network Analysis', 'MQTT Broker', 'Gateway Monitoring']
            }
        }
    
    def detect_device_type(self, ip_address, ttl=None, tcp_window_size=None, open_ports=None, mac_address=None):
        """
        Detect the type of device based on network characteristics.
        
        Args:
            ip_address: IP address of the device
            ttl: Time to Live value from packets
            tcp_window_size: TCP Window Size
            open_ports: List of open ports
            mac_address: MAC address of the device
            
        Returns:
            DeviceType enum value
        """
        scores = {}
        
        for device_type, fingerprint in self.device_fingerprints.items():
            score = 0
            
            # Check TTL if provided
            if ttl is not None and 'ttl_range' in fingerprint:
                if fingerprint['ttl_range'][0] <= ttl <= fingerprint['ttl_range'][1]:
                    score += 1
            
            # Check TCP window size if provided
            if tcp_window_size is not None and 'tcp_window_size' in fingerprint:
                if tcp_window_size in fingerprint['tcp_window_size']:
                    score += 1
            
            # Check open ports if provided
            if open_ports is not None and 'open_ports' in fingerprint:
                common_ports = set(open_ports).intersection(set(fingerprint['open_ports']))
                score += len(common_ports) * 0.5
            
            # Check MAC address prefix if provided
            if mac_address is not None and 'mac_prefix' in fingerprint:
                mac_upper = mac_address.upper()
                for prefix in fingerprint['mac_prefix']:
                    if mac_upper.startswith(prefix.replace(':', '')):
                        score += 2
                        break
            
            scores[device_type] = score
        
        # Get the device type with the highest score
        if scores:
            best_match = max(scores.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                return DeviceType(best_match[0])
        
        # Try to detect OS type for more information
        try:
            # Simple OS detection via ICMP ping
            os_type = self._detect_os_via_ping(ip_address)
            if os_type:
                if 'windows' in os_type.lower():
                    return DeviceType.WINDOWS_WORKSTATION
                elif 'linux' in os_type.lower():
                    return DeviceType.LINUX_WORKSTATION
                elif 'darwin' in os_type.lower() or 'mac' in os_type.lower():
                    return DeviceType.MAC_WORKSTATION
            
            # Try to detect if it's a router or network device
            if open_ports and (23 in open_ports or 22 in open_ports) and (161 in open_ports):
                # Likely a network device
                if mac_address:
                    mac_prefix = mac_address[:8].upper().replace(':', '')
                    # Check against common network device prefixes
                    if mac_prefix in ['00000C', '0001C7', '001AA1']:  # Cisco prefixes
                        return DeviceType.CISCO_ROUTER
                    elif mac_prefix in ['100E7E', '28C0DA']:  # Juniper prefixes
                        return DeviceType.JUNIPER_ROUTER
                    elif mac_prefix in ['085B0E', '00090F']:  # Fortinet prefixes
                        return DeviceType.FORTINET_FIREWALL
        
        except Exception as e:
            logger.error(f"Error in OS detection: {str(e)}")
        
        return DeviceType.UNKNOWN
    
    def _detect_os_via_ping(self, ip_address):
        """
        Detect operating system via ping TTL.
        
        Args:
            ip_address: IP address to ping
            
        Returns:
            Detected OS type or None
        """
        try:
            # Different ping command based on the platform
            os_type = platform.system().lower()
            
            if os_type == 'windows':
                command = ['ping', '-n', '1', ip_address]
            else:
                command = ['ping', '-c', '1', ip_address]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                # Extract TTL value
                ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # Estimate OS based on TTL
                    if ttl <= 64:
                        return 'Linux/Unix'
                    elif ttl <= 128:
                        return 'Windows'
                    elif ttl <= 255:
                        return 'Network Device'
            
            return None
            
        except Exception as e:
            logger.error(f"Error in ping detection: {str(e)}")
            return None
    
    def get_connection_methods(self, device_type):
        """
        Get available connection methods for a device type.
        
        Args:
            device_type: DeviceType enum value
            
        Returns:
            Dictionary of connection methods
        """
        if isinstance(device_type, DeviceType):
            device_type = device_type.value
            
        if device_type in self.device_profiles:
            profile = self.device_profiles[device_type]
            return {
                'scanning_protocols': profile.get('scanning_protocols', []),
                'monitoring_protocols': profile.get('monitoring_protocols', []),
                'authentication_methods': profile.get('authentication_methods', [])
            }
        
        return {
            'scanning_protocols': [],
            'monitoring_protocols': [],
            'authentication_methods': []
        }
    
    def get_monitoring_capabilities(self, device_type):
        """
        Get monitoring capabilities for a device type.
        
        Args:
            device_type: DeviceType enum value
            
        Returns:
            Dictionary of monitoring capabilities
        """
        if isinstance(device_type, DeviceType):
            device_type = device_type.value
            
        if device_type in self.device_profiles:
            profile = self.device_profiles[device_type]
            return {
                'supported_analysis': profile.get('supported_analysis', []),
                'log_paths': profile.get('log_paths', []),
                'vulnerability_scanners': profile.get('vulnerability_scanners', [])
            }
        
        return {
            'supported_analysis': [],
            'log_paths': [],
            'vulnerability_scanners': []
        }
    
    def get_os_compatibility(self, os_type):
        """
        Get compatibility information for an OS type.
        
        Args:
            os_type: Operating system type (windows, linux, macos, etc.)
            
        Returns:
            Dictionary of compatibility information
        """
        os_type = os_type.lower()
        
        if os_type in self.os_compatibility:
            return self.os_compatibility[os_type]
        
        return {}
    
    def identify_device_from_mac(self, mac_address):
        """
        Identify device vendor from MAC address.
        
        Args:
            mac_address: MAC address to look up
            
        Returns:
            Vendor name or None
        """
        if not mac_address:
            return None
            
        # Normalize MAC address format
        mac_normalized = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')
        
        # Try different prefix lengths (6, 8, and 10 characters)
        for prefix_len in [6, 8, 10]:
            prefix = mac_normalized[:prefix_len]
            prefix_formatted = ':'.join([prefix[i:i+2] for i in range(0, len(prefix), 2)])
            
            if prefix_formatted in self.network_device_mappings.get('mac_prefix', {}):
                return self.network_device_mappings['mac_prefix'][prefix_formatted]
        
        return None
    
    def get_port_info(self, port_number):
        """
        Get information about a port number.
        
        Args:
            port_number: Port number
            
        Returns:
            Dictionary of port information
        """
        if port_number in self.network_device_mappings.get('port_signature', {}):
            return self.network_device_mappings['port_signature'][port_number]
        
        # Try to get standard service name
        try:
            service = socket.getservbyport(port_number)
            return {
                'protocol': service.upper(),
                'description': f'{service.upper()} Service',
                'risk_level': 'unknown'
            }
        except:
            return {
                'protocol': 'Unknown',
                'description': 'Unknown Service',
                'risk_level': 'unknown'
            }
    
    def register_custom_device_profile(self, device_type, profile):
        """
        Register a custom device profile.
        
        Args:
            device_type: Custom device type name
            profile: Device profile dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not isinstance(profile, dict):
                return False
                
            # Ensure required fields are present
            required_fields = ['name', 'scanning_protocols', 'monitoring_protocols']
            for field in required_fields:
                if field not in profile:
                    return False
            
            # Add or update profile
            self.device_profiles[device_type] = profile
            
            # Save to file
            profiles_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'device_profiles.json')
            with open(profiles_path, 'w') as f:
                json.dump(self.device_profiles, f, indent=4)
                
            return True
            
        except Exception as e:
            logger.error(f"Error registering custom device profile: {str(e)}")
            return False
    
    def get_supported_devices(self):
        """
        Get a list of all supported device types.
        
        Returns:
            Dictionary of device types and their display names
        """
        supported_devices = {}
        
        for device_type, profile in self.device_profiles.items():
            if 'name' in profile:
                supported_devices[device_type] = profile['name']
        
        return supported_devices 