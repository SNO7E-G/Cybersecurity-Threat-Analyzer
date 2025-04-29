import os
import logging
import importlib
from django.conf import settings
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime

from .crypto_security import CryptoSecurity
from .device_support import DeviceSupport, DeviceType
from ml.advanced_algorithms import AdvancedSecurityAlgorithms

logger = logging.getLogger('core')

class SystemIntegration:
    """
    Central integration module that connects all components of the system.
    Provides high-level APIs for seamless interaction between subsystems.
    """
    
    def __init__(self):
        """Initialize the integration module and load all components."""
        # Initialize core components
        self.crypto = CryptoSecurity()
        self.device_support = DeviceSupport()
        self.ml_algorithms = AdvancedSecurityAlgorithms()
        
        # Component registry for dynamic loading
        self.components = {}
        self.plugins = {}
        
        # Integration cache for optimized cross-component operations
        self.cache = {}
        
        # Load optional components
        self._load_optional_components()
        
        # Initialize plugin system
        self._init_plugin_system()
        
        logger.info("System Integration module initialized successfully")
    
    def _load_optional_components(self):
        """Load optional system components based on configuration."""
        try:
            # Dynamic component loading based on settings
            component_settings = getattr(settings, 'SYSTEM_COMPONENTS', {})
            
            for component_name, component_config in component_settings.items():
                if not component_config.get('enabled', True):
                    continue
                    
                try:
                    # Import the component module
                    module_path = component_config.get('module')
                    class_name = component_config.get('class')
                    
                    if not module_path or not class_name:
                        logger.warning(f"Invalid component configuration for {component_name}")
                        continue
                    
                    module = importlib.import_module(module_path)
                    component_class = getattr(module, class_name)
                    
                    # Initialize with any provided parameters
                    params = component_config.get('params', {})
                    component_instance = component_class(**params)
                    
                    # Store in component registry
                    self.components[component_name] = {
                        'instance': component_instance,
                        'config': component_config
                    }
                    
                    logger.info(f"Loaded optional component: {component_name}")
                    
                except Exception as e:
                    logger.error(f"Error loading component {component_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error in component loading: {str(e)}")
    
    def _init_plugin_system(self):
        """Initialize the plugin system for extensibility."""
        try:
            # Check if plugin directory exists
            plugin_dir = os.path.join(settings.BASE_DIR, 'plugins')
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir, exist_ok=True)
                
            # Create __init__.py if it doesn't exist
            init_file = os.path.join(plugin_dir, '__init__.py')
            if not os.path.exists(init_file):
                with open(init_file, 'w') as f:
                    f.write("# Plugin system initialization\n")
            
            # Load plugins from directory
            for item in os.listdir(plugin_dir):
                if os.path.isdir(os.path.join(plugin_dir, item)) and not item.startswith('__'):
                    try:
                        plugin_module = importlib.import_module(f"plugins.{item}")
                        
                        # Look for a Plugin class
                        if hasattr(plugin_module, 'Plugin'):
                            plugin_class = getattr(plugin_module, 'Plugin')
                            plugin_instance = plugin_class()
                            
                            # Store in plugin registry
                            self.plugins[item] = {
                                'instance': plugin_instance,
                                'name': getattr(plugin_instance, 'name', item),
                                'version': getattr(plugin_instance, 'version', '0.1.0'),
                                'description': getattr(plugin_instance, 'description', ''),
                                'enabled': getattr(plugin_instance, 'enabled', True)
                            }
                            
                            logger.info(f"Loaded plugin: {item} v{getattr(plugin_instance, 'version', '0.1.0')}")
                    
                    except Exception as e:
                        logger.error(f"Error loading plugin {item}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error initializing plugin system: {str(e)}")
    
    def detect_and_analyze_device(self, ip_address: str, perform_scan: bool = False) -> Dict[str, Any]:
        """
        Detect device type and perform comprehensive analysis.
        
        Args:
            ip_address: IP address of the device to analyze
            perform_scan: Whether to perform an active scan or just use passive detection
            
        Returns:
            Dictionary with device information, analysis results, and security assessment
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'scan_type': 'active' if perform_scan else 'passive'
        }
        
        try:
            # Get basic device information
            device_info = self._get_device_info(ip_address, perform_scan)
            results['device_info'] = device_info
            
            device_type = device_info.get('device_type', DeviceType.UNKNOWN)
            
            # Get connection methods and monitoring capabilities
            results['connection_methods'] = self.device_support.get_connection_methods(device_type)
            results['monitoring_capabilities'] = self.device_support.get_monitoring_capabilities(device_type)
            
            # Perform security assessment if requested
            if perform_scan:
                results['security_assessment'] = self._perform_security_assessment(ip_address, device_type)
                
                # Get vulnerability information if available
                if 'security_assessment' in results and results['security_assessment'].get('vulnerabilities'):
                    results['vulnerability_details'] = self._get_vulnerability_details(
                        results['security_assessment']['vulnerabilities']
                    )
            
            # Generate a security token for this analysis session
            results['analysis_token'] = self._generate_analysis_token(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing device {ip_address}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def _get_device_info(self, ip_address: str, perform_scan: bool) -> Dict[str, Any]:
        """Get basic device information."""
        device_info = {
            'ip_address': ip_address,
        }
        
        if perform_scan:
            # Perform active scanning to gather more information
            # This would integrate with various scanning functions
            # For now, we'll just use basic detection
            pass
        
        # Detect device type using device support module
        device_type = self.device_support.detect_device_type(ip_address)
        device_info['device_type'] = device_type
        
        # Get OS compatibility if available
        if device_type in [DeviceType.WINDOWS_WORKSTATION, DeviceType.WINDOWS_SERVER]:
            device_info['os_compatibility'] = self.device_support.get_os_compatibility('windows')
        elif device_type in [DeviceType.LINUX_WORKSTATION, DeviceType.LINUX_SERVER]:
            device_info['os_compatibility'] = self.device_support.get_os_compatibility('linux')
        elif device_type == DeviceType.MAC_WORKSTATION:
            device_info['os_compatibility'] = self.device_support.get_os_compatibility('macos')
        
        return device_info
    
    def _perform_security_assessment(self, ip_address: str, device_type: DeviceType) -> Dict[str, Any]:
        """Perform security assessment based on device type."""
        assessment = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'device_type': device_type.value if isinstance(device_type, DeviceType) else device_type,
            'risk_level': 'unknown',
            'vulnerabilities': []
        }
        
        # This would integrate with the vulnerability scanning system
        # For now, we'll return a placeholder assessment
        
        # Check if any specialized scanners exist for this device type
        if device_type in [DeviceType.WINDOWS_WORKSTATION, DeviceType.WINDOWS_SERVER]:
            assessment['scanner_used'] = 'Windows-specific'
            assessment['risk_level'] = 'medium'
        elif device_type in [DeviceType.LINUX_WORKSTATION, DeviceType.LINUX_SERVER]:
            assessment['scanner_used'] = 'Linux-specific'
            assessment['risk_level'] = 'medium'
        elif device_type in [DeviceType.CISCO_ROUTER, DeviceType.CISCO_SWITCH, 
                           DeviceType.JUNIPER_ROUTER, DeviceType.FORTINET_FIREWALL]:
            assessment['scanner_used'] = 'Network-device-specific'
            assessment['risk_level'] = 'high'
        
        return assessment
    
    def _get_vulnerability_details(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get detailed information about vulnerabilities."""
        # This would integrate with a vulnerability database
        # For now, we'll return placeholder information
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'remediation_available': True,
            'details': vulnerabilities
        }
    
    def _generate_analysis_token(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a secure token for this analysis session."""
        # Create a simplified version of results for the token payload
        token_payload = {
            'ip_address': analysis_results.get('ip_address'),
            'device_type': analysis_results.get('device_info', {}).get('device_type', DeviceType.UNKNOWN.value),
            'timestamp': analysis_results.get('timestamp'),
            'scan_type': analysis_results.get('scan_type')
        }
        
        # Generate a token with 4-hour expiration
        return self.crypto.generate_token(token_payload, expiration_hours=4)
    
    def analyze_threats(self, packet_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze network packets for potential threats using all available detection methods.
        
        Args:
            packet_data: List of packet data dictionaries
            
        Returns:
            List of detected threats with details and confidence scores
        """
        threats = []
        
        try:
            # Skip empty data
            if not packet_data:
                return threats
            
            # Extract features for ML analysis
            features = self._extract_features_from_packets(packet_data)
            
            # Use ML algorithms for detection
            ml_results = self._detect_threats_with_ml(features)
            
            # Add ML-detected threats
            threats.extend(ml_results)
            
            # Use signature-based detection for each packet
            for packet in packet_data:
                signature_results = self._detect_threats_with_signatures(packet)
                if signature_results:
                    threats.extend(signature_results)
            
            # Use behavioral analysis
            behavioral_results = self._detect_threats_with_behavioral_analysis(packet_data)
            if behavioral_results:
                threats.extend(behavioral_results)
            
            # Check for encrypted traffic anomalies
            if any(p.get('is_encrypted', False) for p in packet_data):
                encrypted_results = self._analyze_encrypted_traffic(packet_data)
                if encrypted_results:
                    threats.extend(encrypted_results)
            
            # De-duplicate and score threats
            threats = self._consolidate_threats(threats)
            
            # Add secure hash for verification
            for threat in threats:
                # Create signature for threat data
                threat_data = f"{threat['threat_type']}:{threat['severity']}:{threat['source']}:{threat['confidence']}"
                threat['signature'] = self.crypto.secure_hash(threat_data)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error analyzing threats: {str(e)}")
            return threats
    
    def _extract_features_from_packets(self, packet_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract ML features from packet data."""
        # This would extract relevant features for ML analysis
        # For now, we'll return a simplified feature set
        return {
            'num_packets': len(packet_data),
            'protocols': list(set(p.get('protocol', 'UNKNOWN') for p in packet_data)),
            'src_ips': list(set(p.get('src_ip') for p in packet_data if 'src_ip' in p)),
            'dst_ips': list(set(p.get('dst_ip') for p in packet_data if 'dst_ip' in p)),
            'avg_packet_size': sum(p.get('packet_length', 0) for p in packet_data) / len(packet_data) if packet_data else 0,
            'port_counts': {},  # Would contain port frequency
            'flag_counts': {},  # Would contain TCP flag frequency
        }
    
    def _detect_threats_with_ml(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use ML algorithms to detect threats."""
        threats = []
        
        # Use each algorithm type for detection
        # For demonstration, we'll use two of the algorithms
        
        # Use zero-day detector (hybrid approach)
        try:
            zero_day_results = self.ml_algorithms.predict('zero_day_detector', features)
            if zero_day_results and any(zero_day_results.values()):
                threats.append({
                    'threat_type': 'Zero-Day Attack',
                    'severity': 'critical',
                    'confidence': 0.85,  # Would be a real score from the model
                    'description': 'Potential zero-day attack detected by ML analysis',
                    'source': 'ml_zero_day_detector'
                })
        except Exception as e:
            logger.warning(f"Error using zero-day detector: {str(e)}")
        
        # Use encrypted traffic analyzer
        try:
            if 'is_encrypted' in features and features['is_encrypted']:
                enc_results = self.ml_algorithms.predict('encrypted_traffic_analyzer', features)
                if enc_results and enc_results[0] > 0.8:  # Assuming binary classification with threshold
                    threats.append({
                        'threat_type': 'Malicious Encrypted Traffic',
                        'severity': 'high',
                        'confidence': float(enc_results[0]),
                        'description': 'Suspicious patterns detected in encrypted traffic',
                        'source': 'ml_encrypted_analyzer'
                    })
        except Exception as e:
            logger.warning(f"Error using encrypted traffic analyzer: {str(e)}")
        
        return threats
    
    def _detect_threats_with_signatures(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use signature-based detection for a packet."""
        # This would use signature database to detect known threats
        # For now, we'll return an empty list
        return []
    
    def _detect_threats_with_behavioral_analysis(self, packet_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use behavioral analysis to detect anomalous patterns."""
        # This would analyze traffic patterns for anomalies
        # For now, we'll return an empty list
        return []
    
    def _analyze_encrypted_traffic(self, packet_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze encrypted traffic for suspicious patterns."""
        # This would use specialized techniques for encrypted traffic
        # For now, we'll return an empty list
        return []
    
    def _consolidate_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """De-duplicate and consolidate similar threats."""
        if not threats:
            return []
            
        # Group by threat type
        threat_groups = {}
        for threat in threats:
            threat_type = threat.get('threat_type', 'Unknown')
            if threat_type not in threat_groups:
                threat_groups[threat_type] = []
            threat_groups[threat_type].append(threat)
        
        # Consolidate each group
        consolidated_threats = []
        for threat_type, group in threat_groups.items():
            if len(group) == 1:
                # Only one threat of this type, add as is
                consolidated_threats.append(group[0])
            else:
                # Multiple threats of same type, consolidate
                max_confidence = max(t.get('confidence', 0) for t in group)
                max_severity = max((t.get('severity', 'low') for t in group), 
                                 key=lambda s: {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(s, 0))
                
                sources = set(t.get('source', '') for t in group)
                
                consolidated_threats.append({
                    'threat_type': threat_type,
                    'severity': max_severity,
                    'confidence': max_confidence,
                    'description': f"Multiple detections of {threat_type}",
                    'source': ', '.join(sources),
                    'detections': len(group)
                })
        
        return consolidated_threats
    
    def get_component(self, component_name: str) -> Any:
        """Get a registered component by name."""
        component_data = self.components.get(component_name)
        if component_data:
            return component_data.get('instance')
        return None
    
    def get_plugin(self, plugin_name: str) -> Any:
        """Get a registered plugin by name."""
        plugin_data = self.plugins.get(plugin_name)
        if plugin_data and plugin_data.get('enabled', True):
            return plugin_data.get('instance')
        return None
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins with their information."""
        return [
            {
                'name': data.get('name', name),
                'version': data.get('version', '0.1.0'),
                'description': data.get('description', ''),
                'enabled': data.get('enabled', True)
            }
            for name, data in self.plugins.items()
        ]
    
    def generate_secure_token(self, data: Dict[str, Any], expiration_hours: int = 24) -> str:
        """Generate a secure token for authentication or session management."""
        return self.crypto.generate_token(data, expiration_hours)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a secure token and return its payload if valid."""
        return self.crypto.verify_token(token)
    
    def encrypt_sensitive_data(self, data: Union[str, bytes], key: Optional[bytes] = None) -> Dict[str, str]:
        """Encrypt sensitive data for secure storage or transmission."""
        return self.crypto.encrypt_aes_gcm(data, key)
    
    def decrypt_sensitive_data(self, ciphertext: str, nonce: str, tag: str, key: str) -> bytes:
        """Decrypt sensitive data."""
        return self.crypto.decrypt_aes_gcm(ciphertext, nonce, tag, key)
    
    def register_custom_device_profile(self, device_type: str, profile: Dict[str, Any]) -> bool:
        """Register a custom device profile."""
        return self.device_support.register_custom_device_profile(device_type, profile)
    
    def train_ml_model(self, model_name: str, X, y=None, **kwargs) -> Any:
        """Train a machine learning model with the given data."""
        return self.ml_algorithms.train_model(model_name, X, y, **kwargs)
    
# Singleton instance for global access
integration = SystemIntegration() 