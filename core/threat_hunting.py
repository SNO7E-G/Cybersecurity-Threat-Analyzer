import logging
import re
import json
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.conf import settings

from .crypto_security import CryptoSecurity
from .device_support import DeviceSupport, DeviceType

logger = logging.getLogger('core')

class ThreatHunting:
    """
    Advanced threat hunting module for proactive discovery of threats and
    sophisticated attack patterns within the network.
    """
    
    def __init__(self, crypto=None, device_support=None):
        """Initialize the threat hunting module."""
        self.crypto = crypto or CryptoSecurity()
        self.device_support = device_support or DeviceSupport()
        
        # Load hunting rules
        self.hunting_rules = self._load_hunting_rules()
        
        # Initialize detection techniques
        self.techniques = {
            'lateral_movement': self._detect_lateral_movement,
            'data_exfiltration': self._detect_data_exfiltration,
            'privilege_escalation': self._detect_privilege_escalation,
            'persistence': self._detect_persistence_mechanisms,
            'command_and_control': self._detect_command_and_control,
            'defense_evasion': self._detect_defense_evasion,
            'unusual_process': self._detect_unusual_processes,
            'unusual_network': self._detect_unusual_network_activity,
            'unusual_authentication': self._detect_unusual_authentication,
            'iot_anomalies': self._detect_iot_anomalies
        }
        
        # Initialize threat intelligence feeds
        self.intel_feeds = self._initialize_threat_intel()
        
        # Historical context cache
        self.historical_context = {}
        
        logger.info("Threat Hunting module initialized")
    
    def _load_hunting_rules(self) -> Dict[str, Any]:
        """Load hunting rules from configuration files."""
        rules = {}
        
        try:
            rules_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'hunting_rules.json')
            if os.path.exists(rules_path):
                with open(rules_path, 'r') as f:
                    rules = json.load(f)
            else:
                # Create default rules
                rules = self._create_default_rules()
                
                # Save default rules
                os.makedirs(os.path.join(settings.BASE_DIR, 'core', 'data'), exist_ok=True)
                with open(rules_path, 'w') as f:
                    json.dump(rules, f, indent=4)
                    
        except Exception as e:
            logger.error(f"Error loading hunting rules: {str(e)}")
            rules = self._create_default_rules()
            
        return rules
    
    def _create_default_rules(self) -> Dict[str, Any]:
        """Create default hunting rules."""
        return {
            "lateral_movement": {
                "enabled": True,
                "techniques": [
                    {
                        "name": "Multiple Authentication Attempts",
                        "description": "Detection of multiple authentication attempts from a single source to multiple destinations",
                        "threshold": 5,
                        "timeframe_minutes": 15,
                        "severity": "high"
                    },
                    {
                        "name": "Unusual Remote Service Usage",
                        "description": "Detection of unusual usage of remote services (RDP, SSH, WMI, etc.)",
                        "threshold": 3,
                        "timeframe_minutes": 60,
                        "severity": "medium"
                    }
                ]
            },
            "data_exfiltration": {
                "enabled": True,
                "techniques": [
                    {
                        "name": "Large Outbound Data Transfer",
                        "description": "Detection of large volumes of data being transferred to external destinations",
                        "threshold": 50,  # In MB
                        "timeframe_minutes": 60,
                        "severity": "high"
                    },
                    {
                        "name": "DNS Tunneling",
                        "description": "Detection of potential DNS tunneling for data exfiltration",
                        "threshold": 50,  # Number of unusual DNS queries
                        "timeframe_minutes": 30,
                        "severity": "critical"
                    }
                ]
            },
            "privilege_escalation": {
                "enabled": True,
                "techniques": [
                    {
                        "name": "Unusual Privilege Changes",
                        "description": "Detection of unusual privilege changes or elevation",
                        "threshold": 1,
                        "timeframe_minutes": 60,
                        "severity": "critical"
                    }
                ]
            },
            "iot_anomalies": {
                "enabled": True,
                "techniques": [
                    {
                        "name": "Unusual IoT Communication",
                        "description": "Detection of IoT devices communicating with unusual destinations",
                        "threshold": 2,
                        "timeframe_minutes": 60,
                        "severity": "high"
                    }
                ]
            }
        }
    
    def _initialize_threat_intel(self) -> Dict[str, Any]:
        """Initialize threat intelligence feeds."""
        return {
            "ip_blacklist": set(),
            "domain_blacklist": set(),
            "file_hashes": set(),
            "indicators": {},
            "last_updated": None
        }
    
    def update_threat_intel(self) -> bool:
        """Update threat intelligence data from configured sources."""
        # This would integrate with external threat intel feeds
        # For now, we'll just update the timestamps
        try:
            self.intel_feeds["last_updated"] = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {str(e)}")
            return False
    
    def hunt_for_threats(self, data_sources: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Actively hunt for threats across multiple data sources.
        
        Args:
            data_sources: Dictionary of data sources to analyze
                network_traffic: List of network traffic records
                authentication_logs: List of authentication log entries
                process_logs: List of process execution logs
                file_activities: List of file activity records
                
        Returns:
            List of discovered threat findings
        """
        findings = []
        
        # Skip if no data sources provided
        if not data_sources:
            return findings
        
        # Store datetime of analysis for consistent timestamps
        analysis_time = datetime.utcnow()
        
        try:
            # Use multithreading to run threat hunting techniques in parallel
            with ThreadPoolExecutor(max_workers=min(10, len(self.techniques))) as executor:
                future_to_technique = {}
                
                for technique_name, technique_func in self.techniques.items():
                    # Skip disabled techniques
                    technique_config = self.hunting_rules.get(technique_name, {})
                    if not technique_config.get("enabled", True):
                        continue
                    
                    # Submit hunting technique to thread pool
                    future = executor.submit(
                        technique_func, 
                        data_sources,
                        technique_config,
                        analysis_time
                    )
                    future_to_technique[future] = technique_name
                
                # Collect results as they complete
                for future in as_completed(future_to_technique):
                    technique_name = future_to_technique[future]
                    try:
                        technique_findings = future.result()
                        if technique_findings:
                            findings.extend(technique_findings)
                            logger.info(f"Threat hunting technique '{technique_name}' found {len(technique_findings)} issues")
                    except Exception as e:
                        logger.error(f"Error in threat hunting technique '{technique_name}': {str(e)}")
            
            # Run cross-correlation analysis on all findings
            correlated_findings = self._correlate_findings(findings, analysis_time)
            
            # Add cryptographic signatures for verification
            for finding in correlated_findings:
                finding_id = self._generate_finding_id(finding)
                finding["finding_id"] = finding_id
                finding["signature"] = self._sign_finding(finding)
            
            return correlated_findings
        
        except Exception as e:
            logger.error(f"Error in threat hunting: {str(e)}")
            return findings
    
    def _detect_lateral_movement(self, data_sources: Dict[str, Any], 
                               config: Dict[str, Any], 
                               analysis_time: datetime) -> List[Dict[str, Any]]:
        """
        Detect signs of lateral movement within the network.
        
        This looks for patterns like:
        - One source connecting to multiple destinations
        - Multiple authentication attempts
        - Use of lateral movement tools
        """
        findings = []
        
        # Check if required data sources are available
        if "network_traffic" not in data_sources or "authentication_logs" not in data_sources:
            return findings
        
        network_traffic = data_sources["network_traffic"]
        auth_logs = data_sources["authentication_logs"]
        
        # Get techniques from config
        techniques = config.get("techniques", [])
        
        for technique in techniques:
            if technique["name"] == "Multiple Authentication Attempts":
                # Implementation for multiple auth attempts detection
                threshold = technique.get("threshold", 5)
                timeframe_minutes = technique.get("timeframe_minutes", 15)
                severity = technique.get("severity", "high")
                
                # Count authentication attempts by source
                auth_sources = {}
                timeframe_start = analysis_time - timedelta(minutes=timeframe_minutes)
                
                for log in auth_logs:
                    # Skip logs outside timeframe
                    log_time = log.get("timestamp", datetime.min)
                    if isinstance(log_time, str):
                        try:
                            log_time = datetime.fromisoformat(log_time)
                        except:
                            continue
                    
                    if log_time < timeframe_start:
                        continue
                    
                    source_ip = log.get("source_ip")
                    dest_ip = log.get("dest_ip")
                    
                    if not source_ip or not dest_ip:
                        continue
                    
                    if source_ip not in auth_sources:
                        auth_sources[source_ip] = set()
                    
                    auth_sources[source_ip].add(dest_ip)
                
                # Check if any source exceeds threshold
                for source_ip, destinations in auth_sources.items():
                    if len(destinations) >= threshold:
                        findings.append({
                            "technique": "lateral_movement",
                            "detection": technique["name"],
                            "severity": severity,
                            "source_ip": source_ip,
                            "destination_count": len(destinations),
                            "destinations": list(destinations),
                            "description": f"Source IP {source_ip} attempted authentication with {len(destinations)} different destinations in {timeframe_minutes} minutes",
                            "timestamp": analysis_time.isoformat(),
                            "mitre_technique": "T1210",
                            "confidence": 0.8
                        })
            
            elif technique["name"] == "Unusual Remote Service Usage":
                # Implementation for unusual remote service usage
                # (Simplified implementation for brevity)
                pass
        
        return findings
    
    def _detect_data_exfiltration(self, data_sources: Dict[str, Any], 
                                config: Dict[str, Any], 
                                analysis_time: datetime) -> List[Dict[str, Any]]:
        """
        Detect potential data exfiltration activities.
        
        This looks for patterns like:
        - Large data transfers to external destinations
        - DNS tunneling
        - Encrypted uploads to untrusted destinations
        """
        findings = []
        
        # Check if required data sources are available
        if "network_traffic" not in data_sources:
            return findings
        
        # Get techniques from config
        techniques = config.get("techniques", [])
        
        # Implementation for specific techniques
        # (Simplified for brevity)
        
        return findings
    
    def _detect_privilege_escalation(self, data_sources: Dict[str, Any], 
                                   config: Dict[str, Any], 
                                   analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect signs of privilege escalation."""
        # Simplified implementation
        return []
    
    def _detect_persistence_mechanisms(self, data_sources: Dict[str, Any], 
                                     config: Dict[str, Any], 
                                     analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect persistence mechanisms."""
        # Simplified implementation
        return []
    
    def _detect_command_and_control(self, data_sources: Dict[str, Any], 
                                  config: Dict[str, Any], 
                                  analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect command and control communication."""
        # Simplified implementation
        return []
    
    def _detect_defense_evasion(self, data_sources: Dict[str, Any], 
                              config: Dict[str, Any], 
                              analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect defense evasion techniques."""
        # Simplified implementation
        return []
    
    def _detect_unusual_processes(self, data_sources: Dict[str, Any], 
                               config: Dict[str, Any], 
                               analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect unusual process execution."""
        # Simplified implementation
        return []
    
    def _detect_unusual_network_activity(self, data_sources: Dict[str, Any], 
                                      config: Dict[str, Any], 
                                      analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect unusual network activity."""
        # Simplified implementation
        return []
    
    def _detect_unusual_authentication(self, data_sources: Dict[str, Any], 
                                    config: Dict[str, Any], 
                                    analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect unusual authentication patterns."""
        # Simplified implementation
        return []
    
    def _detect_iot_anomalies(self, data_sources: Dict[str, Any], 
                           config: Dict[str, Any], 
                           analysis_time: datetime) -> List[Dict[str, Any]]:
        """Detect anomalies in IoT device behavior."""
        findings = []
        
        # Check if required data sources are available
        if "network_traffic" not in data_sources or "iot_devices" not in data_sources:
            return findings
        
        network_traffic = data_sources["network_traffic"]
        iot_devices = data_sources["iot_devices"]
        
        # Get techniques from config
        techniques = config.get("techniques", [])
        
        for technique in techniques:
            if technique["name"] == "Unusual IoT Communication":
                # Implementation for unusual IoT communication
                threshold = technique.get("threshold", 2)
                timeframe_minutes = technique.get("timeframe_minutes", 60)
                severity = technique.get("severity", "high")
                
                # Get IoT device IPs
                iot_ips = [device.get("ip_address") for device in iot_devices if "ip_address" in device]
                
                # Track unusual destinations by device
                unusual_comms = {}
                timeframe_start = analysis_time - timedelta(minutes=timeframe_minutes)
                
                for traffic in network_traffic:
                    # Skip traffic outside timeframe
                    traffic_time = traffic.get("timestamp", datetime.min)
                    if isinstance(traffic_time, str):
                        try:
                            traffic_time = datetime.fromisoformat(traffic_time)
                        except:
                            continue
                    
                    if traffic_time < timeframe_start:
                        continue
                    
                    source_ip = traffic.get("source_ip")
                    dest_ip = traffic.get("destination_ip")
                    
                    if not source_ip or not dest_ip:
                        continue
                    
                    # Check if source is an IoT device
                    if source_ip in iot_ips:
                        # Check if destination is unusual
                        # (In a real implementation, this would check against known IoT communication patterns)
                        is_unusual = self._is_unusual_destination(source_ip, dest_ip)
                        
                        if is_unusual:
                            if source_ip not in unusual_comms:
                                unusual_comms[source_ip] = set()
                            unusual_comms[source_ip].add(dest_ip)
                
                # Check if any device exceeds threshold
                for source_ip, destinations in unusual_comms.items():
                    if len(destinations) >= threshold:
                        findings.append({
                            "technique": "iot_anomalies",
                            "detection": technique["name"],
                            "severity": severity,
                            "source_ip": source_ip,
                            "destination_count": len(destinations),
                            "destinations": list(destinations),
                            "description": f"IoT device {source_ip} communicated with {len(destinations)} unusual destinations",
                            "timestamp": analysis_time.isoformat(),
                            "mitre_technique": "T1020",
                            "confidence": 0.75
                        })
        
        return findings
    
    def _is_unusual_destination(self, source_ip: str, dest_ip: str) -> bool:
        """Determine if a destination is unusual for a source."""
        # In a real implementation, this would check:
        # - Known legitimate destinations for this device type
        # - Historical communication patterns
        # - Threat intelligence data
        # For now, return a dummy value
        return dest_ip.startswith("10.") and int(dest_ip.split(".")[-1]) > 200
    
    def _correlate_findings(self, findings: List[Dict[str, Any]], 
                          analysis_time: datetime) -> List[Dict[str, Any]]:
        """Correlate findings to identify attack campaigns and reduce false positives."""
        if not findings:
            return []
        
        # Group findings by source IP
        findings_by_source = {}
        for finding in findings:
            source_ip = finding.get("source_ip")
            if not source_ip:
                continue
                
            if source_ip not in findings_by_source:
                findings_by_source[source_ip] = []
            findings_by_source[source_ip].append(finding)
        
        # Look for attack campaigns (multiple techniques from same source)
        correlated_findings = []
        campaigns = []
        
        for source_ip, source_findings in findings_by_source.items():
            if len(source_findings) > 1:
                # Check if findings represent different techniques
                techniques = set(f.get("technique") for f in source_findings)
                if len(techniques) > 1:
                    # Potential campaign
                    campaign = {
                        "campaign_id": self._generate_campaign_id(source_ip, techniques, analysis_time),
                        "source_ip": source_ip,
                        "techniques": list(techniques),
                        "findings": source_findings,
                        "severity": "critical",
                        "timestamp": analysis_time.isoformat(),
                        "description": f"Potential attack campaign from {source_ip} using multiple techniques: {', '.join(techniques)}",
                        "confidence": 0.9
                    }
                    campaigns.append(campaign)
                    
                    # Increase confidence and severity of individual findings
                    for finding in source_findings:
                        finding["confidence"] = min(1.0, finding.get("confidence", 0.7) + 0.2)
                        finding["campaign_id"] = campaign["campaign_id"]
                        correlated_findings.append(finding)
                else:
                    # Same technique multiple times
                    correlated_findings.extend(source_findings)
            else:
                # Single finding
                correlated_findings.extend(source_findings)
        
        # Add campaigns to findings
        correlated_findings.extend(campaigns)
        
        return correlated_findings
    
    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate a unique ID for a finding."""
        # Create a string with key finding attributes
        finding_str = f"{finding.get('technique', 'unknown')}:{finding.get('source_ip', 'unknown')}:{finding.get('timestamp', 'unknown')}"
        
        # Hash the string
        return hashlib.sha256(finding_str.encode()).hexdigest()[:16]
    
    def _generate_campaign_id(self, source_ip: str, techniques: set, timestamp: datetime) -> str:
        """Generate a unique ID for a campaign."""
        campaign_str = f"{source_ip}:{','.join(sorted(techniques))}:{timestamp.isoformat()}"
        return hashlib.sha256(campaign_str.encode()).hexdigest()[:16]
    
    def _sign_finding(self, finding: Dict[str, Any]) -> str:
        """Create a cryptographic signature for a finding."""
        # Create a string representation of key finding attributes
        finding_str = json.dumps({
            "finding_id": finding.get("finding_id", ""),
            "technique": finding.get("technique", ""),
            "detection": finding.get("detection", ""),
            "source_ip": finding.get("source_ip", ""),
            "timestamp": finding.get("timestamp", ""),
            "severity": finding.get("severity", "")
        }, sort_keys=True)
        
        # Sign the string
        hmac_result = self.crypto.create_hmac(finding_str)
        
        return hmac_result["hmac"]
    
    def add_hunting_rule(self, technique: str, rule: Dict[str, Any]) -> bool:
        """
        Add a new hunting rule.
        
        Args:
            technique: Technique category for the rule
            rule: Rule definition
            
        Returns:
            True if successfully added, False otherwise
        """
        try:
            if technique not in self.hunting_rules:
                self.hunting_rules[technique] = {
                    "enabled": True,
                    "techniques": []
                }
            
            # Check if rule already exists
            for existing_rule in self.hunting_rules[technique]["techniques"]:
                if existing_rule["name"] == rule["name"]:
                    # Update existing rule
                    existing_rule.update(rule)
                    return True
            
            # Add new rule
            self.hunting_rules[technique]["techniques"].append(rule)
            
            # Save updated rules
            rules_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'hunting_rules.json')
            with open(rules_path, 'w') as f:
                json.dump(self.hunting_rules, f, indent=4)
                
            return True
            
        except Exception as e:
            logger.error(f"Error adding hunting rule: {str(e)}")
            return False
    
    def enable_technique(self, technique: str, enabled: bool = True) -> bool:
        """
        Enable or disable a hunting technique.
        
        Args:
            technique: Technique to enable/disable
            enabled: Whether to enable (True) or disable (False)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if technique in self.hunting_rules:
                self.hunting_rules[technique]["enabled"] = enabled
                
                # Save updated rules
                rules_path = os.path.join(settings.BASE_DIR, 'core', 'data', 'hunting_rules.json')
                with open(rules_path, 'w') as f:
                    json.dump(self.hunting_rules, f, indent=4)
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating hunting technique: {str(e)}")
            return False 