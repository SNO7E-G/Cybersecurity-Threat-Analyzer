# Cybersecurity Threat Analyzer

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-yellow.svg)

An advanced network security monitoring and threat detection system with cutting-edge machine learning integration. This comprehensive platform provides real-time traffic analysis, advanced threat detection, and automated incident response capabilities with expanded device support and enhanced security algorithms.

**© 2025 Mahmoud Ashraf (SNO7E). All Rights Reserved.**

## Features

- **Real-Time Traffic Monitoring**: Capture and analyze network packets in real-time with microsecond precision
- **Advanced Threat Detection**: Multi-layered detection using signature, behavioral, and anomaly-based approaches
- **AI-Powered Analytics**: Uses ensemble machine learning models to detect zero-day threats and predict attack vectors
- **Cross-Platform Support**: Compatible with Windows, Linux, macOS, and various network devices (Cisco, Juniper, etc.)
- **Container Support**: Deployable in Docker, Kubernetes, and cloud environments
- **Automated Response**: Configurable automated responses for containment and mitigation
- **Enterprise-Grade Dashboard**: Rich visualization with real-time updates and customizable layouts
- **Comprehensive Alerting**: Multi-channel notifications via email, SMS, webhooks, and SIEM integration
- **Advanced Packet Analysis**: Deep packet inspection with protocol-specific analyzers
- **Vulnerability Management**: Integration with CVE databases and automated vulnerability assessment
- **Secure API Gateway**: RESTful and GraphQL APIs with OAuth2 and JWT authentication
- **User & Role Management**: Fine-grained access control with customizable permissions
- **Audit & Compliance**: Detailed logging with tamper-evident storage for compliance (GDPR, HIPAA, PCI DSS)
- **Threat Intelligence**: Integration with MITRE ATT&CK, AlienVault OTX, and custom threat feeds

## Advanced Security Features

### Next-Generation Threat Detection

- **Behavioral Analysis Engine**: Baseline normal network behavior and detect deviations
- **Encrypted Traffic Analysis**: Identify malicious patterns in encrypted traffic without decryption
- **Zero-Day Attack Detection**: ML-powered identification of previously unknown threats
- **Lateral Movement Detection**: Track and identify attacker movement within networks
- **Advanced Persistent Threat (APT) Detection**: Multi-stage attack recognition algorithms
- **DNS Analytics**: Detect DNS tunneling, domain generation algorithms, and DNS poisoning
- **DeepPacket Analysis**: Layer 7 inspection for sophisticated application-level attacks
- **Quantum-Resistant Cryptography**: Implementing post-quantum cryptographic algorithms for future-proof security
- **Side-Channel Attack Prevention**: Protection against timing, power analysis, and cache-based attacks
- **Advanced Anti-Tampering**: Real-time integrity monitoring of system files and configurations

### Machine Learning Algorithms

- **Ensemble Detection**: Combines multiple ML models (Isolation Forest, LSTM, XGBoost)
- **Federated Learning Support**: Share threat intelligence without exposing sensitive data
- **Reinforcement Learning**: Self-improving detection capabilities
- **NLP for Log Analysis**: Advanced parsing and correlation of security logs
- **Neural Networks**: Deep learning for traffic classification and anomaly detection
- **Adversarial ML Protection**: Resilience against ML evasion techniques
- **Variational Autoencoders (VAE)**: Advanced anomaly detection using probabilistic encoding
- **Transformer Architecture**: Sequence analysis using attention-based models for time-series attacks
- **BERT-based Log Analyzers**: Deep contextual understanding of system logs for subtle threat identification
- **LightGBM and XGBoost**: Gradient-boosted decision trees for high-speed classification
- **Transfer Learning**: Adapting pre-trained models for new threat categories with minimal data
- **Zero-Shot Detection**: Identifying threats in categories never seen during training

### Defense-in-Depth Approach

- **Runtime Application Self-Protection (RASP)**: Self-monitoring for attack attempts
- **Deception Technology**: Honeypots and honeytokens to identify and study attackers
- **Binary Analysis**: Static and dynamic analysis of suspicious binaries
- **Memory Forensics**: Real-time memory scanning for fileless malware
- **Supply Chain Attack Detection**: Monitoring for compromised dependencies
- **Moving Target Defense**: Dynamically changing system configurations to prevent attacks
- **Sandboxed Execution**: Isolated environment for analyzing suspicious code
- **Hardware-based Security**: Integration with TPM, Intel SGX, and ARM TrustZone
- **Homomorphic Encryption Support**: Processing encrypted data without decryption
- **Blockchain-based Integrity**: Immutable audit logs using distributed ledger technology

## Advanced Cryptographic Security

- **AES-GCM Encryption**: Authenticated encryption with associated data (AEAD)
- **RSA-OAEP**: Asymmetric encryption with optimal asymmetric encryption padding
- **HMAC Authentication**: Message authentication using cryptographic hash functions
- **ECDSA Digital Signatures**: Elliptic Curve Digital Signature Algorithm for compact signatures
- **PBKDF2 & Argon2 Key Derivation**: Secure password hashing with tunable parameters
- **Zero-Knowledge Proofs**: Authentication without revealing sensitive information
- **Secure Key Management**: Hardware security module (HSM) integration for key storage
- **Forward Secrecy**: Ensuring past communications remain secure if keys are compromised
- **Certificate Pinning**: Preventing man-in-the-middle attacks in SSL/TLS connections
- **Secure Multi-party Computation**: Joint analysis of data while keeping inputs private

## Cross-Platform Support

### Operating Systems
- **Desktop Platforms**: Windows 7-11, macOS 10.15+, Ubuntu/Debian/CentOS/RHEL/Fedora Linux
- **Server Platforms**: Windows Server 2016-2022, Linux Server distributions, FreeBSD
- **Mobile Platforms**: Android 10+, iOS 14+

### Network Devices
- **Enterprise Routers**: Cisco (IOS, IOS-XE, IOS-XR), Juniper (JunOS), Huawei, Arista
- **Firewalls**: Fortinet FortiGate, Palo Alto, Check Point, Sophos, Cisco ASA
- **Switches**: Cisco Catalyst/Nexus, Juniper EX/QFX, Arista, HP/Aruba
- **SD-WAN Appliances**: Cisco Viptela, VMware VeloCloud, Versa Networks

### Cloud Environments
- **Public Cloud**: AWS, Azure, Google Cloud, Oracle Cloud, IBM Cloud
- **Private Cloud**: OpenStack, VMware vSphere, Microsoft Azure Stack
- **Hybrid Cloud**: Multi-cloud deployments with unified monitoring
- **Serverless**: AWS Lambda, Azure Functions, Google Cloud Functions

### IoT and Embedded
- **IoT Devices**: Smart devices, IP cameras, industrial sensors
- **Embedded Systems**: ARM-based devices, MIPS architecture, custom hardware
- **Industrial Control**: SCADA systems, PLCs, RTUs, industrial protocols
- **Medical Devices**: Connected healthcare equipment with specialized monitoring

### Mobile and BYOD
- **Endpoint Agents**: Lightweight monitoring for laptops, tablets, smartphones
- **MDM Integration**: Mobile Device Management platforms for enterprise fleets
- **Containerized Apps**: Monitoring of containerized applications on mobile devices
- **BYOD Security**: Policy enforcement for bring-your-own-device environments

## Installation

### Prerequisites

- Python 3.9 or higher
- PostgreSQL 13+ (production) or SQLite (development)
- 8GB RAM minimum (16GB recommended for production)
- Admin/root privileges for packet capture

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/SNO7E-G/Cybersecurity-Threat-Analyzer.git
   cd Cybersecurity-Threat-Analyzer
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root:
   ```
   SECRET_KEY=your_secret_key_here
   DEBUG=False
   ALLOWED_HOSTS=localhost,127.0.0.1
   DB_ENGINE=django.db.backends.sqlite3
   DB_NAME=db.sqlite3
   JWT_SECRET_KEY=your_jwt_secret_key
   CRYPTO_SALT=your_crypto_salt
   ```

5. Initialize the database:
   ```bash
   python manage.py migrate
   python manage.py loaddata initial_data
   ```

6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

7. Start the development server:
   ```bash
   python manage.py runserver
   ```

### Docker Deployment

```bash
# Build the container
docker build -t cyber-threat-analyzer .

# Run with proper network access
docker run -d --network host --cap-add=NET_ADMIN --name cta cyber-threat-analyzer
```

### Cloud Deployment

For cloud deployment, we provide infrastructure-as-code templates:

```bash
# AWS CloudFormation
aws cloudformation deploy --template-file deploy/aws-template.yaml --stack-name cta-stack

# Azure ARM Template
az deployment group create --resource-group myResourceGroup --template-file deploy/azure-template.json

# Google Cloud Deployment Manager
gcloud deployment-manager deployments create cta-deployment --config deploy/gcp-config.yaml
```

## Usage

### Detection Engines Configuration

1. Access the Configuration panel at `http://localhost:8000/dashboard/settings/`
2. Enable desired detection engines:
   - Signature-based detection (fastest, lowest false positives)
   - Behavioral analysis (moderate resource usage)
   - Machine learning (highest accuracy, resource intensive)
   - Heuristic analysis (balanced approach)
   - Advanced AI models (transformer-based, BERT, deep learning)
   - Ensemble detection (combines multiple approaches)

### ML Model Training

For optimal threat detection, train the ML models on your network:

1. Collect baseline data:
   ```bash
   python manage.py collect_baseline --days 7
   ```

2. Train the ML model:
   ```bash
   python manage.py train_ml_model --algorithm ensemble --training_data baseline
   ```

3. Use advanced algorithms:
   ```bash
   python manage.py train_ml_model --algorithm transformer_sequence --sequence_length 30 --training_data baseline
   ```

### Running a Network Scan

1. Go to the "Network Scans" page
2. Click "New Scan"
3. Configure scan parameters:
   - Scan Name: Descriptive name for the scan
   - Target Network: IP range to scan (e.g., 192.168.1.0/24)
   - Interface: Network interface to use
   - Analysis Depth: Packet headers only, Full packet capture, or Deep inspection
   - Scan Type: Passive monitoring, Active scanning, or Vulnerability assessment
   - Device Types: Target specific device types (Windows, IoT, Network Devices)
   - Custom Detection Rules: Apply specialized detection algorithms

### Device Management

1. Navigate to the "Devices" dashboard
2. View auto-discovered devices or add devices manually
3. Configure device-specific monitoring:
   - Windows workstations: WMI monitoring, event logs, registry changes
   - Network devices: SNMP, Syslog, NetFlow collection
   - IoT devices: Protocol-specific monitoring (MQTT, CoAP, custom)
   - Industrial systems: Modbus, DNP3, OPC UA monitoring

## Architecture

The system follows a modular microservices architecture:

- **Core Engine**: Central packet processing pipeline
  - Packet capture module (libpcap/npcap)
  - Protocol analyzers 
  - Detection engines coordinator
- **Detection Engines**:
  - Signature matcher (rule-based detection)
  - Behavioral analyzer (statistical anomaly detection)
  - Machine learning engine (multiple algorithms)
  - Heuristic analyzer (expert systems)
  - Advanced AI models (deep learning, transformers)
- **Device Support Layer**:
  - OS-specific monitoring adapters
  - Network device protocols
  - Cloud platform connectors
  - IoT protocol handlers
  - Industrial system interfaces
- **Cryptographic Security**:
  - Encryption services (symmetric/asymmetric)
  - Key management system
  - Digital signature verification
  - Secure token handling
  - Cryptographic hash functions
- **Orchestration Layer**:
  - API gateway
  - Authentication and authorization
  - Event bus for notifications
  - Workflow automation engine
- **Storage Layer**:
  - Time-series database for metrics
  - Document store for alerts and events
  - Relational database for configuration
  - Encrypted storage for sensitive data
- **Presentation Layer**:
  - Web dashboard
  - Real-time visualization
  - Reporting engine
  - Mobile companion app

## API Documentation

Our REST API enables seamless integration with other security tools:

```bash
# Get API documentation
curl -X GET http://localhost:8000/api/docs/

# Authentication example
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

Full OpenAPI documentation is available at `http://localhost:8000/api/schema/`

## Security Considerations

- **Defense in Depth**: Multiple layers of security controls
- **Secure by Default**: Conservative default settings
- **Principle of Least Privilege**: Fine-grained access control
- **Data Protection**: End-to-end encryption for sensitive data
- **API Security**: Rate limiting, CORS protection, and input validation
- **Secure Development**: OWASP guidelines and regular security audits
- **Auditability**: Cryptographically signed logs for forensic integrity
- **Zero Trust Architecture**: Verify every access attempt regardless of source
- **Secure Supply Chain**: Verification of dependencies and third-party components
- **Regulatory Compliance**: Built-in controls for GDPR, HIPAA, PCI DSS, NIST framework

## Extending the System

### Writing Custom Detection Rules

```python
# Example custom detection rule
def detect_data_exfiltration(packet, context):
    """
    Detects potential data exfiltration based on unusual outbound DNS queries
    """
    if packet.haslayer(DNS) and packet.qr == 0:  # DNS query
        query = packet[DNSQR].qname.decode()
        if len(query) > 50 and entropy(query) > 4.0:
            return Threat(
                threat_type="Data Exfiltration",
                severity="high",
                confidence=0.85,
                description=f"Potential DNS tunneling detected: {query}"
            )
    return None
```

### Adding New ML Models

```python
# Example of adding a custom ML model
from ml.advanced_algorithms import AdvancedSecurityAlgorithms

# Initialize the advanced algorithms manager
alg_manager = AdvancedSecurityAlgorithms()

# Create and train a custom model
custom_model = alg_manager.get_algorithm('zero_day_detector')
alg_manager.train_model('zero_day_detector', X_train, y_train)

# Use the model for detection
predictions = alg_manager.predict('zero_day_detector', X_test)
```

See `docs/extending_ml.md` for detailed instructions on adding custom ML models.

### Adding Custom Device Support

```python
# Example of registering a custom device profile
from core.device_support import DeviceSupport

device_support = DeviceSupport()

# Define a custom device profile
custom_profile = {
    'name': 'Medical IoT Device',
    'scanning_protocols': ['DICOM', 'HL7', 'MQTT'],
    'monitoring_protocols': ['SNMP', 'Syslog', 'MQTT'],
    'authentication_methods': ['OAuth2', 'Certificate'],
    'vulnerability_scanners': ['Medical-specific', 'General'],
    'log_paths': ['/var/log/device', '/data/logs'],
    'default_ports': [104, 2575, 1883, 8883],
    'supported_analysis': ['network', 'protocols', 'data_access']
}

# Register the custom profile
device_support.register_custom_device_profile('medical_iot', custom_profile)
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## About the Author

**Mahmoud Ashraf (SNO7E)** is a cybersecurity researcher and developer focusing on advanced threat detection and machine learning applications in security.

GitHub: [@SNO7E-G](https://github.com/SNO7E-G)

## Acknowledgements

- Scapy for packet manipulation capabilities
- Django for the web framework
- Scikit-learn, TensorFlow, PyTorch for machine learning functionality
- MITRE ATT&CK for threat intelligence framework
- The cybersecurity community for continuous knowledge sharing 