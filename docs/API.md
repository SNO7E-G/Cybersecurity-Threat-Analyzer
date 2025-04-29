# Cybersecurity Threat Analyzer API Documentation

## Overview
This document provides comprehensive documentation for the Cybersecurity Threat Analyzer API endpoints, which enable programmatic access to the system's threat detection, analysis, and reporting capabilities.

## Base URL
```
https://api.cyberthreatanalyzer.example.com/v1
```

## Authentication
All API requests require authentication using API keys via the Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

## Endpoints

### Threat Detection

#### Analyze Network Traffic
`POST /analyze/network`

Analyzes network traffic for potential threats.

**Request Body:**
```json
{
  "pcap_data": "base64_encoded_pcap_data",
  "analysis_params": {
    "deep_inspection": true,
    "threat_categories": ["malware", "phishing", "data_exfiltration"]
  }
}
```

**Response:**
```json
{
  "analysis_id": "a1b2c3d4",
  "threats_detected": [
    {
      "threat_id": "THR-12345",
      "category": "malware",
      "confidence": 0.89,
      "source_ip": "192.168.1.100",
      "destination_ip": "203.0.113.5",
      "timestamp": "2023-10-15T08:30:45Z",
      "details": {
        "malware_signature": "TROJAN.WIN32.EMOTET",
        "behavior_patterns": ["encrypted_communication", "data_exfiltration"]
      }
    }
  ],
  "analysis_summary": {
    "total_packets": 15420,
    "analyzed_packets": 15420,
    "processing_time_ms": 1250
  }
}
```

#### Scan Device
`POST /analyze/device`

Scans a device for vulnerabilities and security issues.

**Request Body:**
```json
{
  "device_id": "DEV-789",
  "scan_type": "comprehensive",
  "include_patches": true
}
```

**Response:**
```json
{
  "scan_id": "SCN-56789",
  "device_id": "DEV-789",
  "vulnerabilities": [
    {
      "vuln_id": "CVE-2023-1234",
      "severity": "high",
      "affected_component": "OpenSSL 1.1.1k",
      "description": "Buffer overflow vulnerability in TLS handshake",
      "remediation": "Update to OpenSSL 1.1.1l or later"
    }
  ],
  "security_posture": {
    "score": 72,
    "rating": "fair",
    "improvement_areas": ["patch_management", "encryption_standards"]
  }
}
```

### Threat Intelligence

#### Query Threat Database
`GET /intelligence/threats`

Retrieves information about known threats matching the specified criteria.

**Query Parameters:**
- `threat_type` - Type of threat (e.g., malware, phishing)
- `severity` - Severity level (low, medium, high, critical)
- `date_range` - Time range for threats (ISO 8601 format)
- `limit` - Maximum number of results (default: 20)

**Response:**
```json
{
  "threats": [
    {
      "threat_id": "THR-45678",
      "name": "Ryuk Ransomware",
      "type": "ransomware",
      "severity": "critical",
      "first_seen": "2021-03-15T00:00:00Z",
      "last_seen": "2023-09-28T14:22:11Z",
      "ioc": {
        "file_hashes": ["a1b2c3d4e5f6..."],
        "domains": ["malicious-domain.example.com"],
        "ip_addresses": ["198.51.100.123"]
      },
      "description": "Ryuk is a sophisticated ransomware that targets enterprise environments."
    }
  ],
  "total_results": 1,
  "page": 1
}
```

### Reporting

#### Generate Threat Report
`POST /reports/generate`

Generates a comprehensive threat report based on specified parameters.

**Request Body:**
```json
{
  "report_type": "executive_summary",
  "time_period": {
    "start": "2023-09-01T00:00:00Z",
    "end": "2023-09-30T23:59:59Z"
  },
  "include_sections": ["threat_overview", "critical_incidents", "recommendations"],
  "format": "pdf"
}
```

**Response:**
```json
{
  "report_id": "RPT-123456",
  "status": "generating",
  "estimated_completion_time": "2023-10-15T10:15:30Z",
  "download_url": null
}
```

#### Check Report Status
`GET /reports/{report_id}`

Checks the status of a previously requested report.

**Response:**
```json
{
  "report_id": "RPT-123456",
  "status": "completed",
  "completion_time": "2023-10-15T10:14:22Z",
  "download_url": "https://api.cyberthreatanalyzer.example.com/v1/reports/RPT-123456/download",
  "expires_at": "2023-10-22T10:14:22Z"
}
```

### Plugin Management

#### List Available Plugins
`GET /plugins`

Lists all available plugins and their status.

**Response:**
```json
{
  "plugins": [
    {
      "plugin_id": "ai_detector",
      "name": "AI-Powered Threat Detector",
      "version": "1.0.0",
      "status": "active",
      "capabilities": ["advanced_threat_detection", "behavioral_analysis"]
    },
    {
      "plugin_id": "sandbox_analyzer",
      "name": "Malware Sandbox Analyzer",
      "version": "2.1.3",
      "status": "inactive",
      "capabilities": ["malware_analysis", "code_deobfuscation"]
    }
  ]
}
```

#### Enable Plugin
`POST /plugins/{plugin_id}/enable`

Activates a specific plugin.

**Response:**
```json
{
  "plugin_id": "sandbox_analyzer",
  "name": "Malware Sandbox Analyzer",
  "status": "active",
  "message": "Plugin successfully enabled"
}
```

## Error Handling

All API errors follow a standard format:

```json
{
  "error": {
    "code": "authentication_failed",
    "message": "Invalid API key provided",
    "request_id": "req-abc123"
  }
}
```

Common error codes:
- `authentication_failed` - Invalid or missing API key
- `invalid_parameters` - Malformed request parameters
- `resource_not_found` - Requested resource doesn't exist
- `rate_limit_exceeded` - Too many requests in a given time period
- `internal_error` - Server-side error

## Rate Limiting

API requests are limited to 100 requests per minute per API key. Rate limit information is included in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1634243400
```

## Webhooks

The API supports webhooks for asynchronous event notifications.

### Webhook Events
- `threat.detected` - New threat detected
- `scan.completed` - Device scan completed
- `report.ready` - Report generation finished

### Webhook Payload Example
```json
{
  "event": "threat.detected",
  "timestamp": "2023-10-15T09:45:30Z",
  "data": {
    "threat_id": "THR-98765",
    "severity": "high",
    "affected_device": "DEV-123",
    "details_url": "https://api.cyberthreatanalyzer.example.com/v1/threats/THR-98765"
  }
}
```

## SDKs and Client Libraries

Official client libraries are available for:
- Python: `pip install cyberthreat-analyzer-client`
- JavaScript: `npm install cyberthreat-analyzer-client`
- Go: `go get github.com/cyberthreatanalyzer/client-go` 