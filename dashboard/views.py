import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Q
from django.utils import timezone
from django.contrib import messages
from datetime import datetime, timedelta
import psutil

from core.models import (
    NetworkScan, Packet, Threat, VulnerabilityScan,
    Vulnerability, Report, Alert, UserProfile, MLModel, SystemSettings
)
from core.network_monitor import NetworkMonitor
from ml.anomaly_detector import AnomalyDetector
from core.integration import integration
from plugins import get_registry


@login_required
def dashboard(request):
    """Dashboard view showing overview of the system."""
    # Placeholder data - would be replaced with real data in production
    context = {
        'scan_count': 157,
        'packet_count': 1458972,
        'threat_count': 42,
        'alert_count': 12,
        'recent_threats': [
            {
                'threat_type': 'Ransomware',
                'severity': 'critical',
                'status': 'Active',
                'timestamp': datetime.now() - timedelta(hours=2)
            },
            {
                'threat_type': 'Data Exfiltration',
                'severity': 'high',
                'status': 'Investigating',
                'timestamp': datetime.now() - timedelta(hours=5)
            },
            {
                'threat_type': 'Suspicious Login',
                'severity': 'medium',
                'status': 'Resolved',
                'timestamp': datetime.now() - timedelta(days=1)
            }
        ],
        'recent_alerts': [
            {
                'title': 'Critical Vulnerability',
                'message': 'Critical vulnerability detected in OpenSSL 1.1.1k',
                'severity': 'critical',
                'timestamp': datetime.now() - timedelta(hours=1)
            },
            {
                'title': 'Unusual Network Activity',
                'message': 'Unusual outbound traffic detected from 192.168.1.155',
                'severity': 'warning',
                'timestamp': datetime.now() - timedelta(hours=3)
            }
        ],
        'recent_scans': [
            {
                'id': 'scan-123',
                'name': 'Weekly Full Network Scan',
                'target_network': '192.168.1.0/24',
                'status': 'completed',
                'start_time': datetime.now() - timedelta(days=1)
            },
            {
                'id': 'scan-124',
                'name': 'Server Vulnerability Scan',
                'target_network': '10.0.0.0/8',
                'status': 'running',
                'start_time': datetime.now() - timedelta(hours=2)
            }
        ],
        'severity_data': {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'data': [12, 18, 7, 5],
            'colors': ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
        }
    }
    
    return render(request, 'dashboard/dashboard.html', context)


@login_required
def network_scans(request):
    """View all network scans."""
    scans = NetworkScan.objects.all().order_by('-created_at')
    
    # Handle creating a new scan
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        target_network = request.POST.get('target_network')
        scan_type = request.POST.get('scan_type')
        interface = request.POST.get('interface')
        filter_str = request.POST.get('filter_str')
        
        # Create the scan
        scan = NetworkScan.objects.create(
            name=name,
            description=description,
            target_network=target_network,
            scan_type=scan_type,
            status='pending',
            created_by=request.user
        )
        
        # Start the network monitoring
        monitor = NetworkMonitor(
            scan_id=scan.id,
            interface=interface,
            filter_str=filter_str
        )
        
        if monitor.start_capture():
            messages.success(request, 'Network scan started successfully')
        else:
            messages.error(request, 'Failed to start network scan')
        
        return redirect('network_scans')
    
    context = {
        'scans': scans,
        'active_tab': 'network_scans'
    }
    
    return render(request, 'dashboard/network_scans.html', context)


@login_required
def network_scan_detail(request, scan_id):
    """View details of a specific network scan."""
    scan = get_object_or_404(NetworkScan, id=scan_id)
    packets = Packet.objects.filter(scan_id=scan_id).order_by('-timestamp')[:100]
    threats = Threat.objects.filter(scan_id=scan_id).order_by('-timestamp')
    
    # Handle stopping the scan
    if request.method == 'POST' and 'stop_scan' in request.POST:
        monitor = NetworkMonitor(scan_id=scan_id)
        if monitor.stop_capture():
            messages.success(request, 'Network scan stopped successfully')
        else:
            messages.error(request, 'Failed to stop network scan')
        
        return redirect('network_scan_detail', scan_id=scan_id)
    
    context = {
        'scan': scan,
        'packets': packets,
        'threats': threats,
        'active_tab': 'network_scans'
    }
    
    return render(request, 'dashboard/network_scan_detail.html', context)


@login_required
def threats(request):
    """View all threats."""
    # Get filter parameters
    severity = request.GET.get('severity')
    status = request.GET.get('status')
    
    # Base query
    threats = Threat.objects.all()
    
    # Apply filters
    if severity:
        threats = threats.filter(severity=severity)
    if status:
        threats = threats.filter(status=status)
    
    # Order by timestamp
    threats = threats.order_by('-timestamp')
    
    # Get severity counts for charts
    severity_counts = Threat.objects.values('severity').annotate(count=Count('id'))
    severity_data = {
        'labels': [],
        'data': [],
        'colors': []
    }
    
    severity_colors = {
        'low': '#28a745',      # Green
        'medium': '#ffc107',   # Yellow
        'high': '#fd7e14',     # Orange
        'critical': '#dc3545'  # Red
    }
    
    for entry in severity_counts:
        severity = entry['severity']
        severity_data['labels'].append(severity.capitalize())
        severity_data['data'].append(entry['count'])
        severity_data['colors'].append(severity_colors.get(severity, '#007bff'))
    
    context = {
        'threats': threats,
        'severity_data': json.dumps(severity_data),
        'active_tab': 'threats'
    }
    
    return render(request, 'dashboard/threats.html', context)


@login_required
def threat_detail(request, threat_id):
    """View details of a specific threat."""
    threat = get_object_or_404(Threat, id=threat_id)
    related_packets = threat.related_packets.all().order_by('-timestamp')
    
    # Handle threat mitigation
    if request.method == 'POST':
        status = request.POST.get('status')
        
        if status:
            threat.status = status
            threat.mitigated_by = request.user
            threat.mitigated_at = timezone.now()
            threat.save()
            
            messages.success(request, f'Threat status updated to {status}')
            
            return redirect('threat_detail', threat_id=threat_id)
    
    context = {
        'threat': threat,
        'related_packets': related_packets,
        'active_tab': 'threats'
    }
    
    return render(request, 'dashboard/threat_detail.html', context)


@login_required
def vulnerabilities(request):
    """View all vulnerabilities."""
    vulnerabilities = Vulnerability.objects.all().order_by('-vulnerability_scan__timestamp')
    
    context = {
        'vulnerabilities': vulnerabilities,
        'active_tab': 'vulnerabilities'
    }
    
    return render(request, 'dashboard/vulnerabilities.html', context)


@login_required
def packets(request):
    """View captured packets."""
    # Get filter parameters
    scan_id = request.GET.get('scan_id')
    protocol = request.GET.get('protocol')
    source_ip = request.GET.get('source_ip')
    destination_ip = request.GET.get('destination_ip')
    
    # Base query
    packets = Packet.objects.all()
    
    # Apply filters
    if scan_id:
        packets = packets.filter(scan_id=scan_id)
    if protocol:
        packets = packets.filter(protocol=protocol)
    if source_ip:
        packets = packets.filter(source_ip=source_ip)
    if destination_ip:
        packets = packets.filter(destination_ip=destination_ip)
    
    # Order by timestamp and limit to 1000 packets
    packets = packets.order_by('-timestamp')[:1000]
    
    # Get list of scans for filter dropdown
    scans = NetworkScan.objects.all().order_by('-created_at')
    
    context = {
        'packets': packets,
        'scans': scans,
        'active_tab': 'packets'
    }
    
    return render(request, 'dashboard/packets.html', context)


@login_required
def reports(request):
    """View and generate reports."""
    reports = Report.objects.all().order_by('-created_at')
    
    # Handle generating a new report
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        title = request.POST.get('title')
        description = request.POST.get('description')
        report_type = request.POST.get('report_type')
        
        if scan_id:
            try:
                scan = NetworkScan.objects.get(id=scan_id)
                
                # Create the report
                report = Report.objects.create(
                    scan=scan,
                    title=title or f'Report for {scan.name}',
                    description=description or '',
                    created_by=request.user,
                    report_type=report_type or 'summary'
                )
                
                messages.success(request, 'Report generation initiated')
                
                # In a real system, you would generate the actual report file here
                
                return redirect('reports')
                
            except NetworkScan.DoesNotExist:
                messages.error(request, 'Scan not found')
    
    # Get list of completed scans for report generation
    completed_scans = NetworkScan.objects.filter(status='completed').order_by('-created_at')
    
    context = {
        'reports': reports,
        'completed_scans': completed_scans,
        'active_tab': 'reports'
    }
    
    return render(request, 'dashboard/reports.html', context)


@login_required
def alerts(request):
    """View system alerts."""
    # Get filter parameters
    severity = request.GET.get('severity')
    acknowledged = request.GET.get('acknowledged')
    
    # Base query
    alerts = Alert.objects.all()
    
    # Apply filters
    if severity:
        alerts = alerts.filter(severity=severity)
    if acknowledged is not None:
        if acknowledged == 'true':
            alerts = alerts.filter(acknowledged=True)
        elif acknowledged == 'false':
            alerts = alerts.filter(acknowledged=False)
    
    # Order by timestamp
    alerts = alerts.order_by('-timestamp')
    
    # Handle acknowledging alerts
    if request.method == 'POST':
        alert_id = request.POST.get('alert_id')
        
        if alert_id:
            try:
                alert = Alert.objects.get(id=alert_id)
                alert.acknowledged = True
                alert.acknowledged_by = request.user
                alert.acknowledged_at = timezone.now()
                alert.save()
                
                messages.success(request, 'Alert acknowledged')
                
                return redirect('alerts')
                
            except Alert.DoesNotExist:
                messages.error(request, 'Alert not found')
    
    context = {
        'alerts': alerts,
        'active_tab': 'alerts'
    }
    
    return render(request, 'dashboard/alerts.html', context)


@login_required
def profile(request):
    """View and edit user profile."""
    # Get or create user profile
    profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    # Handle updating profile
    if request.method == 'POST':
        # Update user info
        request.user.first_name = request.POST.get('first_name', request.user.first_name)
        request.user.last_name = request.POST.get('last_name', request.user.last_name)
        request.user.email = request.POST.get('email', request.user.email)
        request.user.save()
        
        # Update profile info
        profile.phone_number = request.POST.get('phone_number', profile.phone_number)
        profile.telegram_id = request.POST.get('telegram_id', profile.telegram_id)
        profile.receive_email_alerts = 'receive_email_alerts' in request.POST
        profile.receive_sms_alerts = 'receive_sms_alerts' in request.POST
        profile.save()
        
        messages.success(request, 'Profile updated successfully')
        
        return redirect('profile')
    
    context = {
        'profile': profile,
        'active_tab': 'profile'
    }
    
    return render(request, 'dashboard/profile.html', context)


@login_required
def settings(request):
    """View and edit system settings."""
    # Only staff members can access settings
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access settings')
        return redirect('dashboard')
    
    # Handle updating settings
    if request.method == 'POST':
        # Update each setting
        for key, value in request.POST.items():
            if key.startswith('setting_'):
                setting_key = key[8:]  # Remove 'setting_' prefix
                SystemSettings.set(setting_key, value)
        
        messages.success(request, 'Settings updated successfully')
        
        return redirect('settings')
    
    # Get all settings
    all_settings = SystemSettings.objects.all()
    
    context = {
        'settings': all_settings,
        'active_tab': 'settings'
    }
    
    return render(request, 'dashboard/settings.html', context)


@login_required
def ml_models(request):
    """View and manage ML models."""
    # Only staff members can access ML models
    if not request.user.is_staff:
        messages.error(request, 'You do not have permission to access ML models')
        return redirect('dashboard')
    
    models = MLModel.objects.all().order_by('-created_at')
    
    # Handle training a new model
    if request.method == 'POST' and 'train_model' in request.POST:
        scan_ids = request.POST.getlist('scan_ids')
        
        if scan_ids:
            # This would be handled by a background task in a real system
            messages.info(request, 'Model training initiated. This may take some time.')
            return redirect('ml_models')
        else:
            messages.error(request, 'No scans selected for training')
    
    # Get scans for training selection
    scans = NetworkScan.objects.filter(status='completed').order_by('-created_at')
    
    context = {
        'models': models,
        'scans': scans,
        'active_tab': 'ml_models'
    }
    
    return render(request, 'dashboard/ml_models.html', context)


@login_required
def system_overview(request):
    """System overview displaying all connected components."""
    # Get CPU and memory information
    cpu_load = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    
    # Determine system status based on resource usage
    if cpu_load > 80 or memory_usage > 80:
        status_color = 'danger'
        status = 'Critical'
    elif cpu_load > 60 or memory_usage > 60:
        status_color = 'warning'
        status = 'Warning'
    else:
        status_color = 'success'
        status = 'Normal'
    
    # Calculate uptime
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time
    uptime_str = f"{uptime.days} days, {uptime.seconds // 3600} hours"
    
    # Get system components
    core_components = [
        {
            'name': 'System Integration',
            'icon': 'fas fa-cogs',
            'status': 'active',
            'version': '1.2.0',
            'last_updated': '2023-08-15',
            'health': 95
        },
        {
            'name': 'Cryptographic Security',
            'icon': 'fas fa-shield-alt',
            'status': 'active',
            'version': '1.1.5',
            'last_updated': '2023-07-22',
            'health': 100
        },
        {
            'name': 'Device Support',
            'icon': 'fas fa-laptop',
            'status': 'active',
            'version': '1.0.8',
            'last_updated': '2023-09-10',
            'health': 93
        },
        {
            'name': 'Threat Hunting',
            'icon': 'fas fa-search',
            'status': 'active',
            'version': '1.3.2',
            'last_updated': '2023-10-05',
            'health': 98
        },
        {
            'name': 'ML Algorithms',
            'icon': 'fas fa-brain',
            'status': 'active',
            'version': '2.0.1',
            'last_updated': '2023-09-28',
            'health': 87
        },
        {
            'name': 'Network Monitor',
            'icon': 'fas fa-wifi',
            'status': 'warning',
            'version': '1.1.0',
            'last_updated': '2023-08-30',
            'health': 76
        }
    ]
    
    # Get installed plugins from plugin registry
    plugin_registry = get_registry()
    registered_plugins = plugin_registry.list_plugins()
    
    # Format plugins for display
    plugins = []
    for plugin in registered_plugins:
        plugins.append({
            'id': plugin['id'],
            'name': plugin['name'],
            'description': plugin['description'],
            'type': plugin['type'],
            'status': 'active',  # Would come from actual plugin status
            'version': plugin['version'],
            'author': plugin['author']
        })
    
    # Add example plugins if none found for demonstration
    if not plugins:
        plugins = [
            {
                'id': 'ai_detector',
                'name': 'AI-Based Threat Detector',
                'description': 'Advanced threat detection using transformer-based AI models',
                'type': 'detection',
                'status': 'active',
                'version': '1.0.0',
                'author': 'CyberSecurity Team'
            },
            {
                'id': 'sandbox_analyzer',
                'name': 'Malware Sandbox Analyzer',
                'type': 'analysis',
                'description': 'Analyzes potential malware in a secure sandbox environment',
                'status': 'inactive',
                'version': '2.1.3',
                'author': 'Security Research Team'
            }
        ]
    
    # Simulated system logs
    system_logs = [
        {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'component': 'System Integration',
            'level': 'INFO',
            'message': 'All components synchronized successfully'
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'),
            'component': 'Network Monitor',
            'level': 'WARNING',
            'message': 'Unusual traffic pattern detected on interface eth0'
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'),
            'component': 'Threat Hunting',
            'level': 'INFO',
            'message': 'Scheduled threat hunting task completed'
        },
        {
            'timestamp': (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S'),
            'component': 'Plugin System',
            'level': 'INFO',
            'message': 'Loaded plugin: AI-Based Threat Detector v1.0.0'
        },
        {
            'timestamp': (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
            'component': 'ML Algorithms',
            'level': 'ERROR',
            'message': 'Model training failed: insufficient data points'
        },
    ]
    
    # Component status for architecture diagram
    component_status = {
        'integration': 'active',
        'auth': 'active',
        'event_bus': 'active',
        'plugin_system': 'active',
        'crypto_security': 'active',
        'device_support': 'active',
        'threat_hunting': 'active',
        'network_monitor': 'warning',
        'signature_detection': 'active',
        'behavioral_analysis': 'active',
        'ml_algorithms': 'active',
        'anomaly_detection': 'warning',
        'time_series_db': 'active',
        'document_store': 'active',
        'relational_db': 'active',
        'encrypted_storage': 'active',
    }
    
    context = {
        'system_status': {
            'status': status,
            'color': status_color,
            'uptime': uptime_str,
            'cpu_load': cpu_load,
            'memory_usage': memory_usage
        },
        'core_components': core_components,
        'plugins': plugins,
        'system_logs': system_logs,
        'component_status': component_status
    }
    
    return render(request, 'dashboard/system_overview.html', context) 