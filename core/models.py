from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
import json


class NetworkScan(models.Model):
    """Model for storing network scanning sessions"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    target_network = models.CharField(max_length=50)
    scan_type = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=(
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ), default='pending')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} - {self.target_network}"


class Packet(models.Model):
    """Model for storing captured network packets"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='packets')
    timestamp = models.DateTimeField(default=timezone.now)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=20)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    payload = models.BinaryField(null=True, blank=True)
    packet_length = models.IntegerField()
    flags = models.CharField(max_length=50, blank=True, null=True)
    
    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.protocol})"


class Threat(models.Model):
    """Model for storing detected threats"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='threats')
    timestamp = models.DateTimeField(default=timezone.now)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=(
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ))
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    affected_system = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=(
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('mitigated', 'Mitigated'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ), default='new')
    mitigated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    mitigated_at = models.DateTimeField(null=True, blank=True)
    related_packets = models.ManyToManyField(Packet, blank=True)
    
    def __str__(self):
        return f"{self.threat_type} - {self.severity} ({self.source_ip} -> {self.destination_ip})"


class VulnerabilityScan(models.Model):
    """Model for storing vulnerability scanning results"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='vulnerability_scans')
    target_ip = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    scan_type = models.CharField(max_length=50)
    results = models.JSONField(default=dict)
    
    def __str__(self):
        return f"Vulnerability Scan - {self.target_ip} ({self.scan_type})"


class Vulnerability(models.Model):
    """Model for storing detected vulnerabilities"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability_scan = models.ForeignKey(VulnerabilityScan, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=50, blank=True, null=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=(
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ))
    affected_service = models.CharField(max_length=100, blank=True, null=True)
    affected_port = models.IntegerField(null=True, blank=True)
    remediation = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} - {self.cve_id or 'No CVE'} ({self.severity})"


class Report(models.Model):
    """Model for storing generated reports"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    report_file = models.FileField(upload_to='reports/', null=True, blank=True)
    report_type = models.CharField(max_length=20, choices=(
        ('summary', 'Summary'),
        ('detailed', 'Detailed'),
        ('executive', 'Executive'),
        ('compliance', 'Compliance'),
    ))
    
    def __str__(self):
        return f"{self.title} - {self.report_type} - {self.created_at.strftime('%Y-%m-%d')}"


class Alert(models.Model):
    """Model for storing system alerts"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    title = models.CharField(max_length=255)
    message = models.TextField()
    severity = models.CharField(max_length=20, choices=(
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ))
    related_threat = models.ForeignKey(Threat, on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_alerts')
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    recipients = models.ManyToManyField(User, related_name='alerts')
    sent_email = models.BooleanField(default=False)
    sent_sms = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.title} - {self.severity} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class UserProfile(models.Model):
    """Extended user profile for additional settings"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    telegram_id = models.CharField(max_length=50, blank=True, null=True)
    receive_email_alerts = models.BooleanField(default=True)
    receive_sms_alerts = models.BooleanField(default=False)
    dashboard_layout = models.JSONField(default=dict)
    
    def __str__(self):
        return f"Profile for {self.user.username}"


class MLModel(models.Model):
    """Model for storing machine learning model information"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    model_type = models.CharField(max_length=50)
    version = models.CharField(max_length=20)
    accuracy = models.FloatField(null=True, blank=True)
    precision = models.FloatField(null=True, blank=True)
    recall = models.FloatField(null=True, blank=True)
    f1_score = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)
    model_file = models.FileField(upload_to='ml_models/', null=True, blank=True)
    
    def __str__(self):
        return f"{self.name} v{self.version} ({self.model_type})"


class SystemSettings(models.Model):
    """Model for storing system-wide settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.key}: {self.value}"
    
    @classmethod
    def get(cls, key, default=None):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default
    
    @classmethod
    def set(cls, key, value, description=None):
        obj, created = cls.objects.update_or_create(
            key=key,
            defaults={'value': value, 'description': description}
        )
        return obj 