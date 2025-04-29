from django.contrib import admin
from .models import (
    NetworkScan, Packet, Threat, VulnerabilityScan, Vulnerability,
    Report, Alert, UserProfile, MLModel, SystemSettings
)

@admin.register(NetworkScan)
class NetworkScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'target_network', 'scan_type', 'status', 'start_time', 'created_by')
    list_filter = ('status', 'scan_type', 'created_at')
    search_fields = ('name', 'target_network', 'description')
    date_hierarchy = 'start_time'

@admin.register(Packet)
class PacketAdmin(admin.ModelAdmin):
    list_display = ('scan', 'timestamp', 'source_ip', 'destination_ip', 'protocol', 'source_port', 'destination_port')
    list_filter = ('protocol', 'scan')
    search_fields = ('source_ip', 'destination_ip')
    date_hierarchy = 'timestamp'

@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ('threat_type', 'severity', 'source_ip', 'destination_ip', 'status', 'timestamp')
    list_filter = ('severity', 'status', 'threat_type')
    search_fields = ('description', 'source_ip', 'destination_ip', 'affected_system')
    date_hierarchy = 'timestamp'

@admin.register(VulnerabilityScan)
class VulnerabilityScanAdmin(admin.ModelAdmin):
    list_display = ('scan', 'target_ip', 'scan_type', 'timestamp')
    list_filter = ('scan_type',)
    search_fields = ('target_ip',)
    date_hierarchy = 'timestamp'

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name', 'cve_id', 'severity', 'affected_service', 'affected_port')
    list_filter = ('severity', 'affected_service')
    search_fields = ('name', 'cve_id', 'description', 'affected_service')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'scan', 'report_type', 'created_at', 'created_by')
    list_filter = ('report_type', 'created_at')
    search_fields = ('title', 'description')
    date_hierarchy = 'created_at'

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'acknowledged', 'timestamp')
    list_filter = ('severity', 'acknowledged', 'sent_email', 'sent_sms')
    search_fields = ('title', 'message')
    date_hierarchy = 'timestamp'

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone_number', 'telegram_id', 'receive_email_alerts', 'receive_sms_alerts')
    list_filter = ('receive_email_alerts', 'receive_sms_alerts')
    search_fields = ('user__username', 'user__email', 'phone_number')

@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'model_type', 'version', 'accuracy', 'is_active', 'created_at')
    list_filter = ('model_type', 'is_active')
    search_fields = ('name', 'description')
    date_hierarchy = 'created_at'

@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ('key', 'value', 'last_updated')
    search_fields = ('key', 'value', 'description') 