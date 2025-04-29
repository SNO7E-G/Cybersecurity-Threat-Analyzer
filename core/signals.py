import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import (
    NetworkScan, Packet, Threat, Alert, Report, UserProfile
)

logger = logging.getLogger('core')

# Create user profile when a new user is created
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        logger.info(f"Created profile for user: {instance.username}")

# Create alerts for high and critical threats
@receiver(post_save, sender=Threat)
def create_threat_alert(sender, instance, created, **kwargs):
    if created and instance.severity in ('high', 'critical'):
        # Create alert for the threat
        alert = Alert.objects.create(
            title=f"{instance.severity.upper()} Threat: {instance.threat_type}",
            message=f"Detected {instance.threat_type} from {instance.source_ip} to {instance.destination_ip}. {instance.description}",
            severity='critical' if instance.severity == 'critical' else 'error',
            related_threat=instance
        )
        
        # Add staff users as recipients
        staff_users = User.objects.filter(is_staff=True)
        alert.recipients.add(*staff_users)
        
        logger.info(f"Created alert for threat: {instance.id}")

# Log when a network scan is deleted
@receiver(post_delete, sender=NetworkScan)
def log_scan_deletion(sender, instance, **kwargs):
    logger.warning(f"Network scan deleted: {instance.name} (ID: {instance.id}) by user ID {instance.created_by_id}")

# Log when a report is generated
@receiver(post_save, sender=Report)
def log_report_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(f"Report generated: {instance.title} (ID: {instance.id}) by user ID {instance.created_by_id}")

# Update alert status when a threat is mitigated
@receiver(post_save, sender=Threat)
def update_alert_on_threat_mitigation(sender, instance, **kwargs):
    if instance.status == 'mitigated' and instance.mitigated_by:
        # Find related alerts
        related_alerts = Alert.objects.filter(related_threat=instance, acknowledged=False)
        
        if related_alerts.exists():
            # Update alerts to acknowledged
            related_alerts.update(
                acknowledged=True,
                acknowledged_by=instance.mitigated_by,
                acknowledged_at=instance.mitigated_at
            )
            
            logger.info(f"Updated alerts for mitigated threat: {instance.id}") 