import json
import uuid
import socket
import netifaces
import pandas as pd
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.db.models import Count, Q

from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core.models import (
    NetworkScan, Packet, Threat, VulnerabilityScan,
    Vulnerability, Report, Alert, MLModel, SystemSettings
)
from core.network_monitor import NetworkMonitor
from ml.anomaly_detector import AnomalyDetector
from .serializers import (
    NetworkScanSerializer, PacketSerializer, ThreatSerializer,
    VulnerabilitySerializer, ReportSerializer, AlertSerializer
)


# ViewSets for CRUD operations
class NetworkScanViewSet(viewsets.ModelViewSet):
    queryset = NetworkScan.objects.all().order_by('-created_at')
    serializer_class = NetworkScanSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class PacketViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Packet.objects.all().order_by('-timestamp')
    serializer_class = PacketSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        return queryset[:1000]  # Limit to 1000 packets


class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.all().order_by('-timestamp')
    serializer_class = ThreatSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        return queryset


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Report.objects.all().order_by('-created_at')
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all().order_by('-timestamp')
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_update(self, serializer):
        # If acknowledging an alert, set acknowledged_by and acknowledged_at
        if serializer.validated_data.get('acknowledged') and not serializer.instance.acknowledged:
            serializer.save(acknowledged_by=self.request.user, acknowledged_at=timezone.now())
        else:
            serializer.save()


# Network related API views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def network_interfaces(request):
    """Get available network interfaces."""
    try:
        interfaces = []
        for iface in netifaces.interfaces():
            if_info = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in if_info:
                for link in if_info[netifaces.AF_INET]:
                    interfaces.append({
                        'name': iface,
                        'ip': link.get('addr', ''),
                        'netmask': link.get('netmask', '')
                    })
        
        return Response(interfaces)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_network_scan(request):
    """Start a new network scan."""
    try:
        # Create a new scan
        scan = NetworkScan.objects.create(
            name=request.data.get('name', f'Scan {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}'),
            description=request.data.get('description', ''),
            target_network=request.data.get('target_network', ''),
            scan_type=request.data.get('scan_type', 'packet_capture'),
            status='pending',
            created_by=request.user
        )
        
        # Start the network monitoring in the background
        monitor = NetworkMonitor(
            scan_id=scan.id,
            interface=request.data.get('interface'),
            filter_str=request.data.get('filter_str'),
            count=int(request.data.get('count', 0)),
            timeout=int(request.data.get('timeout', 0)) or None
        )
        
        if monitor.start_capture():
            return Response({
                'scan_id': scan.id,
                'status': 'started',
                'message': 'Network scan started successfully'
            })
        else:
            scan.status = 'failed'
            scan.save()
            return Response({
                'error': 'Failed to start network scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def stop_network_scan(request, scan_id):
    """Stop a running network scan."""
    try:
        scan = NetworkScan.objects.get(id=scan_id)
        
        # Only the creator or an admin can stop a scan
        if request.user != scan.created_by and not request.user.is_staff:
            return Response({
                'error': 'You do not have permission to stop this scan'
            }, status=status.HTTP_403_FORBIDDEN)
        
        monitor = NetworkMonitor(scan_id=scan_id)
        if monitor.stop_capture():
            return Response({
                'scan_id': scan_id,
                'status': 'stopped',
                'message': 'Network scan stopped successfully'
            })
        else:
            return Response({
                'error': 'Failed to stop network scan'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except NetworkScan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def network_scan_status(request, scan_id):
    """Get the status of a network scan."""
    try:
        scan = NetworkScan.objects.get(id=scan_id)
        packet_count = Packet.objects.filter(scan_id=scan_id).count()
        threat_count = Threat.objects.filter(scan_id=scan_id).count()
        
        return Response({
            'scan_id': scan_id,
            'name': scan.name,
            'status': scan.status,
            'start_time': scan.start_time,
            'end_time': scan.end_time,
            'packet_count': packet_count,
            'threat_count': threat_count
        })
            
    except NetworkScan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ML related API views
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def train_ml_model(request):
    """Train the ML model on historical data."""
    try:
        # Only admin users can train the ML model
        if not request.user.is_staff:
            return Response({
                'error': 'You do not have permission to train the ML model'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get training data
        scan_ids = request.data.get('scan_ids', [])
        if not scan_ids:
            return Response({
                'error': 'No scan IDs provided for training'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Collect packet data for training
        packets = Packet.objects.filter(scan_id__in=scan_ids).order_by('-timestamp')[:10000]
        
        if not packets:
            return Response({
                'error': 'No packet data available for training'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract features for training
        features = []
        for packet in packets:
            feature_dict = {
                'protocol': packet.protocol,
                'packet_length': packet.packet_length,
                'src_port': packet.source_port or 0,
                'dst_port': packet.destination_port or 0,
                'tcp_flags': packet.flags or ''
            }
            features.append(feature_dict)
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # One-hot encode protocol
        df['protocol_TCP'] = (df['protocol'] == 'TCP').astype(int)
        df['protocol_UDP'] = (df['protocol'] == 'UDP').astype(int)
        df['protocol_ICMP'] = (df['protocol'] == 'ICMP').astype(int)
        
        # Drop non-numeric columns
        df = df.drop(['protocol'], axis=1)
        
        # Fill NaN values
        df = df.fillna(0)
        
        # Initialize and train anomaly detector
        detector = AnomalyDetector()
        success = detector.train(df)
        
        if success:
            return Response({
                'status': 'success',
                'message': 'ML model trained successfully',
                'data_points': len(df)
            })
        else:
            return Response({
                'error': 'Failed to train ML model'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Threat related API views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_summary(request):
    """Get a summary of detected threats."""
    try:
        # Count threats by severity
        severity_counts = Threat.objects.values('severity').annotate(count=Count('id')).order_by('severity')
        
        # Count threats by type
        type_counts = Threat.objects.values('threat_type').annotate(count=Count('id')).order_by('-count')[:10]
        
        # Count threats by status
        status_counts = Threat.objects.values('status').annotate(count=Count('id')).order_by('status')
        
        # Recent threats
        recent_threats = ThreatSerializer(
            Threat.objects.all().order_by('-timestamp')[:5],
            many=True
        ).data
        
        return Response({
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'status_counts': status_counts,
            'recent_threats': recent_threats,
            'total_count': Threat.objects.count()
        })
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mitigate_threat(request, threat_id):
    """Mitigate a detected threat."""
    try:
        threat = Threat.objects.get(id=threat_id)
        
        # Update threat status
        threat.status = request.data.get('status', 'mitigated')
        threat.mitigated_by = request.user
        threat.mitigated_at = timezone.now()
        threat.save()
        
        # Implement mitigation action if provided
        action = request.data.get('action')
        if action == 'block_ip' and threat.source_ip:
            # In a real system, you would implement firewall rules or other mitigation strategies
            pass
        
        return Response({
            'threat_id': threat_id,
            'status': threat.status,
            'message': 'Threat mitigation initiated successfully'
        })
            
    except Threat.DoesNotExist:
        return Response({'error': 'Threat not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Report related API views
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_report(request, scan_id):
    """Generate a report for a completed scan."""
    try:
        scan = NetworkScan.objects.get(id=scan_id)
        
        # Check if scan is completed
        if scan.status != 'completed':
            return Response({
                'error': 'Cannot generate report for an incomplete scan'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create report
        report = Report.objects.create(
            scan=scan,
            title=request.data.get('title', f'Report for {scan.name}'),
            description=request.data.get('description', ''),
            created_by=request.user,
            report_type=request.data.get('report_type', 'summary')
        )
        
        # In a real system, you would generate a PDF report
        # For now, we'll just return the report ID
        
        return Response({
            'report_id': report.id,
            'message': 'Report generation initiated'
        })
            
    except NetworkScan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Dashboard related API views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """Get statistics for the dashboard."""
    try:
        # Total counts
        scan_count = NetworkScan.objects.count()
        packet_count = Packet.objects.count()
        threat_count = Threat.objects.count()
        alert_count = Alert.objects.count()
        
        # Recent scans
        recent_scans = NetworkScanSerializer(
            NetworkScan.objects.all().order_by('-created_at')[:5],
            many=True
        ).data
        
        # Active threats by severity
        active_threats = Threat.objects.filter(
            status__in=['new', 'investigating']
        ).values('severity').annotate(count=Count('id'))
        
        # Unacknowledged alerts
        unacknowledged_alerts = Alert.objects.filter(
            acknowledged=False
        ).count()
        
        return Response({
            'scan_count': scan_count,
            'packet_count': packet_count,
            'threat_count': threat_count,
            'alert_count': alert_count,
            'recent_scans': recent_scans,
            'active_threats': active_threats,
            'unacknowledged_alerts': unacknowledged_alerts
        })
            
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 