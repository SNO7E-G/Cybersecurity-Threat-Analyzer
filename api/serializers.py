from rest_framework import serializers
from django.contrib.auth.models import User
from core.models import (
    NetworkScan, Packet, Threat, VulnerabilityScan,
    Vulnerability, Report, Alert, UserProfile, MLModel
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class NetworkScanSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    packet_count = serializers.SerializerMethodField()
    threat_count = serializers.SerializerMethodField()
    
    class Meta:
        model = NetworkScan
        fields = '__all__'
    
    def get_packet_count(self, obj):
        return obj.packets.count()
    
    def get_threat_count(self, obj):
        return obj.threats.count()


class PacketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Packet
        fields = '__all__'
        
    def to_representation(self, instance):
        rep = super().to_representation(instance)
        # Convert binary payload to hex string for readability
        if rep['payload']:
            rep['payload'] = '0x' + rep['payload'].hex()
        return rep


class ThreatSerializer(serializers.ModelSerializer):
    mitigated_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Threat
        fields = '__all__'


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'


class ReportSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Report
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    related_threat = ThreatSerializer(read_only=True)
    acknowledged_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'


class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = '__all__'


class MLModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModel
        fields = '__all__' 