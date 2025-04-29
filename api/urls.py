from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'scans', views.NetworkScanViewSet)
router.register(r'packets', views.PacketViewSet)
router.register(r'threats', views.ThreatViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)
router.register(r'reports', views.ReportViewSet)
router.register(r'alerts', views.AlertViewSet)

urlpatterns = [
    path('network/interfaces/', views.network_interfaces, name='network_interfaces'),
    path('network/start_scan/', views.start_network_scan, name='start_network_scan'),
    path('network/stop_scan/<uuid:scan_id>/', views.stop_network_scan, name='stop_network_scan'),
    path('network/scan_status/<uuid:scan_id>/', views.network_scan_status, name='network_scan_status'),
    path('ml/train/', views.train_ml_model, name='train_ml_model'),
    path('threats/summary/', views.threat_summary, name='threat_summary'),
    path('threats/mitigate/<uuid:threat_id>/', views.mitigate_threat, name='mitigate_threat'),
    path('reports/generate/<uuid:scan_id>/', views.generate_report, name='generate_report'),
    path('dashboard/stats/', views.dashboard_stats, name='dashboard_stats'),
]

urlpatterns += router.urls 