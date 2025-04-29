from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('network_scans/', views.network_scans, name='network_scans'),
    path('network_scan/<int:scan_id>/', views.network_scan_detail, name='network_scan_detail'),
    path('threats/', views.threats, name='threats'),
    path('threat/<uuid:threat_id>/', views.threat_detail, name='threat_detail'),
    path('vulnerabilities/', views.vulnerabilities, name='vulnerabilities'),
    path('packets/', views.packets, name='packets'),
    path('reports/', views.reports, name='reports'),
    path('alerts/', views.alerts, name='alerts'),
    path('profile/', views.profile, name='profile'),
    path('settings/', views.settings, name='settings'),
    path('ml_models/', views.ml_models, name='ml_models'),
    path('device_management/', views.device_management, name='device_management'),
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    path('system_overview/', views.system_overview, name='system_overview'),
] 