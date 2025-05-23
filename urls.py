"""
URL Configuration for cyber_threat_analyzer project.
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('dashboard/', include('dashboard.urls')),
    path('api/', include('api.urls')),
    path('', RedirectView.as_view(url='dashboard/', permanent=False)),
] 