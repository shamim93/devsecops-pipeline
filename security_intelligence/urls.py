from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='security-dashboard'),
    path('vulnerabilities/', views.vulnerability_list, name='vuln-list'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vuln-detail'),
    path('scans/', views.scan_list, name='scan-list'),
    path('correlation/', views.correlation_view, name='correlation-view'),
    path('api/severity/', views.api_severity_data, name='api-severity'),
    path('api/tools/', views.api_tool_data, name='api-tool'),
    path('api/history/', views.api_score_history, name='api-history'),
]