from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('tasks.api_urls')),
    path('security/', include('security_intelligence.urls')),
    path('', include('tasks.web_urls')),
]