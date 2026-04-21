from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('tasks.api_urls')),  # API routes
    path('', include('tasks.web_urls')),      # Web routes
]