from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# API Router
router = DefaultRouter()
router.register(r'tasks', views.TaskViewSet, basename='task')

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.register_user, name='api-register'),
    path('auth/login/', views.login_user, name='api-login'),
    path('auth/logout/', views.logout_user, name='api-logout'),
    path('auth/me/', views.current_user, name='api-current-user'),
    
    # Task endpoints (CRUD)
    path('', include(router.urls)),
]