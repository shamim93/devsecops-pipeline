from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'tasks', views.TaskViewSet, basename='task')

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.register_user, name='register'),
    path('auth/login/', views.login_user, name='login'),
    path('auth/logout/', views.logout_user, name='logout'),
    path('auth/me/', views.current_user, name='current-user'),
    
    # Task endpoints (CRUD)
    path('', include(router.urls)),
]