from django.urls import path
from django.contrib.auth import views as auth_views
from . import web_views

urlpatterns = [
    # Web Interface URLs
    path('', web_views.dashboard_view, name='dashboard'),
    path('register/', web_views.register_view, name='register'),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('task/new/', web_views.TaskCreateView.as_view(), name='task-create'),
    path('task/<int:pk>/edit/', web_views.TaskUpdateView.as_view(), name='task-update'),
    path('task/<int:pk>/delete/', web_views.TaskDeleteView.as_view(), name='task-delete'),
    path('search/', web_views.search_tasks_vulnerable, name='search-tasks'),
]