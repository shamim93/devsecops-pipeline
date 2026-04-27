from django.test import TestCase
from django.contrib.auth.models import User
from .models import Task

class TaskModelTest(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_task_creation(self):
        """Test creating a task"""
        task = Task.objects.create(
            title='Test Task',
            description='Test Description',
            status='pending',
            created_by=self.user
        )
        self.assertEqual(task.title, 'Test Task')
        self.assertEqual(task.status, 'pending')
        self.assertEqual(task.created_by, self.user)
    
    def test_task_str(self):
        """Test task string representation"""
        task = Task.objects.create(
            title='Test Task',
            description='Test Description',
            created_by=self.user
        )
        self.assertEqual(str(task), 'Test Task')

class TaskAPITest(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_user_registration(self):
        """Test user can register"""
        response = self.client.post('/api/auth/register/', {
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'newpass123'
        }, content_type='application/json')
        self.assertEqual(response.status_code, 201)
    
    def test_task_list_requires_auth(self):
        """Test task list requires authentication"""
        response = self.client.get('/api/tasks/')
        self.assertEqual(response.status_code, 403)  # Forbidden
    
    def test_insecure_endpoint_no_auth(self):
        """Test insecure endpoint works without auth (vulnerability!)"""
        response = self.client.get('/api/insecure/all-tasks/')
        self.assertEqual(response.status_code, 200)  # Should work!