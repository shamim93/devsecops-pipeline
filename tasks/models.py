from django.db import models
from django.contrib.auth.models import User
class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    ]
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length = 20,
        choices = STATUS_CHOICES,   
        default = 'pending',
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='tasks',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    def __str__(self):
        return self.title

