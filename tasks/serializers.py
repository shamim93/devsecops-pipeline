from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Task

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email']

class TaskSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only = True)
    class Meta:
        model = Task
        fields = ['id','title','description','status','created_by','created_at','updated_at']
        read_only_fields = ['created_at','udpdated_at']

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username','email','password']

    def create(self,validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get['email',''],
            password=validated_data['password']
        )
        return user
