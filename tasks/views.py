from django.shortcuts import render
from rest_framework import viewsets,status
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate,login,logout
from .models import Task
from .serializers import TaskSerializer, UserRegistrationSerializer,UserSerializer

#User Registration
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({
            'message': 'User created successfully',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors,status=status.HTTP_201_CREATED)

#Login user

@api_view(['POST'])
@permission_classes([AllowAny])

def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user =  authenticate(username=username, password=password)
    
    if user:
        login(request,user)
        return Response(
            {
                'message': 'Loging successfull',
                'user' : UserSerializer(user).data
            }
        )
    return Response(
        {
            'error': 'Invalid credentials'

        }, status=status.HTTP_401_UNAUTHORIZED
    )

# user logout
@permission_classes([IsAuthenticated])
def logout_user(request):
    logout(request)
    return Response(
        {
            'message': 'Logout Successfully'

        }
    )
# get current user
@api_view(['GET'])
@permission_classes([IsAuthenticated])

def current_user(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

# tasks viewset
class TaskViewSet(viewsets.ModelViewSet):
    serializer_class =  TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Task.objects.filter(created_by=self.request.user)
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

