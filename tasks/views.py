from django.shortcuts import render
from .serializers import TaskAssignSerializer, TaskSerializer
from rest_framework import viewsets
from .models import Task,AssignTask
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from django.contrib.auth.models import Group


class TaskCreateView(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    # authentication_classes = (TokenAuthentication, SessionAuthentication)
    # http_method_names = ['post']


class TaskAssignView(viewsets.ModelViewSet):
    # queryset = AssignTask.objects.all()
    serializer_class = TaskAssignSerializer
    # authentication_classes = (TokenAuthentication, SessionAuthentication)
    # http_method_names = ['post']

    def get_queryset(self):
        if self.request.user.groups.filter(name='Supervisor').exists() or self.request.user.is_superuser:
            return AssignTask.objects.all()
        else:
            return AssignTask.objects.filter(user = self.request.user)
