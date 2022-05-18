from django.shortcuts import render
from .serializers import TaskAssignSerializer, TaskSerializer, MarkTaskSerializer
from rest_framework import viewsets
from .models import Task,AssignTask, MarkTask
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from django.contrib.auth.models import Group
from IMS.pagination import StandardPagination

class TaskCreateView(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    pagination_class = (StandardPagination)
class TaskAssignView(viewsets.ModelViewSet):
    queryset = AssignTask.objects.all()
    serializer_class = TaskAssignSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    pagination_class = (StandardPagination)

    def get_queryset(self):
        if self.request.user.groups.filter(name='Supervisor').exists() or self.request.user.is_superuser:
            return AssignTask.objects.all()
        else:
            return AssignTask.objects.filter(user = self.request.user)

class MarkTaskView(viewsets.ModelViewSet):
    queryset = MarkTask.objects.all()
    serializer_class = MarkTaskSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    pagination_class = (StandardPagination)

    def get_queryset(self):
        task = self.request.GET.get('task')
        if self.request.user.groups.filter(name='Supervisor').exists() or self.request.user.is_superuser:
            return MarkTask.objects.all()
        else:
            return MarkTask.objects.filter(task=task)