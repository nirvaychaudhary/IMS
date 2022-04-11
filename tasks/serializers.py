from ast import Assign
from rest_framework import serializers
from .models import Task,  AssignTask


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'



class TaskAssignSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignTask
        fields = '__all__'