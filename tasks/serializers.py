from ast import Assign
from rest_framework import serializers
from .models import MarkTask, Task,  AssignTask


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'



class TaskAssignSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssignTask
        fields = '__all__'

class MarkTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = MarkTask
        fields = '__all__'
