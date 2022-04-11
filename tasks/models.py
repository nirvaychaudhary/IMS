from pyexpat import model
from unicodedata import category
from django.db import models
from accounts.models import CustomUser


class Task(models.Model):
    title = models.CharField(max_length=50, null=True, blank=True)
    category = models.CharField(max_length=50, null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add = True)

   
    def ___str__(self):
        return self.title




class AssignTask(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE,null = True, blank=True)
    user = models.ForeignKey(CustomUser,on_delete=models.CASCADE,null = True, blank=True)
    start_date = models.DateTimeField(null = True, blank = True)
    finish_date = models.DateTimeField(null = True, blank = True)
    
    def ___str__(self):
        return self.task__title