from email.policy import default
from enum import auto
from statistics import mode
from tokenize import blank_re
from django.db import models
from authentication.models import CustomUser



class Attendence(models.Model):
    status_choices = (
        ('Present', 'Present'),
        ('Absent', 'Absent')
    )
    date = models.DateTimeField(auto_now_add = True)
    status = models.BooleanField(default=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,null = True, blank=True)

    def ___str__(self):
        return self.status