from .views import *
from django.urls import path



app_name = 'tasks'

urlpatterns = [
    path('task/create/', TaskCreateView.as_view),
   


]
