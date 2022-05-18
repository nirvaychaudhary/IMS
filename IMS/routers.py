from rest_framework import routers
from django.urls import path, include
from authentication.api.views import *
from attendence.views import AttendenceViewset
from tasks.views import MarkTaskView, TaskCreateView,TaskAssignView

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'register', UserRegister, 'register')
router.register(r'users', UserAPIView, 'user')
router.register(r'group', GroupAPIView, 'group')
router.register(r'tasks', TaskCreateView, 'task')
router.register(r'tasks-assign', TaskAssignView, 'task-assign')
router.register(r'mark-task', MarkTaskView, 'mark-task')
router.register(r'attendance', AttendenceViewset, 'attendance') 

urlpatterns = [
    path('', include(router.urls)),
    path('authentication/', include('authentication.api.urls', namespace='authentication')),
            #   path('', include('tasks.urls', namespace='tasks')),

]+router.urls



