from rest_framework import routers
from django.urls import path, include
from accounts.api.views import *
from attendence.views import AttendenceViewset
from tasks.views import TaskCreateView,TaskAssignView

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'register', UserRegister, 'register')
router.register(r'tasks', TaskCreateView, 'register')
router.register(r'tasks-assign', TaskAssignView, 'register')
router.register(r'users', UserAPIView, 'user')
router.register(r'groups', UserGroupAPIView, 'group'),
router.register(r'attendance', AttendenceViewset, 'attendance'),



urlpatterns = [
    path('', include(router.urls)),
        path('authentication/', include('accounts.api.urls', namespace='accounts')),
            #   path('', include('tasks.urls', namespace='tasks')),

]+router.urls



