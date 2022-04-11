import json
from django.contrib.auth.hashers import check_password
from django.core import serializers
from django.http.response import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.models import Group, Permission
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from djoser.serializers import SendEmailResetSerializer, SetPasswordSerializer, PasswordResetConfirmSerializer, TokenCreateSerializer
from djoser import utils
from django.contrib.auth.tokens import default_token_generator
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets
from accounts.models import CustomUser as User
from django.core.mail import send_mail
from django.contrib import messages
from django.db.models.query_utils import Q
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
import djoser
from accounts.api.serializers import GroupSerializer,AccessGroupSerializer, PermissionSerializer, UserAuthSerializer, UsersSerializer
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django import template
import base64
from djoser.views import UserViewSet
from django.utils.timezone import now


@api_view(['POST'])
def token_create(request):
    data = request.POST
    data._mutable = True
    request.data['email'] = request.data['email'].lower()
    # print(request.data['email'])
    serializer = TokenCreateSerializer(data=request.data)
    response_data = {}
    if serializer.is_valid():
        token = utils.login_user(request, serializer.user)
        token_serializer_class = djoser.serializers.TokenSerializer
        response_data['status'] = 200
        response_data['message'] = 'Token created successfully'
        data = token_serializer_class(token).data
        user = Token.objects.get(key=data['auth_token']).user
        data['id'] = user.id
        # data['permissions'] = user.get_all_permissions()
        response_data['results'] = data
        data['user_id'] = serializer.user.id
        return Response(
            data=response_data, status=status.HTTP_200_OK,
        )
    else:
        response_data['status'] = 400
        response_data['message'] = 'Email or Password do not match'
        response_data['results'] = serializer.errors
        return Response(data=response_data, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_user_permissions(request):
    permissions = Permission.objects.all()
    serializers = PermissionSerializer(permissions, many=True)
    return Response(data=serializers.data, status=status.HTTP_200_OK)


# drf user api to provide permissions to user
@api_view(['GET'])
def user_permissions_detail(request, pk):
    if request.user.is_authenticated:
        try:
            user = User.objects.get(pk=pk)
            permissions = user.user_permissions.all()
            tmpJson = serializers.serialize("json", permissions)
            tmpObj = json.loads(tmpJson)
            return Response(tmpObj, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(data={'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    else:
        return Response(data={'message': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)


class UserProfile(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UsersSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)


class UserRegister(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UsersSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    http_method_names = ['post']
    

@api_view(["GET"])
def profile_api(request, *args, **kwargs):    
    if request.user.is_authenticated:
        data = {}
        data['id'] = request.user.id
        group=request.user.groups.first()
        if group:
            permissions = Permission.objects.filter(group=group.id)
        else:
            permissions = Permission.objects.filter(user=request.user)
        data['username'] = request.user.username
        data['email'] = request.user.email
        data['permissions'] = PermissionSerializer(permissions, many=True).data
        return Response(data={'data':data}, status=status.HTTP_200_OK) 
    else:
        return Response(data={'error':"Authentication Failed"}, status=status.HTTP_401_UNAUTHORIZED)


class UserAPIView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    # authentication_classes = (TokenAuthentication,)
    serializer_class = UsersSerializer
    permission_classes = (IsAuthenticated,)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            data = serializer.data
            for d in data:
                user = User.objects.get(email=d['email'])
                d['permissions'] = user.get_user_permissions()
            return self.get_paginated_response(data)

        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        for d in data:
            user = User.objects.get(email=d['email'])
            d['permissions'] = user.get_user_permissions()
        return Response(data)

@api_view(["POST"])
def edit_permission(request, *args, **kwargs):    
    if request.method == 'POST':
        if request.user.is_authenticated and request.user.is_superuser:
            errors = []
            try:
                id = request.data['id']
            except:
                id = None

            try:
                permissions = request.data['permissions']
            except:
                permissions = None
            
            try:
                action = request.data['action']
            except:
                action = None

            if not id:
                errors.append({"id": "This field is required"})

            if not permissions:
                errors.append({"permissions": "This field is required"})

            if not action:
                errors.append({"action": "This field is required"})
                
            if errors:
                return Response(data={'message':errors}, status=status.HTTP_400_BAD_REQUEST) 

            try:
                user = User.objects.get(id=id)
            except:
                return Response(data={'message':'User not found'}, status=status.HTTP_400_BAD_REQUEST) 

            error_ids = []
            for permission in permissions:
                try:
                    permission_instance = Permission.objects.get(id=permission)
                    if action == 'add':
                        user.user_permissions.add(permission_instance)
                    elif action == 'remove':
                        user.user_permissions.remove(permission_instance)
                except:
                    error_ids.append(permission)
            if error_ids:
                return Response(data={'message':'error','not_found_id': error_ids}, status=status.HTTP_400_BAD_REQUEST) 

            return Response(data={'message':'success'}, status=status.HTTP_200_OK) 
        else:
            return Response(data={'message':'You dont have permission'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


class UserGroupAPIView(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (IsAuthenticated,)

    # def check_permissions(self, request):
    #     for permission in self.get_permissions():
    #         if not permission.has_permission(request, self):
    #             self.permission_denied(
    #                 request, message=getattr(permission, 'message', None)
    #             )

    # def list(self, request, *args, **kwargs):

    # access-groups
class UserAccessGroupAPIView(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = AccessGroupSerializer
    http_method_names = ['get']



@api_view(["POST"])
def edit_group_permission(request, *args, **kwargs):    
    if request.method == 'POST':
        if request.user.is_authenticated and request.user.is_superuser:
            errors = []
            try:
                group_id = request.data['group_id']
            except:
                group_id = None

            try:
                permissions = request.data['permissions']
            except:
                permissions = None
            
            try:
                action = request.data['action']
            except:
                action = None

            if not group_id:
                errors.append({"group_id": "This field is required"})

            if not permissions:
                errors.append({"permissions": "This field is required"})

            if not action:
                errors.append({"action": "This field is required"})
                
            if errors:
                return Response(data={'message':errors}, status=status.HTTP_400_BAD_REQUEST) 

            try:
                group = Group.objects.get(id=group_id)
            except:
                return Response(data={'message':'Group not found'}, status=status.HTTP_400_BAD_REQUEST) 

            error_ids = []
            for permission in permissions:
                try:
                    permission_instance = Permission.objects.get(id=permission)
                    if action == 'add':
                        group.permissions.add(permission_instance)
                    elif action == 'remove':
                        group.permissions.remove(permission_instance)
                except:
                    error_ids.append(permission)
            if error_ids:
                return Response(data={'message':'error','not_found_id': error_ids}, status=status.HTTP_400_BAD_REQUEST) 

            return Response(data={'message':'success'}, status=status.HTTP_200_OK) 
        else:
            return Response(data={'message':'You dont have permission'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        user1 = User.objects.get(id =user.id)
        user1.groups.add(user1.group)  # add user to group
        messages.success(
            request, 'Congratulations! Your account is activated.')
        return JsonResponse({'message': 'Congratulations! Your account is activated.'}, status=200)
    else:
        messages.error(request, 'Invalid activation link')
        return JsonResponse({'message': 'Invalid activation link'}, status=400)