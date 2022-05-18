import json
from django.core import serializers
from django.http.response import JsonResponse
from rest_framework.decorators import api_view
from django.contrib.auth.models import Group, Permission
from IMS.pagination import StandardPagination
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from djoser.serializers import TokenCreateSerializer
from rest_framework.permissions import AllowAny
from djoser import utils
from django.contrib.auth.tokens import default_token_generator
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets
from authentication.models import CustomUser as User
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
import djoser
from authentication.api.serializers import *
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
import base64
from rest_framework.views import APIView
from IMS.permissions import CustomDjangoModelPermissions
from django.contrib.auth import login, logout
from django.core.cache import cache
import jwt
from django.conf import settings
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from ..authentication import *
from rest_framework.generics import UpdateAPIView
from rest_framework.decorators import action
from djoser.serializers import TokenCreateSerializer

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

class GroupAPIView(viewsets.ModelViewSet):
    queryset=Group.objects.all()
    serializer_class=GroupSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    pagination_class = (StandardPagination)

class PermissionView(viewsets.ModelViewSet):
    queryset=Permission.objects.all()
    serializer_class=PermissionSerializer
    permission_classes = (CustomDjangoModelPermissions)
    pagination_class =None

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

class UserRegister(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = CustomUsersSerializer
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
    serializer_class = CustomUsersSerializer
    permission_classes = (IsAuthenticated, CustomDjangoModelPermissions)
    pagination_class = (StandardPagination)

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

    @action(methods=['get'], detail=False)
    def profile(self, request, *args, **kwargs):
        try:
            user = request.user
            serializer = CustomUsersSerializer(user)
            result = serializer.data
            result.pop('password')
            result['permission']=user.get_group_permissions()
            # import pdb;pdb.set_trace()
            return Response(result, status=status.HTTP_200_OK)
        except:
            return Response({'status': 'No detail found for the request user'})

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


class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(
            {'message': 'Enter credentials to login'},
            status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):

        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        # import pdb;pdb.set_trace()
        login(request, user)
        cache.set('user',user)
        token, created = Token.objects.get_or_create(user=user)
        jwt_token=jwt.encode({"token":token.key},settings.SECRET_KEY, algorithm="HS512")
        response = Response({
            "jwt":jwt_token,
            'token': token.key,
            'email': user.email,
            'is_active': user.is_active,
            'is_verified': user.is_verified,

        }, status=status.HTTP_200_OK)
        response.set_cookie('auth_token', token, httponly=True, samesite='Lax')
        return response

class UserLogoutView(APIView):
    def post(self,request,format=None): 
        token=Token.objects.get(user=request.user)
        deletetoken(token)
        logout(request)
        return Response({'detail':f"Successfully logout"},status=204)

class ChangePasswordView(UpdateAPIView):
    
	"""
	View to Update New Password given by User
	"""
	serializer_class = ChangePasswordSerializer

	def update(self, request, *args, **kwargs):
		serializer = self.get_serializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		user = serializer.save()
		# if using drf authtoken, create a new token
		if hasattr(user, 'auth_token'):
			user.auth_token.delete()
		token, created = Token.objects.get_or_create(user=user)
		response = {
			'success': 'Password updated successfully'
		}
		return Response(response, status=status.HTTP_200_OK)

class UserLogView(viewsets.ModelViewSet):
    queryset = UserLog.objects.all()
    serializer_class = UserLogSerializer
    permission_classes=[CustomDjangoModelPermissions]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['email']
    search_fields = ['email']

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