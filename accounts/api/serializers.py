from rest_framework.serializers import ModelSerializer
from accounts.models import CustomUser as User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import Group, Permission
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from rest_framework.exceptions import APIException

class UsersSerializer(ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = User
        fields=('id','username','password','password2', 'full_name','email','group','organization','is_active')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            organization=validated_data['organization'],
            group=validated_data['group']
        )

        user.set_password(validated_data['password'])
        user.is_active = True
        user.save() 
        return user
    
    
class UserAuthSerializer(ModelSerializer):
    class Meta:
        model = User
        fields=('id','username', 'full_name','email','group','is_active')


class PermissionSerializer(serializers.ModelSerializer):
    permission = serializers.SerializerMethodField()
    class Meta:
        ref_name="document_serializer"
        model = Permission
        fields = '__all__'

    def get_permission(self, obj):
        return obj.content_type.app_label+'.'+obj.codename

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id','name','permissions')
        
class GroupNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id','name')

class AccessGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id','name')

