from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
# for password resert
from django.dispatch import receiver
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail, BadHeaderError
from django import template
from rest_framework.response import Response
from rest_framework import status

class CustomUserManager(BaseUserManager):

    def create_user(self,username, first_name, middle_name, last_name, contact_no, email, password=None, **extra_fields):
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            username = username,
            email = self.normalize_email(email),
            password = password,
            first_name = first_name,
            middle_name = middle_name,
            last_name = last_name,
            contact_no = contact_no,
            group = extra_fields.get('group'),
        )

        user.set_password(password)
        #set password in built for password
        user.save(using=self._db)
        return user

    def create_superuser(self,username, first_name, middle_name, last_name, contact_no, email, password):

        user = self.create_user(
            email = self.normalize_email(email),
            #normalize email makes capital email small
            username = username,
            password = password,
            first_name = first_name,
            middle_name = middle_name,
            last_name = last_name,
            contact_no = contact_no,
            # group = group,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google','email': 'email'}
class CustomUser(AbstractUser):
    GENDER_TYPE_CHOICES = (
        ('male', 'male'),
        ('female', 'female'),
        ('other', 'other')
    )
    first_name = models.CharField(max_length=50, null=True, blank=True)
    middle_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    contact_no = models.CharField(max_length=14, null=True, blank=True)
    email = models.EmailField(("Email Address"), max_length=254, unique=True)
    gender=models.CharField(max_length=10, choices=GENDER_TYPE_CHOICES)
    photo=models.ImageField(upload_to='user_profile/%Y/%m/%d/',null=True, blank=True)
    group=models.ForeignKey(Group,on_delete=models.CASCADE,null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    auth_provider = models.CharField(max_length=255, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'middle_name', 'last_name', 'contact_no', 'username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, add_label):
        return True

class UserLog(models.Model):
    action = models.CharField(max_length=255)
    ip = models.GenericIPAddressField(null=True)
    email = models.CharField(max_length=255, null=True)
    last_login = models.DateTimeField(null=True, blank=True)
    last_logout = models.DateTimeField(null=True, blank=True)
    user_id = models.CharField(max_length=255, null=True)

    class Meta:
        ordering=['-id']
    
    def __str__(self):
        return self.email

def get_client_ip(request):
	x_forwarded_for = request.META.get('HTTP_X_REAL_IP')
	if x_forwarded_for:
		ip = x_forwarded_for.split(', ')[0]
	else:
		ip = request.META.get('REMOTE_ADDR')
	return ip

@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    user_id = request.user.id
    ip = get_client_ip(request)
    now = timezone.now()
    email = request.user.email
    if UserLog.objects.filter(email=email).exists():
        UserLog.objects.filter(email=email).update(action='user_logged_in', user_id=user_id, ip=ip, email=email, last_login=now)
    else:
	    UserLog.objects.create(action='user_logged_in', user_id=user_id, ip=ip, email=email, last_login=now)

@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    user_id = request.user.id
    ip = get_client_ip(request)
    email = request.user.email
    now = timezone.now()
    if UserLog.objects.filter(email=email).exists():
        UserLog.objects.filter(email=email).update(action='user_logged_out', user_id=user_id, ip=ip, email=email, last_logout=now)
    else:
	    UserLog.objects.create(action='user_logged_out', user_id=user_id, ip=ip, email=email, last_logout=now)

class OldHashes(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,editable=False)
    pwd = models.CharField('Password hash',max_length=255,editable=False)
    date = models.DateTimeField('Date',auto_now_add=True,editable=False)
   
    def __str__(self) -> str:
        return self.user

@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    email_address=reset_password_token.user.email
    subject = "Confirm QuintPros Password Reset"
    email_plaintext_message = "http://127.0.0.1:8000/api/password_reset/confirm/" + "?token="+reset_password_token.key
    htmltemp = template.loader.get_template('email_authentication/account_password_reset_email.html')
    c = { 
        "email":reset_password_token.user.email,
        "user": reset_password_token.user,
        'token': reset_password_token.key,
        'protocol': 'http',
        'url': email_plaintext_message
        }
    html_content = htmltemp.render(c)
    try:
        send_mail(subject, email_plaintext_message, "nirvayachaudhary6145ns@gmail.com", [email_address], fail_silently=True, html_message=html_content)
        return Response(status=status.HTTP_200_OK,data={'message':"Password reset instructions have been sent to the email address entered."})
    except BadHeaderError:
            return Response(status=status.HTTP_400_BAD_REQUEST,data={'message':'Invalid header found.'})