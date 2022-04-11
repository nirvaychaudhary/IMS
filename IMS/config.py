import os
from pathlib import Path
import base64

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-&41t@#=92=))x-4(*xab5&t#(b6adjfk4dvq3xtdlxtm+!#h)%'

# SECURITY WARNING: don't run with debug turned on in production!
BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = True


# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR,'staticfiles/')

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static')
]
MEDIA_URL = '/media/' 
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
