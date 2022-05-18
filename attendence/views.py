import imp
from django.shortcuts import render
from .models import *
from .serializers import *
from rest_framework.viewsets import ModelViewSet
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from IMS.pagination import StandardPagination
from django.db.models.base import ModelBase
from rest_framework.response import Response
# Create your views here.

def list_to_queryset(model, data):

    if not isinstance(model, ModelBase):
        raise ValueError(
            "%s must be Model" % model
        )
    if not isinstance(data, list):
        raise ValueError(
            "%s must be List Object" % data
        )

    pk_list = [obj.pk for obj in data]
    return model.objects.filter(pk__in=pk_list).order_by('-created_at')

class AttendenceViewset(ModelViewSet):
    # queryset = Attendence.objects.all()
    serializer_class = AttendenceSerializer
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    pagination_class = (StandardPagination)

    def get_queryset(self):
        if self.request.user.is_superuser:
            return Attendence.objects.all()
        else:
            return Attendence.objects.filter(user = self.request.user)

    # def perform_update(self, serializer):
    #     return serializer.save()

    # def create(self, request, *args, **kwargs):
    #     return super().create(request, *args, **kwargs)


    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        saved = self.perform_update(serializer)
        saved.user = request.user
        saved.save()

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)



