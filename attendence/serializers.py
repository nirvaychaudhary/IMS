from rest_framework.serializers import ModelSerializer
from attendence.models  import Attendence

class AttendenceSerializer(ModelSerializer):
    class Meta:
        model = Attendence
        fields = '__all__'
        
    def create(self, validated_data):
        attendance = Attendence.objects.create(
            status=validated_data['status'],
            # user=validated_data['user']
        )

        attendance.save() 
        return attendance