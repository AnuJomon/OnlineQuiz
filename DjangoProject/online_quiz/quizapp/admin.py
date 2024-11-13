from django.contrib import admin
from .models import Quiz, Category,Question,Option,Participant,ParticipantAnswer
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from rest_framework.decorators import api_view
from rest_framework import status
from .serializers import AdminSerializer
from rest_framework.response import Response

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    # Specify the fields to be shown in the admin panel
    list_display = ['email', 'name', 'role', 'is_active', 'is_staff']
    list_filter = ['email', 'name', 'role', 'is_active', 'is_staff']
    search_fields = ['email', 'name']
    ordering = ['email']

    # Fields to display in forms
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('role',)}),  # Adding the 'role' field to the form
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('role',)}),  # Adding the 'role' field to the add form
    )

# Register the custom user model in the admin
admin.site.register(CustomUser, CustomUserAdmin)


@api_view(['POST'])
def create_admin(request):
    if request.method == 'POST':
        serializer = AdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class QuizAdmin(admin.ModelAdmin):
    list_display = ('id', 'category', 'duration', 'total_points', 'created_by') 

admin.site.register(Quiz, QuizAdmin)
admin.site.register(Category)
admin.site.register(Question)
admin.site.register(Option)
admin.site.register(Participant)
admin.site.register(ParticipantAnswer)