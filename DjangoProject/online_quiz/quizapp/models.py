from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import User 
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from django.core.exceptions import ValidationError


# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)  # Automatically hashes the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, name, password, **extra_fields)
    

# Custom User Model

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models

class CustomUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.AutoField(primary_key=True)  # You can leave this or remove if not needed.
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=50, default='participant', choices=[('admin', 'Admin'), ('participant', 'Participant')])
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Staff can access the admin site
    created_at = models.DateTimeField(auto_now_add=True)

    # Custom user manager
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  # Email is used for login
    REQUIRED_FIELDS = ['name']  # Name is required to create a user or superuser

    def __str__(self):
        return self.email
    
#####Category table

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"ID: {self.id}, Name: {self.name}"
    
###### Quiz table

class Quiz(models.Model):
    category = models.ForeignKey('Category', on_delete=models.CASCADE)
    duration = models.PositiveIntegerField(default=60)  # Duration in minutes
    total_points = models.PositiveIntegerField(default=100)  # Total points for the quiz
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
   
    def __str__(self):
        return f"Quiz: {self.id} - {self.category.name} (Duration: {self.duration} min)"

    
############# Question table

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, related_name='questions', on_delete=models.CASCADE)
    question_text = models.TextField()
    answer_text = models.TextField(default='')  # Set a default value, e.g., an empty string
    point = models.IntegerField(default=0)
    
    def __str__(self):
        return self.question_text

############# Option table

class Option(models.Model):
    question = models.ForeignKey(Question, related_name='options', on_delete=models.CASCADE)
    option_text = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)  # To indicate if it's the correct answer

    def __str__(self):
        return self.option_text


#####Participant table

class Participant(models.Model):
    participant_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Links to the custom user model
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)  # Links to the Quiz model
    start_time = models.DateTimeField(auto_now_add=True)  # Records when the quiz started
    total_score = models.IntegerField(default=0)  # To store the participant's score

    def __str__(self):
        return f"{self.user.email} - {self.quiz.title}"
    
class ParticipantAnswer(models.Model):
    participant_answer_id = models.AutoField(primary_key=True)
    participant = models.ForeignKey(Participant, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    option = models.ForeignKey(Option, on_delete=models.CASCADE)
    is_correct = models.BooleanField(default=False)
    mark = models.IntegerField(default=0)  # Score for this specific answer

    def __str__(self):
        return f"{self.participant.user.email} - {self.question.question_text}"

