from rest_framework import serializers,generics
from .models import CustomUser,Category,Question,Quiz,Option,Participant,ParticipantAnswer
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.shortcuts import get_object_or_404


# User Serializer for regular users
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'name', 'password', 'role']
        extra_kwargs = {
            'password': {'write_only': True},  # Password should not be exposed in responses
        }

    def validate_email(self, value):
        """
        Ensure email is unique and valid.
        """
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already taken.")
        return value

    def create(self, validated_data):
        # Use the CustomUserManager to create the user
        user = CustomUser.objects.create_user(**validated_data)
        return user

    def validate_password(self, value):
        """
        Ensure password meets minimum length requirement.
        """
        if len(value) < 6:
            raise serializers.ValidationError("Password should be at least 6 characters long.")
        return value

    def validate_role(self, value):
        """
        Ensure role is either 'admin' or 'participant'.
        """
        if value not in ['admin', 'participant']:
            raise serializers.ValidationError("Invalid role. Choose either 'admin' or 'participant'.")
        return value
    
# Admin Serializer for admin users
class AdminSerializer(UserSerializer):
    class Meta:
        model = CustomUser  # Use the custom user model here
        fields = ['email', 'name', 'password', 'is_staff', 'is_superuser', 'role']  # Added 'role' as it's in your model
        extra_kwargs = {
            'password': {'write_only': True},
        }

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email  # Add user's email to the token
        return token

##############################################################

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = [ 'id','name']


class OptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Option
        fields = ['id', 'option_text', 'is_correct']

class QuestionSerializer(serializers.ModelSerializer):
    options = OptionSerializer(many=True)  # Assuming you have an OptionSerializer

    class Meta:
        model = Question
        fields = ['id', 'question_text', 'answer_text', 'point', 'options']

    def create(self, validated_data):
        options_data = validated_data.pop('options')
        question = Question.objects.create(**validated_data)
        for option_data in options_data:
            Option.objects.create(question=question, **option_data)
        return question

    def update(self, instance, validated_data):
        # Update the question fields
        options_data = validated_data.pop('options', [])  # Get the options data, or use an empty list if not provided

        instance.question_text = validated_data.get('question_text', instance.question_text)
        instance.answer_text = validated_data.get('answer_text', instance.answer_text)
        instance.point = validated_data.get('point', instance.point)
        instance.save()

        # Update or create options
        existing_options = {option.id: option for option in instance.options.all()}  # Get existing options for comparison

        for option_data in options_data:
            option_id = option_data.get('id')
            if option_id:  # If there's an option ID, update the existing option
                option_instance = existing_options.get(option_id)
                if option_instance:
                    option_instance.option_text = option_data.get('option_text', option_instance.option_text)
                    option_instance.is_correct = option_data.get('is_correct', option_instance.is_correct)
                    option_instance.save()
                else:
                    # If the option ID doesn't exist, create a new option
                    Option.objects.create(question=instance, **option_data)
            else:
                # If no option ID is provided, create a new option
                Option.objects.create(question=instance, **option_data)

        # Delete any options that were not included in the request
        for option_id, option_instance in existing_options.items():
            if option_id not in [option_data.get('id') for option_data in options_data]:
                option_instance.delete()

        return instance
class QuizSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True)

    class Meta:
        model = Quiz
        fields = ['id', 'duration', 'total_points', 'created_by', 'questions']  

    def create(self, validated_data):
        # Extract questions data from validated_data
        questions_data = validated_data.pop('questions')

        # Create the quiz instance
        quiz = Quiz.objects.create(**validated_data)

        # Create questions for the quiz
        for question_data in questions_data:
            # We use the QuestionSerializer's create method to create each question
            QuestionSerializer.create(QuestionSerializer(), validated_data=question_data)

        return quiz

    def update(self, instance, validated_data):
        # Extract questions data from validated_data (optional, since it may or may not be present)
        questions_data = validated_data.pop('questions', [])

        # Update the basic fields of the quiz
        instance.duration = validated_data.get('duration', instance.duration)
        instance.total_points = validated_data.get('total_points', instance.total_points)
        instance.created_by = validated_data.get('created_by', instance.created_by)
        instance.save()

        # Update or create questions if they are part of the update
        for question_data in questions_data:
            question_id = question_data.get('id')
            if question_id:  # If question_id is provided, try to update the existing question
                try:
                    question = Question.objects.get(id=question_id, quiz=instance)
                    QuestionSerializer.update(QuestionSerializer(), instance=question, validated_data=question_data)
                except Question.DoesNotExist:
                    raise serializers.ValidationError(f"Question with id {question_id} does not exist in this quiz.")
            else:  # If no question_id is provided, create a new question
                QuestionSerializer.create(QuestionSerializer(), validated_data=question_data)

        return instance
    
class QuizShowSerializer(serializers.ModelSerializer):
   class Meta:
        model = Quiz
        fields = ['id', 'duration', 'total_points', 'created_by']
        read_only_fields = ['created_by']  # Make created_by read-only

class QuizDurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['duration', 'total_points']  # Include both fields

    def update(self, instance, validated_data):
        # Update duration and total_points
        instance.duration = validated_data.get('duration', instance.duration)
        instance.total_points = validated_data.get('total_points', instance.total_points)
        instance.save()
        return instance   
##############################################################


class ParticipantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Participant
        fields = ['participant_id', 'user', 'quiz', 'start_time', 'total_score']
        read_only_fields = ['start_time', 'total_score']  # Keeping these read-only is a good practice


class SimpleQuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['id', 'duration', 'total_points']

class QuizOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Option
        fields = ['option_text']
class QuizWithQuestionsSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True)  # Include questions

    class Meta:
        model = Quiz
        fields = ['id', 'duration', 'total_points', 'questions']  # Include fields you want

class QuestionWithOptinSerializer(serializers.ModelSerializer):
    options = QuizOptionSerializer(many=True)  # Serialize options for each question

    class Meta:
        model = Question
        fields = ['id', 'question_text', 'options']  # Include ID and question text   


class QuizStartSerializer(serializers.ModelSerializer):
    questions = QuestionWithOptinSerializer(many=True, read_only=True)  # Include questions and options

    class Meta:
        model = Quiz
        fields = [ 'duration', 'total_points', 'questions']  # Include quiz details   
                  
class ParticipantAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParticipantAnswer
        fields = ['participant_answer_id', 'participant', 'question', 'option', 'is_correct', 'mark']
        read_only_fields = ['participant_answer_id', 'is_correct', 'mark']  # Automatically managed fields

class SubmitAnswerSerializer(serializers.Serializer):
    question_id = serializers.IntegerField()
    option_text = serializers.CharField()

    def validate_question_id(self, value):
        if not Question.objects.filter(id=value).exists():
            raise serializers.ValidationError("Question does not exist.")
        return value

    def validate_option_text(self, value):
        question_id = self.initial_data.get('question_id')
        if not Option.objects.filter(question_id=question_id, option_text=value).exists():
            raise serializers.ValidationError("Invalid option for the selected question.")
        return value
    

#####  Quiz report

class ParticipantReportSerializer(serializers.ModelSerializer):
    # Serialize the user information (user_id and email)
    user_id = serializers.IntegerField(source='user.user_id')  # Corrected from 'user.id' to 'user.user_id'
    user_email = serializers.CharField(source='user.email')

    # Serialize quiz information (quiz id and category name)
    quiz_id = serializers.IntegerField(source='quiz.id')
    category_name = serializers.CharField(source='quiz.category.name')

    # Serialize the total score for the participant
    total_score = serializers.IntegerField()

    class Meta:
        model = Participant
        fields = ['user_id', 'user_email', 'quiz_id', 'category_name', 'total_score']

    def validate_total_score(self, value):
        """Custom validation for total_score to ensure it's non-negative."""
        if value < 0:
            raise serializers.ValidationError("Total score must be a positive integer.")
        return value

    def to_representation(self, instance):
        """Customize the output representation if needed (e.g., formatting or additional fields)."""
        representation = super().to_representation(instance)
        
        # For example, we could add custom formatting or manipulate data here
        representation['total_score'] = f"Score: {representation['total_score']}"
        
        return representation


