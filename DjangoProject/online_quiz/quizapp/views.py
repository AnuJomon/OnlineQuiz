from rest_framework import status,generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer
from rest_framework.permissions import BasePermission
from .permissions import IsAdmin
from django.http import HttpResponse
from .models import CustomUser,Quiz,Question, Option,Category,Participant,ParticipantAnswer
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomLoginForm,QuestionForm,OptionForm,CustomUserCreationForm
from django.contrib import messages
from .serializers import UserSerializer, AdminSerializer
from .serializers import CategorySerializer,QuestionSerializer,ParticipantSerializer,ParticipantAnswerSerializer
from rest_framework.exceptions import PermissionDenied,NotFound,APIException
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.decorators import login_required, user_passes_test
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from .serializers import QuizSerializer,OptionSerializer,CustomTokenObtainPairSerializer,SubmitAnswerSerializer,SimpleQuizSerializer,QuizWithQuestionsSerializer
from .serializers import QuizWithQuestionsSerializer,QuestionWithOptinSerializer,QuizStartSerializer,QuizShowSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from django.utils import timezone
from datetime import timedelta,datetime
import logging
from django.contrib.auth import logout
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import ParticipantReportSerializer
from django.utils.dateparse import parse_datetime


def home(request):
    # Redirect users to the login (token obtain) view
    return redirect('token_obtain_pair')  # Redirect to the TokenObtainPairView

#########View for Token Authentication:

# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer
class CustomTokenObtainPairView(TokenObtainPairView):
    # This view is for handling login and returning access and refresh tokens.
    # You can override any methods if you want to customize token creation or validation.

    # Optionally, if you want to customize the token payload (claims)
    def get_tokens_for_user(self, user):
        # Get the default tokens
        refresh = RefreshToken.for_user(user)
        
        # Optionally, add custom claims to the access token
        access = refresh.access_token
        access['username'] = user.username  # Add custom data to access token, if needed
        
        return {
            'access': str(access),
            'refresh': str(refresh),
        }

#########User registration view

class RegisterUserView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Optionally create a participant for a specific quiz
            quiz_id = request.data.get('quiz_id')
            if quiz_id:
                quiz = Quiz.objects.get(id=quiz_id)  # Ensure the quiz exists
                Participant.objects.create(user=user, quiz=quiz)

            # Log the user in
            login(request, user)

            return Response({
                "message": "User registered and logged in successfully"
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class RegisterAdminView(APIView):
    """
    Admin registration view.
    """
    def post(self, request):
        serializer = AdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Admin registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Apply Permission to Create User View

class AdminView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Only admins can access this view

    def get(self, request):
        return Response({"message": "You are an admin!"})


@api_view(['POST'])
@permission_classes([IsAdmin])  # Only admins can create users
def create_user(request):
    """
    Endpoint for creating a new user. Only accessible by admins.
    """
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#Logout for Both Admin and Participant using JWT (Stateless Authentication)


# Initialize logger
logger = logging.getLogger(__name__)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the refresh token from the request body
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a RefreshToken object from the refresh token string
            refresh_token_obj = RefreshToken(refresh_token)
            
            # Blacklist the refresh token
            refresh_token_obj.blacklist()

            return Response({"detail": "Successfully logged out."}, status=status.HTTP_205_RESET_CONTENT)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)



##########View Categories (List of Categories)

# This view lists all categories and allows authenticated users to create new categories.
class CategoryListCreateView(generics.ListCreateAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # Only authenticated users can access

    queryset = Category.objects.all()  # Fetch all categories
    serializer_class = CategorySerializer  # Use the CategorySerializer to serialize the category data

    def get(self, request, *args, **kwargs):
        # You don't need to manually handle the GET response since ListCreateAPIView handles it
        return super().get(request, *args, **kwargs)


######Category View (Admin-Only Creation)

class CategoryCreateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]  # Only admin users can create categories

    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Save the category
            return Response({"message": "Category created successfully", "category": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# Retrieve, Update, and Delete a Category
class CategoryDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = CategorySerializer

    def get_object(self):
        # Get the category ID from the URL
        category_id = self.kwargs.get('id')  # Now you're getting the category ID
        try:
            # Retrieve the category by ID
            return Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            # If category doesn't exist, raise a NotFound exception
            raise NotFound("Category not found.")

    def get(self, request, *args, **kwargs):
        category = self.get_object()  # Get the category object
        serializer = self.get_serializer(category)  # Serialize the category
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        category = self.get_object()  # Get the category object
        serializer = self.get_serializer(category, data=request.data)  # Pass the updated data
        serializer.is_valid(raise_exception=True)  # Validate data
        serializer.save()  # Save the changes
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        category = self.get_object()  # Get the category object
        category.delete()  # Delete the category
        return Response(status=status.HTTP_204_NO_CONTENT)
    


# View for listing and creating quizzes

class QuizListCreateView(generics.ListCreateAPIView):
    serializer_class = QuizShowSerializer

    def get_queryset(self):
        # Get category_id from the URL
        category_id = self.kwargs.get('id')  # Retrieve category ID
        try:
            # Retrieve the category using the ID
            category = Category.objects.get(id=category_id)
            return Quiz.objects.filter(category=category)  # Filter quizzes based on the category
        except Category.DoesNotExist:
            # Raise error if category not found
            raise NotFound("Category not found.")

    def perform_create(self, serializer):
        # Get category_id from the URL
        category_id = self.kwargs.get('id')
        try:
            # Retrieve the category by ID
            category = Category.objects.get(id=category_id)
            # Save the quiz with the associated category and user
            serializer.save(category=category, created_by=self.request.user)
        except Category.DoesNotExist:
            # Handle error if the category ID is invalid
            raise NotFound("Category not found.")

# API view to retrieve a specific quiz and its questions

class QuizDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = QuizSerializer
    permission_classes = [IsAuthenticated]  # Ensure that only authenticated users can update or delete

    def get_queryset(self):
        # Retrieve category_id and quiz_id from the URL
        category_id = self.kwargs.get('id')  # 'id' corresponds to category_id in the URL
        quiz_id = self.kwargs.get('pk')  # 'pk' corresponds to quiz_id in the URL

        try:
            # Retrieve the category using category_id
            category = Category.objects.get(id=category_id)
            # Return the quiz filtered by both category and quiz_id
            return Quiz.objects.filter(category=category, id=quiz_id)
        except Category.DoesNotExist:
            raise NotFound("Category not found.")
        except Quiz.DoesNotExist:
            raise NotFound("Quiz not found.")

    def update(self, request, *args, **kwargs):
        quiz = self.get_object()
        # If you want to validate or transform the data before updating, you can do it here
        serializer = self.get_serializer(quiz, data=request.data, partial=True)
        
        # If the data is valid, save and return the updated object
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        # If validation fails, return error responses
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        # Retrieve the quiz object to be deleted
        quiz = self.get_object()
        quiz.delete()  # Delete the quiz
        return Response(status=status.HTTP_204_NO_CONTENT)



#######################################################################

# API view to list all questions for a specific quiz
class QuestionList(generics.ListCreateAPIView):
    serializer_class = QuestionSerializer
    permission_classes = [IsAuthenticated]  # Optionally add authentication

    def get_queryset(self):
        quiz_id = self.kwargs['quiz_id']
        return Question.objects.filter(quiz_id=quiz_id)

    def perform_create(self, serializer):
        quiz_id = self.kwargs['quiz_id']
        quiz = get_object_or_404(Quiz, id=quiz_id)
        serializer.save(quiz=quiz)  # Associate the question with the quiz



### Add , Update, and delete the exixting Quiz
# Initialize logger
logger = logging.getLogger(__name__)

class QuestionDetail(APIView):
    """
    View to retrieve, update, or delete a specific question in a quiz.
    """

    # Retrieve a question along with its options
    def get(self, request, category_id, quiz_id, pk):
        try:
            logger.info(f"Fetching details for question ID {pk} in quiz ID {quiz_id} under category ID {category_id}")
            
            # Retrieve the category, quiz, and question to ensure they exist
            category = get_object_or_404(Category, pk=category_id)
            logger.info(f"Category ID {category_id} found.")
            
            quiz = get_object_or_404(Quiz, pk=quiz_id, category=category)
            logger.info(f"Quiz ID {quiz_id} found in category ID {category_id}.")
            
            question = get_object_or_404(Question, pk=pk, quiz=quiz)
            logger.info(f"Question ID {pk} found for quiz ID {quiz_id}.")
            
            # Serialize the question along with its options
            serializer = QuestionSerializer(question)
            return Response(serializer.data)
        
        except Exception as e:
            logger.error(f"Error fetching question ID {pk} for quiz ID {quiz_id}: {str(e)}")
            return Response({"error": "Internal Server Error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Update a specific question
    def put(self, request, category_id, quiz_id, pk):
        try:
            logger.info(f"Updating question ID {pk} for quiz ID {quiz_id} in category ID {category_id}")
            
            # Retrieve the category, quiz, and question to ensure they exist
            category = get_object_or_404(Category, pk=category_id)
            quiz = get_object_or_404(Quiz, pk=quiz_id, category=category)
            question = get_object_or_404(Question, pk=pk, quiz=quiz)
            
            # Pass the existing question instance and the updated data to the serializer
            serializer = QuestionSerializer(question, data=request.data)

            # Check if the provided data is valid
            if serializer.is_valid():
                # Save the updated question to the database
                serializer.save()
                logger.info(f"Question ID {pk} updated successfully.")
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            # If validation fails, return the error details
            logger.warning(f"Validation failed for updating question ID {pk}: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error updating question ID {pk} for quiz ID {quiz_id} in category ID {category_id}: {e}")
            return Response({"error": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Delete a specific question
    def delete(self, request, category_id, quiz_id, pk):
        try:
            logger.info(f"Deleting question ID {pk} for quiz ID {quiz_id} under category ID {category_id}")
            
            # Retrieve the category, quiz, and question to ensure they exist
            category = get_object_or_404(Category, pk=category_id)
            quiz = get_object_or_404(Quiz, pk=quiz_id, category=category)
            question = get_object_or_404(Question, pk=pk, quiz=quiz)

            # Delete all options associated with this question first
            question.options.all().delete()
            logger.info(f"Options for question ID {pk} deleted successfully.")

            # Delete the question itself
            question.delete()
            logger.info(f"Question ID {pk} deleted successfully.")

            return Response(status=status.HTTP_204_NO_CONTENT)

        except Question.DoesNotExist:
            logger.error(f"Question ID {pk} does not exist for quiz ID {quiz_id} in category ID {category_id}.")
            return Response({"error": "Question not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error deleting question ID {pk} for quiz ID {quiz_id} in category ID {category_id}: {e}")
            return Response({"error": "Internal Server Error", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##############################################################

# API view to list and create options for a specific question
class OptionList(generics.ListCreateAPIView):
    serializer_class = OptionSerializer

    def get_queryset(self):
        question_id = self.kwargs['question_id']
        return Option.objects.filter(question_id=question_id)

    def perform_create(self, serializer):
        question_id = self.kwargs['question_id']
        serializer.save(question_id=question_id)

# API view to retrieve, update, or delete a specific option
class OptionDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Option.objects.all()
    serializer_class = OptionSerializer

    def get_queryset(self):
        question_id = self.kwargs['question_id']
        return Option.objects.filter(question_id=question_id)
    

#################################################################
                       #Participant Area
#################################################################

#To View all the categories when the participant logged in
    

class QuizCategoryListView(APIView):
    permission_classes = [IsAuthenticated]  # Require user to be authenticated

    def get(self, request):
        # Fetch all categories from the database
        categories = Category.objects.all()
        
        # Serialize the categories
        serializer = CategorySerializer(categories, many=True)
        
        # Return the serialized data in the response
        return Response(serializer.data)

# To view all Quizzes of specific category

# Set up logger
logger = logging.getLogger(__name__)

class QuizByCategoryView(generics.ListAPIView):
    serializer_class = SimpleQuizSerializer  # Use the simplified serializer

    def get_queryset(self):
        # Get category_id from the URL parameter
        category_id = self.kwargs.get('category_id')
        logger.info(f"Fetching quizzes for category ID: {category_id}")
        
        try:
            # Retrieve the category by ID
            category = Category.objects.filter(id=category_id).first()

            # If category is not found, raise a NotFound exception
            if not category:
                logger.warning(f"Category with ID {category_id} not found.")
                raise NotFound(detail=f"Category with ID {category_id} not found.")
            
            # Log the number of quizzes found for the category
            quizzes = Quiz.objects.filter(category=category)
            logger.info(f"Found {quizzes.count()} quizzes for category '{category.name}' (ID: {category_id}).")

            # Return the serialized quizzes
            return quizzes

        except Exception as e:
            logger.error(f"Error fetching quizzes for category ID {category_id}: {str(e)}")
            raise APIException(detail=f"An error occurred: {str(e)}")

# To view the specific Quiz

class QuizDetailView(APIView):
    permission_classes = [IsAuthenticated]  # Optional, adjust as necessary

    def get(self, request, category_id, quiz_id):
        try:
            # Fetch the category by category_id
            category = Category.objects.filter(id=category_id).first()

            if not category:
                return Response({"error": "Category not found"}, status=404)

            # Fetch the quiz by quiz_id and ensure it belongs to the given category
            quiz = Quiz.objects.filter(id=quiz_id, category=category).first()

            if not quiz:
                return Response({"error": "Quiz not found in the specified category"}, status=404)

            # Serialize the quiz details (excluding the questions and options)
            serializer = SimpleQuizSerializer(quiz)

            # Return the quiz details along with the custom message
            response_data = serializer.data
            response_data['message'] = "Start the quiz"  # Add a custom message

            return Response(response_data)

        except Exception as e:
            return Response({"error": str(e)}, status=500)


########################################################################################################


# To View all questions of specific Quiz ##########      Quiz Start    ##################



# Initialize logger
logger = logging.getLogger(__name__)

class StartQuizView(APIView):
    permission_classes = [IsAuthenticated]  # Require authentication for starting the quiz

    def post(self, request, category_id, quiz_id):
        try:
            # Fetch the quiz by quiz_id and category_id
            quiz = get_object_or_404(Quiz, id=quiz_id, category__id=category_id)

            # Create a new participant entry for the quiz
            participant = Participant.objects.create(user=request.user, quiz=quiz)

            # Calculate end time based on quiz duration
            end_time = participant.start_time + timedelta(minutes=quiz.duration)

            # Fetch questions and options related to the quiz
            questions = quiz.questions.all()  # Assuming quiz has a 'questions' related manager
            question_data = []

            for question in questions:
                options = question.options.all()  # Assuming question has a related 'options' manager
                option_data = [{"option_text": option.option_text} for option in options]

                question_data.append({
                    "question_id": question.id,
                    "question_text": question.question_text,
                    "options": option_data
                })

            return Response({
                "participant_id": participant.participant_id,
                "start_time": participant.start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "participant_name": request.user.email,  # You can use 'username' if you prefer
                "questions": question_data,
                "message": "Quiz started successfully!"
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error starting quiz: {str(e)}", exc_info=True)  # Log the error with traceback
            return Response({"error": "Internal server error, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, category_id, quiz_id):
        # If you want to provide quiz details (questions, options, etc.) for the `GET` request
        try:
            quiz = get_object_or_404(Quiz, id=quiz_id, category__id=category_id)
            serializer = SimpleQuizSerializer(quiz)
            return Response(serializer.data)
        except Quiz.DoesNotExist:
            return Response({"error": "Quiz not found"}, status=status.HTTP_404_NOT_FOUND)
        
############################### Submit the Quiz ##########################################


# Set up logger for debugging and error handling
logger = logging.getLogger(__name__)

class SubmitQuizAnswersView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, category_id, quiz_id):
        logger.debug("Starting answer submission process.")
        try:
            # Fetch the latest participant entry for the quiz
            participant = Participant.objects.filter(user=request.user, quiz_id=quiz_id).order_by('-start_time').first()
            
            if not participant:
                return Response({"error": "Participant not found."}, status=status.HTTP_404_NOT_FOUND)

            # Calculate elapsed time (in minutes)
            elapsed_time = (timezone.now() - participant.start_time).total_seconds() / 60
            quiz_duration = participant.quiz.duration
            
            # Check if submission is within the allowed time
            if elapsed_time > quiz_duration:
                return Response({"error": "Submission time exceeded."}, status=status.HTTP_400_BAD_REQUEST)

            # Get the submitted answers from the request data
            submitted_answers = request.data.get('answers', [])
            logger.debug(f"Submitted answers: {submitted_answers}")

            if not submitted_answers:
                return Response({"error": "No answers submitted."}, status=status.HTTP_400_BAD_REQUEST)

            total_score = 0

            for answer in submitted_answers:
                question_id = answer.get('question_id')
                selected_option_text = answer.get('option_text')

                if not question_id or not selected_option_text:
                    logger.warning("Invalid answer format. Missing 'question_id' or 'option_text'.")
                    return Response({"error": "Each answer must include 'question_id' and 'option_text'"}, status=status.HTTP_400_BAD_REQUEST)

                # Fetch the question and the selected option
                question = get_object_or_404(Question, id=question_id)
                selected_option = get_object_or_404(Option, question=question, option_text=selected_option_text)

                is_correct = selected_option.is_correct
                score_for_this_answer = question.point if is_correct else 0
                total_score += score_for_this_answer

                # Save the participant's answer
                ParticipantAnswer.objects.create(
                    participant=participant,
                    question=question,
                    option=selected_option,
                    is_correct=is_correct,
                    mark=score_for_this_answer  # This will be zero if incorrect
                )

            # Update the participant's total score
            participant.total_score += total_score
            participant.save()

            return Response({
                "message": "Quiz submitted successfully",
                "total_score": participant.total_score,
                "time_taken": elapsed_time
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, category_id, quiz_id):
        # Return a 405 error for GET requests
        return Response({"error": "GET method not allowed."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    



class SubmitQuizAndLogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this endpoint

    def post(self, request, category_id, quiz_id):
        try:
            # Log the user out (clear the session or invalidate the JWT token)
            logout(request)

            # Return a success message
            return Response({
                "message": "You have been logged out successfully after quiz submission."
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

##########################################################################################

class QuizReportView(APIView):
    permission_classes = [IsAdminUser]  # Only accessible by admin users

    def get(self, request):
        try:
            # Extract filters from query parameters
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            category_name = request.query_params.get('category_name')
            quiz_id = request.query_params.get('quiz_id')  # Optional: filter by specific quiz
            participant_id = request.query_params.get('participant_id')  # Optional: filter by participant ID

            # If start_date or end_date are provided, parse them; otherwise, use default range
            if start_date:
                start_date = parse_datetime(start_date) or datetime.min
            else:
                start_date = datetime.min

            if end_date:
                end_date = parse_datetime(end_date) or datetime.max
            else:
                end_date = datetime.max

            # Start by getting all participants in the given date range
            participants = Participant.objects.select_related('user', 'quiz__category') \
                .filter(start_time__range=[start_date, end_date])

            # Filter by quiz_id if provided
            if quiz_id:
                participants = participants.filter(quiz_id=quiz_id)

            # Filter by category_name if provided
            if category_name:
                participants = participants.filter(quiz__category__name__icontains=category_name)

            # Filter by participant_id if provided
            if participant_id:
                participants = participants.filter(id=participant_id)

            # If no participants match the filter, return a 404 response
            if not participants.exists():
                return Response({"error": "Participant(s) not found"}, status=status.HTTP_404_NOT_FOUND)

            # Serialize the participants using ParticipantReportSerializer
            serializer = ParticipantReportSerializer(participants, many=True)

            # Return the serialized data
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            # Catch any unexpected exceptions and return a 500 error
            return Response({"error": "Failed to generate report", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class QuizReportViewbycategory(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, quiz_id):
        try:
            # Optional: Filtering by start_date, end_date, and category_name
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            category_name = request.query_params.get('category_name')
            user_id = request.query_params.get('user_id')  # Get user_id from query params if available

            # If no start_date or end_date provided, set defaults
            if start_date:
                start_date = parse_datetime(start_date) or datetime.min
            else:
                start_date = datetime.min

            if end_date:
                end_date = parse_datetime(end_date) or datetime.max
            else:
                end_date = datetime.max

            # Build the query based on the provided filters
            participants = Participant.objects.select_related('user', 'quiz__category') \
                .filter(quiz_id=quiz_id, start_time__range=[start_date, end_date])

            # Filter by category_name if provided
            if category_name:
                participants = participants.filter(quiz__category__name__icontains=category_name)

            # Filter by user_id if provided
            if user_id:
                participants = participants.filter(user_id=user_id)

            # If no participants match the criteria, return 404
            if not participants.exists():
                return Response({"error": "No participants found matching the criteria."}, status=status.HTTP_404_NOT_FOUND)

            # Serialize the data
            serializer = ParticipantReportSerializer(participants, many=True)

            # Return the serialized report data
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Failed to generate report", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class QuizReportViewbyuser(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, quiz_id, user_id):
        try:
            # Optional: Filtering by start_date, end_date, and category_name
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            category_name = request.query_params.get('category_name')

            # If no start_date or end_date provided, set defaults
            if start_date:
                start_date = parse_datetime(start_date) or datetime.min
            else:
                start_date = datetime.min

            if end_date:
                end_date = parse_datetime(end_date) or datetime.max
            else:
                end_date = datetime.max

            # Build the query based on the provided filters
            participants = Participant.objects.select_related('user', 'quiz__category') \
                .filter(quiz_id=quiz_id, user_id=user_id, start_time__range=[start_date, end_date])

            # Filter by category_name if provided
            if category_name:
                participants = participants.filter(quiz__category__name__icontains=category_name)

            # If no participants match the criteria, return 404
            if not participants.exists():
                return Response({"error": "No participants found matching the criteria."}, status=status.HTTP_404_NOT_FOUND)

            # Serialize the data
            serializer = ParticipantReportSerializer(participants, many=True)

            # Return the serialized report data
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": "Failed to generate report", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)