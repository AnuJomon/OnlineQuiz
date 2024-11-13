from django.urls import path
from .views import RegisterUserView,RegisterAdminView,home
from rest_framework_simplejwt import views as jwt_views
from . import views
from rest_framework.authtoken.views import obtain_auth_token
from .serializers import CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .views import AdminView,CategoryListCreateView,QuizListCreateView,QuizDetail,CustomTokenObtainPairView,QuestionList,QuestionDetail,OptionList,OptionDetail,SubmitQuizAndLogoutView
from .views import QuizCategoryListView,QuizByCategoryView,SubmitQuizAnswersView,QuizDetailView,StartQuizView,CategoryDetailView,LogoutView,QuizReportView,QuizReportViewbycategory,QuizReportViewbyuser

urlpatterns = [
   
    path('', home, name='home'),  # Root URL now redirects to the login page 
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'), 
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
     
    # Register routes
    path('register/', RegisterUserView.as_view(), name='register'),
    path('register-admin/', RegisterAdminView.as_view(), name='register_admin'),
    path('admin-view/', AdminView.as_view(), name='admin-view'),

    #### Report ########
    path('quiz/report/', QuizReportView.as_view(), name='quiz-report'),
    path('quiz/report/<int:quiz_id>/', QuizReportViewbycategory.as_view(), name='quiz-report'),
    path('quiz/report/<int:quiz_id>/<int:user_id>/', QuizReportViewbyuser.as_view(), name='quiz-report'),

    ####  admin logout ###
    path('logout/', LogoutView.as_view(), name='logout'),  # Logout endpoint




    ###                            Admin Side View
    #################################################################################################

    ########  Category Creation, Retrieve, Update, Deletion  #############

    path('categories/', CategoryListCreateView.as_view(), name='category-list'),  # Category list view
    
    path('categories/<int:id>/', CategoryDetailView.as_view(), name='category-detail'), # Retrieve, Update, and Delete a Category


    ########  Quiz Creation, Retrieve, Update, Deletion      ##############
 
    path('categories/<int:id>/quizzes/', QuizListCreateView.as_view(), name='quiz-list-create'),
    path('categories/<int:id>/quizzes/<int:pk>/', QuizDetail.as_view(), name='quiz-detail'),  # Updated URL for detail view
    
    
    path('categories/<int:id>/quizzes/<int:quiz_id>/questions/', QuestionList.as_view(), name='question_list'), #to create , list all questions for a specific quiz
    path('categories/<int:category_id>/quizzes/<int:quiz_id>/questions/<int:pk>/', QuestionDetail.as_view(), name='question-detail'),

    ###############################################################################################################


    ###                                  Quiz Start
    ##############################################################################################################

    path('quiz-categories/', QuizCategoryListView.as_view(), name='quiz-category-list'),
    path('quiz-categories/<int:category_id>/', QuizByCategoryView.as_view(), name='quiz-by-category'),

    path('quiz-categories/<int:category_id>/<int:quiz_id>/', QuizDetailView.as_view(), name='quiz-detail'),
    path('quiz-categories/<int:category_id>/<int:quiz_id>/start/', StartQuizView.as_view(), name='start_quiz'),
    path('quiz-categories/<int:category_id>/<int:quiz_id>/start/submit/', SubmitQuizAnswersView.as_view(), name='submit_quiz'),
    path('quiz-categories/<int:category_id>/<int:quiz_id>/start/submit/logout/', SubmitQuizAndLogoutView.as_view(), name='submit_and_logout_quiz'),



]
