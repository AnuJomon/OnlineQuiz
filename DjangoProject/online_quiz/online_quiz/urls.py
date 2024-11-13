# online_quiz/online_quiz/urls.py
from django.contrib import admin
from django.urls import path,include
# from .views import homepage  # Import the homepage view from views.py

urlpatterns = [
    # path('', homepage, name='homepage'),  # Define the root URL
    path('admin/', admin.site.urls),
    path('', include('quizapp.urls')),  # Include the quizapp URLs
]
