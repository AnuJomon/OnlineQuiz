from django import forms
from django.contrib.auth.forms import AuthenticationForm
from .models import CustomUser,Category,Quiz,Question,Option



class CustomUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)
    
    class Meta:
        model = CustomUser
        fields = ['name', 'email', 'password1', 'password2', 'role']
    
    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Passwords do not match')
        return password2
    
    
class CustomLoginForm(AuthenticationForm):
    email = forms.EmailField(label="Email", max_length=255)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']



class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name']

class QuizForm(forms.ModelForm):
    class Meta:
        model = Quiz
        fields = ['category', 'duration', 'total_points', 'created_by']  # Update this as necessary

class QuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ['quiz', 'question_text', 'answer_text', 'point']  # Include answer_text if needed

class OptionForm(forms.ModelForm):
    class Meta:
        model = Option
        fields = ['option_text', 'is_correct']  # Use 'option_text' not 'answer'

    option_text = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 2, 'placeholder': 'Enter the option text'})
    )
    is_correct = forms.BooleanField(required=False, initial=False)  # Default to False