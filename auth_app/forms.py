from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from .models import AllowedEmail

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = get_user_model()
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data['email']
        if not AllowedEmail.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is not allowed to register.")
        # Check if the email has already been used
        if get_user_model().objects.filter(email=email).exists():
            raise forms.ValidationError("A user with that email already exists.")

        return email
    
    def clean_username(self):
        username = self.cleaned_data['username']
        if get_user_model().objects.filter(username=username).exists():
            raise forms.ValidationError("A user with that username already exists.")
        return username