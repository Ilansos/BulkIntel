from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import CustomUserCreationForm
from .models import AllowedEmail
from axes.helpers import get_client_username
from axes.handlers.proxy import AxesProxyHandler
from axes.utils import reset

# def register(request):
#     if request.method == 'POST':
#         form = CustomUserCreationForm(request.POST)
#         if form.is_valid():
#             user = form.save()
#             login(request, user)
#             return redirect('/')
#     else:
#         form = CustomUserCreationForm()
#     return render(request, 'auth_app/register.html', {'form': form})

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Specify the ModelBackend explicitly
            backend = 'axes.backends.AxesBackend'
            login(request, user, backend=backend)
            return redirect('/')
    else:
        form = CustomUserCreationForm()
    return render(request, 'auth_app/register.html', {'form': form})

# def custom_login(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             if AllowedEmail.objects.filter(email=user.email).exists():
#                 login(request, user)
#                 return redirect('/')
#             else:
#                 return render(request, 'auth_app/login.html', {'error': 'This email is not allowed to log in.'})
#         else:
#             return render(request, 'auth_app/login.html', {'error': 'Invalid username or password.'})
#     else:
#         return render(request, 'auth_app/login.html')

def account_locked(request):
    return render(request, 'auth_app/lockout.html')


def custom_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Check if the user is already locked out
        if AxesProxyHandler.is_locked(request):
            return render(request, 'auth_app/lockout.html')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if AllowedEmail.objects.filter(email=user.email).exists():
                reset(request, get_client_username(request))  # Reset failed attempts on successful login
                login(request, user)
                return redirect('/')
            else:
                return render(request, 'auth_app/login.html', {'error': 'This email is not allowed to log in.'})
        else:
            return render(request, 'auth_app/login.html', {'error': 'Invalid username or password.'})
    else:
        return render(request, 'auth_app/login.html')
