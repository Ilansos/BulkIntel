from django.urls import path
from .views import register, custom_login, account_locked

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', custom_login, name='login'),
    path('account_locked/', account_locked, name='account_locked'),
]
