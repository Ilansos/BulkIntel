# app/urls.py
from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static

app_name = 'app'
urlpatterns = [
    path('', views.home, name='home'),
    path('check_ip/', views.check_ip, name='check_ip'),
    path('check_ip_virustotal/', views.check_ip_virustotal, name='check_ip_virustotal'),
    path('check_domain_virustotal/', views.check_domain_virustotal, name='check_domain_virustotal'),
    path('check_hash_virustotal/', views.check_hash_virustotal, name='check_hash_virustotal'),
    path('check_url_virustotal/', views.check_url_virustotal, name='check_url_virustotal'),
    path('check_user_agent/', views.check_user_agent, name='check_user_agent'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
