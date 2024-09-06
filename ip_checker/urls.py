from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('new-admin/', admin.site.urls),
    path('', include('auth_app.urls')),
    path('', include('app.urls')),  # Adjust this line if your app is named differently
]
# Serving static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)