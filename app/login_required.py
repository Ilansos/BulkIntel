from django.shortcuts import redirect
from django.urls import reverse

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            if not request.path.startswith(reverse('login')) and not request.path.startswith('/new-admin/') and not request.path.startswith('/register/') and not request.path.startswith('/static/') and not request.path.startswith('/static/app/login.css'):
                return redirect('%s?next=%s' % (reverse('login'), request.path))
        response = self.get_response(request)
        return response

