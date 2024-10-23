from django.http import HttpRequest
from django.shortcuts import redirect
from core.models import Session

class SessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        unrestricted_endpoints = ['/', '/users/new/', '/sessions/new/', '/sessions/', '/users/']

        if request.path not in unrestricted_endpoints:
            
            token = request.COOKIES.get('token')
            if token:
                try:
                    session = Session.objects.get(token=token)
                    request.user = session.user  
                except Session.DoesNotExist:
                    request.user = None  
            else:
                request.user = None  

            if request.user is None:
                return redirect('new_sessions')

        response = self.get_response(request)
        return response