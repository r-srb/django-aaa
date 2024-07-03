# aaa/views.py

from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse


# Login pres HTML stranku:
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect(reverse('index'))
        else:
            return HttpResponse('Could not verify your access level for that URL.\nYou have to <a href="/">login</a> with proper credentials', status=401)
    return render(request, 'login.html')

# def login_view(request):
#     if request.method == 'POST' or request.method == 'GET':
#         auth = request.META.get('HTTP_AUTHORIZATION')
#         if auth:
#             auth = auth.split()
#             if len(auth) == 2 and auth[0].lower() == 'basic':
#                 import base64
#                 try:
#                     username, password = base64.b64decode(auth[1]).decode('utf-8').split(':')
#                 except (TypeError, ValueError):
#                     return HttpResponse('Invalid credentials', status=401)

#                 user = authenticate(request, username=username, password=password)
#                 if user is not None:
#                     login(request, user)
#                     return redirect(reverse('index'))
        
#         response = HttpResponse(
#             'Could not verify your access level for that URL.\nYou have to login with proper credentials',
#             status=401
#         )
#         response['WWW-Authenticate'] = 'Basic realm="Login Required"'
#         return response

def logout_view(request):
    logout(request)
    response = HttpResponse('''
        <p>Logged out! Redirecting...</p>
        <script>
            setTimeout(function() {
                window.location.href = "/login";
            }, 3500);  // Redirect after 3.5 seconds
        </script>
    ''', status=401)
    # response['WWW-Authenticate'] = 'Basic realm="Login Required"'
    return response

@login_required
def index(request):
    return HttpResponse("Hello world!<br><a href='logout/'>Logout<a> " + request.user.username)
