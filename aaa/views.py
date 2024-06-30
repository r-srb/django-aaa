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

# from django.contrib.auth.models import Group
# from .models import IPSubnet
# import ipaddress

# @login_required
# def index(request):
#     subnets = ["10.1.0.0/16", "10.2.0.0/16", "10.2.3.0/24"]
#     # Get the user's groups
#     user_groups = request.user.groups.all()

#     # Get the IPSubnets for the user's groups
#     user_ip_subnets = IPSubnet.objects.filter(group__in=user_groups)

#     # Extract the subnets from the user's IPSubnets
#     user_subnet_list = [ipaddress.ip_network(ip_subnet.subnet) for ip_subnet in user_ip_subnets]

#     # Convert predefined subnets to ip_network objects
#     predefined_subnets = [ipaddress.ip_network(subnet) for subnet in subnets]

#     # Find the subnets that are in both the predefined subnets list and the user's subnet list
#     matching_subnets = [str(subnet) for subnet in predefined_subnets if any(subnet.subnet_of(user_subnet) for user_subnet in user_subnet_list)]

#     # Prepare the response
#     response = "Hello in " + ", ".join(matching_subnets) + " world!<br>"
#     response += f"<a href='logout/'>Logout</a> {request.user.username}"

#     return HttpResponse(response)

# from django.contrib.auth.models import Group
# from aaa.models import IPSubnet

# group, created = Group.objects.get_or_create(name="AD:GL-SG-NetGlobalAdmins")
# IPSubnet.objects.create(group=group, subnet="0.0.0.0/0")
# group, created = Group.objects.get_or_create(name="AD:PL-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.16.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:CZ-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.32.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:RS-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.48.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:IT-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.64.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:RO-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.96.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:SK-SG-InfraAdmins")
# IPSubnet.objects.create(group=group, subnet="10.112.0.0/12")

# Generator:
# while read gr ip; do
# cat << EOF
# group, created = Group.objects.get_or_create(name="AD:$gr")
# IPSubnet.objects.create(group=group, subnet="$ip")
# EOF
# done << EOF
# GL-SG-NetGlobalAdmins 0.0.0.0/0
# PL-SG-InfraAdmins 10.16.0.0/12
# CZ-SG-InfraAdmins 10.32.0.0/12
# RS-SG-InfraAdmins 10.48.0.0/12
# IT-SG-InfraAdmins 10.64.0.0/12
# RO-SG-InfraAdmins 10.96.0.0/12
# SK-SG-InfraAdmins 10.112.0.0/12
# EOF
