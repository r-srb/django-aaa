from django.shortcuts import render, HttpResponse

# def index(request):
#     return HttpResponse("<h1>dhcp</h1>Welcome!")

from django.contrib.auth.decorators import login_required

from django.contrib.auth.models import Group
from .models import ScopePerm
import ipaddress

@login_required
def index(request):
    subnets = ["10.1.0.0/16", "10.2.0.0/16", "10.2.3.0/24"]
    # Get the user's groups
    user_groups = request.user.groups.all()

    # Get the ScopePerms for the user's groups
    user_ip_subnets = ScopePerm.objects.filter(group__in=user_groups)

    # Extract the subnets from the user's ScopePerms
    user_subnet_list = [ipaddress.ip_network(ip_subnet.subnet) for ip_subnet in user_ip_subnets]

    # Convert predefined subnets to ip_network objects
    predefined_subnets = [ipaddress.ip_network(subnet) for subnet in subnets]

    # Find the subnets that are in both the predefined subnets list and the user's subnet list
    matching_subnets = [str(subnet) for subnet in predefined_subnets if any(subnet.subnet_of(user_subnet) for user_subnet in user_subnet_list)]

    # Prepare the response
    response = "Hello in " + ", ".join(matching_subnets) + " world!<br>"
    response += f"<a href='logout/'>Logout</a> {request.user.username}"

    return HttpResponse(response)

# from django.contrib.auth.models import Group
# from aaa.models import ScopePerm

# group, created = Group.objects.get_or_create(name="AD:GL-SG-NetGlobalAdmins")
# ScopePerm.objects.create(group=group, subnet="0.0.0.0/0")
# group, created = Group.objects.get_or_create(name="AD:PL-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.16.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:CZ-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.32.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:RS-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.48.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:IT-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.64.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:RO-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.96.0.0/12")
# group, created = Group.objects.get_or_create(name="AD:SK-SG-InfraAdmins")
# ScopePerm.objects.create(group=group, subnet="10.112.0.0/12")

# Generator:
# while read gr ip; do
# cat << EOF
# group, created = Group.objects.get_or_create(name="AD:$gr")
# ScopePerm.objects.create(group=group, subnet="$ip")
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
