from django.shortcuts import render, HttpResponse

# def index(request):
#     return HttpResponse("<h1>dhcp</h1>Welcome!")

from django.contrib.auth.decorators import login_required

from django.contrib.auth.models import Group
from .models import ScopePerm
import ipaddress

from .DhcpServerApi import DhcpServer
import json


@login_required
def index(request):
    subnets = ["10.1.0.0/16", "10.2.0.0/16", "10.2.3.0/24"]
    # Convert predefined subnets to ip_network objects
    predefined_subnets = [ipaddress.ip_network(subnet) for subnet in subnets]

    # Get the Subnets from ScopePerms for the user's groups
    user_subnets = ScopePerm.objects.filter(group__in=request.user.groups.all())

    # Extract the subnets from the user's ScopePerms
    permited_user_subnets = [ipaddress.ip_network(ip_subnet.subnet) for ip_subnet in user_subnets]

    # Find the subnets that are in both the predefined subnets list and the user's subnet list
    permited_subnets = [str(subnet) for subnet in predefined_subnets if any(subnet.subnet_of(user_subnet) for user_subnet in permited_user_subnets)]

    # Prepare the response
    response = "Hello in " + ", ".join(permited_subnets) + " world!<br>"
    response += f"<a href='/logout/'>Logout</a> {request.user.username}"

    return HttpResponse(response)

@login_required
def init(request):
    '''
    Add/Set default AD groups
    '''
    from django.contrib.auth.models import Group
    from .models import ScopePerm

    groups = {
        "AD:GL-SG-NetGlobalAdmins":"0.0.0.0/0",
        "AD:PL-SG-InfraAdmins":"10.16.0.0/12",
        "AD:CZ-SG-InfraAdmins":"10.32.0.0/12",
        "AD:RS-SG-InfraAdmins":"10.48.0.0/12",
        "AD:IT-SG-InfraAdmins":"10.64.0.0/12",
        "AD:RO-SG-InfraAdmins":"10.96.0.0/12",
        "AD:SK-SG-InfraAdmins":"10.112.0.0/12"
    }
    for group_name in groups:
        group, created = Group.objects.get_or_create(name=group_name)
        ScopePerm.objects.create(group=group, subnet=groups[group_name])

    return HttpResponse('Init Groups')

def test(request):
    # dhcp_server = DhcpServer('cz11win016p')
    # dhcp_server = DhcpServer('10.231.253.12')
    dhcp_server = DhcpServer('127.0.0.1')

    # result = dhcp_server.ScopeGet(scope='10.34.8.0')
    # result = dhcp_server.ScopeGet(scope='192.168.0.0')
    # result = dhcp_server.SuperScopeGet(scope='RO-WH-02-HQ-SERVERS', cims=True)
    # result = dhcp_server.ExclusionRangeGet()
    # result = dhcp_server.LeaseGet('192.168.0.0')
    result = dhcp_server.ReservationGet('192.168.0.0')
    if result['error'] is None:
        return HttpResponse(json.dumps(result['data']), content_type="application/json")
    # Special errors
    elif result['error'] == 'NO DATA':
        return HttpResponse(f"{result['error']}")
    # Generic error
    else:
        return HttpResponse(f"Error occurred with code: {result['error']}")
    
