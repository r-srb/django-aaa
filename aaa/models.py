from django.db import models

# Create your models here.

# from django.contrib.auth.models import Group
# 
# class DHCPRole(models.Model):
#     role = models.CharField(max_length=255, unique=True)
#     group_name = models.ForeignKey(Group, on_delete=models.CASCADE)
#     ip_subnet = models.CharField(max_length=50)  # IP subnet ve formátu CIDR (např. 192.168.1.0/24)

#     def __str__(self):
#         # return f'{self.group_name} -> {self.role.name}'
#         # return f'{self.role} -> {self.group_name.name}'
#         return self.ip_subnet

from django.contrib.auth.models import Group

class GroupRoleMapping(models.Model):
    role = models.CharField(max_length=255, unique=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    ip_subnet = models.CharField(max_length=50)  # IP subnet in CIDR format (ex. 192.168.1.0/24)

    def __str__(self):
        return f'{self.role} -> {self.group.name}'
