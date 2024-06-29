# aaa/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User, Group
import subprocess
import json

class AdPwshAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        PScmd = '(new-object directoryservices.directoryentry "", "%s", "%s").psbase.name -ne $null' % (username, password)
        try:
            output = subprocess.check_output(["powershell", "-command", PScmd], text=True).strip()
            if output != "True":
                return None
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = User(username=username)
            user.set_unusable_password()
            user.save()

        # Remove all AD: groups from the user account
        ad_groups = user.groups.filter(name__startswith="AD:")
        user.groups.remove(*ad_groups)

        # Add User to groups
        user_groups = self.get_user_groups(username)
        if user_groups:
            for group_name in user_groups:
                try:
                    group = Group.objects.get(name="AD:" + group_name)
                    user.groups.add(group)
                except Group.DoesNotExist:
                    pass  # Group does not exist in Django, skip it

        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get_user_groups(self, username):
        PScmd = "Get-ADPrincipalGroupMembership -Identity %s | ConvertTo-Json" % username
        try:
            output = subprocess.check_output(["powershell", "-command", PScmd], text=True)
        except subprocess.CalledProcessError:
            return None

        try:
            AdGroups = json.loads(output)
        except json.JSONDecodeError:
            return None

        UserGroups = []
        for AdGroup in AdGroups:
            UserGroups.append(AdGroup['Name'])

        return UserGroups
