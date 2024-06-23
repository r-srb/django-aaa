# aaa/backends.py

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
import subprocess

class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        PScmd = '(new-object directoryservices.directoryentry "", "%s", "%s").psbase.name -ne $null' % (username, password)
        try:
            output = subprocess.check_output(["powershell", "-command", PScmd], text=True).strip()
            if output == "True":
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    user = User(username=username)
                    user.set_unusable_password()
                    user.save()
                return user
            else:
                return None
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            # return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
