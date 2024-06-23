"""
ASGI config for _site project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', '_site.settings')

# application = get_asgi_application()

# Custom code start here

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import powershell_terminal.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', '_site.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            powershell_terminal.routing.websocket_urlpatterns
        )
    ),
})
