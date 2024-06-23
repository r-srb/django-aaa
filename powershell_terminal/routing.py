from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/powershell/', consumers.PowerShellConsumer.as_asgi()),
]
