from django.urls import path
from . import views

urlpatterns = [
    path('powershell/', views.powershell, name='powershell'),
]
