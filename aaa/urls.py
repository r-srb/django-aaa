# aaa/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('logout_complete/', views.logout_complete, name='logout_complete'),
    path('', views.index, name='index'),
]