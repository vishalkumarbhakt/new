"""
URL configuration for the frontend app.
"""
from django.urls import path
from django.views.generic import RedirectView
from .views import frontend_view

app_name = 'frontend'

urlpatterns = [
    path('', frontend_view, name='home'),
]
