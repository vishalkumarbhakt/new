"""
Frontend views for serving the S2Cart e-commerce frontend.
"""
from django.shortcuts import render
from django.views.generic import TemplateView
from django.conf import settings
import os


class FrontendView(TemplateView):
    """
    Serves the main frontend application.
    """
    template_name = 'index.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['debug'] = settings.DEBUG
        return context


def frontend_view(request):
    """
    Function-based view to serve the frontend HTML.
    """
    return render(request, 'index.html', {
        'debug': settings.DEBUG
    })
