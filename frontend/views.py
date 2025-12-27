"""
Frontend views for serving the S2Cart e-commerce frontend.
"""
from django.shortcuts import render
from django.conf import settings


def frontend_view(request):
    """
    Function-based view to serve the frontend HTML.
    """
    return render(request, 'index.html', {
        'debug': settings.DEBUG
    })
