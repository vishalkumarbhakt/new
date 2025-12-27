from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.middleware.csrf import get_token
from django.middleware.gzip import GZipMiddleware
import logging
import re

# Set up logging
logger = logging.getLogger('django')

class ServerPortMiddleware:
    """
    Custom middleware to ensure API URLs include the proper port number.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add server port to response headers for client-side URL construction
        port = getattr(settings, 'SERVER_PORT', '9000')
        response['X-Server-Port'] = port
        
        return response

class CSRFCookieMiddleware:
    """
    Middleware to handle CSRF token for mobile clients
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # Ensure CSRF cookie is set
        get_token(request)
        return response

class MobileOptimizedGZipMiddleware(GZipMiddleware):
    """
    Extends Django's GZip middleware to optimize for mobile devices
    """
    def process_response(self, request, response):
        # Only compress responses for mobile clients
        if 'HTTP_X_DEVICE_TYPE' in request.META and request.META['HTTP_X_DEVICE_TYPE'].lower() == 'android':
            return super().process_response(request, response)
        return response

class MobileAPIVersionMiddleware:
    """
    Middleware to handle API versioning for mobile clients
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add API version to response headers
        response['X-API-Version'] = getattr(settings, 'API_VERSION', '1.0.0')
        
        # Check if client version is provided
        client_version = request.headers.get('X-Client-Version')
        if client_version:
            response['X-Min-Client-Version'] = getattr(settings, 'ANDROID_API_MINIMUM_VERSION', '1.0.0')
            response['X-Latest-Client-Version'] = getattr(settings, 'ANDROID_API_LATEST_VERSION', '1.0.0')
        
        return response