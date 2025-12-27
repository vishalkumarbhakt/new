from django.core.cache import cache
from django.conf import settings
from django.http import JsonResponse
import re
import logging
import json
from packaging import version

logger = logging.getLogger(__name__)

class AndroidCacheMiddleware:
    """
    Custom caching middleware for Android clients that respects cache control headers
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.cache_patterns = {
            r'^/api/auth/profile/': 300,  # 5 minutes
            r'^/api/products/': 600,      # 10 minutes
            r'^/api/categories/': 1800,   # 30 minutes
        }

    def __call__(self, request):
        logger.info(f"AndroidCacheMiddleware processing: {request.method} {request.path}")
        
        # Skip caching for non-GET methods
        if request.method != 'GET':
            logger.debug(f"Skipping cache for non-GET method: {request.method}")
            return self.get_response(request)

        # Skip caching if client sends no-cache header
        if 'HTTP_CACHE_CONTROL' in request.META:
            if 'no-cache' in request.META['HTTP_CACHE_CONTROL'].lower():
                logger.debug("Skipping cache due to no-cache header")
                return self.get_response(request)

        # Get user ID safely
        user_id = getattr(request, 'user', None)
        if user_id and hasattr(user_id, 'id'):
            user_id = user_id.id
        else:
            user_id = 'anon'

        # Generate cache key based on path and user
        cache_key = f"android_cache_{request.path}_{user_id}"
        logger.debug(f"Cache key: {cache_key}")
        
        # Check if path matches any cache pattern
        cache_timeout = None
        for pattern, timeout in self.cache_patterns.items():
            if re.match(pattern, request.path):
                cache_timeout = timeout
                logger.debug(f"Path {request.path} matches pattern {pattern}, timeout: {timeout}")
                break

        # If path should be cached
        if cache_timeout:
            # Try to get response from cache
            cached_response = cache.get(cache_key)
            if cached_response is not None:
                logger.info(f"Returning cached response for {cache_key}")
                try:
                    # Ensure we're returning a proper JsonResponse with serializable data
                    if isinstance(cached_response, dict):
                        return JsonResponse(cached_response)
                    else:
                        logger.warning(f"Cached response is not a dict: {type(cached_response)}. Clearing cache.")
                        cache.delete(cache_key)
                except Exception as e:
                    logger.error(f"Error returning cached response: {str(e)}. Clearing cache.")
                    cache.delete(cache_key)

        # Get response
        response = self.get_response(request)
        logger.debug(f"Got response with status: {response.status_code}")
        
        # Cache successful responses
        if cache_timeout and response.status_code == 200:
            try:
                if hasattr(response, 'data') and isinstance(response.data, dict):
                    # Only cache serializable data
                    logger.debug(f"Caching response data for {cache_key}")
                    cache.set(cache_key, response.data, cache_timeout)
                else:
                    logger.debug(f"Response data not cacheable for {cache_key}")
            except Exception as e:
                logger.error(f"Error caching response: {str(e)}")
        
        return response
        
        return response

class AndroidSecurityHeadersMiddleware:
    """
    Add security headers specifically for Android clients
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add security headers for all requests
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy - different for admin/swagger vs API
        if (request.path.startswith('/admin/') or 
            request.path.startswith('/swagger/') or 
            request.path.startswith('/redoc/')):
            # More permissive CSP for Django admin and Swagger
            from django.conf import settings
            if hasattr(settings, 'CSP_DEFAULT_SRC'):
                # Use configured CSP from settings
                csp_parts = []
                if hasattr(settings, 'CSP_DEFAULT_SRC'):
                    csp_parts.append(f"default-src {' '.join(settings.CSP_DEFAULT_SRC)}")
                if hasattr(settings, 'CSP_SCRIPT_SRC'):
                    csp_parts.append(f"script-src {' '.join(settings.CSP_SCRIPT_SRC)}")
                if hasattr(settings, 'CSP_STYLE_SRC'):
                    csp_parts.append(f"style-src {' '.join(settings.CSP_STYLE_SRC)}")
                if hasattr(settings, 'CSP_IMG_SRC'):
                    csp_parts.append(f"img-src {' '.join(settings.CSP_IMG_SRC)}")
                if hasattr(settings, 'CSP_FONT_SRC'):
                    csp_parts.append(f"font-src {' '.join(settings.CSP_FONT_SRC)}")

                if csp_parts:
                    response['Content-Security-Policy'] = '; '.join(csp_parts)
                else:
                    # Fallback CSP for admin/swagger
                    response['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;"
            else:
                # Fallback CSP for admin/swagger when no CSP settings configured
                response['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;"
        else:
            # Restrictive CSP for API endpoints
            response['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none';"
        
        # Additional security headers for Android clients
        if request.META.get('HTTP_X_DEVICE_TYPE', '').lower() == 'android':
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'

        return response

class AndroidVersionCheckMiddleware:
    """
    Middleware to check Android app version and enforce updates
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.META.get('HTTP_X_DEVICE_TYPE', '').lower() == 'android':
            client_version = request.META.get('HTTP_X_APP_VERSION')
            
            if client_version:
                try:
                    client_ver = version.parse(client_version)
                    min_ver = version.parse(getattr(settings, 'ANDROID_API_MINIMUM_VERSION', '1.0.0'))
                    
                    # Check if version is in force update list
                    force_update_versions = getattr(settings, 'ANDROID_FORCE_UPDATE_VERSIONS', [])
                    if client_version in force_update_versions:
                        return JsonResponse({
                            'status': 'error',
                            'code': 426,
                            'message': 'Please update your app to continue',
                            'force_update': True,
                            'latest_version': getattr(settings, 'ANDROID_API_LATEST_VERSION', '1.0.0')
                        }, status=426)
                    
                    # Check if version is below minimum
                    if client_ver < min_ver:
                        return JsonResponse({
                            'status': 'error',
                            'code': 426,
                            'message': 'Please update your app to continue',
                            'force_update': True,
                            'latest_version': getattr(settings, 'ANDROID_API_LATEST_VERSION', '1.0.0')
                        }, status=426)
                        
                except version.InvalidVersion:
                    pass  # Invalid version format, let the request through
                    
        return self.get_response(request)