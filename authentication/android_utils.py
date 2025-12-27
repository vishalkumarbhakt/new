from typing import Dict, Any
from rest_framework.response import Response
from rest_framework import status

def format_mobile_response(data: Any, message: str = None, status_code: int = 200) -> Response:
    """
    Format API response specifically for Android clients
    """
    response = {
        'status': 'success' if status_code < 400 else 'error',
        'code': status_code,
        'data': data
    }
    if message:
        response['message'] = message
    
    return Response(response, status=status_code)

def format_mobile_error(message: str, code: int = 400, errors: Dict = None) -> Response:
    """
    Format error response for Android clients
    """
    response = {
        'status': 'error',
        'code': code,
        'message': message
    }
    if errors:
        response['errors'] = errors
    
    return Response(response, status=code)

def format_validation_errors(errors: Dict) -> Response:
    """
    Format validation errors for Android clients
    """
    return format_mobile_error(
        message="Validation failed",
        code=status.HTTP_400_BAD_REQUEST,
        errors=errors
    )

def get_device_info(request) -> Dict:
    """
    Extract device information from request headers
    """
    return {
        'device_type': request.META.get('HTTP_X_DEVICE_TYPE', 'unknown'),
        'app_version': request.META.get('HTTP_X_APP_VERSION', 'unknown'),
        'os_version': request.META.get('HTTP_X_OS_VERSION', 'unknown'),
        'device_id': request.META.get('HTTP_X_DEVICE_ID', 'unknown'),
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'ip_address': get_client_ip(request)
    }

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def should_paginate(request) -> bool:
    """
    Determine if response should be paginated based on client request
    """
    return request.META.get('HTTP_X_DISABLE_PAGINATION', '').lower() != 'true'