"""
Custom exception handling for the Customer-Database-Api
"""
import logging
import traceback
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler
from authentication.android_utils import format_mobile_error

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom exception handler optimized for Android client responses
    """
    # Get the request from context
    request = context.get('request', None)
    view = context.get('view', None)
    
    # Log detailed error information
    logger.error(f"Exception in view {view.__class__.__name__ if view else 'Unknown'}: {str(exc)}")
    logger.error(f"Exception type: {type(exc).__name__}")
    logger.error(f"Request path: {request.path if request else 'Unknown'}")
    logger.error(f"Request method: {request.method if request else 'Unknown'}")
    
    if request:
        logger.error(f"Request data: {getattr(request, 'data', 'No data')}")
        logger.error(f"Request user: {getattr(request, 'user', 'No user')}")
    
    # Log device info for debugging if available
    if request and request.META.get('HTTP_X_DEVICE_TYPE'):
        logger.error(f"Device info - Type: {request.META.get('HTTP_X_DEVICE_TYPE')} "
                    f"App Version: {request.META.get('HTTP_X_APP_VERSION')} "
                    f"User Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}")

    # Log the full traceback for debugging
    logger.error(f"Full traceback: {traceback.format_exc()}")
    
    response = exception_handler(exc, context)

    if response is None:
        if isinstance(exc, Http404):
            logger.info("404 error occurred")
            return format_mobile_error(
                message="Resource not found",
                code=status.HTTP_404_NOT_FOUND
            )
        else:
            logger.error(f"Unhandled exception: {str(exc)}")
            return format_mobile_error(
                message="An unexpected error occurred",
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    logger.info(f"DRF handled exception with status: {response.status_code}")

    # Format validation errors
    if response.status_code == 400:
        return format_mobile_error(
            message="Validation failed",
            code=status.HTTP_400_BAD_REQUEST,
            errors=response.data
        )

    # Format authentication errors
    if response.status_code == 401:
        return format_mobile_error(
            message="Authentication failed",
            code=status.HTTP_401_UNAUTHORIZED
        )

    # Format permission errors
    if response.status_code == 403:
        return format_mobile_error(
            message="Permission denied",
            code=status.HTTP_403_FORBIDDEN
        )

    # Format other errors
    return format_mobile_error(
        message=str(response.data.get('detail', 'An error occurred')),
        code=response.status_code
    )

class ServiceUnavailableException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _('Service temporarily unavailable, please try again later.')
    default_code = 'service_unavailable'

class ThrottlingException(APIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = _('Request was throttled. Please try again later.')
    default_code = 'throttled'

class AndroidAPIException(APIException):
    """
    Custom exception class for Android-specific API errors
    """
    def __init__(self, message, code=status.HTTP_400_BAD_REQUEST):
        self.status_code = code
        self.default_detail = message
        self.default_code = 'android_error'