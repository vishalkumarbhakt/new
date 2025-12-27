from django.http import JsonResponse
import logging

logger = logging.getLogger(__name__)

def handler404(request, exception=None):
    """
    Custom 404 handler that returns a JSON response for API consistency
    """
    logger.warning(f"404 error: {request.path}")
    return JsonResponse({
        'error': 'Not found',
        'message': 'The requested resource was not found',
        'status_code': 404
    }, status=404)

def handler500(request):
    """
    Custom 500 handler that returns a JSON response for API consistency
    """
    logger.error(f"500 error: {request.path}", exc_info=True)
    return JsonResponse({
        'error': 'Server error',
        'message': 'An internal server error occurred',
        'status_code': 500
    }, status=500)