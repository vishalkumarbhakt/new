"""
Health check endpoints for S2Cart API
"""
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.db import connection
from django.conf import settings
import logging
import time
import datetime
from django.core.cache import cache

# Try to import psutil, but handle gracefully if not installed
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logging.warning("psutil module not available. Some system metrics will not be reported.")
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

logger = logging.getLogger('django')

@never_cache
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Simple health check endpoint that verifies:
    1. API server is running
    2. Database connection is working
    3. Cache is functioning
    """
    start_time = time.time()
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'services': {},
        'environment': 'production' if not settings.DEBUG else 'development'
    }
    
    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        health_status['services']['database'] = 'up'
    except Exception as e:
        health_status['services']['database'] = 'down'
        health_status['status'] = 'unhealthy'
        logger.error(f"Health check: Database connection failed: {str(e)}")
    
    # Check cache connection
    try:
        cache_key = 'health_check'
        cache_value = 'working'
        cache.set(cache_key, cache_value, 10)
        retrieved = cache.get(cache_key)
        if retrieved == cache_value:
            health_status['services']['cache'] = 'up'
        else:
            health_status['services']['cache'] = 'down'
            health_status['status'] = 'unhealthy'
    except Exception as e:
        health_status['services']['cache'] = 'down'
        health_status['status'] = 'unhealthy'
        logger.error(f"Health check: Cache connection failed: {str(e)}")
    
    # Add response time
    health_status['response_time_ms'] = round((time.time() - start_time) * 1000, 2)
    
    # Set appropriate status code
    status_code = 200 if health_status['status'] == 'healthy' else 503
    
    return JsonResponse(health_status, status=status_code)


@never_cache
@api_view(['GET'])
@permission_classes([AllowAny])
def readiness_check(request):
    """
    More detailed health check that includes system metrics
    """
    health_data = {
        'status': 'ready',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': getattr(settings, 'API_VERSION', '1.0'),
        'services': {},
        'system': {}
    }
    
    # Add system metrics if psutil is available
    if HAS_PSUTIL:
        health_data['system'] = {
            'cpu_usage': psutil.cpu_percent(interval=0.1),
            'memory_usage': dict(psutil.virtual_memory()._asdict()),
            'disk_usage': dict(psutil.disk_usage('/')._asdict()),
        }
    else:
        health_data['system'] = {
            'message': 'System metrics unavailable - psutil module not installed'
        }

    
    # Check database
    try:
        with connection.cursor() as cursor:
            start = time.time()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            db_response_time = time.time() - start
            
        health_data['services']['database'] = {
            'status': 'up',
            'response_time_ms': round(db_response_time * 1000, 2)
        }
    except Exception as e:
        health_data['services']['database'] = {
            'status': 'down',
            'error': str(e)
        }
        health_data['status'] = 'not_ready'
    
    # Check cache
    try:
        cache_key = f'readiness_check_{time.time()}'
        start = time.time()
        cache.set(cache_key, 'value', 10)
        cache.get(cache_key)
        cache_response_time = time.time() - start
        
        health_data['services']['cache'] = {
            'status': 'up',
            'response_time_ms': round(cache_response_time * 1000, 2)
        }
    except Exception as e:
        health_data['services']['cache'] = {
            'status': 'down',
            'error': str(e)
        }
        health_data['status'] = 'not_ready'
    
    # Check if disk space is critical (< 10%) - only if psutil is available
    if HAS_PSUTIL and 'disk_usage' in health_data['system'] and health_data['system']['disk_usage']['percent'] > 90:
        health_data['status'] = 'warning'
        health_data['warnings'] = ['Low disk space']
    
    # Check if memory usage is critical (> 95%) - only if psutil is available
    if HAS_PSUTIL and 'memory_usage' in health_data['system'] and health_data['system']['memory_usage']['percent'] > 95:
        health_data['status'] = 'warning' if health_data['status'] != 'not_ready' else 'not_ready'
        if 'warnings' not in health_data:
            health_data['warnings'] = []
        health_data['warnings'].append('High memory usage')
    
    # Determine HTTP status code
    if health_data['status'] == 'not_ready':
        status_code = 503  # Service Unavailable
    elif health_data['status'] == 'warning':
        status_code = 200  # OK with warning
    else:
        status_code = 200  # OK
        
    return JsonResponse(health_data, status=status_code)
