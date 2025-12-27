"""
URL configuration for Customer_API project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.views.generic import RedirectView

# Import health checks
from .health_checks import health_check, readiness_check

# Import Swagger documentation (only in DEBUG mode)
if settings.DEBUG:
    from drf_yasg.views import get_schema_view
    from drf_yasg import openapi
    from rest_framework import permissions

    schema_view = get_schema_view(
        openapi.Info(
            title="S2Cart API",
            default_version='v1',
            description="API documentation for S2Cart Mobile App",
            terms_of_service=f"https://customer-api.www.s2cart.com/terms/",

            contact=openapi.Contact(email="s2cartofficial@gmail.com"),
            license=openapi.License(name="Private License"),
        ),
        public=True,
        permission_classes=(permissions.AllowAny,),
    )

# Simple view for root URL
def index_view(request):
    return JsonResponse({
        'name': 'S2Cart API',
        'description': 'Backend API for S2Cart Android App',
        'endpoints': {
            'api': '/api/auth/',
            'jwt': '/api/auth/jwt/',
            'admin': '/admin/',
            'health': '/health/'
        }
    })

urlpatterns = [
    path('', index_view, name='index'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/auth/jwt/', include('authentication.jwt_urls')),  # JWT token endpoints
    path('health/', health_check, name='health_check'),
    path('health/readiness/', readiness_check, name='readiness_check'),
    path('health/liveness/', health_check, name='liveness_check'),  # Alias for Kubernetes
    path('favicon.ico', RedirectView.as_view(url='/static/favicon.ico')),
]

# Add Swagger documentation URLs only in development mode
if settings.DEBUG:
    urlpatterns += [
        re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
        path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
        path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
        path('__debug__/', include('debug_toolbar.urls')),  # Debug Toolbar URLs
    ]

    # Serve media and static files in development
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Handle 404 and 500 errors
handler404 = 'Customer_API.views.handler404'
handler500 = 'Customer_API.views.handler500'
