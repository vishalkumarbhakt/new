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

# Import Swagger documentation (enabled for all environments)
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

# Import product URL patterns
from products.urls import public_urlpatterns as product_public_urls
from products.urls import customer_urlpatterns as product_customer_urls
from products.urls import admin_urlpatterns as product_admin_urls

schema_view = get_schema_view(
    openapi.Info(
        title="S2Cart E-Commerce API",
        default_version='v1',
        description="""
## S2Cart E-Commerce Backend API

A complete production-ready e-commerce backend API built with Django REST Framework.

### Features:
- **Authentication**: JWT and Token-based authentication with device tracking
- **Products**: Complete product catalog with categories, images, and reviews
- **Cart**: Multi-store cart management with item tracking
- **Orders**: Full order lifecycle management
- **Payments**: PhonePe and Paytm payment gateway integration
- **User Management**: Profile, addresses, and wishlist management

### API Namespaces:
- `/api/public/*` - Public APIs (no authentication required)
- `/api/customer/*` - Customer APIs (authentication required)
- `/api/admin/*` - Admin APIs (staff authentication required)
- `/api/auth/*` - Authentication and legacy APIs

### Authentication:
Use Bearer token authentication. Include the JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```
        """,
        terms_of_service="https://customer-api.s2cart.com/terms/",
        contact=openapi.Contact(email="s2cartofficial@gmail.com"),
        license=openapi.License(name="Private License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# Simple view for root URL
def index_view(request):
    return JsonResponse({
        'name': 'S2Cart E-Commerce API',
        'version': '1.0.0',
        'description': 'Complete E-Commerce Backend API for S2Cart',
        'frontend': '/frontend/',
        'store': '/store/',
        'documentation': {
            'swagger': '/swagger/',
            'redoc': '/redoc/'
        },
        'endpoints': {
            'public': {
                'products': '/api/public/products/',
                'categories': '/api/public/categories/',
            },
            'customer': {
                'wishlist': '/api/customer/wishlist/',
                'reviews': '/api/customer/products/<slug>/reviews/',
            },
            'admin': {
                'products': '/api/admin/products/',
                'categories': '/api/admin/categories/',
                'orders': '/api/admin/orders/',
            },
            'auth': '/api/auth/',
            'jwt': '/api/auth/jwt/',
            'admin_panel': '/admin/',
            'health': '/health/'
        }
    })

# Import admin URLs from authentication app
from authentication.admin_urls import urlpatterns as auth_admin_urls

# Import frontend views
from frontend.views import frontend_view

urlpatterns = [
    # Root and documentation
    path('', index_view, name='index'),
    
    # Frontend (E-commerce store UI)
    path('frontend/', frontend_view, name='frontend'),
    path('store/', frontend_view, name='store'),  # Alias for frontend
    
    # Swagger/OpenAPI documentation (enabled for all environments)
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # Admin panel
    path('admin/', admin.site.urls),
    
    # Public APIs - No authentication required
    path('api/public/', include((product_public_urls, 'public'), namespace='public')),
    
    # Customer APIs - Authentication required
    path('api/customer/', include((product_customer_urls, 'customer'), namespace='customer')),
    
    # Admin APIs - Staff authentication required (products)
    path('api/admin/', include((product_admin_urls, 'admin_api'), namespace='admin_api')),
    # Admin APIs - Orders and Users management
    path('api/admin/', include((auth_admin_urls, 'admin_auth'), namespace='admin_auth')),
    
    # Authentication APIs (legacy and new)
    path('api/auth/', include('authentication.urls')),
    path('api/auth/jwt/', include('authentication.jwt_urls')),  # JWT token endpoints
    
    # Health check endpoints
    path('health/', health_check, name='health_check'),
    path('health/readiness/', readiness_check, name='readiness_check'),
    path('health/liveness/', health_check, name='liveness_check'),  # Alias for Kubernetes
    
    # Favicon
    path('favicon.ico', RedirectView.as_view(url='/static/favicon.ico')),
]

# Add Debug Toolbar URLs in development mode
if settings.DEBUG:
    urlpatterns += [
        path('__debug__/', include('debug_toolbar.urls')),
    ]
    # Serve media and static files in development
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    # Serve frontend static files
    urlpatterns += static('/frontend/static/', document_root=settings.BASE_DIR / 'frontend' / 'static')

# Handle 404 and 500 errors
handler404 = 'Customer_API.views.handler404'
handler500 = 'Customer_API.views.handler500'
