"""
JWT-specific URL patterns for authentication
"""
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
    TokenBlacklistView,
)
from .views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    JWTLogoutView,
    JWTUserSessionsView,
)

urlpatterns = [
    # JWT Token endpoints
    path('', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    
    # Custom JWT endpoints
    path('logout/', JWTLogoutView.as_view(), name='jwt_logout'),
    path('sessions/', JWTUserSessionsView.as_view(), name='jwt_user_sessions'),
    path('sessions/<str:session_id>/', JWTUserSessionsView.as_view(), name='jwt_terminate_session'),
]
