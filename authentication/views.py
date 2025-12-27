import uuid
import json
import hashlib
import logging
from datetime import timedelta
import time
import base64

from django.shortcuts import render, get_object_or_404
from django.http import Http404
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from django.http import JsonResponse
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError

from rest_framework import status, generics, permissions, throttling, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import permission_classes, api_view, throttle_classes
from rest_framework.reverse import reverse

# JWT imports
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication

# Import our email utility functions
from .utils import send_verification_email, send_password_reset_email
from .email_validators import RateLimitValidator

from .serializers import (
    RegisterSerializer,
    UserSerializer,
    LoginSerializer,
    ProfileUpdateSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    CartSerializer,
    CartCreateSerializer,
    CartItemSerializer,
    OrderSerializer,
    OrderItemSerializer,
    SearchHistorySerializer,
    SearchHistoryGroupSerializer,
    CustomerChatSerializer,
    CustomerSupportTicketSerializer,
    CardPaymentMethodSerializer,
    UPIPaymentMethodSerializer,
    PaymentHistorySerializer,
    PaymentTransactionSerializer,
    UserAddressSerializer,
    CustomTokenObtainPairSerializer,
    JWTRefreshSerializer,
    SessionSerializer,
    LogoutSerializer,
    SessionTerminateSerializer
)
from .models import (
    Cart, CartItem, Order, OrderItem, ExpiringToken,
    SearchHistoryGroup, SearchHistory, CustomerSupportTicket, CustomerChat,
    CardPaymentMethod, UPIPaymentMethod, PaymentHistory, PaymentTransaction,
    UserAddress, JWTSession
)
from .paytm_utils import PaytmPayment
from .phonepe_utils import PhonePePayment
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .android_utils import format_mobile_response, format_mobile_error, get_device_info, should_paginate

# Setup logging
logger = logging.getLogger(__name__)

# Global rate limiter instance
email_rate_limiter = RateLimitValidator()

def get_client_ip(request):
    """Get client IP address with proper forwarded IP handling"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip

def check_email_submission_rate_limit(request, max_attempts=3, window_minutes=15):
    """
    Enhanced rate limiting specifically for email-based operations
    """
    client_ip = get_client_ip(request)
    
    if email_rate_limiter.is_rate_limited(client_ip, max_attempts, window_minutes):
        logger.warning(f"Email submission rate limit exceeded for IP: {client_ip}")
        raise serializers.ValidationError({
            "detail": "Too many email submission attempts. Please try again later.",
            "retry_after": window_minutes * 60  # seconds
        })
    
    return True

def create_or_update_jwt_session(user, jti, device_type='API', device_id=None, user_agent=None, ip_address=None, expires_at=None):
    """
    Create or update JWT session record with enhanced security validation
    """
    try:
        # Input validation
        if not user or not jti:
            raise ValueError("User and JTI are required")
        
        if len(jti) < 10:  # JTI should be reasonably long for security
            raise ValueError("JTI too short")
        
        # Validate device_type
        valid_device_types = ['ANDROID', 'WEB', 'IOS', 'API']
        if device_type not in valid_device_types:
            device_type = 'API'
        
        # Sanitize inputs
        if user_agent:
            user_agent = user_agent[:500]  # Limit length
        
        if device_id:
            device_id = device_id[:255]  # Limit length
        
        # Try to get existing session by JTI
        session = JWTSession.objects.get(jti=jti)
        # Update existing session
        session.last_activity = timezone.now()
        session.user_agent = user_agent
        session.ip_address = ip_address
        if expires_at:
            session.expires_at = expires_at
        session.save(update_fields=['last_activity', 'user_agent', 'ip_address', 'expires_at'])
        logger.debug(f"Updated existing JWT session for JTI: {jti}")
        return session
    except JWTSession.DoesNotExist:
        # Create new session
        session = JWTSession.objects.create(
            user=user,
            jti=jti,
            device_type=device_type,
            device_id=device_id,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=expires_at or (timezone.now() + timedelta(days=7))
        )
        logger.info(f"Created new JWT session for user {user.username} with JTI: {jti}")
        return session
    except Exception as e:
        logger.error(f"Error creating/updating JWT session: {str(e)}")
        return None


# Create custom throttle classes
class LoginRateThrottle(throttling.ScopedRateThrottle):
    scope = 'login'

class PaymentRateThrottle(throttling.ScopedRateThrottle):
    scope = 'payment'
    
class RegistrationRateThrottle(throttling.ScopedRateThrottle):
    scope = 'registration'

def rate_limited_error(request, exception):
    """View to handle rate limited requests"""
    return JsonResponse({
        'error': 'Too many requests, please try again later.',
        'status_code': 429
    }, status=429)

@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request, format=None):
    """
    API root view that provides links to all available authentication endpoints.
    """
    
    # Get the base URL components
    scheme = request.scheme
    host = request.get_host()
    base_url = f"{scheme}://{host}"
    
    return Response({
        # JWT Authentication endpoints (Recommended)
        'jwt': {
            'login': f"{base_url}/api/token/",
            'refresh': f"{base_url}/api/token/refresh/",
            'verify': f"{base_url}/api/token/verify/",
            'logout': f"{base_url}/api/token/logout/",
            'blacklist': f"{base_url}/api/token/blacklist/",
            'sessions': f"{base_url}/api/token/sessions/"
        },
        # Legacy Token Authentication endpoints (Backward compatibility)
        'legacy': {
            'login': f"{base_url}/api/auth/login/",
            'logout': f"{base_url}/api/auth/logout/",
            'sessions': f"{base_url}/api/auth/sessions/"
        },
        # General endpoints
        'register': f"{base_url}/api/auth/register/",
        'profile': f"{base_url}/api/auth/profile/",
        'profile_update': f"{base_url}/api/auth/profile/update/",
        'password_reset_request': f"{base_url}/api/auth/password-reset/request/",
        'password_reset_confirm': f"{base_url}/api/auth/password-reset/confirm/",
        'verify_resend': f"{base_url}/api/auth/verify/resend/",
        'carts': {
            'list_create': f"{base_url}/api/auth/carts/",
            'detail': f"{base_url}/api/auth/carts/<id>/",
            'by_store': f"{base_url}/api/auth/carts/store/<store_id>/",
            'items': f"{base_url}/api/auth/carts/items/",
            'item_detail': f"{base_url}/api/auth/carts/items/<id>/",
            'clear': f"{base_url}/api/auth/carts/clear/",
            'clear_store': f"{base_url}/api/auth/carts/clear/?store_id=<store_id>"
        },
        'orders': {
            'list': f"{base_url}/api/auth/orders/",
            'detail': f"{base_url}/api/auth/orders/<id>/"
        },
        'payments': {
            # Unified Payment Processing (Recommended)
            'initiate': f"{base_url}/api/auth/payments/initiate/",
            'status': f"{base_url}/api/auth/payments/status/<order_id>/",
            # Gateway-specific endpoints (Legacy/Specialized)
            'paytm': {
                'initiate': f"{base_url}/api/auth/payments/paytm/initiate/",
                'callback': f"{base_url}/api/auth/payments/paytm/callback/",
                'status': f"{base_url}/api/auth/payments/paytm/status/<order_id>/"
            },
            'phonepe': {
                'initiate': f"{base_url}/api/auth/payments/phonepe/initiate/",
                'callback': f"{base_url}/api/auth/payments/phonepe/callback/",
                'redirect': f"{base_url}/api/auth/payments/phonepe/redirect/",
                'status': f"{base_url}/api/auth/payments/phonepe/status/<order_id>/"
            },
            # Legacy endpoints
            'legacy': {
                'list': f"{base_url}/api/auth/payments/",
                'detail': f"{base_url}/api/auth/payments/<id>/"
            },
            'methods': {
                'cards': {
                    'list': f"{base_url}/api/auth/payment-methods/cards/",
                    'detail': f"{base_url}/api/auth/payment-methods/cards/<id>/"
                },
                'upi': {
                    'list': f"{base_url}/api/auth/payment-methods/upi/",
                    'detail': f"{base_url}/api/auth/payment-methods/upi/<id>/"
                }
            },
            'history': {
                'list': f"{base_url}/api/auth/payments/history/",
                'detail': f"{base_url}/api/auth/payments/history/<id>/",
                'transactions': f"{base_url}/api/auth/payments/history/<id>/transactions/"
            }
        },
        'search_history': {
            'group': f"{base_url}/api/auth/search-history-group/",
            'list': f"{base_url}/api/auth/search-history/",
            'detail': f"{base_url}/api/auth/search-history/<id>/",
            'clear': f"{base_url}/api/auth/search-history/clear/"
        },
        'support': {
            'tickets': {
                'list': f"{base_url}/api/auth/support/tickets/",
                'detail': f"{base_url}/api/auth/support/tickets/<id>/",
                'messages': f"{base_url}/api/auth/support/tickets/<id>/messages/"
            }
        },
        'addresses': {
            'list': f"{base_url}/api/auth/addresses/",
            'detail': f"{base_url}/api/auth/addresses/<id>/",
            'set_default': f"{base_url}/api/auth/addresses/set-default/<id>/"
        }
    })

User = get_user_model()

class AndroidAPIView(generics.GenericAPIView):
    """
    Base view for Android API endpoints with optimized response handling
    """
    def get_paginated_response(self, data):
        if should_paginate(self.request):
            return super().get_paginated_response(data)
        return format_mobile_response(data)

    def handle_exception(self, exc):
        if isinstance(exc, Http404):
            from rest_framework.response import Response
            return Response({
                'status': 'error',
                'code': status.HTTP_404_NOT_FOUND,
                'message': 'Resource not found'
            }, status=status.HTTP_404_NOT_FOUND)
        return super().handle_exception(exc)

    def finalize_response(self, request, response, *args, **kwargs):
        # First call the parent method to get the proper response
        response = super().finalize_response(request, response, *args, **kwargs)
        
        # Convert regular DRF response to mobile-optimized format
        if hasattr(response, 'data') and not isinstance(response.data, str):
            # Check if data is already in mobile format
            if not (isinstance(response.data, dict) and 'status' in response.data and 'code' in response.data):
                # Format the data in mobile-friendly way but keep it as DRF Response
                mobile_data = {
                    'status': 'success' if response.status_code < 400 else 'error',
                    'code': response.status_code,
                    'data': response.data
                }
                response.data = mobile_data
        
        # Add API version to response headers
        response['X-API-Version'] = getattr(request, 'version', '1.0')
        
        # Log device info for analytics
        device_info = get_device_info(request)
        logger.info(f"API request from device: {device_info}")
        
        return response

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer
    throttle_classes = [RegistrationRateThrottle]  # Enhanced rate limiting

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        # Enhanced security checks
        client_ip = get_client_ip(request)
        logger.info(f"Registration attempt from IP: {client_ip} for user: {request.data.get('username', 'unknown')}")
        
        # Check email submission rate limit
        try:
            check_email_submission_rate_limit(
                request, 
                max_attempts=getattr(settings, 'EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS', 3),
                window_minutes=getattr(settings, 'EMAIL_RATE_LIMIT_REGISTRATION_WINDOW', 15)
            )
        except serializers.ValidationError as e:
            return Response(e.detail, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        try:
            serializer = self.get_serializer(data=request.data)
            logger.debug("Serializer created successfully")
            
            serializer.is_valid(raise_exception=True)
            logger.debug("Serializer validation passed")
            
            # Create user
            user = serializer.save()
            logger.info(f"User created successfully: {user.username}")
            
            # Generate verification token with a secure method
            token = get_random_string(64)
            # Hash the token before storing
            user.verification_token = hashlib.sha256(token.encode()).hexdigest()
            
            # Generate OTP for verification
            otp = user.generate_verification_otp()
            user.save()
            logger.debug("Verification token and OTP generated and saved")
            
            # Clear any existing ExpiringTokens to prevent conflicts
            ExpiringToken.objects.filter(user=user).delete()
            logger.debug("Existing tokens cleared")
            
            # Then create a new token
            auth_token = ExpiringToken.objects.create(user=user)
            # Set the expiry
            auth_token.set_expiry(days=settings.TOKEN_EXPIRY_TIME)
            logger.debug(f"New auth token created with expiry: {auth_token.expiry}")
            
            # Try to send verification email, but handle failure gracefully
            email_sent = False
            try:
    
                # Get the base URL components
                scheme = request.scheme
                host = request.get_host()
                base_url = f"{scheme}://{host}"
                verification_url = f"{base_url}/api/auth/verify/{token}/"
                logger.debug(f"Attempting to send verification email to: {user.email}")
                
                email_sent = send_verification_email(user, verification_url, otp)
                logger.info(f"Verification email sent: {email_sent}")

                if not email_sent:
                    logger.error(f"Failed to send verification email to {user.email}")
            except Exception as e:
                logger.error(f"Email sending error: {str(e)}", exc_info=True)

            # Prepare response data
            response_data = {
                "status": "success",
                "code": 201,
                "data": {
                    "user": UserSerializer(user, context=self.get_serializer_context()).data,
                    "token": auth_token.key,
                    "expires_at": auth_token.expiry,
                    "message": "User registered successfully. Check your email for verification code or link.",
                    "verification_method": "Both OTP and Token available",
                    "otp_expires_in": "25 minutes",
                    "email_sent": email_sent
                }
            }
            
            logger.info(f"Registration successful for user: {user.username}")
            logger.debug(f"Response data prepared: {type(response_data)}")
            
            # Return mobile-optimized response
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except serializers.ValidationError as e:
            logger.error(f"Registration validation error: {str(e)}", exc_info=True)
            raise e
        except Exception as e:
            logger.error(f"Registration error: {str(e)}", exc_info=True)
            return Response({
                "status": "error",
                "code": 500,
                "message": "Registration failed. Please try again.",
                "detail": str(e) if settings.DEBUG else "See server logs for details."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(AndroidAPIView, generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request, *args, **kwargs):
        # Enhanced security checks
        client_ip = get_client_ip(request)
        logger.info(f"Login attempt from IP: {client_ip}")
        
        # Check email submission rate limit if email is being used for login
        email = request.data.get('email')
        if email:
            try:
                check_email_submission_rate_limit(
                    request, 
                    max_attempts=getattr(settings, 'EMAIL_RATE_LIMIT_LOGIN_ATTEMPTS', 5),
                    window_minutes=getattr(settings, 'EMAIL_RATE_LIMIT_LOGIN_WINDOW', 10)
                )
            except serializers.ValidationError as e:
                return Response(e.detail, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            
            # Check if account is locked
            if user.is_locked:
                if user.locked_until and user.locked_until > timezone.now():
                    lock_time_remaining = int((user.locked_until - timezone.now()).total_seconds() / 60)
                    return Response({
                        "error": f"Account is temporarily locked due to multiple failed login attempts. Try again in {lock_time_remaining} minutes."
                    }, status=status.HTTP_403_FORBIDDEN)
                else:
                    # If lock time has passed, unlock the account
                    user.is_locked = False
                    user.locked_until = None
                    user.save()
            
            # Check if account is verified
            if not user.is_verified:
                return Response({
                    "error": "Email not verified. Please check your email for verification instructions.",
                    "needs_verification": True
                }, status=status.HTTP_403_FORBIDDEN)
                
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.save(update_fields=['failed_login_attempts'])
            
            # Get device information
            device_type = request.data.get('device_type', 'API')
            device_id = request.data.get('device_id')  # Unique device identifier
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip_address = self.get_client_ip(request)
            
            # Validate device_type
            valid_device_types = ['ANDROID', 'WEB', 'IOS', 'API']
            if device_type not in valid_device_types:
                device_type = 'API'
            
            # Create or get token with device tracking
            token = ExpiringToken.get_or_create_token(
                user=user,
                device_type=device_type,
                device_id=device_id,
                user_agent=user_agent,
                ip_address=ip_address,
                expiry_days=settings.TOKEN_EXPIRY_TIME_LOGIN
            )
            
            # Log successful login
            logger.info(f"Successful login for user {user.username} from {device_type} device (IP: {ip_address})")
            
            return Response({
                "user": UserSerializer(user, context=self.get_serializer_context()).data,
                "token": token.key,
                "expires_at": token.expiry,
                "device_type": token.device_type,
                "session_info": {
                    "device_type": token.device_type,
                    "device_id": token.device_id,
                    "created_at": token.created_at,
                    "last_used": token.last_used
                }
            })
            
        except serializers.ValidationError:
            # If login failed, increment the counter
            username = request.data.get('username')
            email = request.data.get('email')
            
            try:
                if email:
                    user = User.objects.get(email=email)
                elif username:
                    user = User.objects.get(username=username)
                else:
                    return Response({
                        "error": "Username or email is required."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                user.failed_login_attempts += 1
                user.last_failed_login = timezone.now()
                
                # Check if account should be locked
                max_attempts = getattr(settings, 'MAX_FAILED_LOGIN_ATTEMPTS', 5)
                if user.failed_login_attempts >= max_attempts:
                    lock_minutes = getattr(settings, 'ACCOUNT_LOCKOUT_MINUTES', 30)
                    user.lock_account(minutes=lock_minutes)
                    logger.warning(f"Account locked for user {user.username} due to {user.failed_login_attempts} failed login attempts")
                else:
                    user.save(update_fields=['failed_login_attempts', 'last_failed_login'])
                    
                # Log failed login attempt
                logger.warning(f"Failed login attempt #{user.failed_login_attempts} for user {user.username} from IP {self.get_client_ip(request)}")
                    
            except User.DoesNotExist:
                # Don't provide detailed feedback about whether username or password was wrong
                pass
                
            return Response({
                "error": "Unable to log in with provided credentials."
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        """
        Logout from current session or all sessions
        """
        logout_all = request.data.get('logout_all', False)
        device_type = request.data.get('device_type')
        
        try:
            if logout_all:
                # Logout from all devices
                count = ExpiringToken.objects.filter(user=request.user).count()
                ExpiringToken.objects.filter(user=request.user).delete()
                return Response({
                    "message": f"Successfully logged out from all {count} sessions."
                }, status=status.HTTP_200_OK)
            elif device_type:
                # Logout from specific device type
                count = ExpiringToken.objects.filter(user=request.user, device_type=device_type).count()
                ExpiringToken.objects.filter(user=request.user, device_type=device_type).delete()
                return Response({
                    "message": f"Successfully logged out from {count} {device_type} sessions."
                }, status=status.HTTP_200_OK)
            else:
                # Logout from current session only
                if hasattr(request, 'auth') and request.auth:
                    request.auth.delete()
                    return Response({
                        "message": "Successfully logged out from current session."
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "message": "No active session found."
                    }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during logout for user {request.user.username}: {str(e)}")
            return Response({
                "error": "An error occurred during logout."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSessionsView(APIView):
    """
    View to manage user sessions (both ExpiringToken and JWT sessions)
    """
    permission_classes = (IsAuthenticated,)
    
    def get(self, request):
        """Get all active sessions for the current user"""
        try:
            sessions = []
            
            # Get ExpiringToken sessions
            tokens = ExpiringToken.objects.filter(user=request.user)
            for token in tokens:
                # Check if this is the current session
                is_current = False
                if hasattr(request, 'auth') and request.auth:
                    if hasattr(request.auth, 'key'):
                        is_current = token.key == request.auth.key
                
                sessions.append({
                    "id": token.key,
                    "device_type": token.device_type,
                    "device_id": token.device_id,
                    "user_agent": token.user_agent,
                    "ip_address": token.ip_address,
                    "created_at": token.created_at,
                    "last_activity": token.last_used or token.created_at,
                    "is_current_session": is_current,
                    "session_type": "TOKEN"
                })
            
            # Get JWT sessions
            jwt_sessions = JWTSession.objects.filter(user=request.user, is_active=True)
            for jwt_session in jwt_sessions:
                # Check if this is the current session
                is_current = False
                if hasattr(request, 'auth') and hasattr(request.auth, 'payload'):
                    current_jti = request.auth.payload.get('jti')
                    is_current = jwt_session.jti == current_jti
                
                sessions.append({
                    "id": jwt_session.jti,
                    "device_type": jwt_session.device_type,
                    "device_id": jwt_session.device_id,
                    "user_agent": jwt_session.user_agent,
                    "ip_address": jwt_session.ip_address,
                    "created_at": jwt_session.created_at,
                    "last_activity": jwt_session.last_activity,
                    "is_current_session": is_current,
                    "session_type": "JWT",
                    "expires_at": jwt_session.expires_at
                })
            
            # Sort by last activity (most recent first)
            sessions.sort(key=lambda x: x['last_activity'], reverse=True)
            
            return format_mobile_response(
                data=sessions,
                message=f"Found {len(sessions)} active sessions"
            )
            
        except Exception as e:
            logger.error(f"Error fetching user sessions: {str(e)}", exc_info=True)
            return format_mobile_error(
                message="Failed to fetch sessions",
                code=500
            )
    
    def delete(self, request, session_id=None):
        """Terminate a specific session"""
        try:
            if not session_id:
                return format_mobile_error(
                    message="Session ID is required",
                    code=400
                )
            
            # Try to find JWT session first
            session_found = False
            session_info = {}
            
            try:
                jwt_session = JWTSession.objects.get(jti=session_id, user=request.user, is_active=True)
                
                # Don't allow terminating current JWT session
                is_current = False
                if hasattr(request, 'auth') and hasattr(request.auth, 'payload'):
                    current_jti = request.auth.payload.get('jti')
                    is_current = jwt_session.jti == current_jti
                
                if is_current:
                    return format_mobile_error(
                        message="Cannot terminate current session. Use logout endpoint instead.",
                        code=400
                    )
                
                session_info = {
                    "device_type": jwt_session.device_type,
                    "device_id": jwt_session.device_id,
                    "session_id": session_id,
                    "session_type": "JWT"
                }
                
                jwt_session.terminate()
                session_found = True
                
            except JWTSession.DoesNotExist:
                # Try to find ExpiringToken session
                try:
                    token = ExpiringToken.objects.get(key=session_id, user=request.user)
                    
                    # Don't allow terminating current token session
                    is_current = False
                    if hasattr(request, 'auth') and hasattr(request.auth, 'key'):
                        is_current = token.key == request.auth.key
                    
                    if is_current:
                        return format_mobile_error(
                            message="Cannot terminate current session. Use logout endpoint instead.",
                            code=400
                        )
                    
                    session_info = {
                        "device_type": token.device_type,
                        "device_id": token.device_id,
                        "session_id": session_id,
                        "session_type": "TOKEN"
                    }
                    
                    token.delete()
                    session_found = True
                    
                except ExpiringToken.DoesNotExist:
                    pass
            
            if not session_found:
                return format_mobile_error(
                    message="Session not found",
                    code=404
                )
            
            return format_mobile_response(
                data={"terminated_session": session_info},
                message=f"Successfully terminated {session_info['session_type']} session"
            )
            
        except Exception as e:
            logger.error(f"Error terminating session {session_id}: {str(e)}", exc_info=True)
            return format_mobile_error(
                message="Failed to terminate session",
                code=500
            )


class UserDetailView(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    
    def get_object(self):
        return self.request.user


class ProfileUpdateView(generics.UpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileUpdateSerializer
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response(UserSerializer(instance, context=self.get_serializer_context()).data)


class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetRequestSerializer
    throttle_classes = [LoginRateThrottle]  # Apply rate limiting to prevent abuse
    
    def post(self, request, *args, **kwargs):
        # Enhanced security checks
        client_ip = get_client_ip(request)
        logger.info(f"Password reset request from IP: {client_ip}")
        
        # Check email submission rate limit
        try:
            check_email_submission_rate_limit(
                request, 
                max_attempts=getattr(settings, 'EMAIL_RATE_LIMIT_PASSWORD_RESET_ATTEMPTS', 3),
                window_minutes=getattr(settings, 'EMAIL_RATE_LIMIT_PASSWORD_RESET_WINDOW', 30)
            )
        except serializers.ValidationError as e:
            return Response(e.detail, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Generate token and OTP and set expiry
            token = get_random_string(64)
            # Hash token for security
            user.reset_password_token = hashlib.sha256(token.encode()).hexdigest()
            user.reset_password_expires = timezone.now() + timedelta(hours=24)
            
            # Generate OTP for password reset
            otp = user.generate_password_reset_otp()
            user.save(update_fields=['reset_password_token', 'reset_password_expires'])
            

            # Get the base URL components
            scheme = request.scheme
            host = request.get_host()
            base_url = f"{scheme}://{host}"
            reset_url = f"{base_url}/api/auth/password-reset/confirm/?token={token}"
            
            # Send email with token and OTP using our utility function
            email_sent = send_password_reset_email(user, reset_url, otp)
            
            # Don't reveal whether the user exists or not
            return Response({
                "status": "success",
                "message": "If your email exists in our system, password reset instructions will be sent.",
                "reset_method": "Both OTP and Token available",
                "otp_expires_in": "25 minutes",
                "email_sent": email_sent if settings.DEBUG else None
            })
            
        except User.DoesNotExist:
            # Don't reveal that the user doesn't exist
            return Response({
                "status": "success",
                "message": "If your email exists in our system, password reset instructions will be sent."
            })


class PasswordResetConfirmView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetConfirmSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        token = serializer.validated_data.get('token')
        otp = serializer.validated_data.get('otp')
        email = serializer.validated_data.get('email')
        password = serializer.validated_data['password']
        
        user = None
        verification_method = None
        
        # Handle token-based reset
        if token:
            # Hash the token to compare with stored hash
            hashed_token = hashlib.sha256(token.encode()).hexdigest()
            try:
                user = User.objects.get(reset_password_token=hashed_token)
                
                # Check if token is expired
                if not user.is_password_reset_token_valid():
                    return Response({
                        "status": "error",
                        "message": "Password reset token has expired. Please request a new one."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                verification_method = "token"
                
            except User.DoesNotExist:
                return Response({
                    "status": "error",
                    "message": "Invalid or expired password reset token."
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle OTP-based reset
        elif email and otp:
            try:
                user = User.objects.get(email=email)
                
                if not user.is_password_reset_otp_valid():
                    return Response({
                        "status": "error",
                        "message": "OTP has expired or is invalid. Please request a new password reset."
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if user.reset_password_otp != otp:
                    return Response({
                        "status": "error",
                        "message": "Invalid OTP. Please check and try again."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                verification_method = "otp"
                
            except User.DoesNotExist:
                return Response({
                    "status": "error",
                    "message": "User with this email does not exist."
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Reset password
        if user:
            user.set_password(password)
            user.reset_password_token = None
            user.reset_password_expires = None
            user.clear_password_reset_otp()
            
            # Reset any failed login attempts when password is reset
            user.failed_login_attempts = 0
            user.is_locked = False
            user.locked_until = None
            
            user.save()
            
            logger.info(f"Password reset successful via {verification_method} for user {user.username}")
            
            return Response({
                "status": "success",
                "message": "Password has been reset successfully.",
                "verification_method": verification_method
            })
        
        return Response({
            "status": "error",
            "message": "Invalid request. Please try again."
        }, status=status.HTTP_400_BAD_REQUEST)


class VerifyAccountView(APIView):
    permission_classes = (AllowAny,)
    
    def get(self, request, token):
        """Token-based verification via URL"""
        try:
            # Hash the token to compare with stored hash
            hashed_token = hashlib.sha256(token.encode()).hexdigest()
            user = User.objects.get(verification_token=hashed_token)
            user.is_verified = True
            user.verification_token = None
            user.clear_verification_otp()  # Clear OTP as well
            user.save()
            
            logger.info(f"Account verified via token for user {user.username}")
            return Response({
                "status": "success",
                "message": "Account verified successfully.",
                "verification_method": "token"
            })
        except User.DoesNotExist:
            logger.warning(f"Invalid verification token attempted: {token[:10]}...")
            return Response({
                "status": "error",
                "message": "Invalid verification token."
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def post(self, request):
        """OTP-based verification via POST request"""
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        if not email or not otp:
            return Response({
                "status": "error",
                "message": "Email and OTP are required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            
            if user.is_verified:
                return Response({
                    "status": "success",
                    "message": "Account is already verified."
                }, status=status.HTTP_200_OK)
            
            if not user.is_verification_otp_valid():
                return Response({
                    "status": "error", 
                    "message": "OTP has expired or is invalid. Please request a new verification email."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if user.verification_otp != otp:
                return Response({
                    "status": "error",
                    "message": "Invalid OTP. Please check and try again."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify the account
            user.is_verified = True
            user.verification_token = None
            user.clear_verification_otp()
            user.save()
            
            logger.info(f"Account verified via OTP for user {user.username}")
            return Response({
                "status": "success",
                "message": "Account verified successfully.",
                "verification_method": "otp"
            })
            
        except User.DoesNotExist:
            logger.warning(f"Invalid email attempted for OTP verification: {email}")
            return Response({
                "status": "error",
                "message": "User with this email does not exist."
            }, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(APIView):
    """
    Endpoint for resending verification email
    """
    permission_classes = (AllowAny,)
    throttle_classes = [LoginRateThrottle]  # Apply rate limiting to prevent abuse
    
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            
            if user.is_verified:
                return Response({"message": "Account is already verified"}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            # Generate new verification token and OTP
            token = get_random_string(64)
            user.verification_token = hashlib.sha256(token.encode()).hexdigest()
            otp = user.generate_verification_otp()
            user.save()

            # Get the base URL components
            scheme = request.scheme
            host = request.get_host()
            base_url = f"{scheme}://{host}"
            verification_url = f"{base_url}/api/auth/verify/{token}/"
            
            email_sent = send_verification_email(user, verification_url, otp)
            
            if email_sent:
                return Response({
                    "status": "success",
                    "message": "Verification email resent successfully",
                    "verification_method": "Both OTP and Token available",
                    "otp_expires_in": "25 minutes"
                })
            else:
                logger.error(f"Failed to send verification email to {user.email}")
                return Response({
                    "status": "error",
                    "message": "Failed to send verification email"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except User.DoesNotExist:
            # Don't reveal that the user doesn't exist
            return Response({
                "status": "success",
                "message": "If your email exists in our system, you will receive a verification link and OTP"
            })


# Updated Cart views with security improvements
# Updated Cart views with multiple store support
class CartListCreateView(generics.ListCreateAPIView):
    """
    List all carts for user or create a new cart for a store
    """
    permission_classes = (IsAuthenticated,)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CartCreateSerializer
        return CartSerializer
    
    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user).order_by('-updated_at')
    
    def list(self, request, *args, **kwargs):
        """List all user carts with additional info"""
        queryset = self.get_queryset()
        serializer = CartSerializer(queryset, many=True, context={'request': request})
        
        # Add summary information
        total_carts = queryset.count()
        max_carts = Cart.get_max_carts_per_user()
        can_create_more = Cart.can_create_new_cart(request.user)
        
        return format_mobile_response(
            data={
                'carts': serializer.data,
                'summary': {
                    'total_carts': total_carts,
                    'max_carts_allowed': max_carts,
                    'can_create_more': can_create_more,
                    'remaining_slots': max_carts - total_carts if can_create_more else 0
                }
            },
            message=f"Found {total_carts} cart(s)"
        )
    
    def create(self, request, *args, **kwargs):
        """Create a new cart for a store"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            cart = serializer.save()
            response_serializer = CartSerializer(cart, context={'request': request})
            
            return format_mobile_response(
                data=response_serializer.data,
                message=f"Cart created for store: {cart.store_name or cart.store_id}"
            )
        except Exception as e:
            return format_mobile_error(
                message=str(e),
                code=400
            )


class CartDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Get, update or delete a specific cart
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CartSerializer
    
    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)
    
    def retrieve(self, request, *args, **kwargs):
        """Get specific cart details"""
        try:
            cart = self.get_object()
            serializer = self.get_serializer(cart)
            
            return format_mobile_response(
                data=serializer.data,
                message=f"Cart details for store: {cart.store_name or cart.store_id}"
            )
        except Exception as e:
            return format_mobile_error(
                message="Cart not found",
                code=404
            )
    
    def destroy(self, request, *args, **kwargs):
        """Delete a specific cart"""
        try:
            cart = self.get_object()
            store_info = cart.store_name or cart.store_id
            cart.delete()
            
            return format_mobile_response(
                data={"deleted": True},
                message=f"Cart deleted for store: {store_info}"
            )
        except Exception as e:
            return format_mobile_error(
                message="Failed to delete cart",
                code=400
            )


class CartByStoreView(APIView):
    """
    Get or create cart for a specific store
    """
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, store_id):
        """Get cart for specific store"""
        try:
            cart = Cart.objects.get(user=request.user, store_id=store_id)
            serializer = CartSerializer(cart, context={'request': request})
            
            return format_mobile_response(
                data=serializer.data,
                message=f"Cart found for store: {store_id}"
            )
        except Cart.DoesNotExist:
            return format_mobile_error(
                message=f"No cart found for store: {store_id}",
                code=404
            )
    
    def post(self, request, store_id):
        """Create cart for specific store"""
        store_name = request.data.get('store_name', '')
        
        cart, created, error_message = Cart.get_or_create_cart(
            user=request.user,
            store_id=store_id,
            store_name=store_name
        )
        
        if error_message:
            return format_mobile_error(
                message=error_message,
                code=400
            )
        
        serializer = CartSerializer(cart, context={'request': request})
        message = "Cart created" if created else "Cart already exists"
        
        return format_mobile_response(
            data=serializer.data,
            message=f"{message} for store: {store_id}"
        )


class CartItemListCreateView(generics.ListCreateAPIView):
    """
    List all items in a user's carts or add a new item to a specific store cart
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CartItemSerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return CartItem.objects.none()
        
        # Get store_id from query params to filter items by store
        store_id = self.request.query_params.get('store_id')
        
        if store_id:
            # Return items for specific store cart
            try:
                cart = Cart.objects.get(user=self.request.user, store_id=store_id)
                return CartItem.objects.filter(cart=cart)
            except Cart.DoesNotExist:
                return CartItem.objects.none()
        else:
            # Return items from all user's carts
            user_carts = Cart.objects.filter(user=self.request.user)
            return CartItem.objects.filter(cart__in=user_carts)
    
    def list(self, request, *args, **kwargs):
        """List cart items with store information"""
        queryset = self.get_queryset()
        store_id = request.query_params.get('store_id')
        
        if store_id:
            # Items for specific store
            serializer = CartItemSerializer(queryset, many=True, context={'request': request})
            try:
                cart = Cart.objects.get(user=request.user, store_id=store_id)
                return format_mobile_response(
                    data={
                        'store_id': store_id,
                        'store_name': cart.store_name,
                        'items': serializer.data
                    },
                    message=f"Cart items for store: {store_id}"
                )
            except Cart.DoesNotExist:
                return format_mobile_error(
                    message=f"No cart found for store: {store_id}",
                    code=404
                )
        else:
            # Items from all carts grouped by store
            serializer = CartItemSerializer(queryset, many=True, context={'request': request})
            
            # Group items by store
            items_by_store = {}
            for item in serializer.data:
                cart = CartItem.objects.get(id=item['id']).cart
                store_key = cart.store_id
                if store_key not in items_by_store:
                    items_by_store[store_key] = {
                        'store_id': cart.store_id,
                        'store_name': cart.store_name,
                        'items': []
                    }
                items_by_store[store_key]['items'].append(item)
            
            return format_mobile_response(
                data={
                    'stores': list(items_by_store.values()),
                    'total_items': len(serializer.data)
                },
                message=f"All cart items from {len(items_by_store)} store(s)"
            )
    
    def create(self, request, *args, **kwargs):
        """Add item to cart with store validation"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            cart_item = serializer.save()
            response_serializer = CartItemSerializer(cart_item, context={'request': request})
            
            return format_mobile_response(
                data=response_serializer.data,
                message="Item added to cart successfully"
            )
        except Exception as e:
            return format_mobile_error(
                message=str(e),
                code=400
            )


class CartItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a cart item
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CartItemSerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return CartItem.objects.none()
        
        # Return items from all user's carts
        user_carts = Cart.objects.filter(user=self.request.user)
        return CartItem.objects.filter(cart__in=user_carts)
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        # Handle quantity updates
        if 'quantity' in request.data:
            new_quantity = int(request.data['quantity'])
            
            # If quantity is 0 or negative, delete the item
            if new_quantity <= 0:
                instance.delete()
                return format_mobile_response(
                    data={"deleted": True},
                    message="Item removed from cart"
                )
                
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return format_mobile_response(
            data=serializer.data,
            message="Cart item updated successfully"
        )
    
    def destroy(self, request, *args, **kwargs):
        """Delete cart item"""
        instance = self.get_object()
        instance.delete()
        
        return format_mobile_response(
            data={"deleted": True},
            message="Item removed from cart"
        )


class ClearCartView(APIView):
    """
    Clear all items from user's carts or specific store cart
    """
    permission_classes = (IsAuthenticated,)
    
    def delete(self, request):
        store_id = request.query_params.get('store_id')
        
        if store_id:
            # Clear specific store cart
            try:
                cart = Cart.objects.get(user=request.user, store_id=store_id)
                cart.clear_cart()
                
                return format_mobile_response(
                    data={"cleared": True},
                    message=f"Cart cleared for store: {store_id}"
                )
            except Cart.DoesNotExist:
                return format_mobile_error(
                    message=f"No cart found for store: {store_id}",
                    code=404
                )
        else:
            # Clear all user carts
            user_carts = Cart.objects.filter(user=request.user)
            total_items = 0
            
            for cart in user_carts:
                total_items += cart.item_count
                cart.clear_cart()
            
            return format_mobile_response(
                data={
                    "cleared": True,
                    "total_items_removed": total_items,
                    "carts_cleared": user_carts.count()
                },
                message=f"All carts cleared. {total_items} items removed from {user_carts.count()} cart(s)"
            )


class OrderListCreateView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = OrderSerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return Order.objects.none()
        return Order.objects.filter(user=self.request.user)
    
    @transaction.atomic
    def perform_create(self, serializer):
        """
        Military-grade order creation with comprehensive security validation
        Prevents price manipulation and financial attacks
        Includes stock deduction for products
        """
        from decimal import Decimal, InvalidOperation
        
        # Get store_id from request (for multi-store support)
        store_id = self.request.data.get('store_id')
        
        # Get cart items and validate prices before creating order
        if store_id:
            cart = get_object_or_404(Cart, user=self.request.user, store_id=store_id)
        else:
            # Get the first cart with items if no store_id specified
            # Find a cart that actually has items
            user_carts = Cart.objects.filter(user=self.request.user)
            cart = None
            for potential_cart in user_carts:
                if CartItem.objects.filter(cart=potential_cart, is_saved_for_later=False).exists():
                    cart = potential_cart
                    break
            
            if not cart:
                raise serializers.ValidationError("No cart with items found. Please add items to your cart first.")
        
        cart_items = CartItem.objects.filter(cart=cart, is_saved_for_later=False)
        
        if not cart_items:
            raise serializers.ValidationError("Cannot create order with empty cart")
        
        try:
            # Military-grade calculation with null-safety and overflow protection
            subtotal = Decimal('0.00')
            discount_amount = Decimal('0.00')
            
            # Track products for stock deduction
            products_to_update = []
            
            for item in cart_items:
                # Validate each item's financial data
                if item.unit_price is None or item.quantity is None:
                    logger.critical(f"Security Alert: Null price/quantity in CartItem ID {item.id}")
                    raise serializers.ValidationError("Invalid cart item data detected")
                
                # Convert to Decimal for precision
                unit_price = Decimal(str(item.unit_price))
                quantity = int(item.quantity)
                item_discount = Decimal(str(item.discount_amount or 0))
                
                # Security validation
                if unit_price < Decimal('0.01') or quantity < 1:
                    logger.critical(f"Security Alert: Invalid price/quantity in CartItem ID {item.id}")
                    raise serializers.ValidationError("Invalid item pricing detected")
                
                if item_discount < 0:
                    logger.critical(f"Security Alert: Negative discount in CartItem ID {item.id}")
                    raise serializers.ValidationError("Invalid discount detected")
                
                # Check stock availability if product exists
                try:
                    from products.models import Product
                    product = Product.objects.get(id=item.product_id)
                    if product.is_track_stock and not product.allow_backorder:
                        if product.stock_quantity < quantity:
                            raise serializers.ValidationError(
                                f"Insufficient stock for {item.product_name}. Available: {product.stock_quantity}"
                            )
                    products_to_update.append((product, quantity))
                except Product.DoesNotExist:
                    # Product might be from external source, continue without stock check
                    pass
                except Exception as e:
                    logger.warning(f"Could not check stock for product {item.product_id}: {e}")
                
                # Overflow protection
                item_total = unit_price * quantity
                if item_total > Decimal('100000.00'):  # ₹1 Lakh per item max
                    logger.critical(f"Security Alert: Excessive item total in CartItem ID {item.id}: ₹{item_total}")
                    raise serializers.ValidationError("Item total exceeds security limits")
                
                subtotal += item_total
                discount_amount += item_discount
            
            # Final security checks
            if subtotal > Decimal('1000000.00'):  # ₹10 Lakh max order
                logger.critical(f"Security Alert: Excessive order subtotal: ₹{subtotal}")
                raise serializers.ValidationError("Order total exceeds security limits")
            
            if discount_amount > subtotal:
                logger.critical(f"Security Alert: Discount exceeds subtotal: ₹{discount_amount} > ₹{subtotal}")
                raise serializers.ValidationError("Invalid discount amount")
            
            # Calculate total amount with security validation
            server_calculated_total = subtotal - discount_amount
            
            # Military-grade client validation
            client_total = serializer.validated_data.get('total_amount')
            if client_total:
                client_total = Decimal(str(client_total))
                difference = abs(client_total - server_calculated_total)
                
                if difference > Decimal('0.01'):
                    logger.critical(
                        f"Security Alert: Price manipulation attempt - User {self.request.user.username} "
                        f"submitted ₹{client_total} but actual total is ₹{server_calculated_total}"
                    )
                    raise serializers.ValidationError({
                        "total_amount": f"Total amount mismatch. Expected: ₹{server_calculated_total}"
                    })
        
        except (InvalidOperation, ValueError) as e:
            logger.critical(f"Security Alert: Financial calculation error in order creation: {str(e)}")
            raise serializers.ValidationError("Invalid financial data detected")
        
        # Create order with server-calculated values and CREATED status
        order = serializer.save(
            user=self.request.user,
            status='CREATED',
            subtotal=subtotal,
            discount_amount=discount_amount,
            total_amount=server_calculated_total
        )
        
        # Create order items from cart items with validation
        order_items = []
        for item in cart_items:
            order_items.append(OrderItem(
                order=order,
                product_id=item.product_id,
                product_name=item.product_name,
                product_image_url=item.product_image_url,
                product_sku=item.product_sku,
                product_variant=item.product_variant,
                quantity=item.quantity,
                unit_price=item.unit_price,
                discount_amount=item.discount_amount or Decimal('0.00')
            ))
        OrderItem.objects.bulk_create(order_items)
        
        # Deduct stock from products
        for product, quantity in products_to_update:
            product.decrement_stock(quantity)
            logger.info(f"Stock decremented: {product.name} by {quantity} units")
            
        # Clear the cart after order creation if requested
        if self.request.data.get('clear_cart', True):
            cart_items.delete()
            
        logger.info(f"Secure order created: ID {order.id}, Total: ₹{server_calculated_total}")
            
        return order


class OrderDetailView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = OrderSerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return Order.objects.none()
        return Order.objects.filter(user=self.request.user)


# Updated search history views
class SearchHistoryGroupDetailView(generics.RetrieveAPIView):
    """
    Get the current user's search history group
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = SearchHistoryGroupSerializer
    def get_object(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            # Return a dummy object for schema generation
            return SearchHistoryGroup(user=None)
        # Get or create search history group for the current user
        group, created = SearchHistoryGroup.objects.get_or_create(user=self.request.user)
        return group


class SearchHistoryListCreateView(generics.ListCreateAPIView):
    """
    List all search history items or add a new search
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = SearchHistorySerializer
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return SearchHistory.objects.none()
        group, created = SearchHistoryGroup.objects.get_or_create(user=self.request.user)
        return SearchHistory.objects.filter(search_group=group).order_by('-searched_at')
    
    def perform_create(self, serializer):
        group, created = SearchHistoryGroup.objects.get_or_create(user=self.request.user)
        serializer.save(search_group=group)


class SearchHistoryDetailView(generics.RetrieveAPIView):
    """
    Retrieve a search history item
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = SearchHistorySerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return SearchHistory.objects.none()
        group = get_object_or_404(SearchHistoryGroup, user=self.request.user)
        return SearchHistory.objects.filter(search_group=group)


class SearchHistoryClearView(APIView):
    """
    Clear all search history for the current user
    """
    permission_classes = (IsAuthenticated,)
    
    def delete(self, request, *args, **kwargs):
        group = get_object_or_404(SearchHistoryGroup, user=request.user)
        SearchHistory.objects.filter(search_group=group).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Updated customer support views
class CustomerSupportTicketListCreateView(generics.ListCreateAPIView):
    """
    List all support tickets or create a new one
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomerSupportTicketSerializer
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return CustomerSupportTicket.objects.none()
        return CustomerSupportTicket.objects.filter(user=self.request.user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CustomerSupportTicketDetailView(generics.RetrieveUpdateAPIView):
    """
    Retrieve or update a support ticket
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomerSupportTicketSerializer
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return CustomerSupportTicket.objects.none()
        return CustomerSupportTicket.objects.filter(user=self.request.user)
    
    def update(self, request, *args, **kwargs):
        # Users should only be able to update status to "CLOSED"
        instance = self.get_object()
        if 'status' in request.data and request.data['status'] not in ['CLOSED']:
            return Response(
                {"detail": "You can only close tickets. Support staff will update other statuses."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().update(request, *args, **kwargs)


class CustomerChatListCreateView(generics.ListCreateAPIView):
    """
    List all chat messages for a ticket or add a new message
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomerChatSerializer
    
    def get_queryset(self):
        ticket_id = self.kwargs.get('ticket_id')
        ticket = get_object_or_404(CustomerSupportTicket, id=ticket_id, user=self.request.user)
        return CustomerChat.objects.filter(ticket=ticket).order_by('timestamp')
    
    def perform_create(self, serializer):
        ticket_id = self.kwargs.get('ticket_id')
        ticket = get_object_or_404(CustomerSupportTicket, id=ticket_id, user=self.request.user)
        
        # Set is_user_message to True for messages created by users
        serializer.save(ticket=ticket, is_user_message=True)
        
        # Update the ticket's updated_at timestamp
        ticket.updated_at = timezone.now()
        
        # If ticket is closed, reopen it
        if ticket.status == 'CLOSED':
            ticket.status = 'OPEN'
        
        ticket.save()


# Add a health check endpoint for monitoring
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint to verify API is running
    """
    from django.db import connection
    
    # Check database connection
    db_ok = True
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
            db_ok = row[0] == 1
    except Exception as e:
        db_ok = False
        logger.error(f"Database health check failed: {str(e)}")
    
    if db_ok:
        return Response({"status": "healthy"}, status=status.HTTP_200_OK)
    else:
        return Response({"status": "unhealthy", "details": "Database connection failed"}, 
                      status=status.HTTP_503_SERVICE_UNAVAILABLE)


# New payment system views
class PaymentMethodListView(generics.ListCreateAPIView):
    """Base view for payment methods"""
    permission_classes = (IsAuthenticated,)
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return self.serializer_class.Meta.model.objects.none()
        return self.serializer_class.Meta.model.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        # If setting this method as default, unset other default methods
        if serializer.validated_data.get('is_default', False):
            self.get_queryset().filter(is_default=True).update(is_default=False)
        serializer.save(user=self.request.user)

class CardPaymentMethodView(PaymentMethodListView):
    """List and create card payment methods"""
    serializer_class = CardPaymentMethodSerializer

class UPIPaymentMethodView(PaymentMethodListView):
    """List and create UPI payment methods"""
    serializer_class = UPIPaymentMethodSerializer

class PaymentMethodDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Base view for managing individual payment methods"""
    permission_classes = (IsAuthenticated,)
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return self.serializer_class.Meta.model.objects.none()
        return self.serializer_class.Meta.model.objects.filter(user=self.request.user)
    
    def perform_update(self, serializer):
        # If setting this method as default, unset other default methods
        if serializer.validated_data.get('is_default', False):
            self.get_queryset().filter(is_default=True).update(is_default=False)
        serializer.save()

class CardPaymentMethodDetailView(PaymentMethodDetailView):
    """Manage individual card payment methods"""
    serializer_class = CardPaymentMethodSerializer

class UPIPaymentMethodDetailView(PaymentMethodDetailView):
    """Manage individual UPI payment methods"""
    serializer_class = UPIPaymentMethodSerializer

class PaymentHistoryListView(generics.ListCreateAPIView):
    """List and create payment history records"""
    permission_classes = (IsAuthenticated,)
    serializer_class = PaymentHistorySerializer
    
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return PaymentHistory.objects.none()
        return PaymentHistory.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        payment = serializer.save(user=self.request.user)
        # Create initial transaction record
        PaymentTransaction.objects.create(
            payment=payment,
            action='initiate',
            status=payment.status,
            amount=payment.amount
        )

class PaymentHistoryDetailView(generics.RetrieveAPIView):
    """Retrieve payment history details"""
    permission_classes = (IsAuthenticated,)
    serializer_class = PaymentHistorySerializer
    
    def get_queryset(self):
        return PaymentHistory.objects.filter(user=self.request.user)

class PaymentTransactionCreateView(generics.CreateAPIView):
    """Create a new transaction for a payment"""
    permission_classes = (IsAuthenticated,)
    serializer_class = PaymentTransactionSerializer
    
    def perform_create(self, serializer):
        payment_id = self.kwargs.get('payment_id')
        payment = get_object_or_404(PaymentHistory, id=payment_id, user=self.request.user)
        serializer.save(payment=payment)
        
        # Update payment status based on transaction
        if serializer.validated_data['action'] == 'capture' and serializer.validated_data['status'] == 'success':
            payment.status = 'COMPLETED'
        elif serializer.validated_data['action'] == 'refund' and serializer.validated_data['status'] == 'success':
            payment.status = 'REFUNDED'
        payment.save()


@method_decorator(csrf_exempt, name='dispatch')
class InitiatePaymentView(APIView):
    """
    UNIFIED secure server-side payment initiation for Android/Mobile clients
    Supports multiple payment gateways: PAYTM, PHONEPE
    """
    permission_classes = (IsAuthenticated,)  # Require authentication
    throttle_classes = [PaymentRateThrottle]  # Enhanced rate limiting for payments
    
    def post(self, request):
        try:
            order_id = request.data.get('order_id')
            payment_method = request.data.get('payment_method', 'PAYTM')

            # Validate required parameters
            if not order_id:
                return Response({
                    'error': 'Order ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate payment method
            supported_methods = ['PAYTM', 'PHONEPE']
            if payment_method not in supported_methods:
                return Response({
                    'error': f'Payment method must be one of: {", ".join(supported_methods)}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate order exists and belongs to current user
            try:
                order = Order.objects.get(id=order_id, user=request.user)
            except Order.DoesNotExist:
                logger.warning(f"Unauthorized payment attempt: User {request.user.username} tried to pay for order {order_id}")
                return Response({
                    'error': 'Invalid order ID or unauthorized access'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Security checks
            if order.status == 'PAID':
                return Response({
                    'error': 'This order has already been paid',
                    'order_status': order.status
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if order.status == 'CANCELLED':
                return Response({
                    'error': 'Cannot pay for cancelled order',
                    'order_status': order.status
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check for any existing successful payment
            existing_payment = PaymentHistory.objects.filter(
                order=order, 
                status='COMPLETED'
            ).exists()
            
            if existing_payment:
                return Response({
                    'error': 'A successful payment already exists for this order',
                    'order_status': order.status
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Cancel any pending payments for this order to prevent double payment
            PaymentHistory.objects.filter(
                order=order, 
                status__in=['INITIATED', 'PENDING']
            ).update(status='CANCELLED')
            
            # Server-calculated amount (NEVER trust client)
            amount = float(order.total_amount)
            
            if amount <= 0:
                return Response({
                    'error': 'Invalid order amount'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate secure transaction ID with timestamp, user info, and UUID for uniqueness
            timestamp = int(time.time())
            unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for uniqueness
            security_hash = hashlib.sha256(f"{order.id}{request.user.id}{timestamp}{unique_id}".encode()).hexdigest()[:8]
            transaction_id = f"TXN_{payment_method}_{order.id}_{request.user.id}_{timestamp}_{unique_id}_{security_hash}"
            
            # Create payment record with INITIATED status
            payment = PaymentHistory.objects.create(
                user=request.user,
                amount=amount,
                status='INITIATED',
                payment_type=payment_method,
                transaction_id=transaction_id,
                order=order,
                payment_gateway_order_id=f"ORD_{payment_method}_{order.id}_{timestamp}",
                description=f"{payment_method} payment for order {order.order_number}"
            )
            
            # Generate payment token/data based on payment method
            payment_data = None
            if payment_method == 'PAYTM':
                payment_data = PaytmPayment.generate_secure_transaction_token(
                    amount=amount,
                    user_id=request.user.id,
                    order_id=payment.payment_gateway_order_id,
                    payment_id=payment.id
                )
            elif payment_method == 'PHONEPE':
                payment_data = PhonePePayment.generate_secure_transaction_token(
                    amount=amount,
                    user_id=request.user.id,
                    order_id=payment.payment_gateway_order_id,
                    payment_id=payment.id
                )
                
            if payment_data is None:
                payment.status = 'FAILED'
                payment.description = f'Failed to generate {payment_method} payment token'
                payment.save()
                return Response({
                    'error': f'Failed to generate {payment_method} payment token'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Update payment status to PENDING after successful token generation
            payment.status = 'PENDING'
            payment.save()
            
            # Create initial transaction record
            PaymentTransaction.objects.create(
                payment=payment,
                action='initiate',
                status='pending',
                amount=amount
            )
            
            # Prepare secure response for Android client
            response_data = {
                'payment_id': payment.id,
                'transaction_id': payment.transaction_id,
                'order_id': order.id,
                'amount': str(amount),
                'currency': 'INR',
                'payment_method': payment_method,
                'payment_data': payment_data,
                'expires_at': (timezone.now() + timedelta(minutes=15)).isoformat(),  # 15 min expiry
                'callback_required': True,
                'security_note': f'{payment_method} payment verification will be done server-side'
            }
            
            logger.info(f"{payment_method} payment initiated: {payment.id} for user {request.user.username}, order {order.id}, amount {amount}")
            
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error initiating payment: {str(e)}", exc_info=True)
            return Response({
                'error': 'Failed to initiate payment'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Legacy views for backward compatibility - these will redirect to the unified view
@method_decorator(csrf_exempt, name='dispatch')
class InitiatePaytmPaymentView(APIView):
    """
    DEPRECATED: Use InitiatePaymentView instead
    Legacy Paytm-specific payment initiation for backward compatibility
    """
    permission_classes = (IsAuthenticated,)
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request):
        # Add payment_method to request data if not present
        mutable_data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        mutable_data['payment_method'] = 'PAYTM'
        
        # Create new request with DRF Request
        from rest_framework.request import Request
        from django.http import HttpRequest
        
        # Create a new HttpRequest object
        new_http_request = HttpRequest()
        new_http_request.method = 'POST'
        new_http_request.user = request.user
        new_http_request.META = request.META.copy()
        
        # Create new DRF Request with modified data
        new_request = Request(new_http_request)
        new_request._full_data = mutable_data
        new_request.user = request.user
        new_request.auth = request.auth
        
        # Delegate to the unified view
        unified_view = InitiatePaymentView()
        unified_view.request = new_request
        unified_view.format_kwarg = None
        return unified_view.post(new_request)


@method_decorator(csrf_exempt, name='dispatch')
class InitiatePhonePePaymentView(APIView):
    """
    PhonePe-specific payment initiation endpoint
    """
    permission_classes = (IsAuthenticated,)
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request):
        # Add payment_method to request data
        mutable_data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        mutable_data['payment_method'] = 'PHONEPE'
        
        # Create new request with DRF Request
        from rest_framework.request import Request
        from django.http import HttpRequest
        
        # Create a new HttpRequest object
        new_http_request = HttpRequest()
        new_http_request.method = 'POST'
        new_http_request.user = request.user
        new_http_request.META = request.META.copy()
        
        # Create new DRF Request with modified data
        new_request = Request(new_http_request)
        new_request._full_data = mutable_data
        new_request.user = request.user
        new_request.auth = request.auth
        
        # Delegate to the unified view
        unified_view = InitiatePaymentView()
        unified_view.request = new_request
        unified_view.format_kwarg = None
        return unified_view.post(new_request)

@method_decorator(csrf_exempt, name='dispatch')
class PaytmCallbackView(APIView):
    permission_classes = (AllowAny,)  # Paytm needs to access this endpoint
    def post(self, request):
        try:            # Get payment details from callback
            received_data = request.POST.dict() if request.POST else request.data
            
            # Check for required parameters
            required_params = ['ORDERID', 'TXNID', 'STATUS']
            missing_params = [param for param in required_params if param not in received_data]
            
            if missing_params:
                logger.error(f"Missing required parameters in Paytm callback: {missing_params}")
                return Response({
                    'error': f"Missing required parameters: {', '.join(missing_params)}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            order_id = received_data.get('ORDERID')
            transaction_id = received_data.get('TXNID', '')
            payment_status = received_data.get('STATUS', '')
              # Find the payment record
            try:
                payment = PaymentHistory.objects.get(payment_gateway_order_id=order_id)
            except PaymentHistory.DoesNotExist:
                # If payment not found by order_id, try transaction_id
                if transaction_id:
                    try:
                        payment = PaymentHistory.objects.get(transaction_id=transaction_id)
                    except PaymentHistory.DoesNotExist:
                        return Response({
                            'error': 'Payment record not found'
                        }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({
                        'error': 'Payment record not found'
                    }, status=status.HTTP_400_BAD_REQUEST)
              # Verify payment with Paytm
            is_success, response = PaytmPayment.verify_payment(received_data)
            
            # Update payment status
            payment.status = 'COMPLETED' if is_success else 'FAILED'
            payment.transaction_id = transaction_id
            
            # Store response details for debugging
            failure_reason = None
            if not is_success and isinstance(response, dict):
                failure_reason = response.get('RESPMSG') or response.get('error')
                payment.description = f"Payment failed: {failure_reason}"
                logger.error(f"Payment {transaction_id} failed: {failure_reason}")
            
            payment.save()
            
            # Create transaction record
            PaymentTransaction.objects.create(
                payment=payment,
                action='complete',
                status='success' if is_success else 'failed',
                amount=payment.amount,
                gateway_response=received_data
            )
              # If payment successful, update order status
            if is_success and payment.order:
                # Verify the payment amount matches the order amount
                received_amount = float(received_data.get('TXNAMOUNT', '0'))
                order_amount = float(payment.order.total_amount)
                
                if abs(received_amount - order_amount) < 0.01:  # Allow for small rounding differences
                    payment.order.status = 'PAID'
                    payment.order.save()
                else:
                    # Log the amount mismatch
                    logger.error(f"Payment amount mismatch: received {received_amount}, expected {order_amount}")
                    payment.status = 'FAILED'
                    payment.save()
                    is_success = False
            
            return Response({
                'status': 'success' if is_success else 'failed',
                'payment_id': payment.id,
                'transaction_id': transaction_id,
                'order_id': order_id,
                'amount': payment.amount
            })        
        except Exception as e:
            error_message = f"Error processing Paytm callback: {str(e)}"
            logger.error(error_message)
            
            # Send notification to admin if configured
            try:
                if hasattr(settings, 'PAYMENT_ERROR_EMAIL') and settings.PAYMENT_ERROR_EMAIL:
                    send_mail(
                        subject="Payment Processing Error",
                        message=f"{error_message}\n\nPayload: {received_data if 'received_data' in locals() else 'No data'}",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[settings.PAYMENT_ERROR_EMAIL],
                        fail_silently=True
                    )
            except Exception as email_error:
                logger.error(f"Failed to send payment error notification: {str(email_error)}")
                
            return Response({
                'error': 'Failed to process payment callback'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class PhonePeCallbackView(APIView):
    """
    SECURE PhonePe payment callback handler with multi-layer verification
    """
    permission_classes = (AllowAny,)  # PhonePe needs to access this endpoint
    
    def post(self, request):
        try:
            # Get payment details from callback
            received_data = request.POST.dict() if request.POST else request.data
            
            # Log the callback for security monitoring
            logger.info(f"PhonePe callback received from IP: {self.get_client_ip(request)}")
            logger.debug(f"PhonePe callback data: {received_data}")
            
            # Validate required parameters for PhonePe
            required_params = ['response', 'checksum']
            missing_params = [param for param in required_params if param not in received_data]
            
            if missing_params:
                logger.error(f"Missing required parameters in PhonePe callback: {missing_params}")
                return Response({
                    'error': f"Missing required parameters: {', '.join(missing_params)}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Decode the response payload
            try:
                response_payload = received_data.get('response', '')
                decoded_response = base64.b64decode(response_payload).decode()
                response_data = json.loads(decoded_response)
            except Exception as e:
                logger.error(f"Failed to decode PhonePe response: {str(e)}")
                return Response({
                    'error': 'Invalid response format'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            merchant_transaction_id = response_data.get('merchantTransactionId', '')
            transaction_id = response_data.get('transactionId', '')
            payment_status = response_data.get('state', '')
            amount = response_data.get('amount', 0)
            
            # SECURITY LAYER 1: Find the payment record
            payment = None
            try:
                # Extract payment ID from merchant transaction ID
                # Format: TXN_{payment_id}_{timestamp}
                payment_id = merchant_transaction_id.split('_')[1] if '_' in merchant_transaction_id else None
                if payment_id:
                    payment = PaymentHistory.objects.get(id=payment_id, payment_type='PHONEPE')
                else:
                    raise PaymentHistory.DoesNotExist
            except (PaymentHistory.DoesNotExist, IndexError, ValueError):
                logger.error(f"Payment record not found for merchant_txn_id: {merchant_transaction_id}")
                return Response({
                    'error': 'Payment record not found'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # SECURITY LAYER 2: Anti-replay protection
            if payment.status == 'COMPLETED':
                logger.warning(f"Duplicate PhonePe callback for already completed payment {payment.id}")
                return Response({
                    'status': 'already_processed',
                    'payment_id': payment.id,
                    'message': 'Payment already processed'
                })
            
            # SECURITY LAYER 3: Cryptographic verification with PhonePe
            is_checksum_valid, checksum_response = PhonePePayment.verify_payment_checksum(received_data)
            
            if not is_checksum_valid:
                logger.error(f"PhonePe checksum verification failed for payment {payment.id}: {checksum_response}")
                payment.status = 'FAILED'
                payment.description = 'Checksum verification failed'
                payment.save()
                
                PaymentTransaction.objects.create(
                    payment=payment,
                    action='verify',
                    status='failed',
                    amount=payment.amount,
                    error_message='Checksum verification failed',
                    gateway_response=received_data
                )
                
                return Response({
                    'error': 'Payment verification failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # SECURITY LAYER 4: Independent server-side verification with PhonePe
            verification_result = PhonePePayment.verify_transaction_with_phonepe(merchant_transaction_id)
            
            if not verification_result.get('success'):
                logger.error(f"Independent PhonePe verification failed for payment {payment.id}: {verification_result}")
                payment.status = 'FAILED'
                payment.description = f"Independent verification failed: {verification_result.get('error')}"
                payment.save()
                
                PaymentTransaction.objects.create(
                    payment=payment,
                    action='verify',
                    status='failed',
                    amount=payment.amount,
                    error_message=f"Independent verification failed: {verification_result.get('error')}",
                    gateway_response=received_data
                )
                
                return Response({
                    'error': 'Payment verification failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # SECURITY LAYER 5: Amount verification (PhonePe amounts are in paise)
            phonepe_confirmed_amount = float(verification_result.get('amount', 0)) / 100  # Convert paise to rupees
            expected_amount = float(payment.amount)
            
            if abs(phonepe_confirmed_amount - expected_amount) > 0.01:  # Allow 1 paisa tolerance
                logger.error(f"Amount mismatch for PhonePe payment {payment.id}: Expected {expected_amount}, Got {phonepe_confirmed_amount}")
                payment.status = 'FAILED'
                payment.description = f"Amount mismatch: Expected {expected_amount}, Got {phonepe_confirmed_amount}"
                payment.save()
                
                PaymentTransaction.objects.create(
                    payment=payment,
                    action='verify',
                    status='failed',
                    amount=payment.amount,
                    error_message=f"Amount mismatch: Expected {expected_amount}, Got {phonepe_confirmed_amount}",
                    gateway_response=received_data
                )
                
                return Response({
                    'error': 'Payment amount verification failed'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # SECURITY LAYER 6: Final status determination
            phonepe_status = verification_result.get('status')
            is_success = (
                phonepe_status in ['COMPLETED', 'PAYMENT_SUCCESS'] and 
                payment_status in ['COMPLETED', 'PAYMENT_SUCCESS']
            )
            
            # Update payment status
            if is_success:
                payment.status = 'COMPLETED'
                payment.transaction_id = transaction_id
                payment.description = 'Payment completed successfully'
                
                # Update order status atomically
                if payment.order:
                    payment.order.status = 'PAID'
                    payment.order.paid_at = timezone.now()
                    payment.order.save()
                    
                    logger.info(f"PhonePe payment successful: {payment.id}, Order: {payment.order.id}, Amount: {payment.amount}")
                
            else:
                payment.status = 'FAILED'
                payment.description = f"Payment failed: {verification_result.get('message', 'Unknown error')}"
                logger.warning(f"PhonePe payment failed: {payment.id}, Reason: {payment.description}")
            
            payment.save()
            
            # Create final transaction record
            PaymentTransaction.objects.create(
                payment=payment,
                action='complete',
                status='success' if is_success else 'failed',
                amount=payment.amount,
                error_message=payment.description if not is_success else None,
                gateway_response=received_data
            )
            
            # Send webhook notification to admin if configured
            if not is_success:
                try:
                    if hasattr(settings, 'PAYMENT_ERROR_EMAIL') and settings.PAYMENT_ERROR_EMAIL:
                        from django.core.mail import send_mail
                        send_mail(
                            subject=f"PhonePe Payment Failed - ID: {payment.id}",
                            message=f"PhonePe Payment {payment.id} failed.\nReason: {payment.description}\nOrder: {payment.order.id if payment.order else 'N/A'}\nAmount: {payment.amount}",
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[settings.PAYMENT_ERROR_EMAIL],
                            fail_silently=True
                        )
                except Exception as e:
                    logger.error(f"Failed to send PhonePe payment failure notification: {str(e)}")
            
            return Response({
                'status': 'success' if is_success else 'failed',
                'payment_id': payment.id,
                'transaction_id': transaction_id,
                'merchant_transaction_id': merchant_transaction_id,
                'order_id': payment.order.id if payment.order else None,
                'amount': str(payment.amount),
                'message': 'Payment processed successfully' if is_success else 'Payment failed'
            })
            
        except Exception as e:
            error_message = f"Error processing PhonePe callback: {str(e)}"
            logger.error(error_message, exc_info=True)
            
            return Response({
                'error': 'Failed to process payment callback'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_client_ip(self, request):
        """Get the real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

@method_decorator(csrf_exempt, name='dispatch')
class PhonePeRedirectView(APIView):
    """
    PhonePe redirect handler for payment completion
    """
    permission_classes = (AllowAny,)
    
    def post(self, request):
        """Handle POST redirect from PhonePe"""
        return self.handle_redirect(request)
    
    def get(self, request):
        """Handle GET redirect from PhonePe"""
        return self.handle_redirect(request)
    
    def handle_redirect(self, request):
        """Common redirect handling logic"""
        try:
            # Extract merchant transaction ID from request
            merchant_transaction_id = request.GET.get('id') or request.POST.get('id')
            
            if not merchant_transaction_id:
                logger.error("No merchant transaction ID found in PhonePe redirect")
                return Response({
                    'status': 'error',
                    'message': 'Invalid redirect parameters'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Find the payment record
            try:
                payment_id = merchant_transaction_id.split('_')[1] if '_' in merchant_transaction_id else None
                if payment_id:
                    payment = PaymentHistory.objects.get(id=payment_id, payment_type='PHONEPE')
                else:
                    raise PaymentHistory.DoesNotExist
            except (PaymentHistory.DoesNotExist, IndexError, ValueError):
                logger.error(f"Payment record not found for redirect merchant_txn_id: {merchant_transaction_id}")
                return Response({
                    'status': 'error',
                    'message': 'Payment record not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check current payment status
            verification_result = PhonePePayment.verify_transaction_with_phonepe(merchant_transaction_id)
            
            response_data = {
                'status': 'success' if verification_result.get('success') else 'failed',
                'payment_id': payment.id,
                'merchant_transaction_id': merchant_transaction_id,
                'order_id': payment.order.id if payment.order else None,
                'amount': str(payment.amount),
                'payment_status': payment.status,
                'message': 'Payment redirect processed successfully'
            }
            
            logger.info(f"PhonePe redirect processed for payment {payment.id}")
            return Response(response_data)
            
        except Exception as e:
            error_message = f"Error processing PhonePe redirect: {str(e)}"
            logger.error(error_message, exc_info=True)
            
            return Response({
                'status': 'error',
                'message': 'Failed to process redirect'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CheckPaymentStatusView(APIView):
    """
    SECURE endpoint for Android app to check payment status
    """
    permission_classes = (IsAuthenticated,)
    throttle_classes = [LoginRateThrottle]
    
    def get(self, request, payment_id):
        try:
            # Ensure user can only check their own payments
            try:
                payment = PaymentHistory.objects.get(id=payment_id, user=request.user)
            except PaymentHistory.DoesNotExist:
                return Response({
                    'error': 'Payment not found or unauthorized access'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Get latest transactions for this payment
            transactions = PaymentTransaction.objects.filter(
                payment=payment
            ).order_by('-created_at')[:5]
            
            transaction_data = []
            for txn in transactions:
                transaction_data.append({
                    'action': txn.action,
                    'status': txn.status,
                    'created_at': txn.created_at,
                    'description': txn.description
                })
            
            # Prepare response
            response_data = {
                'payment_id': payment.id,
                'transaction_id': payment.transaction_id,
                'status': payment.status,
                'amount': str(payment.amount),
                'payment_type': payment.payment_type,
                'created_at': payment.created_at,
                'updated_at': payment.updated_at,
                'description': payment.description,
                'order': {
                    'id': payment.order.id,
                    'order_number': payment.order.order_number,
                    'status': payment.order.status,
                    'total_amount': str(payment.order.total_amount)
                } if payment.order else None,
                'transactions': transaction_data,
                'is_completed': payment.status == 'COMPLETED',
                'is_failed': payment.status in ['FAILED', 'CANCELLED']
            }
            
            return Response(response_data)
            
        except Exception as e:
            logger.error(f"Error checking payment status: {str(e)}")
            return Response({
                'error': 'Failed to check payment status'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CheckPaytmTransactionStatusView(APIView):
    """
    Admin endpoint to check Paytm transaction status (requires staff access)
    """
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, order_id):
        # Only allow staff/admin users to use this endpoint
        if not request.user.is_staff:
            return Response({
                'error': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)
            
        try:
            response = PaytmPayment.check_transaction_status(order_id)
            return Response(response)
        except Exception as e:
            logger.error(f"Error checking transaction status: {str(e)}")
            return Response({
                'error': 'Failed to check transaction status'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CheckPhonePeTransactionStatusView(APIView):
    """
    Admin endpoint to check PhonePe transaction status (requires staff access)
    """
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, order_id):
        # Only allow staff/admin users to use this endpoint
        if not request.user.is_staff:
            return Response({
                'error': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)
            
        try:
            response = PhonePePayment.check_transaction_status(order_id)
            return Response(response)
        except Exception as e:
            logger.error(f"Error checking PhonePe transaction status: {str(e)}")
            return Response({
                'error': 'Failed to check PhonePe transaction status'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Address Management Views
class UserAddressListCreateView(generics.ListCreateAPIView):
    """
    List all addresses for the authenticated user or create a new address
    """
    serializer_class = UserAddressSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return UserAddress.objects.none()
        return UserAddress.objects.filter(user=self.request.user).order_by('-is_default', '-created_at')
    
    def perform_create(self, serializer):
        # If this is set as default, remove default from other addresses
        if serializer.validated_data.get('is_default', False):
            UserAddress.objects.filter(user=self.request.user, is_default=True).update(is_default=False)
        serializer.save(user=self.request.user)
        
        return format_mobile_response({
            'status': 'success',
            'message': 'Address created successfully',
            'data': serializer.data
        })

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error fetching user addresses: {str(e)}")
            return format_mobile_error('Failed to fetch addresses')

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            
            return format_mobile_response({
                'status': 'success',
                'message': 'Address created successfully',
                'data': serializer.data
            })
        except Exception as e:
            logger.error(f"Error creating address: {str(e)}")
            return format_mobile_error('Failed to create address')


class UserAddressDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a specific address for the authenticated user
    """
    serializer_class = UserAddressSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        # Handle schema generation when user is anonymous
        if not self.request.user.is_authenticated:
            return UserAddress.objects.none()
        return UserAddress.objects.filter(user=self.request.user)
    
    def perform_update(self, serializer):
        # If this is set as default, remove default from other addresses
        if serializer.validated_data.get('is_default', False):
            UserAddress.objects.filter(user=self.request.user, is_default=True).exclude(
                id=self.get_object().id
            ).update(is_default=False)
        serializer.save()

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            
            return format_mobile_response({
                'status': 'success',
                'data': serializer.data
            })
        except UserAddress.DoesNotExist:
            return format_mobile_error('Address not found')
        except Exception as e:
            logger.error(f"Error fetching address: {str(e)}")
            return format_mobile_error('Failed to fetch address')

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            return format_mobile_response({
                'status': 'success',
                'message': 'Address updated successfully',
                'data': serializer.data
            })
        except UserAddress.DoesNotExist:
            return format_mobile_error('Address not found')
        except Exception as e:
            logger.error(f"Error updating address: {str(e)}")
            return format_mobile_error('Failed to update address')

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            
            # If this was the default address, set another address as default
            if instance.is_default:
                other_address = UserAddress.objects.filter(
                    user=self.request.user
                ).exclude(id=instance.id).first()
                if other_address:
                    other_address.is_default = True
                    other_address.save()
            
            instance.delete()
            
            return format_mobile_response({
                'status': 'success',
                'message': 'Address deleted successfully'
            })
        except UserAddress.DoesNotExist:
            return format_mobile_error('Address not found')
        except Exception as e:
            logger.error(f"Error deleting address: {str(e)}")
            return format_mobile_error('Failed to delete address')


class SetDefaultAddressView(APIView):
    """
    Set a specific address as the default address for the user
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        try:
            # Get the address to set as default
            address = get_object_or_404(UserAddress, pk=pk, user=request.user)
            
            # Remove default from all other addresses
            UserAddress.objects.filter(user=request.user, is_default=True).update(is_default=False)
            
            # Set this address as default
            address.is_default = True
            address.save()
            
            serializer = UserAddressSerializer(address)
            
            return format_mobile_response({
                'status': 'success',
                'message': 'Default address updated successfully',
                'data': serializer.data
            })
        except UserAddress.DoesNotExist:
            return format_mobile_error('Address not found')
        except Exception as e:
            logger.error(f"Error setting default address: {str(e)}")
            return format_mobile_error('Failed to set default address')


class GetDefaultAddressView(generics.RetrieveAPIView):
    """
    Get the default address for the authenticated user
    """
    serializer_class = UserAddressSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        try:
            return UserAddress.objects.get(user=self.request.user, is_default=True)
        except UserAddress.DoesNotExist:
            # If no default address, return the first address
            return UserAddress.objects.filter(user=self.request.user).first()
    
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            if not instance:
                return format_mobile_response({
                    'status': 'success',
                    'message': 'No addresses found',
                    'data': None
                })
            
            serializer = self.get_serializer(instance)
            return format_mobile_response({
                'status': 'success',
                'data': serializer.data
            })
        except Exception as e:
            logger.error(f"Error fetching default address: {str(e)}")
            return format_mobile_error('Failed to fetch default address')


# JWT Authentication Views
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT login view with device tracking and enhanced functionality
    """
    serializer_class = CustomTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.user
            
            # Check if account is locked
            if user.is_locked:
                if user.locked_until and user.locked_until > timezone.now():
                    lock_time_remaining = int((user.locked_until - timezone.now()).total_seconds() / 60)
                    return Response({
                        "error": f"Account is temporarily locked due to multiple failed login attempts. Try again in {lock_time_remaining} minutes."
                    }, status=status.HTTP_403_FORBIDDEN)
                else:
                    # If lock time has passed, unlock the account
                    user.is_locked = False
                    user.locked_until = None
                    user.save()
            
            # Check if account is verified
            if not user.is_verified:
                return Response({
                    "error": "Email not verified. Please check your email for verification instructions.",
                    "needs_verification": True
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Cleanup expired sessions before creating new ones
            JWTSession.cleanup_expired_sessions()
            
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.save(update_fields=['failed_login_attempts'])
            
            # Get device information with sanitization
            device_type = request.data.get('device_type', 'API')
            device_id = request.data.get('device_id')
            user_agent = request.META.get('HTTP_USER_AGENT')
            ip_address = self.get_client_ip(request)
            
            # Sanitize and validate inputs
            if device_id:
                device_id = device_id[:255]  # Limit length
            if user_agent:
                user_agent = user_agent[:500]  # Limit length
            
            # Get the JWT token data
            response_data = serializer.validated_data
            access_token = response_data.get('access')
            
            # Extract JTI from the access token for session tracking
            if access_token:
                try:
                    from rest_framework_simplejwt.tokens import AccessToken
                    from datetime import datetime
                    token = AccessToken(access_token)
                    jti = token.payload.get('jti')
                    exp_timestamp = token.payload.get('exp')
                    
                    if not jti or not exp_timestamp:
                        raise ValueError("Missing JTI or expiration in token payload")
                    
                    expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.get_current_timezone())
                    
                    # Validate that token is not expired
                    if expires_at <= timezone.now():
                        raise ValueError("Token is already expired")
                    
                    # Create JWT session record
                    session = create_or_update_jwt_session(
                        user=user,
                        jti=jti,
                        device_type=device_type,
                        device_id=device_id,
                        user_agent=user_agent,
                        ip_address=ip_address,
                        expires_at=expires_at
                    )
                    
                    if session:
                        logger.info(f"✅ JWT session created successfully with JTI: {jti}")
                    else:
                        logger.error(f"❌ Failed to create JWT session for JTI: {jti}")
                        
                except Exception as session_error:
                    logger.error(f"❌ CRITICAL: Error creating JWT session: {str(session_error)}", exc_info=True)
                    # Don't fail the login, but log the error for monitoring
            
            # Add user data to response
            response_data['user'] = UserSerializer(user).data
            response_data['device_type'] = device_type
            response_data['device_id'] = device_id
            
            # Log successful login
            logger.info(f"Successful JWT login for user {user.username} from {device_type} device (IP: {ip_address})")
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            # Handle failed login attempts
            username = request.data.get('username')
            email = request.data.get('email')
            
            try:
                if email:
                    user = User.objects.get(email=email)
                elif username:
                    user = User.objects.get(username=username)
                else:
                    return Response({
                        "error": "Username or email is required."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                user.failed_login_attempts += 1
                user.last_failed_login = timezone.now()
                
                # Check if account should be locked
                max_attempts = getattr(settings, 'MAX_FAILED_LOGIN_ATTEMPTS', 5)
                if user.failed_login_attempts >= max_attempts:
                    lock_minutes = getattr(settings, 'ACCOUNT_LOCKOUT_MINUTES', 30)
                    user.lock_account(minutes=lock_minutes)
                    logger.warning(f"Account locked for user {user.username} due to {user.failed_login_attempts} failed login attempts")
                else:
                    user.save(update_fields=['failed_login_attempts', 'last_failed_login'])
                    
                # Log failed login attempt
                logger.warning(f"Failed JWT login attempt #{user.failed_login_attempts} for user {user.username} from IP {self.get_client_ip(request)}")
                    
            except User.DoesNotExist:
                # Don't provide detailed feedback about whether username or password was wrong
                pass
                
            return Response({
                "error": "Unable to log in with provided credentials."
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom JWT refresh view with enhanced functionality
    """
    serializer_class = JWTRefreshSerializer
    
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            
            # Log token refresh
            if hasattr(request, 'user') and request.user.is_authenticated:
                logger.info(f"JWT token refreshed for user {request.user.username}")
            
            return response
        except TokenError as e:
            logger.warning(f"JWT token refresh failed: {str(e)}")
            return Response({
                "error": "Token is invalid or expired",
                "detail": str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)


class JWTLogoutView(APIView):
    """
    JWT logout view with token blacklisting
    """
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)
    
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            logout_type = request.data.get('logout_type', 'current')
            device_type = request.data.get('device_type')
            
            if logout_type == 'all':
                # Blacklist all refresh tokens for the user (if using token blacklist)
                # For now, just clean up session tracking
                count = ExpiringToken.objects.filter(user=request.user).count()
                ExpiringToken.objects.filter(user=request.user).delete()
                
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                
                return Response({
                    "message": f"Successfully logged out from all {count} sessions."
                }, status=status.HTTP_200_OK)
                
            elif logout_type == 'device_type' and device_type:
                # Logout from specific device type
                count = ExpiringToken.objects.filter(user=request.user, device_type=device_type).count()
                ExpiringToken.objects.filter(user=request.user, device_type=device_type).delete()
                
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                
                return Response({
                    "message": f"Successfully logged out from {count} {device_type} sessions."
                }, status=status.HTTP_200_OK)
            else:
                # Logout from current session only
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    
                    # Also clean up session tracking
                    ExpiringToken.objects.filter(user=request.user, key=str(token.access_token)).delete()
                    
                    return Response({
                        "message": "Successfully logged out from current session."
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "error": "Refresh token is required for logout."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
        except TokenError as e:
            return Response({
                "error": "Invalid token",
                "detail": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during JWT logout for user {request.user.username}: {str(e)}")
            return Response({
                "error": "An error occurred during logout."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JWTUserSessionsView(APIView):
    """
    View to manage user JWT sessions across devices
    """
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)
    
    def get(self, request):
        """List all active sessions for the user"""
        try:
            # Get all active tokens for the user
            tokens = ExpiringToken.objects.filter(user=request.user).order_by('-created_at')
            
            # Get current session info for comparison
            current_device_id = None
            if hasattr(request, 'auth') and request.auth and hasattr(request.auth, 'get'):
                current_device_id = request.auth.get('device_id')
            
            sessions = []
            for token in tokens:
                is_current_session = (current_device_id and token.device_id == current_device_id)
                
                session_data = {
                    'id': token.key,
                    'device_type': token.device_type,
                    'device_id': token.device_id,
                    'user_agent': token.user_agent,
                    'ip_address': token.ip_address,
                    'created_at': token.created_at.isoformat() if token.created_at else None,
                    'last_activity': token.last_used.isoformat() if token.last_used else token.created_at.isoformat(),
                    'is_current_session': is_current_session,
                    'expires_at': token.expiry.isoformat() if token.expiry else None
                }
                sessions.append(session_data)
            
            return format_mobile_response(
                data=sessions,
                message=f"Found {len(sessions)} active sessions"
            )
            
        except Exception as e:
            logger.error(f"Error fetching JWT user sessions: {str(e)}", exc_info=True)
            return format_mobile_error(
                message="Failed to fetch sessions",
                code=500
            )
    
    def delete(self, request, session_id=None):
        """Terminate a specific session"""
        try:
            if not session_id:
                return format_mobile_error(
                    message="Session ID is required",
                    code=400
                )
            
            try:
                token = ExpiringToken.objects.get(key=session_id, user=request.user)
            except ExpiringToken.DoesNotExist:
                return format_mobile_error(
                    message="Session not found",
                    code=404
                )
            
            device_type = token.device_type
            device_id = token.device_id
            
            # Check if this is the current session
            current_device_id = None
            if hasattr(request, 'auth') and request.auth and hasattr(request.auth, 'get'):
                current_device_id = request.auth.get('device_id')
            
            if current_device_id and token.device_id == current_device_id:
                return format_mobile_error(
                    message="Cannot terminate current session. Use logout endpoint instead.",
                    code=400
                )
            
            token.delete()
            
            return format_mobile_response(
                data={
                    "terminated_session": {
                        "device_type": device_type,
                        "device_id": device_id,
                        "session_id": session_id
                    }
                },
                message=f"Successfully terminated {device_type} session"
            )
            
        except Exception as e:
            logger.error(f"Error terminating JWT session {session_id}: {str(e)}", exc_info=True)
            return format_mobile_error(
                message="Failed to terminate session",
                code=500
            )

