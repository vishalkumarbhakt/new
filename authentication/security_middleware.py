"""
Military-grade security middleware for enhanced protection
"""
import time
import logging
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from collections import defaultdict

logger = logging.getLogger(__name__)

class IPThrottlingMiddleware:
    """
    Advanced IP-based throttling and blocking middleware
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.failed_attempts = defaultdict(int)
        self.blocked_ips = set()
        
    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        
        # Check if IP is permanently blocked
        if self.is_ip_blocked(client_ip):
            logger.warning(f"Blocked IP {client_ip} attempted access")
            return JsonResponse({
                'error': 'Access denied',
                'code': 403
            }, status=403)
        
        # Check for excessive requests from IP
        if self.check_ip_rate_limit(client_ip):
            logger.warning(f"IP {client_ip} exceeded rate limit")
            return JsonResponse({
                'error': 'Too many requests',
                'code': 429
            }, status=429)
        
        response = self.get_response(request)
        
        # Monitor failed login attempts
        if (response.status_code in [400, 401, 403] and 
            request.path in ['/api/auth/login/', '/api/token/']):
            self.record_failed_attempt(client_ip)
        
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def check_ip_rate_limit(self, ip):
        """Check if IP has exceeded rate limits"""
        cache_key = f"ip_requests_{ip}"
        current_time = int(time.time())
        window_start = current_time - 60  # 1 minute window
        
        # Get existing requests
        requests = cache.get(cache_key, [])
        
        # Filter requests within the window
        recent_requests = [req for req in requests if req > window_start]
        
        # Check if limit exceeded
        if len(recent_requests) >= 100:  # 100 requests per minute
            return True
        
        # Add current request
        recent_requests.append(current_time)
        cache.set(cache_key, recent_requests, 60)
        
        return False
    
    def record_failed_attempt(self, ip):
        """Record failed login attempt for IP"""
        cache_key = f"failed_attempts_{ip}"
        attempts = cache.get(cache_key, 0) + 1
        cache.set(cache_key, attempts, 300)  # 5 minutes
        
        # Block IP if too many failed attempts
        if attempts >= getattr(settings, 'IP_BASED_LOCKOUT_THRESHOLD', 10):
            self.block_ip(ip)
            logger.critical(f"IP {ip} blocked due to {attempts} failed login attempts")
            self.send_ip_blocked_email(ip, attempts)
    
    def block_ip(self, ip):
        """Temporarily block an IP"""
        cache_key = f"blocked_ip_{ip}"
        cache.set(cache_key, True, getattr(settings, 'IP_LOCKOUT_DURATION', 300))
        self.blocked_ips.add(ip)
    
    def is_ip_blocked(self, ip):
        """Check if IP is currently blocked"""
        cache_key = f"blocked_ip_{ip}"
        return cache.get(cache_key, False)
    
    def send_ip_blocked_email(self, ip, attempts):
        """Send email notification when IP is blocked"""
        try:
            subject = f"🚨 [SECURITY ALERT] IP Address Blocked - S2Cart API"
            
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    .security-alert {{
                        max-width: 600px;
                        margin: 0 auto;
                        font-family: Arial, sans-serif;
                        background-color: #f8f9fa;
                        border: 2px solid #dc3545;
                        border-radius: 10px;
                        overflow: hidden;
                    }}
                    .alert-header {{
                        background: linear-gradient(135deg, #dc3545, #c82333);
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .alert-icon {{
                        font-size: 48px;
                        margin-bottom: 10px;
                    }}
                    .alert-title {{
                        font-size: 24px;
                        font-weight: bold;
                        margin: 0;
                    }}
                    .alert-body {{
                        padding: 30px;
                        background-color: white;
                    }}
                    .alert-section {{
                        margin-bottom: 20px;
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-left: 4px solid #dc3545;
                        border-radius: 5px;
                    }}
                    .alert-label {{
                        font-weight: bold;
                        color: #dc3545;
                        display: inline-block;
                        width: 150px;
                    }}
                    .alert-value {{
                        color: #333;
                        font-family: monospace;
                        background-color: #e9ecef;
                        padding: 2px 6px;
                        border-radius: 3px;
                    }}
                    .action-required {{
                        background-color: #fff3cd;
                        border: 1px solid #ffeaa7;
                        border-radius: 5px;
                        padding: 15px;
                        margin-top: 20px;
                    }}
                    .action-title {{
                        color: #856404;
                        font-weight: bold;
                        margin-bottom: 10px;
                    }}
                    .action-list {{
                        color: #856404;
                        margin: 0;
                        padding-left: 20px;
                    }}
                    .footer {{
                        background-color: #343a40;
                        color: white;
                        text-align: center;
                        padding: 15px;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="security-alert">
                    <div class="alert-header">
                        <div class="alert-icon">🚨</div>
                        <h1 class="alert-title">SECURITY ALERT</h1>
                        <p>IP Address Automatically Blocked</p>
                    </div>
                    
                    <div class="alert-body">
                        <div class="alert-section">
                            <div><span class="alert-label">Time:</span> <span class="alert-value">{timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</span></div>
                            <div><span class="alert-label">IP Address:</span> <span class="alert-value">{ip}</span></div>
                            <div><span class="alert-label">Failed Attempts:</span> <span class="alert-value">{attempts}</span></div>
                            <div><span class="alert-label">Block Duration:</span> <span class="alert-value">{getattr(settings, 'IP_LOCKOUT_DURATION', 300)} seconds</span></div>
                        </div>
                        
                        <p><strong>Description:</strong> This IP address has been temporarily blocked due to excessive failed login attempts. The security system has automatically implemented protective measures.</p>
                        
                        <div class="action-required">
                            <div class="action-title">⚠️ Action Required:</div>
                            <ul class="action-list">
                                <li>Monitor this IP for continued suspicious activity</li>
                                <li>Consider permanent blocking if attacks persist</li>
                                <li>Review authentication logs for pattern analysis</li>
                                <li>Check for coordinated attacks from multiple IPs</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="footer">
                        S2Cart Security System - Automated Protection Active
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Plain text fallback
            text_message = f"""
            SECURITY ALERT: IP address has been automatically blocked

            Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}
            IP Address: {ip}
            Failed Login Attempts: {attempts}
            Block Duration: {getattr(settings, 'IP_LOCKOUT_DURATION', 300)} seconds

            This IP has been temporarily blocked due to excessive failed login attempts.

            Action Required:
            - Monitor this IP for continued suspicious activity
            - Consider permanent blocking if attacks persist
            - Review authentication logs for pattern analysis

            ---
            S2Cart Security System
            """
            
            admin_email = getattr(settings, 'ADMIN_EMAIL', None)
            if admin_email:
                from django.core.mail import EmailMultiAlternatives
                
                msg = EmailMultiAlternatives(
                    subject,
                    text_message,
                    settings.DEFAULT_FROM_EMAIL,
                    [admin_email]
                )
                msg.attach_alternative(html_message, "text/html")
                msg.send(fail_silently=True)
                
                logger.info(f"IP blocking alert email sent to {admin_email}")
            else:
                logger.warning("ADMIN_EMAIL not configured - IP blocking alert email not sent")
                
        except Exception as e:
            logger.error(f"Failed to send IP blocking alert email: {str(e)}")


class SecurityAuditMiddleware:
    """
    Security audit and monitoring middleware
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # More targeted suspicious patterns to avoid false positives
        self.suspicious_patterns = [
            # SQL injection patterns
            'union select', 'union all select', 'drop table', 'drop database',
            'insert into', 'update set', 'delete from',
            # XSS patterns
            '<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
            # Path traversal
            '../', '..\\', '/etc/passwd', '/proc/', 'cmd.exe',
            # Code injection
            'powershell', 'eval(', 'exec(', '__import__',
        ]
        # Paths to exclude from suspicious pattern checking (like admin)
        self.excluded_paths = [
            '/admin/',
        ]
    
    def __call__(self, request):
        # Log sensitive operations
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            self.log_sensitive_operation(request)
        
        # Skip suspicious pattern checking for admin paths
        if self.is_excluded_path(request.path):
            logger.debug(f"Skipping security checks for admin path: {request.path}")
            return self.get_response(request)
        
        # Check for suspicious patterns
        if self.contains_suspicious_patterns(request):
            logger.critical(f"Suspicious request detected from {self.get_client_ip(request)}: {request.get_full_path()}")
            self.send_security_alert_email(request)
            return JsonResponse({
                'error': 'Request rejected',
                'code': 400
            }, status=400)
        
        response = self.get_response(request)
        
        # Log failed authentication attempts
        if response.status_code in [401, 403]:
            logger.warning(f"Authentication failure from {self.get_client_ip(request)}: {request.get_full_path()}")
        
        return response
    
    def is_excluded_path(self, path):
        """Check if path should be excluded from security checks"""
        return any(path.startswith(excluded) for excluded in self.excluded_paths)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def log_sensitive_operation(self, request):
        """Log sensitive operations for audit"""
        logger.info(f"Sensitive operation: {request.method} {request.get_full_path()} from {self.get_client_ip(request)}")
    
    def contains_suspicious_patterns(self, request):
        """Check for suspicious patterns in request"""
        # Check query parameters
        for key, value in request.GET.items():
            if any(pattern in str(value).lower() for pattern in self.suspicious_patterns):
                return True
        
        # Check POST data
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if any(pattern in str(value).lower() for pattern in self.suspicious_patterns):
                    return True
        
        # Check headers
        for header, value in request.META.items():
            if header.startswith('HTTP_') and value:
                if any(pattern in str(value).lower() for pattern in self.suspicious_patterns):
                    return True
        
        return False
    
    def send_security_alert_email(self, request):
        """Send security alert email to admin"""
        try:
            client_ip = self.get_client_ip(request)
            subject = f"⚠️ [SECURITY ALERT] Suspicious Activity Detected - S2Cart API"
            
            # Get request details
            user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
            referer = request.META.get('HTTP_REFERER', 'Unknown')
            get_params = dict(request.GET) if request.GET else 'None'
            post_data = dict(request.POST) if hasattr(request, 'POST') and request.POST else 'None'
            
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    .security-alert {{
                        max-width: 700px;
                        margin: 0 auto;
                        font-family: Arial, sans-serif;
                        background-color: #f8f9fa;
                        border: 2px solid #fd7e14;
                        border-radius: 10px;
                        overflow: hidden;
                    }}
                    .alert-header {{
                        background: linear-gradient(135deg, #fd7e14, #e86c00);
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .alert-icon {{
                        font-size: 48px;
                        margin-bottom: 10px;
                    }}
                    .alert-title {{
                        font-size: 24px;
                        font-weight: bold;
                        margin: 0;
                    }}
                    .alert-body {{
                        padding: 30px;
                        background-color: white;
                    }}
                    .alert-section {{
                        margin-bottom: 20px;
                        padding: 15px;
                        background-color: #f8f9fa;
                        border-left: 4px solid #fd7e14;
                        border-radius: 5px;
                    }}
                    .section-title {{
                        font-weight: bold;
                        color: #fd7e14;
                        margin-bottom: 10px;
                        font-size: 16px;
                    }}
                    .alert-label {{
                        font-weight: bold;
                        color: #fd7e14;
                        display: inline-block;
                        width: 130px;
                    }}
                    .alert-value {{
                        color: #333;
                        font-family: monospace;
                        background-color: #e9ecef;
                        padding: 2px 6px;
                        border-radius: 3px;
                        word-break: break-all;
                    }}
                    .request-data {{
                        background-color: #fff3cd;
                        padding: 10px;
                        border-radius: 5px;
                        margin: 10px 0;
                        border: 1px solid #ffeaa7;
                    }}
                    .code-block {{
                        background-color: #f8f9fa;
                        padding: 10px;
                        border-radius: 3px;
                        font-family: monospace;
                        font-size: 12px;
                        border: 1px solid #dee2e6;
                        white-space: pre-wrap;
                        word-break: break-all;
                    }}
                    .warning-box {{
                        background-color: #f8d7da;
                        border: 1px solid #f5c6cb;
                        border-radius: 5px;
                        padding: 15px;
                        margin-top: 20px;
                    }}
                    .warning-title {{
                        color: #721c24;
                        font-weight: bold;
                        margin-bottom: 10px;
                    }}
                    .footer {{
                        background-color: #343a40;
                        color: white;
                        text-align: center;
                        padding: 15px;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="security-alert">
                    <div class="alert-header">
                        <div class="alert-icon">⚠️</div>
                        <h1 class="alert-title">SUSPICIOUS ACTIVITY DETECTED</h1>
                        <p>Potential Security Threat Blocked</p>
                    </div>
                    
                    <div class="alert-body">
                        <div class="alert-section">
                            <div class="section-title">🕒 Incident Details</div>
                            <div><span class="alert-label">Time:</span> <span class="alert-value">{timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</span></div>
                            <div><span class="alert-label">IP Address:</span> <span class="alert-value">{client_ip}</span></div>
                            <div><span class="alert-label">Request Path:</span> <span class="alert-value">{request.get_full_path()}</span></div>
                            <div><span class="alert-label">HTTP Method:</span> <span class="alert-value">{request.method}</span></div>
                            <div><span class="alert-label">User Agent:</span> <span class="alert-value">{user_agent}</span></div>
                            <div><span class="alert-label">Referer:</span> <span class="alert-value">{referer}</span></div>
                        </div>
                        
                        <div class="alert-section">
                            <div class="section-title">📋 Request Data</div>
                            <div class="request-data">
                                <strong>GET Parameters:</strong>
                                <div class="code-block">{get_params}</div>
                            </div>
                            <div class="request-data">
                                <strong>POST Data:</strong>
                                <div class="code-block">{post_data}</div>
                            </div>
                        </div>
                        
                        <div class="warning-box">
                            <div class="warning-title">🚨 IMMEDIATE ACTION REQUIRED</div>
                            <p><strong>This request was automatically blocked by the security system due to suspicious patterns.</strong></p>
                            <p>Please investigate this activity immediately and consider:</p>
                            <ul>
                                <li>Analyzing the request patterns for potential attacks</li>
                                <li>Checking if this IP should be permanently blocked</li>
                                <li>Reviewing system logs for coordinated attacks</li>
                                <li>Updating security rules if necessary</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="footer">
                        S2Cart Security System - Real-time Threat Detection Active
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Plain text fallback
            text_message = f"""
            SECURITY ALERT: Suspicious activity detected on S2Cart API

            Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}
            IP Address: {client_ip}
            Request Path: {request.get_full_path()}
            HTTP Method: {request.method}
            User Agent: {user_agent}
            Referer: {referer}

            Request Details:
            - GET Parameters: {get_params}
            - POST Data: {post_data}

            This request was automatically blocked by the security system.

            Please investigate this activity immediately.

            ---
            S2Cart Security System
            """
            
            admin_email = getattr(settings, 'SERVER_EMAIL', None)
            if admin_email:
                from django.core.mail import EmailMultiAlternatives
                
                msg = EmailMultiAlternatives(
                    subject,
                    text_message,
                    settings.DEFAULT_FROM_EMAIL,
                    [admin_email]
                )
                msg.attach_alternative(html_message, "text/html")
                msg.send(fail_silently=True)
                
                logger.info(f"Security alert email sent to {admin_email}")
            else:
                logger.warning("ADMIN_EMAIL not configured - security alert email not sent")
                
        except Exception as e:
            logger.error(f"Failed to send security alert email: {str(e)}")


class SessionSecurityMiddleware:
    """
    Enhanced session security middleware
    """
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check for session hijacking indicators
        if hasattr(request, 'user') and request.user.is_authenticated:
            self.validate_session_security(request)
        
        response = self.get_response(request)
        
        # Add session security headers
        if hasattr(request, 'user') and request.user.is_authenticated:
            response['X-Session-Valid'] = 'true'
            response['X-User-ID'] = str(request.user.id)
        
        return response
    
    def validate_session_security(self, request):
        """Validate session security indicators"""
        # Check for unusual user agent changes (simplified)
        session_ua = request.session.get('user_agent')
        current_ua = request.META.get('HTTP_USER_AGENT', '')
        
        if session_ua and session_ua != current_ua:
            logger.warning(f"User agent change detected for user {request.user.id}")
        
        # Update session user agent
        request.session['user_agent'] = current_ua
