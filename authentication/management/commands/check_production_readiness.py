import os
import socket
import sys
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db import connections
from django.core.mail import send_mail

class Command(BaseCommand):
    help = 'Validates that the production environment is properly configured'

    def add_arguments(self, parser):
        parser.add_argument(
            '--check-mail',
            action='store_true',
            help='Send a test email to verify email configuration',
        )
        parser.add_argument(
            '--check-db',
            action='store_true',
            help='Verify database connection and credentials',
        )
        parser.add_argument(
            '--check-https',
            action='store_true',
            help='Check SSL/HTTPS settings',
        )
        parser.add_argument(
            '--check-all',
            action='store_true',
            help='Run all checks',
        )

    def print_success(self, message):
        """Print success message in green"""
        self.stdout.write(self.style.SUCCESS(f"✓ {message}"))
    
    def print_warning(self, message):
        """Print warning message in yellow"""
        self.stdout.write(self.style.WARNING(f"⚠️ {message}"))
    
    def print_error(self, message):
        """Print error message in red"""
        self.stdout.write(self.style.ERROR(f"❌ {message}"))
    
    def print_section(self, title):
        """Print section title"""
        self.stdout.write(self.style.HTTP_INFO(f"\n=== {title} ===\n"))

    def check_environment_variables(self):
        """Check essential environment variables for production"""
        self.print_section("Environment Variables Check")
        
        # Check DEBUG
        if settings.DEBUG:
            self.print_error("DEBUG is set to True. Must be set to False in production!")
            return False
        else:
            self.print_success("DEBUG is correctly set to False")
        
        # Check SECRET_KEY
        default_key = "your-secure-secret-key-here"
        if settings.SECRET_KEY == default_key or len(settings.SECRET_KEY) < 32:
            self.print_error(f"SECRET_KEY is using the default value or is too short. Generate a secure random key.")
            return False
        else:
            self.print_success("SECRET_KEY is properly configured")
        
        # Check ALLOWED_HOSTS
        if settings.ALLOWED_HOSTS == ['localhost', '127.0.0.1'] or 'yourdomain.com' in settings.ALLOWED_HOSTS:
            self.print_warning("ALLOWED_HOSTS contains default/example values. Make sure to use your actual domain.")
        else:
            self.print_success(f"ALLOWED_HOSTS is configured with: {', '.join(settings.ALLOWED_HOSTS)}")
        
        return True

    def check_database(self):
        """Check database connection and configuration"""
        self.print_section("Database Configuration Check")
        
        # Check database engine
        if 'sqlite' in settings.DATABASES['default']['ENGINE']:
            self.print_warning("Using SQLite in production is not recommended. Consider PostgreSQL for production.")
        else:
            self.print_success(f"Using {settings.DATABASES['default']['ENGINE']} as database engine")
        
        # Test connection
        try:
            connections['default'].ensure_connection()
            self.print_success("Database connection successful")
            return True
        except Exception as e:
            self.print_error(f"Database connection failed: {str(e)}")
            return False

    def check_email_config(self, send_test=False):
        """Check email configuration and optionally send a test email"""
        self.print_section("Email Configuration Check")
        
        # Check basic email settings
        if not settings.EMAIL_HOST:
            self.print_error("EMAIL_HOST is not set")
            return False
        else:
            self.print_success(f"EMAIL_HOST is set to {settings.EMAIL_HOST}")
        
        if not settings.EMAIL_HOST_USER or settings.EMAIL_HOST_USER == 'your_email@gmail.com':
            self.print_error("EMAIL_HOST_USER is not properly configured")
            return False
        else:
            self.print_success(f"EMAIL_HOST_USER is set to {settings.EMAIL_HOST_USER}")
        
        if not settings.EMAIL_HOST_PASSWORD or settings.EMAIL_HOST_PASSWORD == 'your_app_specific_password':
            self.print_error("EMAIL_HOST_PASSWORD is not set or using default value")
            return False
        else:
            self.print_success("EMAIL_HOST_PASSWORD is configured")
        
        # Check admin email configuration
        admins = getattr(settings, 'ADMINS', [])
        if not admins:
            self.print_warning("ADMINS list is empty. Error emails won't be sent to administrators.")
        else:
            self.print_success(f"ADMINS configured with {len(admins)} recipient(s)")
        
        # Optionally send a test email
        if send_test:
            try:
                send_mail(
                    subject='[S2Cart API] Production Configuration Test',
                    message='This is a test email to verify that the email configuration is working correctly.',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[admin[1] for admin in admins] if admins else [settings.EMAIL_HOST_USER],
                    fail_silently=False,
                )
                self.print_success("Test email sent successfully")
            except Exception as e:
                self.print_error(f"Failed to send test email: {str(e)}")
                return False
        
        return True

    def check_https_config(self):
        """Check HTTPS and SSL-related configurations"""
        self.print_section("HTTPS Configuration Check")
        
        # Check USE_HTTPS setting
        use_https = getattr(settings, 'USE_HTTPS', False)
        if not use_https:
            self.print_warning("USE_HTTPS is set to False. SSL is recommended for production.")
        else:
            self.print_success("USE_HTTPS is enabled")
        
        # Check SSL redirect
        if hasattr(settings, 'SECURE_SSL_REDIRECT') and settings.SECURE_SSL_REDIRECT:
            self.print_success("SECURE_SSL_REDIRECT is properly enabled")
        else:
            self.print_warning("SECURE_SSL_REDIRECT is not enabled")
        
        # Check cookie security
        if not settings.SESSION_COOKIE_SECURE:
            self.print_warning("SESSION_COOKIE_SECURE is False. Secure cookies are recommended for production.")
        else:
            self.print_success("Session cookies are secure")
        
        if not settings.CSRF_COOKIE_SECURE:
            self.print_warning("CSRF_COOKIE_SECURE is False. Secure CSRF cookies are recommended for production.")
        else:
            self.print_success("CSRF cookies are secure")
        
        # Check HSTS
        if hasattr(settings, 'SECURE_HSTS_SECONDS') and settings.SECURE_HSTS_SECONDS:
            self.print_success(f"HSTS is configured with {settings.SECURE_HSTS_SECONDS} seconds")
        else:
            self.print_warning("HSTS is not configured. Consider enabling it for enhanced security.")
        
        return True

    def check_paytm_config(self):
        """Check Paytm integration configuration"""
        self.print_section("Paytm Integration Check")
        
        # Check test mode
        if getattr(settings, 'PAYTM_TEST_MODE', True):
            self.print_warning("PAYTM_TEST_MODE is True. This should be False in production.")
        else:
            self.print_success("PAYTM_TEST_MODE is correctly set to False")
        
        # Check merchant ID
        merchant_id = getattr(settings, 'PAYTM_MERCHANT_ID', '')
        if not merchant_id or merchant_id == 'your_merchant_id':
            self.print_error("PAYTM_MERCHANT_ID is not properly configured")
            return False
        else:
            self.print_success("PAYTM_MERCHANT_ID is configured")
        
        # Check merchant key
        merchant_key = getattr(settings, 'PAYTM_MERCHANT_KEY', '')
        if not merchant_key or merchant_key == 'your_merchant_key':
            self.print_error("PAYTM_MERCHANT_KEY is not properly configured")
            return False
        else:
            self.print_success("PAYTM_MERCHANT_KEY is configured")
        
        return True

    def handle(self, *args, **options):
        if settings.DEBUG:
            self.print_error("You are running this command in DEBUG mode. Run with DEBUG=False for a proper check.")
        
        self.print_section("Production Readiness Check")
        self.print_warning("This tool checks if your environment is properly configured for production.")
        
        all_checks_passed = True
        
        # Always check environment variables
        env_check = self.check_environment_variables()
        all_checks_passed = all_checks_passed and env_check
        
        # Database check
        if options['check_db'] or options['check_all']:
            db_check = self.check_database()
            all_checks_passed = all_checks_passed and db_check
        
        # Email check
        if options['check_mail'] or options['check_all']:
            email_check = self.check_email_config(send_test=options['check_mail'])
            all_checks_passed = all_checks_passed and email_check
        
        # HTTPS check
        if options['check_https'] or options['check_all']:
            https_check = self.check_https_config()
            all_checks_passed = all_checks_passed and https_check
        
        # Always check Paytm configuration
        paytm_check = self.check_paytm_config()
        all_checks_passed = all_checks_passed and paytm_check
        
        # Final summary
        self.print_section("Results Summary")
        if all_checks_passed:
            self.print_success("All checked configurations appear to be ready for production!")
        else:
            self.print_error("Some checks failed. Address the issues before deploying to production.")
            
        return 0 if all_checks_passed else 1
