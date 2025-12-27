from django.core.management.base import BaseCommand
import os
import sys
from dotenv import load_dotenv
from django.conf import settings
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()

class Command(BaseCommand):
    help = 'Validates environment variables and checks for required settings'
    
    # Required variables for different environments
    REQUIRED_VARS = {
        'all': [
            'DJANGO_SECRET_KEY',
            'DEBUG',
            'ALLOWED_HOSTS',
            'SERVER_PORT',
            'SITE_PROTOCOL',
            'SITE_DOMAIN',
        ],
        'production': [
            'DB_ENGINE',
            'DB_NAME',
            'DB_USER',
            'DB_PASSWORD',
            'DB_HOST',
            'DB_PORT',
            'EMAIL_HOST',
            'EMAIL_PORT',
            'EMAIL_HOST_USER',
            'EMAIL_HOST_PASSWORD',
            'PAYTM_MERCHANT_ID',
            'PAYTM_MERCHANT_KEY',
            'SERVER_EMAIL',
            'ADMIN_EMAIL',
            'USE_HTTPS',
        ],
    }
    
    # Variables that should be checked for security in production
    SECURITY_CHECKS = {
        'DEBUG': {'should_be': False, 'type': bool},
        'DJANGO_SECRET_KEY': {'min_length': 32, 'type': str},
        'CSRF_COOKIE_SECURE': {'should_be': True, 'type': bool},
        'SESSION_COOKIE_SECURE': {'should_be': True, 'type': bool},
        'USE_HTTPS': {'should_be': True, 'type': bool},
        'SECURE_HSTS_SECONDS': {'min_value': 31536000, 'type': int},
    }
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--env',
            choices=['development', 'production'],
            default='development',
            help='Environment to validate for',
        )
        
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Attempt to fix issues (experimental)',
        )
        
    def handle(self, *args, **options):
        env = options['env']
        fix = options['fix']
        
        self.stdout.write(self.style.SUCCESS(f"Validating environment variables for {env} environment"))
        
        # Load .env file again to make sure we have all variables
        load_dotenv()
        
        # Check for required variables
        missing = []
        for var in self.REQUIRED_VARS['all']:
            if not os.environ.get(var):
                missing.append(var)
        
        if env == 'production':
            for var in self.REQUIRED_VARS['production']:
                if not os.environ.get(var):
                    missing.append(var)
        
        if missing:
            self.stdout.write(self.style.ERROR(f"Missing required environment variables: {', '.join(missing)}"))
            if fix:
                self.try_fix_missing_vars(missing, env)
        else:
            self.stdout.write(self.style.SUCCESS("All required environment variables are present"))
        
        # Security checks for production
        if env == 'production':
            security_issues = []
            
            for var, checks in self.SECURITY_CHECKS.items():
                value = os.environ.get(var)
                
                if not value:
                    security_issues.append(f"{var} is not set")
                    continue
                
                if 'should_be' in checks:
                    expected = checks['should_be']
                    if checks['type'] == bool:
                        actual = value.lower() == 'true'
                        if actual != expected:
                            security_issues.append(f"{var} should be {expected}, but is {actual}")
                
                if 'min_length' in checks and len(value) < checks['min_length']:
                    security_issues.append(f"{var} should be at least {checks['min_length']} characters long")
            
            if security_issues:
                self.stdout.write(self.style.WARNING("Security recommendations:"))
                for issue in security_issues:
                    self.stdout.write(f"  - {Fore.YELLOW}{issue}{Style.RESET_ALL}")
            else:
                self.stdout.write(self.style.SUCCESS("All security checks passed"))
        
        # Check for database configuration
        self.check_database_config()
        
        # Check for static and media files configuration
        self.check_files_config()
        
        # Final advice
        if env == 'production':
            self.stdout.write("\nProduction deployment recommendations:")
            self.stdout.write(f"  - {Fore.CYAN}Use HTTPS with a valid SSL certificate{Style.RESET_ALL}")
            self.stdout.write(f"  - {Fore.CYAN}Enable rate limiting on sensitive endpoints{Style.RESET_ALL}")
            self.stdout.write(f"  - {Fore.CYAN}Set up proper monitoring and logging{Style.RESET_ALL}")
            self.stdout.write(f"  - {Fore.CYAN}Perform regular security audits{Style.RESET_ALL}")
    
    def try_fix_missing_vars(self, missing, env):
        self.stdout.write(self.style.WARNING("Attempting to fix missing variables..."))
        
        # Create appropriate .env file based on environment
        env_file = '.env.development' if env == 'development' else '.env.production'
        dest_file = '.env'
        
        if not os.path.exists(env_file):
            self.stdout.write(self.style.ERROR(f"Cannot find {env_file} template"))
            return
        
        self.stdout.write(f"Copying {env_file} to {dest_file}")
        try:
            with open(env_file, 'r') as src, open(dest_file, 'w') as dst:
                dst.write(src.read())
            self.stdout.write(self.style.SUCCESS("Environment file created. Please restart your application."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating environment file: {str(e)}"))
    
    def check_database_config(self):
        self.stdout.write("\nDatabase configuration:")
        db_engine = os.environ.get('DB_ENGINE', 'django.db.backends.sqlite3')
        
        if 'sqlite3' in db_engine:
            self.stdout.write(f"  - Using {Fore.CYAN}SQLite{Style.RESET_ALL} database")
            self.stdout.write(f"    {Fore.YELLOW}NOTE: SQLite is good for development but not recommended for production{Style.RESET_ALL}")
        elif 'postgresql' in db_engine:
            if all([
                os.environ.get('DB_NAME'),
                os.environ.get('DB_USER'),
                os.environ.get('DB_PASSWORD')
            ]):
                self.stdout.write(f"  - Using {Fore.GREEN}PostgreSQL{Style.RESET_ALL} database - properly configured")
            else:
                self.stdout.write(f"  - Using {Fore.RED}PostgreSQL{Style.RESET_ALL} database - missing configuration")
        else:
            self.stdout.write(f"  - Using {Fore.CYAN}{db_engine}{Style.RESET_ALL} database")
    
    def check_files_config(self):
        self.stdout.write("\nStatic and media files configuration:")
        
        if os.environ.get('USE_GCS', '').lower() == 'true':
            if os.environ.get('GCS_BUCKET_NAME'):
                self.stdout.write(f"  - Using {Fore.GREEN}Google Cloud Storage{Style.RESET_ALL} for files")
            else:
                self.stdout.write(f"  - {Fore.RED}Google Cloud Storage enabled but GCS_BUCKET_NAME not set{Style.RESET_ALL}")
        else:
            self.stdout.write(f"  - Using {Fore.CYAN}local storage{Style.RESET_ALL} for static and media files")
            if settings.DEBUG == False:
                self.stdout.write(f"    {Fore.YELLOW}NOTE: Consider using cloud storage in production for better performance{Style.RESET_ALL}")
