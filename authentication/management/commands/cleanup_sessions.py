"""
Django management command for cleaning up expired sessions and tokens
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from authentication.models import ExpiringToken, JWTSession
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Clean up expired tokens and sessions for security'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Delete sessions older than X days (default: 7)',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days = options['days']
        
        self.stdout.write(f"Starting session cleanup (dry_run={dry_run}, days={days})")
        
        # Clean up expired ExpiringTokens
        expired_tokens = ExpiringToken.objects.filter(
            expiry__lt=timezone.now()
        )
        token_count = expired_tokens.count()
        
        if not dry_run:
            expired_tokens.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Deleted {token_count} expired tokens")
            )
        else:
            self.stdout.write(f"Would delete {token_count} expired tokens")
        
        # Clean up expired JWT sessions
        expired_jwt_sessions = JWTSession.objects.filter(
            expires_at__lt=timezone.now()
        )
        jwt_count = expired_jwt_sessions.count()
        
        if not dry_run:
            expired_jwt_sessions.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Deleted {jwt_count} expired JWT sessions")
            )
        else:
            self.stdout.write(f"Would delete {jwt_count} expired JWT sessions")
        
        # Clean up old inactive sessions (older than specified days)
        cutoff_date = timezone.now() - timedelta(days=days)
        
        old_inactive_tokens = ExpiringToken.objects.filter(
            last_used__lt=cutoff_date
        ).exclude(expiry__gt=timezone.now())
        old_token_count = old_inactive_tokens.count()
        
        if not dry_run:
            old_inactive_tokens.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Deleted {old_token_count} old inactive tokens")
            )
        else:
            self.stdout.write(f"Would delete {old_token_count} old inactive tokens")
        
        old_inactive_jwt = JWTSession.objects.filter(
            last_activity__lt=cutoff_date,
            is_active=False
        )
        old_jwt_count = old_inactive_jwt.count()
        
        if not dry_run:
            old_inactive_jwt.delete()
            self.stdout.write(
                self.style.SUCCESS(f"Deleted {old_jwt_count} old inactive JWT sessions")
            )
        else:
            self.stdout.write(f"Would delete {old_jwt_count} old inactive JWT sessions")
        
        total_cleaned = token_count + jwt_count + old_token_count + old_jwt_count
        
        if not dry_run:
            self.stdout.write(
                self.style.SUCCESS(f"Total cleanup completed: {total_cleaned} items removed")
            )
            logger.info(f"Session cleanup completed: {total_cleaned} items removed")
        else:
            self.stdout.write(f"Dry run completed: {total_cleaned} items would be removed")
