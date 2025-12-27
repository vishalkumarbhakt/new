"""
Django management command for security monitoring and threat detection
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model
from datetime import timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class Command(BaseCommand):
    help = 'Monitor security threats and generate security report'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Monitor last X hours (default: 24)',
        )
    
    def handle(self, *args, **options):
        hours = options['hours']
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        self.stdout.write(f"Security monitoring report for last {hours} hours")
        self.stdout.write("=" * 60)
        
        # Check for locked accounts
        locked_users = User.objects.filter(
            is_locked=True,
            locked_until__gt=timezone.now()
        )
        
        if locked_users.exists():
            self.stdout.write(
                self.style.WARNING(f"🔒 {locked_users.count()} accounts currently locked")
            )
            for user in locked_users[:10]:  # Show first 10
                remaining = (user.locked_until - timezone.now()).total_seconds() / 60
                self.stdout.write(f"  - {user.username} (unlocks in {remaining:.0f} min)")
        
        # Check for users with multiple failed attempts
        users_with_failures = User.objects.filter(
            failed_login_attempts__gt=0,
            last_failed_login__gte=cutoff_time
        ).order_by('-failed_login_attempts')
        
        if users_with_failures.exists():
            self.stdout.write(
                self.style.WARNING(f"⚠️  {users_with_failures.count()} users with recent failed attempts")
            )
            for user in users_with_failures[:10]:
                self.stdout.write(f"  - {user.username}: {user.failed_login_attempts} attempts")
        
        # Check for blocked IPs
        blocked_ips = []
        for i in range(256):  # Check common IP patterns
            for j in range(256):
                cache_key = f"blocked_ip_192.168.{i}.{j}"
                if cache.get(cache_key):
                    blocked_ips.append(f"192.168.{i}.{j}")
                if len(blocked_ips) >= 20:  # Limit output
                    break
            if len(blocked_ips) >= 20:
                break
        
        if blocked_ips:
            self.stdout.write(
                self.style.ERROR(f"🚫 {len(blocked_ips)} IPs currently blocked")
            )
            for ip in blocked_ips[:10]:
                self.stdout.write(f"  - {ip}")
        
        # Security recommendations
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write("Security Recommendations:")
        
        if locked_users.count() > 10:
            self.stdout.write("⚠️  High number of locked accounts - investigate potential attack")
        
        if users_with_failures.count() > 50:
            self.stdout.write("⚠️  High number of failed login attempts - consider additional security measures")
        
        if blocked_ips:
            self.stdout.write("⚠️  IPs are being blocked - monitor for distributed attacks")
        
        # Check for unverified users
        unverified_users = User.objects.filter(
            is_verified=False,
            date_joined__gte=cutoff_time
        )
        
        if unverified_users.count() > 100:
            self.stdout.write("⚠️  High number of unverified registrations - check for spam")
        
        self.stdout.write("\n✅ Security monitoring completed")
        logger.info(f"Security monitoring completed: {locked_users.count()} locked, {users_with_failures.count()} with failures")
