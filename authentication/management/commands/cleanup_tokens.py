import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from authentication.models import ExpiringToken

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Clean up expired authentication tokens'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        self.stdout.write('Starting token cleanup...')
        
        # Get expired tokens
        expired_tokens = ExpiringToken.objects.filter(
            expiry__lt=timezone.now()
        )
        
        count = expired_tokens.count()
        
        if options['dry_run']:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would delete {count} expired tokens'
                )
            )
        else:
            deleted_count = ExpiringToken.cleanup_expired_tokens()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_count} expired tokens'
                )
            )
            logger.info(f'Cleaned up {deleted_count} expired tokens')
