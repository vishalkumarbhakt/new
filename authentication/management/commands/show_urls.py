import logging
from django.core.management.base import BaseCommand
from django.urls import URLPattern, URLResolver
from django.conf import settings
import importlib

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Display all URLs in the project'

    def handle(self, *args, **options):
        self.stdout.write('Available URLs:')
        self.stdout.write('=' * 50)
        
        try:
            # Import the root URLconf
            root_urlconf = importlib.import_module(settings.ROOT_URLCONF)
            urlpatterns = root_urlconf.urlpatterns
            
            self._show_urls(urlpatterns)
            
        except Exception as e:
            self.stdout.write(f'Error: {str(e)}')

    def _show_urls(self, urlpatterns, prefix=''):
        for pattern in urlpatterns:
            if isinstance(pattern, URLPattern):
                # This is a URL pattern
                path = prefix + str(pattern.pattern)
                view_name = getattr(pattern.callback, '__name__', 'Unknown')
                self.stdout.write(f'{path:<50} -> {view_name}')
            elif isinstance(pattern, URLResolver):
                # This includes other URL patterns
                new_prefix = prefix + str(pattern.pattern)
                self._show_urls(pattern.url_patterns, new_prefix)
