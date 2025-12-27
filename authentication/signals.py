from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.contrib.auth import get_user_model
from .models import Cart, ExpiringToken

User = get_user_model()

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """
    Create an expiring token for each new user.
    """
    if created:
        ExpiringToken.get_or_create_token(
            user=instance,
            device_type='API',
            expiry_days=30
        )

@receiver(post_save, sender=User)
def create_user_cart(sender, instance, created, **kwargs):
    """
    Signal to create a cart for a user when they register
    """
    if created:
        Cart.objects.create(user=instance)