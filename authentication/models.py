from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
import secrets

class ExpiringTokenAuthentication(TokenAuthentication):
    """
    Custom token authentication that supports token expiration.
    """
    model = None  # Will be set to ExpiringToken in ready() method
    
    def __init__(self):
        self.model = ExpiringToken
        super().__init__()
    
    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.get(key=key)
        except self.model.DoesNotExist:
            raise AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise AuthenticationFailed(_('User inactive or deleted.'))
        
        if token.is_expired():
            token.delete()
            raise AuthenticationFailed(_('Token has expired.'))

        # Check if account is locked
        if token.user.is_locked:
            if token.user.locked_until and token.user.locked_until > timezone.now():
                raise AuthenticationFailed(_('Account is temporarily locked.'))
            else:
                # If lock time has passed, unlock the account
                token.user.is_locked = False
                token.user.locked_until = None
                token.user.save(update_fields=['is_locked', 'locked_until'])
        
        # Update last used timestamp and refresh expiry
        token.update_last_used()
        
        return (token.user, token)

class ExpiringToken(models.Model):
    """
    Custom token model with expiry time, device tracking, and better security.
    This replaces the default Token model to avoid circular dependencies.
    """
    key = models.CharField(max_length=40, primary_key=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='auth_tokens')
    expiry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    # Device and session tracking
    device_type = models.CharField(
        max_length=20,
        choices=[
            ('ANDROID', 'Android App'),
            ('WEB', 'Web Browser'),
            ('IOS', 'iOS App'),
            ('API', 'API Client'),
        ],
        default='API'
    )
    device_id = models.CharField(max_length=255, blank=True, null=True, help_text="Unique device identifier")
    user_agent = models.TextField(blank=True, null=True, help_text="User agent string")
    ip_address = models.GenericIPAddressField(blank=True, null=True, help_text="IP address when token was created")
    
    class Meta:
        indexes = [
            models.Index(fields=['expiry']),
            models.Index(fields=['last_used']),
            models.Index(fields=['device_type']),
        ]
        # Note: unique_together with inherited fields needs to be handled differently
        # We'll handle uniqueness in the get_or_create_token method instead
    
    def generate_key(self):
        """Generate a more secure token key that fits in 40 characters"""
        # Generate a 30-byte token which will result in exactly 40 characters when base64 encoded
        return secrets.token_urlsafe(30)
    
    def is_expired(self):
        if self.expiry is None:
            return False
        return timezone.now() >= self.expiry
    
    def set_expiry(self, days=1):
        self.expiry = timezone.now() + timedelta(days=days)
        self.save(update_fields=['expiry'])
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])
    
    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)
    
    @classmethod
    def get_or_create_token(cls, user, device_type='API', device_id=None, user_agent=None, ip_address=None, expiry_days=1):
        """
        Get or create a token for a user with device tracking and session management.
        Allows up to 2 concurrent sessions per device type (for redundancy).
        """
        # Clean up expired tokens first
        cls.cleanup_expired_tokens()
        
        # For device-specific tokens, try to find existing token
        if device_id:
            try:
                token = cls.objects.get(user=user, device_type=device_type, device_id=device_id)
                # Update expiry for existing token
                token.set_expiry(days=expiry_days)
                token.user_agent = user_agent
                token.ip_address = ip_address
                token.save(update_fields=['expiry', 'user_agent', 'ip_address'])
                return token
            except cls.DoesNotExist:
                pass
        
        # Limit concurrent sessions per device type (max 2 for redundancy)
        existing_tokens = cls.objects.filter(user=user, device_type=device_type).order_by('-last_used')
        if existing_tokens.count() >= 2:
            # Remove oldest token(s) to make room for new one
            oldest_tokens = existing_tokens[1:]  # Keep the most recent one
            for token in oldest_tokens:
                token.delete()
        
        # Create new token
        token = cls.objects.create(
            user=user,
            device_type=device_type,
            device_id=device_id,
            user_agent=user_agent,
            ip_address=ip_address
        )
        token.set_expiry(days=expiry_days)
        return token
    
    @classmethod
    def cleanup_expired_tokens(cls):
        """Clean up expired tokens"""
        expired_tokens = cls.objects.filter(expiry__lt=timezone.now())
        count = expired_tokens.count()
        expired_tokens.delete()
        return count


class Address(models.Model):
    """Base address model for storing detailed address information"""

    # Phone number validator - exactly 10 digits
    phone_regex = RegexValidator(
        regex=r'^\d{10}$',
        message="Phone number must be exactly 10 digits."
    )
    
    # Country code validator
    country_code_regex = RegexValidator(
        regex=r'^\+\d{1,4}$',
        message="Country code must start with + and be 1-4 digits (e.g., +91, +1)."
    )
    
    # PIN code validator for India
    pin_code_regex = RegexValidator(
        regex=r'^\d{6}$',
        message="PIN code must be 6 digits for Indian addresses."
    )
    
    contact_name = models.CharField(
        max_length=255, 
        help_text="Name of the person at this address"
    )
    street_address = models.CharField(
        max_length=500, 
        help_text="Street address line 1"
    )
    street_address_2 = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="Street address line 2 (optional)"
    )
    landmark = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="Nearby landmark for easy identification"
    )
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    pin_code = models.CharField(
        max_length=10, 
        validators=[pin_code_regex],
        help_text="Postal/ZIP code"
    )
    country = models.CharField(max_length=100, default='India')

    phone_number = models.CharField(
        max_length=10, 
        blank=True, 
        null=True,
        validators=[phone_regex],
        help_text="10-digit phone number without country code",
    )
    
    country_code = models.CharField(
        max_length=5,
        blank=True,
        null=True,
        validators=[country_code_regex],
        default='+91',
        help_text="Country code with + prefix (e.g., +91, +1)"
    )
    
    # Enhanced address types
    address_type = models.CharField(max_length=20, choices=[
        ('HOME', 'Home'),
        ('WORK', 'Work'),
        ('OFFICE', 'Office'),
        ('OTHER', 'Other')
    ], default='HOME')
    
    # Location coordinates for delivery optimization
    latitude = models.DecimalField(
        max_digits=10, 
        decimal_places=8, 
        blank=True, 
        null=True,
        help_text="Latitude coordinate"
    )
    longitude = models.DecimalField(
        max_digits=11, 
        decimal_places=8, 
        blank=True, 
        null=True,
        help_text="Longitude coordinate"
    )
    
    is_default = models.BooleanField(default=False)
    is_verified = models.BooleanField(
        default=False, 
        help_text="Whether this address has been verified"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['pin_code']),
            models.Index(fields=['city', 'state']),
            models.Index(fields=['latitude', 'longitude']),
        ]

    def __str__(self):
        return f"{self.contact_name} - {self.city}, {self.state}"

    @property
    def full_address(self):
        """Return formatted full address"""
        address_parts = [self.contact_name, self.street_address]
        
        if self.street_address_2:
            address_parts.append(self.street_address_2)
        if self.landmark:
            address_parts.append(f"Near {self.landmark}")
            
        address_parts.extend([
            f"{self.city}, {self.state} {self.pin_code}",
            self.country,
            f"Phone: {self.phone_number}"
        ])
        return "\n".join(address_parts)
    
    def clean(self):
        """Custom validation"""
        if not self.contact_name.strip():
            raise ValidationError({'contact_name': 'Contact name cannot be empty.'})
        
        if not self.street_address.strip():
            raise ValidationError({'street_address': 'Street address cannot be empty.'})
        
        # Validate coordinates if provided
        if self.latitude is not None and (self.latitude < -90 or self.latitude > 90):
            raise ValidationError({'latitude': 'Latitude must be between -90 and 90 degrees.'})
        
        if self.longitude is not None and (self.longitude < -180 or self.longitude > 180):
            raise ValidationError({'longitude': 'Longitude must be between -180 and 180 degrees.'})


class UserAddress(Address):
    """User's saved addresses"""
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='addresses')
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'is_default']),
            models.Index(fields=['user', 'address_type']),
            models.Index(fields=['pin_code']),
            models.Index(fields=['city', 'state']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user'], 
                condition=models.Q(is_default=True),
                name='unique_default_address_per_user'
            )
        ]
    
    def save(self, *args, **kwargs):
        """Ensure only one default address per user"""
        if self.is_default:
            # Remove default from other addresses of this user
            UserAddress.objects.filter(
                user=self.user, 
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        
        # If this is the user's first address, make it default
        if not UserAddress.objects.filter(user=self.user).exists():
            self.is_default = True
            
        super().save(*args, **kwargs)


class User(AbstractUser):
    # Override email field to make it unique
    email = models.EmailField(
        _('email address'),
        unique=True,
        help_text=_('Required. Enter a valid email address.'),
        error_messages={
            'unique': _("A user with that email address already exists."),
        }
    )
    
    # Phone number validator - exactly 10 digits
    phone_regex = RegexValidator(
        regex=r'^\d{10}$',
        message="Phone number must be exactly 10 digits."
    )
    
    # Country code validator
    country_code_regex = RegexValidator(
        regex=r'^\+\d{1,4}$',
        message="Country code must start with + and be 1-4 digits (e.g., +91, +1)."
    )
    
    phone_number = models.CharField(
        max_length=10, 
        blank=True, 
        null=True,
        validators=[phone_regex],
        help_text="10-digit phone number without country code"
    )
    
    country_code = models.CharField(
        max_length=5,
        blank=True,
        null=True,
        validators=[country_code_regex],
        default='+91',
        help_text="Country code with + prefix (e.g., +91, +1)"
    )
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    
    # Additional user profile fields
    date_of_birth = models.DateField(blank=True, null=True, help_text="Date of birth")
    gender = models.CharField(
        max_length=20,
        choices=[
            ('MALE', 'Male'),
            ('FEMALE', 'Female'),
            ('OTHER', 'Other'),
            ('PREFER_NOT_TO_SAY', 'Prefer not to say')
        ],
        blank=True,
        null=True
    )
    
    # User preferences
    preferred_language = models.CharField(
        max_length=10,
        choices=[
            ('EN', 'English'),
            ('HI', 'Hindi'),
            ('TA', 'Tamil'),
            ('TE', 'Telugu'),
            ('BN', 'Bengali'),
            ('MR', 'Marathi'),
            ('GU', 'Gujarati'),
            ('KN', 'Kannada'),
            ('ML', 'Malayalam'),
            ('PA', 'Punjabi')
        ],
        default='EN'
    )
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    
    # User verification and metadata
    is_verified = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Verification and reset fields
    verification_token = models.CharField(max_length=128, blank=True, null=True)
    verification_otp = models.CharField(max_length=6, blank=True, null=True, help_text="6-digit OTP for verification")
    verification_otp_expires = models.DateTimeField(null=True, blank=True, help_text="OTP expiry time")
    reset_password_token = models.CharField(max_length=128, blank=True, null=True)
    reset_password_otp = models.CharField(max_length=6, blank=True, null=True, help_text="6-digit OTP for password reset")
    reset_password_otp_expires = models.DateTimeField(null=True, blank=True, help_text="Password reset OTP expiry time")
    reset_password_expires = models.DateTimeField(null=True, blank=True)
    
    # For password reset and security
    failed_login_attempts = models.PositiveIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Define that email should be used for identifying users in addition to username
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'  # Keep username as primary login field
    REQUIRED_FIELDS = ['email']  # Require email when creating superuser
    
    def lock_account(self, minutes=30):
        self.is_locked = True
        self.locked_until = timezone.now() + timedelta(minutes=minutes)
        self.save(update_fields=['is_locked', 'locked_until'])
    
    def reset_login_attempts(self):
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.is_locked = False
        self.locked_until = None
        self.save(update_fields=['failed_login_attempts', 'last_failed_login', 'is_locked', 'locked_until'])
    
    def is_password_reset_token_valid(self):
        if not self.reset_password_token or not self.reset_password_expires:
            return False
        return timezone.now() < self.reset_password_expires
    
    def is_verification_otp_valid(self):
        """Check if verification OTP is valid and not expired"""
        if not self.verification_otp or not self.verification_otp_expires:
            return False
        return timezone.now() < self.verification_otp_expires
    
    def is_password_reset_otp_valid(self):
        """Check if password reset OTP is valid and not expired"""
        if not self.reset_password_otp or not self.reset_password_otp_expires:
            return False
        return timezone.now() < self.reset_password_otp_expires
    
    def generate_verification_otp(self):
        """Generate a 6-digit OTP for email verification"""
        import secrets
        otp = str(secrets.randbelow(900000) + 100000)
        self.verification_otp = otp
        self.verification_otp_expires = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_TIME)
        self.save(update_fields=['verification_otp', 'verification_otp_expires'])
        return otp
    
    def generate_password_reset_otp(self):
        """Generate a 6-digit OTP for password reset"""
        import secrets
        otp = str(secrets.randbelow(900000) + 100000)
        self.reset_password_otp = otp
        self.reset_password_otp_expires = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_TIME)
        self.save(update_fields=['reset_password_otp', 'reset_password_otp_expires'])
        return otp
    
    def clear_verification_otp(self):
        """Clear verification OTP after successful verification"""
        self.verification_otp = None
        self.verification_otp_expires = None
        self.save(update_fields=['verification_otp', 'verification_otp_expires'])
    
    def clear_password_reset_otp(self):
        """Clear password reset OTP after successful reset"""
        self.reset_password_otp = None
        self.reset_password_otp_expires = None
        self.save(update_fields=['reset_password_otp', 'reset_password_otp_expires'])
    
    def clear_expired_reset_token(self):
        """Clear expired password reset token"""
        if self.reset_password_token and self.reset_password_expires:
            if timezone.now() >= self.reset_password_expires:
                self.reset_password_token = None
                self.reset_password_expires = None
                self.save(update_fields=['reset_password_token', 'reset_password_expires'])
                return True
        return False
    
    @property
    def default_address(self):
        """Get user's default address"""
        return self.addresses.filter(is_default=True).first()
    
    @property
    def full_name(self):
        """Get user's full name"""
        return f"{self.first_name} {self.last_name}".strip() or self.username

    class Meta:
        indexes = [
            models.Index(fields=['username']),
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['country_code', 'phone_number']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['verification_token']),
            models.Index(fields=['verification_otp']),
            models.Index(fields=['reset_password_token']),
            models.Index(fields=['reset_password_otp']),
            models.Index(fields=['date_of_birth']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['country_code', 'phone_number'],
                condition=models.Q(phone_number__isnull=False) & ~models.Q(phone_number=''),
                name='unique_country_phone_number'
            )
        ]


class PaymentMethod(models.Model):
    """Base model for payment methods"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class CardPaymentMethod(PaymentMethod):
    """Card payment method details"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='card_payment_methods')
    card_type = models.CharField(max_length=20)  # VISA, Mastercard, etc.
    last_four = models.CharField(max_length=4)
    expiry_month = models.CharField(max_length=2)
    expiry_year = models.CharField(max_length=4)
    card_holder_name = models.CharField(max_length=255)
    card_nickname = models.CharField(max_length=50, blank=True)
    
    class Meta:
        indexes = [models.Index(fields=['user', 'card_type'])]

class UPIPaymentMethod(PaymentMethod):
    """UPI payment method details"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='upi_payment_methods')
    upi_id = models.CharField(max_length=255)
    upi_nickname = models.CharField(max_length=50, blank=True)
    
    class Meta:
        indexes = [models.Index(fields=['user', 'upi_id'])]

class PaymentHistory(models.Model):
    """Central model to track all payment activities"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payment_history')
    amount = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0,
        help_text="Payment amount - secured with default value for data integrity"
    )
    currency = models.CharField(max_length=3, default='INR')
    
    # Enhanced status tracking
    status = models.CharField(max_length=20, choices=[
        ('INITIATED', 'Initiated'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('REFUNDED', 'Refunded'),
        ('PARTIALLY_REFUNDED', 'Partially Refunded'),
        ('CANCELLED', 'Cancelled'),
        ('PENDING', 'Pending'),
        ('EXPIRED', 'Expired')
    ])
    
    # Enhanced payment types
    payment_type = models.CharField(max_length=25, choices=[
        ('CARD', 'Card Payment'),
        ('UPI', 'UPI Payment'),
        ('WALLET', 'Wallet Payment'),
        ('NET_BANKING', 'Net Banking'),
        ('COD', 'Cash on Delivery'),
        ('EMI', 'EMI Payment'),
        ('GIFT_CARD', 'Gift Card'),
        ('STORE_CREDIT', 'Store Credit')
    ])
    
    order = models.ForeignKey('Order', on_delete=models.SET_NULL, null=True, related_name='payments')
    transaction_id = models.CharField(max_length=100, unique=True)
    payment_gateway_order_id = models.CharField(max_length=100, null=True, blank=True)
    payment_method_id = models.CharField(max_length=100, null=True)
    
    # Payment gateway specific fields
    gateway_name = models.CharField(max_length=50, blank=True, null=True, help_text="Payment gateway used")
    gateway_transaction_id = models.CharField(max_length=100, blank=True, null=True)
    gateway_response = models.JSONField(blank=True, null=True, help_text="Full gateway response")
    
    # Tax and fee tracking
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Tax amount")
    convenience_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Convenience fee")
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Discount amount")
    
    # Refund tracking
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Total refunded amount")
    refund_reason = models.TextField(blank=True, null=True, help_text="Reason for refund")
    refund_processed_at = models.DateTimeField(blank=True, null=True)
    
    # Billing address
    billing_address = models.ForeignKey(
        UserAddress, 
        on_delete=models.PROTECT, 
        related_name='billing_payments',
        null=True,
        blank=True,
        help_text="Detailed billing address"
    )
    
    # Additional tracking
    description = models.TextField(blank=True, null=True)
    failure_reason = models.TextField(blank=True, null=True, help_text="Reason for payment failure")
    retry_count = models.PositiveIntegerField(default=0, help_text="Number of retry attempts")
    expires_at = models.DateTimeField(blank=True, null=True, help_text="Payment expiration time")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.transaction_id} ({self.status})"
    
    @property
    def is_successful(self):
        return self.status == 'COMPLETED'
    
    @property
    def is_refundable(self):
        return self.status == 'COMPLETED' and self.refund_amount < self.amount
    
    @property
    def net_amount(self):
        """Calculate net amount after refunds"""
        return self.amount - self.refund_amount
    
    @property
    def total_amount(self):
        """
        Calculate total amount including taxes and fees
        Production-grade null-safety implementation for military-grade security
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            # Secure null-safe conversion with validation
            base_amount = Decimal(str(self.amount or 0))
            tax_amt = Decimal(str(self.tax_amount or 0))
            convenience = Decimal(str(self.convenience_fee or 0))
            discount = Decimal(str(self.discount_amount or 0))
            
            # Validate that all amounts are non-negative for security
            if any(amt < 0 for amt in [base_amount, tax_amt, convenience]) or discount < 0:
                # Log security violation attempt
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Negative amount detected in PaymentHistory ID {self.id}")
                
            # Calculate total with precision control
            total = base_amount + tax_amt + convenience - discount
            
            # Ensure non-negative result for security
            return max(total, Decimal('0.00'))
            
        except (InvalidOperation, ValueError, TypeError) as e:
            # Secure fallback for data integrity
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Payment calculation error for PaymentHistory ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def can_retry(self):
        """Check if payment can be retried"""
        return self.status in ['FAILED', 'EXPIRED'] and self.retry_count < 3

    class Meta:
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['transaction_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['billing_address']),
            models.Index(fields=['gateway_name']),
            models.Index(fields=['payment_type']),
        ]
        ordering = ['-created_at']

class PaymentTransaction(models.Model):
    """Detailed transaction log for each payment attempt"""
    payment = models.ForeignKey(PaymentHistory, on_delete=models.CASCADE, related_name='transactions')
    action = models.CharField(max_length=50)  # e.g., 'authorization', 'capture', 'refund'
    status = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    gateway_response = models.JSONField(null=True)
    error_message = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['payment', 'action']),
            models.Index(fields=['created_at'])
        ]


class Cart(models.Model):
    """
    Cart model representing a user's shopping cart for a specific store.
    Each user can have multiple carts for different stores.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='carts')
    store_id = models.CharField(max_length=100, help_text="Store identifier")
    store_name = models.CharField(max_length=255, blank=True, null=True, help_text="Store name for display")
    
    # Cart metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Shopping session tracking
    session_id = models.CharField(max_length=100, blank=True, null=True, help_text="Session identifier for guest users")
    expires_at = models.DateTimeField(blank=True, null=True, help_text="Cart expiration time")
    
    # Applied discounts and coupons
    applied_coupon = models.CharField(max_length=50, blank=True, null=True)
    coupon_discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    def __str__(self):
        return f"Cart: {self.user.username} - {self.store_name or self.store_id}"
    
    @property
    def total_price(self):
        """
        Calculate total cart price including discounts
        Military-grade null-safety implementation
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            # Secure calculation of cart subtotal
            subtotal = Decimal('0.00')
            for item in self.items.filter(is_saved_for_later=False):
                item_total = item.total_price  # This uses our secure CartItem.total_price
                if isinstance(item_total, (int, float, Decimal)):
                    subtotal += Decimal(str(item_total))
            
            # Secure coupon discount handling
            coupon_discount = Decimal(str(self.coupon_discount or 0))
            
            # Security validation
            if coupon_discount < 0:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Negative coupon discount in Cart ID {self.id}")
                coupon_discount = Decimal('0.00')
            
            # Calculate final total
            total = subtotal - coupon_discount
            return max(total, Decimal('0.00'))
            
        except (InvalidOperation, ValueError, TypeError) as e:
            # Secure fallback for data integrity
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Cart total_price calculation error for ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def subtotal(self):
        """
        Calculate cart subtotal before discounts
        Military-grade null-safety implementation
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            subtotal = Decimal('0.00')
            for item in self.items.filter(is_saved_for_later=False):
                item_total = item.total_price  # Uses secure CartItem method
                if isinstance(item_total, (int, float, Decimal)):
                    subtotal += Decimal(str(item_total))
            
            # Overflow protection
            MAX_CART_SUBTOTAL = Decimal('1000000.00')  # ₹10 Lakh max
            if subtotal > MAX_CART_SUBTOTAL:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Cart subtotal exceeds limit for ID {self.id}: ₹{subtotal}")
                return MAX_CART_SUBTOTAL
                
            return subtotal
            
        except (InvalidOperation, ValueError, TypeError) as e:
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Cart subtotal calculation error for ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def item_count(self):
        """
        Get total number of items in cart (excluding saved for later)
        Military-grade null-safety implementation
        """
        try:
            total_count = 0
            for item in self.items.filter(is_saved_for_later=False):
                quantity = item.quantity
                
                # Null-safety and validation
                if isinstance(quantity, int) and quantity > 0:
                    total_count += quantity
                elif quantity is None:
                    # Secure fallback - treat null quantity as 1
                    total_count += 1
                    import logging
                    logger = logging.getLogger('authentication.security')
                    logger.warning(f"Security Alert: Null quantity in CartItem ID {item.id}")
            
            # Overflow protection
            MAX_CART_ITEMS = 999
            if total_count > MAX_CART_ITEMS:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Cart item count exceeds limit for ID {self.id}: {total_count}")
                return MAX_CART_ITEMS
                
            return total_count
            
        except (ValueError, TypeError, AttributeError) as e:
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Cart item_count calculation error for ID {self.id}: {str(e)}")
            return 0
    
    @property
    def saved_item_count(self):
        """
        Get number of items saved for later
        Military-grade null-safety implementation
        """
        try:
            total_saved = 0
            for item in self.items.filter(is_saved_for_later=True):
                quantity = item.quantity
                
                # Null-safety and validation
                if isinstance(quantity, int) and quantity > 0:
                    total_saved += quantity
                elif quantity is None:
                    # Secure fallback - treat null quantity as 1
                    total_saved += 1
                    import logging
                    logger = logging.getLogger('authentication.security')
                    logger.warning(f"Security Alert: Null quantity in saved item ID {item.id}")
            
            # Overflow protection
            MAX_SAVED_ITEMS = 999
            if total_saved > MAX_SAVED_ITEMS:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Saved items exceed limit for Cart ID {self.id}: {total_saved}")
                return MAX_SAVED_ITEMS
                
            return total_saved
            
        except (ValueError, TypeError, AttributeError) as e:
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Cart saved_item_count calculation error for ID {self.id}: {str(e)}")
            return 0
    
    @property
    def total_discount(self):
        """
        Calculate total discount amount
        Military-grade null-safety implementation
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            # Secure calculation of item discounts
            item_discounts = Decimal('0.00')
            for item in self.items.filter(is_saved_for_later=False):
                item_discount = item.discount_amount
                
                # Null-safe discount handling
                if isinstance(item_discount, (int, float, Decimal)) and item_discount >= 0:
                    item_discounts += Decimal(str(item_discount))
                elif item_discount is None:
                    # Null discount is treated as zero
                    continue
                elif item_discount < 0:
                    # Negative discount protection
                    import logging
                    logger = logging.getLogger('authentication.security')
                    logger.warning(f"Security Alert: Negative item discount in CartItem ID {item.id}")
                    continue
            
            # Secure coupon discount handling
            coupon_discount = Decimal(str(self.coupon_discount or 0))
            
            # Security validation for coupon discount
            if coupon_discount < 0:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Negative coupon discount in Cart ID {self.id}")
                coupon_discount = Decimal('0.00')
            
            total_discount = item_discounts + coupon_discount
            
            # Overflow protection
            MAX_DISCOUNT = Decimal('500000.00')  # ₹5 Lakh max
            if total_discount > MAX_DISCOUNT:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Total discount exceeds limit for Cart ID {self.id}: ₹{total_discount}")
                return MAX_DISCOUNT
                
            return total_discount
            
        except (InvalidOperation, ValueError, TypeError) as e:
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"Cart total_discount calculation error for ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def is_empty(self):
        """Check if cart is empty"""
        return not self.items.filter(is_saved_for_later=False).exists()
    
    def clear_cart(self):
        """Remove all items from cart (not saved for later)"""
        self.items.filter(is_saved_for_later=False).delete()
        self.applied_coupon = None
        self.coupon_discount = 0
        self.save(update_fields=['applied_coupon', 'coupon_discount'])
    
    def apply_coupon(self, coupon_code, discount_amount):
        """Apply coupon to cart"""
        self.applied_coupon = coupon_code
        self.coupon_discount = discount_amount
        self.save(update_fields=['applied_coupon', 'coupon_discount'])
    
    def remove_coupon(self):
        """Remove applied coupon"""
        self.applied_coupon = None
        self.coupon_discount = 0
        self.save(update_fields=['applied_coupon', 'coupon_discount'])
    
    @classmethod
    def get_max_carts_per_user(cls):
        """Get maximum number of carts allowed per user"""
        return getattr(settings, 'MAX_CARTS_PER_USER', 5)
    
    @classmethod
    def can_create_new_cart(cls, user):
        """Check if user can create a new cart"""
        current_cart_count = cls.objects.filter(user=user).count()
        max_carts = cls.get_max_carts_per_user()
        return current_cart_count < max_carts
    
    @classmethod
    def get_or_create_cart(cls, user, store_id, store_name=None):
        """
        Get existing cart for store or create new one if allowed
        Returns tuple (cart, created, error_message)
        """
        try:
            # Try to get existing cart for this store
            cart = cls.objects.get(user=user, store_id=store_id)
            return cart, False, None
        except cls.DoesNotExist:
            # Check if user can create new cart
            if not cls.can_create_new_cart(user):
                max_carts = cls.get_max_carts_per_user()
                return None, False, f"Maximum cart limit reached. You can have up to {max_carts} carts from different stores."
            
            # Create new cart
            cart = cls.objects.create(
                user=user,
                store_id=store_id,
                store_name=store_name
            )
            return cart, True, None
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'store_id']),
            models.Index(fields=['updated_at']),
            models.Index(fields=['session_id']),
            models.Index(fields=['expires_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'store_id'],
                name='unique_user_store_cart'
            )
        ]


class CartItem(models.Model):
    """
    CartItem model representing an item in a shopping cart.
    """
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    
    # Product details
    product_id = models.CharField(max_length=100, help_text="Product identifier")
    product_name = models.CharField(max_length=255, blank=True, null=True)
    product_description = models.TextField(blank=True, null=True)
    product_image_url = models.URLField(blank=True, null=True)
    product_sku = models.CharField(max_length=100, blank=True, null=True)
    
    # Product variants and specifications
    product_variant = models.JSONField(
        blank=True, 
        null=True, 
        help_text="Product variants (size, color, weight, etc.)"
    )
    
    # Pricing and quantity
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Price per unit")
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Availability tracking
    is_available = models.BooleanField(default=True, help_text="Whether product is currently available")
    stock_quantity = models.PositiveIntegerField(blank=True, null=True, help_text="Available stock quantity")
    
    # Wishlist functionality
    is_saved_for_later = models.BooleanField(default=False, help_text="Saved for later (wishlist)")
    
    # Timestamps
    added_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        product_name = self.product_name or self.product_id
        return f"{product_name} (x{self.quantity}) - {self.cart.user.username}"
    
    @property
    def total_price(self):
        """
        Calculate total price including discount
        Military-grade null-safety implementation with overflow protection
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            # Secure null-safe conversion with validation
            unit_price = Decimal(str(self.unit_price or 0))
            quantity = int(self.quantity or 0)
            discount_amount = Decimal(str(self.discount_amount or 0))
            
            # Security validation - prevent negative manipulation
            if unit_price < 0 or quantity < 0 or discount_amount < 0:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Negative value in CartItem ID {self.id}")
                return Decimal('0.00')
            
            # MILITARY-GRADE: Prevent extreme values (buffer overflow protection)
            max_price = Decimal('1000000')  # 10 lakh max per item
            max_quantity = 999  # 999 max quantity per item
            max_discount = Decimal('500000')  # 5 lakh max discount
            
            if unit_price > max_price:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.critical(f"SECURITY BREACH: Extreme price detected in CartItem ID {self.id} - {unit_price}")
                return Decimal('0.00')
            
            if quantity > max_quantity:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.critical(f"SECURITY BREACH: Extreme quantity detected in CartItem ID {self.id} - {quantity}")
                return Decimal('0.00')
            
            if discount_amount > max_discount:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.critical(f"SECURITY BREACH: Extreme discount detected in CartItem ID {self.id} - {discount_amount}")
                return Decimal('0.00')
            
            # Calculate with precision control
            base_total = unit_price * quantity
            total = base_total - discount_amount
            
            # Final overflow protection
            if total > Decimal('999999999'):  # 99.9 crore max total
                import logging
                logger = logging.getLogger('authentication.security')
                logger.critical(f"SECURITY BREACH: Total overflow detected in CartItem ID {self.id} - {total}")
                return Decimal('0.00')
            
            # Ensure non-negative result
            return max(total, Decimal('0.00'))
            
        except (InvalidOperation, ValueError, TypeError) as e:
            # Secure fallback for data integrity
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"CartItem calculation error for ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def subtotal(self):
        """
        Calculate subtotal before discount
        Military-grade null-safety implementation
        """
        from decimal import Decimal, InvalidOperation
        
        try:
            # Secure null-safe conversion with validation
            unit_price = Decimal(str(self.unit_price or 0))
            quantity = int(self.quantity or 0)
            
            # Security validation - prevent negative manipulation
            if unit_price < 0 or quantity < 0:
                import logging
                logger = logging.getLogger('authentication.security')
                logger.warning(f"Security Alert: Negative value in CartItem subtotal ID {self.id}")
                return Decimal('0.00')
            
            # Calculate with precision control
            return unit_price * quantity
            
        except (InvalidOperation, ValueError, TypeError) as e:
            # Secure fallback for data integrity
            import logging
            logger = logging.getLogger('authentication.security')
            logger.error(f"CartItem subtotal calculation error for ID {self.id}: {str(e)}")
            return Decimal('0.00')
    
    @property
    def is_in_stock(self):
        """Check if item is in stock"""
        if self.stock_quantity is None:
            return self.is_available
        return self.is_available and self.stock_quantity >= self.quantity
    
    def clean(self):
        """Custom validation"""
        if self.quantity <= 0:
            raise ValidationError({'quantity': 'Quantity must be greater than 0.'})
        
        if self.unit_price < 0:
            raise ValidationError({'unit_price': 'Unit price cannot be negative.'})
        
        if self.stock_quantity is not None and self.quantity > self.stock_quantity:
            raise ValidationError({'quantity': f'Only {self.stock_quantity} items available in stock.'})
        
        if self.discount_amount > self.subtotal:
            raise ValidationError({'discount_amount': 'Discount amount cannot exceed the subtotal.'})

    def decrement_stock(self):
        if self.stock_quantity is not None:
            self.stock_quantity -= self.quantity
            self.save(update_fields=['stock_quantity'])
    
    class Meta:
        indexes = [
            models.Index(fields=['cart']),
            models.Index(fields=['product_id']),
            models.Index(fields=['added_at']),
            models.Index(fields=['is_available']),
            models.Index(fields=['is_saved_for_later']),
        ]
        unique_together = ['cart', 'product_id', 'product_variant']


class Order(models.Model):
    """Order model representing a customer's order"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    
    # Order identification
    order_number = models.CharField(max_length=50, unique=True, help_text="Unique order number")
    order_date = models.DateTimeField(auto_now_add=True)
    
    # Enhanced order status
    status = models.CharField(
        max_length=25, 
        choices=[
            ('PLACED', 'Placed'),
            ('CONFIRMED', 'Confirmed'),
            ('PAID', 'Paid'),
            ('PROCESSING', 'Processing'),
            ('PACKED', 'Packed'),
            ('SHIPPED', 'Shipped'),
            ('OUT_FOR_DELIVERY', 'Out for Delivery'),
            ('DELIVERED', 'Delivered'),
            ('RETURNED', 'Returned'),
            ('CANCELLED', 'Cancelled'),
            ('REFUNDED', 'Refunded'),
        ],
        default='PLACED'
    )
    
    # Shipping details
    shipping_address = models.ForeignKey(
        UserAddress, 
        on_delete=models.PROTECT, 
        related_name='shipping_orders',
        null=True,
        blank=True,
        help_text="Detailed shipping address"
    )
    
    # Delivery tracking
    tracking_number = models.CharField(max_length=100, blank=True, null=True)
    carrier_name = models.CharField(max_length=100, blank=True, null=True)
    estimated_delivery_date = models.DateTimeField(blank=True, null=True)
    actual_delivery_date = models.DateTimeField(blank=True, null=True)
    
    # Delivery preferences
    delivery_instructions = models.TextField(blank=True, null=True, help_text="Special delivery instructions")
    preferred_delivery_time = models.CharField(
        max_length=20,
        choices=[
            ('MORNING', '9 AM - 12 PM'),
            ('AFTERNOON', '12 PM - 6 PM'),
            ('EVENING', '6 PM - 9 PM'),
            ('ANYTIME', 'Anytime'),
        ],
        default='ANYTIME'
    )
    
    # Financial details
    subtotal = models.DecimalField(max_digits=12, decimal_places=2, help_text="Subtotal before taxes and shipping")
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Total tax amount")
    shipping_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Shipping cost")
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, help_text="Total discount amount")
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, help_text="Final total amount")
    
    # Discount and coupon tracking
    coupon_code = models.CharField(max_length=50, blank=True, null=True)
    coupon_discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Order metadata
    notes = models.TextField(blank=True, null=True, help_text="Internal order notes")
    cancellation_reason = models.TextField(blank=True, null=True)
    cancelled_at = models.DateTimeField(blank=True, null=True)
    
    # Timestamps
    confirmed_at = models.DateTimeField(blank=True, null=True)
    shipped_at = models.DateTimeField(blank=True, null=True)
    delivered_at = models.DateTimeField(blank=True, null=True)
    
    def save(self, *args, **kwargs):
        if not self.order_number:
            self.order_number = self.generate_order_number()
        super().save(*args, **kwargs)
    
    def generate_order_number(self):
        """Generate unique order number"""
        from datetime import datetime
        import random
        timestamp = datetime.now().strftime('%Y%m%d')
        random_part = random.randint(1000, 9999)
        return f"ORD-{timestamp}-{random_part}"
    
    def __str__(self):
        return f"Order {self.order_number} - {self.user.username}"
    
    @property
    def is_complete(self):
        return self.status == 'DELIVERED'
    
    @property
    def can_cancel(self):
        return self.status in ['PLACED', 'CONFIRMED', 'PAID'] and not self.shipped_at
    
    @property
    def can_return(self):
        return self.status == 'DELIVERED' and self.delivered_at
    
    @property
    def item_count(self):
        """Get total number of items in order"""
        return sum(item.quantity for item in self.items.all())
    
    def calculate_totals(self):
        """Recalculate order totals based on items"""
        self.subtotal = sum(item.total_price for item in self.items.all())
        self.total_amount = self.subtotal + self.tax_amount + self.shipping_cost - self.discount_amount - self.coupon_discount
        self.save(update_fields=['subtotal', 'total_amount'])
    
    def clean(self):
        """Custom validation for Order model"""
        super().clean()
        if self.total_amount < 0:
            raise ValidationError({'total_amount': 'Total amount cannot be negative.'})
        
        if self.coupon_discount > self.subtotal:
            raise ValidationError({'coupon_discount': 'Coupon discount cannot exceed subtotal.'})
        
        if self.discount_amount < 0:
            raise ValidationError({'discount_amount': 'Discount amount cannot be negative.'})
    
    def cancel_order(self, reason):
        if self.can_cancel:
            self.status = 'CANCELLED'
            self.cancellation_reason = reason
            self.cancelled_at = timezone.now()
            self.save(update_fields=['status', 'cancellation_reason', 'cancelled_at'])

    def return_order(self):
        if self.can_return:
            self.status = 'RETURNED'
            self.save(update_fields=['status'])
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['order_date']),
            models.Index(fields=['status']),
            models.Index(fields=['shipping_address']),
            models.Index(fields=['order_number']),
            models.Index(fields=['tracking_number']),
        ]
        ordering = ['-order_date']

class OrderItem(models.Model):
    """OrderItem model representing individual items in an order"""
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    
    # Product details
    product_id = models.CharField(max_length=100, help_text="Product identifier")
    product_name = models.CharField(max_length=255, help_text="Product name at time of order")
    product_description = models.TextField(blank=True, null=True, help_text="Product description")
    product_image_url = models.URLField(blank=True, null=True)
    
    # Product variants and specifications
    product_sku = models.CharField(max_length=100, blank=True, null=True, help_text="Product SKU")
    product_variant = models.JSONField(
        blank=True, 
        null=True, 
        help_text="Product variants (size, color, weight, etc.)"
    )
    
    # Pricing
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Price per unit")
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Item status tracking
    status = models.CharField(
        max_length=20,
        choices=[
            ('PENDING', 'Pending'),
            ('CONFIRMED', 'Confirmed'),
            ('PACKED', 'Packed'),
            ('SHIPPED', 'Shipped'),
            ('DELIVERED', 'Delivered'),
            ('RETURNED', 'Returned'),
            ('CANCELLED', 'Cancelled'),
        ],
        default='PENDING'
    )
    
    # Fulfillment details
    weight = models.DecimalField(max_digits=8, decimal_places=3, blank=True, null=True, help_text="Item weight in kg")
    dimensions = models.JSONField(blank=True, null=True, help_text="Item dimensions (length, width, height)")
    
    def __str__(self):
        return f"{self.order.order_number} - {self.product_name} (x{self.quantity})"
    
    @property
    def total_price(self):
        """Calculate total price including tax and discount"""
        if self.unit_price is None or self.quantity is None:
            return 0
        base_total = self.unit_price * self.quantity
        tax_amount = self.tax_amount or 0
        discount_amount = self.discount_amount or 0
        return base_total + tax_amount - discount_amount
    
    @property
    def subtotal(self):
        """Calculate subtotal before tax and discount"""
        if self.unit_price is None or self.quantity is None:
            return 0
        return self.unit_price * self.quantity
    
    def clean(self):
        """Custom validation"""
        if self.quantity <= 0:
            raise ValidationError({'quantity': 'Quantity must be greater than 0.'})
        
        if self.unit_price < 0:
            raise ValidationError({'unit_price': 'Unit price cannot be negative.'})
    
    class Meta:
        indexes = [
            models.Index(fields=['order']),
            models.Index(fields=['product_id']),
            models.Index(fields=['status']),
            models.Index(fields=['product_sku']),
        ]

class SearchHistoryGroup(models.Model):
    """
    SearchHistoryGroup model representing a user's search history collection.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='search_history_group')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Search History: {self.user.username}"
    
    @property
    def search_count(self):
        """Get the total number of searches"""
        return self.searches.count()
    
    @property
    def recent_searches(self):
        """Get the 5 most recent searches"""
        return self.searches.all().order_by('-searched_at')[:5]
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['updated_at']),
        ]


class SearchHistory(models.Model):
    """
    SearchHistory model representing an individual search query.
    """
    search_group = models.ForeignKey(SearchHistoryGroup, on_delete=models.CASCADE, related_name='searches')
    query = models.CharField(max_length=255)
    searched_at = models.DateTimeField(auto_now_add=True)
    results_count = models.IntegerField(default=0)
    category = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return f"{self.search_group.user.username} - {self.query}"
    
    class Meta:
        indexes = [
            models.Index(fields=['search_group']),
            models.Index(fields=['query']),
            models.Index(fields=['searched_at']),
            models.Index(fields=['category']),
        ]


class CustomerSupportTicket(models.Model):
    """CustomerSupportTicket model for handling customer support conversations"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='support_tickets')
    subject = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('OPEN', 'Open'),
            ('IN_PROGRESS', 'In Progress'),
            ('RESOLVED', 'Resolved'),
            ('CLOSED', 'Closed')
        ],
        default='OPEN'
    )
    priority = models.CharField(
        max_length=10,
        choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High')],
        default='MEDIUM',
        help_text='Priority of the ticket'
    )
    
    def __str__(self):
        return f"Ticket #{self.id}: {self.subject} ({self.user.username})"
    
    @property
    def is_active(self):
        return self.status in ['OPEN', 'IN_PROGRESS']
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at'])
        ]

class CustomerChat(models.Model):
    """CustomerChat model for individual support messages"""
    ticket = models.ForeignKey(CustomerSupportTicket, on_delete=models.CASCADE, related_name='messages')
    message = models.TextField()
    is_user_message = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    attachment_url = models.URLField(blank=True, null=True)
    
    def __str__(self):
        sender = "Customer" if self.is_user_message else "Support"
        return f"Ticket #{self.ticket.id} - {sender} Message"
    
    def clean(self):
        if not self.message.strip():
            raise ValidationError({'message': 'Message cannot be empty.'})
    
    class Meta:
        indexes = [
            models.Index(fields=['ticket']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['is_user_message'])
        ]
        ordering = ['timestamp']


class JWTSession(models.Model):
    """
    JWT Session tracking model for managing JWT token sessions
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='jwt_sessions')
    jti = models.CharField(max_length=100, unique=True, help_text="JWT ID from token")
    
    # Device and session tracking
    device_type = models.CharField(
        max_length=20,
        choices=[
            ('ANDROID', 'Android App'),
            ('WEB', 'Web Browser'),
            ('IOS', 'iOS App'),
            ('API', 'API Client'),
        ],
        default='API'
    )
    device_id = models.CharField(max_length=255, blank=True, null=True, help_text="Unique device identifier")
    user_agent = models.TextField(blank=True, null=True, help_text="User agent string")
    ip_address = models.GenericIPAddressField(blank=True, null=True, help_text="IP address when session was created")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(help_text="When the JWT token expires")
    
    # Status
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['jti']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['device_type']),
            models.Index(fields=['device_id']),
        ]
    
    def __str__(self):
        return f"JWT Session - {self.user.username} ({self.device_type})"
    
    @property
    def is_expired(self):
        """Check if the JWT session has expired"""
        return timezone.now() >= self.expires_at
    
    def update_activity(self):
        """Update the last activity timestamp"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])
    
    def terminate(self):
        """Terminate the session"""
        self.is_active = False
        self.save(update_fields=['is_active'])
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Clean up expired sessions"""
        expired_sessions = cls.objects.filter(expires_at__lt=timezone.now())
        count = expired_sessions.count()
        expired_sessions.delete()
        return count
