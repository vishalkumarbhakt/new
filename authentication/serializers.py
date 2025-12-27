from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
import re
import hashlib
from .models import (
    Cart, CartItem, Order, OrderItem, SearchHistoryGroup, 
    SearchHistory, CustomerSupportTicket, CustomerChat, CardPaymentMethod, 
    UPIPaymentMethod, PaymentHistory, PaymentTransaction, UserAddress, ExpiringToken,
    JWTSession
)
from .email_validators import validate_secure_email

User = get_user_model()

class UserAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAddress
        fields = (
            'id', 'contact_name', 'street_address', 'street_address_2', 
            'city', 'state', 'pin_code', 'country', 'country_code', 'phone_number', 
            'address_type', 'is_default', 'full_address', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'full_address', 'created_at', 'updated_at')
    
    def validate_pin_code(self, value):
        """Validate PIN code format"""
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("PIN code must be exactly 6 digits")
        return value
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        if not value:
            return value
        
        if not re.match(r'^\d{10}$', value):
            raise serializers.ValidationError("Phone number must be exactly 10 digits")
        return value
    
    def validate_country_code(self, value):
        """Validate country code format"""
        if not value:
            return '+91'  # Default to India
        
        if not re.match(r'^\+\d{1,4}$', value):
            raise serializers.ValidationError(
                "Country code must start with + and be 1-4 digits (e.g., +91, +1)"
            )
        
        return value
    
    def create(self, validated_data):
        """Create address and ensure user is set"""
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'first_name', 'last_name', 'phone_number', 'country_code')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }
    
    def validate_email(self, value):
        """Validate email with comprehensive security checks"""
        # First, run our secure email validation
        try:
            validated_email = validate_secure_email(value)
        except serializers.ValidationError as e:
            raise e
        except Exception as e:
            raise serializers.ValidationError(f"Email validation error: {str(e)}")
        
        # Check for uniqueness
        if User.objects.filter(email=validated_email).exists():
            raise serializers.ValidationError("A user with that email address already exists.")
        
        return validated_email
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        if not value:
            return value
        
        # Format validation - exactly 10 digits
        if not re.match(r'^\d{10}$', value):
            raise serializers.ValidationError(
                "Phone number must be exactly 10 digits (without country code)"
            )
        
        return value
    
    def validate(self, attrs):
        """Validate phone number uniqueness with country code"""
        phone_number = attrs.get('phone_number')
        country_code = attrs.get('country_code', '+91')
        
        # Check for uniqueness of phone number + country code combination
        if phone_number and User.objects.filter(
            phone_number=phone_number, 
            country_code=country_code
        ).exists():
            raise serializers.ValidationError({
                'phone_number': "A user with this phone number already exists for this country."
            })
        
        return attrs
    
    def validate_country_code(self, value):
        """Validate country code format"""
        if not value:
            return '+91'  # Default to India
        
        if not re.match(r'^\+\d{1,4}$', value):
            raise serializers.ValidationError(
                "Country code must start with + and be 1-4 digits (e.g., +91, +1)"
            )
        
        return value
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_number=validated_data.get('phone_number', ''),
            country_code=validated_data.get('country_code', '+91')
        )
        return user


class CustomerChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerChat
        fields = ('id', 'message', 'is_user_message', 'timestamp', 'attachment_url')
        read_only_fields = ('id', 'timestamp')


class SearchHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = SearchHistory
        fields = ('id', 'query', 'searched_at', 'results_count', 'category')
        read_only_fields = ('id', 'searched_at')


class SearchHistoryGroupSerializer(serializers.ModelSerializer):
    searches = SearchHistorySerializer(many=True, read_only=True)
    
    class Meta:
        model = SearchHistoryGroup
        fields = ('id', 'created_at', 'updated_at', 'searches', 'search_count', 'recent_searches')
        read_only_fields = ('id', 'created_at', 'updated_at', 'search_count')


class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = None  # Abstract base serializer
        fields = ('id', 'is_active', 'is_default', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')


class CardPaymentMethodSerializer(PaymentMethodSerializer):
    class Meta(PaymentMethodSerializer.Meta):
        model = CardPaymentMethod
        fields = PaymentMethodSerializer.Meta.fields + (
            'card_type', 'last_four', 'expiry_month', 'expiry_year',
            'card_holder_name', 'card_nickname'
        )


class UPIPaymentMethodSerializer(PaymentMethodSerializer):
    class Meta(PaymentMethodSerializer.Meta):
        model = UPIPaymentMethod
        fields = PaymentMethodSerializer.Meta.fields + ('upi_id', 'upi_nickname')


class PaymentTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentTransaction
        fields = ('id', 'action', 'status', 'amount', 'error_message', 'created_at')
        read_only_fields = ('id', 'created_at')


class PaymentHistorySerializer(serializers.ModelSerializer):
    transactions = PaymentTransactionSerializer(many=True, read_only=True)
    order_id = serializers.SerializerMethodField()
    billing_address_details = UserAddressSerializer(source='billing_address', read_only=True)
    
    class Meta:
        model = PaymentHistory
        fields = (
            'id', 'amount', 'currency', 'status', 'payment_type',
            'transaction_id', 'payment_gateway_order_id', 'payment_method_id', 
            'billing_address', 'billing_address_details', 
            'description', 'created_at', 'updated_at', 'transactions', 'order_id'
        )
        read_only_fields = ('id', 'created_at', 'updated_at', 'transactions', 'order_id')
    
    def validate_amount(self, value):
        """
        Military-grade payment amount validation
        Prevent financial manipulation attacks
        """
        from decimal import Decimal, InvalidOperation
        import logging
        logger = logging.getLogger('authentication.security')
        
        # Basic null validation
        if value is None:
            raise serializers.ValidationError("Payment amount cannot be null")
        
        # Type and format validation
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            logger.warning(f"Security Alert: Invalid payment amount format attempted: {value}")
            raise serializers.ValidationError("Invalid payment amount format")
        
        # Range validation
        if amount < Decimal('0.01'):
            logger.warning(f"Security Alert: Negative/zero payment amount attempted: {amount}")
            raise serializers.ValidationError("Payment amount must be at least ₹0.01")
        
        # Overflow protection
        MAX_PAYMENT_AMOUNT = Decimal('1000000.00')  # ₹10 Lakh max
        if amount > MAX_PAYMENT_AMOUNT:
            logger.critical(f"Security Alert: Excessive payment amount attempted: ₹{amount}")
            raise serializers.ValidationError(f"Payment amount cannot exceed ₹{MAX_PAYMENT_AMOUNT}")
        
        # Precision validation
        if amount.as_tuple().exponent < -2:
            logger.warning(f"Security Alert: Excessive payment precision attempted: {amount}")
            raise serializers.ValidationError("Payment amount precision limited to 2 decimal places")
        
        return amount
        
    def get_order_id(self, obj):
        if obj.order:
            return obj.order.id
        return None

class CartItemSerializer(serializers.ModelSerializer):
    store_id = serializers.CharField(write_only=True, required=True, help_text="Store identifier for the cart")
    
    class Meta:
        model = CartItem
        fields = ('id', 'product_id', 'quantity', 'added_at', 'unit_price', 'product_name', 'product_image_url', 'total_price', 'store_id')
        read_only_fields = ('id', 'added_at', 'total_price')
    
    def validate_store_id(self, value):
        """Validate store_id is provided"""
        if not value or not value.strip():
            raise serializers.ValidationError("Store ID is required")
        return value.strip()
    
    def validate_quantity(self, value):
        """
        Military-grade quantity validation
        Prevent price manipulation attacks
        """
        import logging
        logger = logging.getLogger('authentication.security')
        
        # Basic null/type validation
        if value is None:
            raise serializers.ValidationError("Quantity cannot be null")
        
        if not isinstance(value, int):
            logger.warning(f"Security Alert: Non-integer quantity attempted: {value}")
            raise serializers.ValidationError("Quantity must be an integer")
        
        # Range validation
        if value < 1:
            logger.warning(f"Security Alert: Negative/zero quantity attempted: {value}")
            raise serializers.ValidationError("Quantity must be at least 1")
        
        # Overflow protection
        MAX_QUANTITY = 999
        if value > MAX_QUANTITY:
            logger.warning(f"Security Alert: Excessive quantity attempted: {value}")
            raise serializers.ValidationError(f"Quantity cannot exceed {MAX_QUANTITY}")
        
        return value
    
    def validate_unit_price(self, value):
        """
        Military-grade unit price validation
        Prevent price manipulation attacks
        """
        from decimal import Decimal, InvalidOperation
        import logging
        logger = logging.getLogger('authentication.security')
        
        # Basic null validation
        if value is None:
            raise serializers.ValidationError("Unit price cannot be null")
        
        # Type and format validation
        try:
            price = Decimal(str(value))
        except (InvalidOperation, ValueError):
            logger.warning(f"Security Alert: Invalid price format attempted: {value}")
            raise serializers.ValidationError("Invalid price format")
        
        # Range validation
        if price < Decimal('0.01'):
            logger.warning(f"Security Alert: Negative/zero price attempted: {price}")
            raise serializers.ValidationError("Price must be at least ₹0.01")
        
        # Overflow protection
        MAX_UNIT_PRICE = Decimal('100000.00')  # ₹1 Lakh max
        if price > MAX_UNIT_PRICE:
            logger.warning(f"Security Alert: Excessive unit price attempted: ₹{price}")
            raise serializers.ValidationError(f"Unit price cannot exceed ₹{MAX_UNIT_PRICE}")
        
        # Precision validation
        if price.as_tuple().exponent < -2:
            logger.warning(f"Security Alert: Excessive precision attempted: {price}")
            raise serializers.ValidationError("Price precision limited to 2 decimal places")
        
        return price
    
    def create(self, validated_data):
        """Create cart item with store-based cart selection"""
        store_id = validated_data.pop('store_id')
        user = self.context['request'].user
        
        # Get or create cart for this store
        cart, created, error_message = Cart.get_or_create_cart(
            user=user,
            store_id=store_id
        )
        
        if error_message:
            raise serializers.ValidationError({"store_id": error_message})
        
        # Check if item already exists in cart
        product_id = validated_data['product_id']
        product_variant = validated_data.get('product_variant')
        
        try:
            # Try to find existing item
            existing_item = CartItem.objects.get(
                cart=cart,
                product_id=product_id,
                product_variant=product_variant
            )
            # Update quantity instead of creating new item
            existing_item.quantity += validated_data.get('quantity', 1)
            existing_item.save()
            return existing_item
        except CartItem.DoesNotExist:
            # Create new item
            validated_data['cart'] = cart
            return super().create(validated_data)


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    
    class Meta:
        model = Cart
        fields = ('id', 'store_id', 'store_name', 'updated_at', 'items', 'total_price', 'item_count', 'applied_coupon', 'coupon_discount')
        read_only_fields = ('id', 'updated_at', 'total_price', 'item_count')
    
    def validate_store_id(self, value):
        """Validate store_id is provided"""
        if not value or not value.strip():
            raise serializers.ValidationError("Store ID is required")
        return value.strip()


class CartCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new carts"""
    store_id = serializers.CharField(required=True, help_text="Store identifier")
    store_name = serializers.CharField(required=False, allow_blank=True, help_text="Store name for display")
    
    class Meta:
        model = Cart
        fields = ('store_id', 'store_name')
    
    def validate_store_id(self, value):
        """Validate store_id is provided"""
        if not value or not value.strip():
            raise serializers.ValidationError("Store ID is required")
        return value.strip()
    
    def create(self, validated_data):
        """Create cart with store validation and limit checking"""
        user = self.context['request'].user
        store_id = validated_data['store_id']
        store_name = validated_data.get('store_name')
        
        # Use the model's get_or_create_cart method
        cart, created, error_message = Cart.get_or_create_cart(
            user=user,
            store_id=store_id,
            store_name=store_name
        )
        
        if error_message:
            raise serializers.ValidationError(error_message)
        
        return cart


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ('id', 'product_id', 'product_name', 'product_image_url', 'quantity', 'unit_price', 'total_price')
        read_only_fields = ('id', 'total_price')


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    payments = PaymentHistorySerializer(many=True, read_only=True)
    shipping_address_details = UserAddressSerializer(source='shipping_address', read_only=True)
    
    class Meta:
        model = Order
        fields = ('id', 'order_date', 'status', 'shipping_address', 'shipping_address_details',
                 'total_amount', 'items', 'payments', 'is_complete', 'can_cancel')
        read_only_fields = ('id', 'order_date', 'is_complete', 'can_cancel')


class CustomerSupportTicketSerializer(serializers.ModelSerializer):
    messages = CustomerChatSerializer(many=True, read_only=True)
    
    class Meta:
        model = CustomerSupportTicket
        fields = ('id', 'subject', 'created_at', 'updated_at', 'status', 
                 'messages', 'is_active')
        read_only_fields = ('id', 'created_at', 'updated_at', 'is_active')


class UserSerializer(serializers.ModelSerializer):
    profile_image = serializers.SerializerMethodField()
    card_payment_methods = CardPaymentMethodSerializer(many=True, read_only=True)
    upi_payment_methods = UPIPaymentMethodSerializer(many=True, read_only=True)
    payment_history = PaymentHistorySerializer(many=True, read_only=True)
    carts = CartSerializer(many=True, read_only=True)  # Changed from 'cart' to 'carts'
    orders = OrderSerializer(many=True, read_only=True)
    search_history_group = SearchHistoryGroupSerializer(read_only=True)

    support_tickets = CustomerSupportTicketSerializer(many=True, read_only=True)
    saved_addresses = UserAddressSerializer(source='addresses', many=True, read_only=True)
    active_sessions_count = serializers.SerializerMethodField()
    total_carts_count = serializers.SerializerMethodField()
    max_carts_allowed = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 
                 'phone_number', 'country_code', 'profile_image', 'date_joined',
                 'card_payment_methods', 'upi_payment_methods', 'payment_history',
                 'carts', 'orders', 'search_history_group', 'support_tickets', 
                 'saved_addresses', 'active_sessions_count', 'total_carts_count', 'max_carts_allowed')
        read_only_fields = ('id', 'username', 'email', 'date_joined')
    
    def get_profile_image(self, obj):
        if obj.profile_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_image.url)
            return obj.profile_image.url
        return None
    
    def get_active_sessions_count(self, obj):
        """Return the count of active sessions for this user"""
        # Count ExpiringToken sessions
        token_sessions = ExpiringToken.objects.filter(user=obj).count()
        
        # Count JWT sessions
        jwt_sessions = JWTSession.objects.filter(
            user=obj, 
            is_active=True,
            expires_at__gt=timezone.now()
        ).count()
        
        return token_sessions + jwt_sessions
    
    def get_total_carts_count(self, obj):
        """Return the total number of carts for this user"""
        return obj.carts.count()
    
    def get_max_carts_allowed(self, obj):
        """Return the maximum number of carts allowed per user"""
        return Cart.get_max_carts_per_user()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    country_code = serializers.CharField(required=False, max_length=4)
    phone_number = serializers.CharField(required=False, max_length=10)
    password = serializers.CharField(style={'input_type': 'password'})
    device_type = serializers.ChoiceField(
        choices=['ANDROID', 'WEB', 'IOS', 'API'],
        required=False,
        default='API',
        help_text="Device type for session management"
    )
    device_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Unique device identifier for session tracking"
    )
    
    def validate(self, attrs):
        username = attrs.get('username')
        country_code = attrs.get('country_code', '+91')  # Default to India
        phone_number = attrs.get('phone_number')
        email = attrs.get('email')
        password = attrs.get('password')
        device_type = attrs.get('device_type', 'API')
        device_id = attrs.get('device_id')
        
        if not username and not email and not phone_number:
            raise serializers.ValidationError(_("Username, email, or phone number is required."))
        
        # Validate device_id for mobile platforms
        if device_type in ['ANDROID', 'IOS'] and not device_id:
            raise serializers.ValidationError({
                'device_id': _("device_id is required for mobile platforms (ANDROID/IOS)")
            })

        # Find user by username
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise serializers.ValidationError(_("User with this username does not exist."))

        # If phone number is provided but not username, find the user by phone
        if (phone_number and phone_number.isdigit() and len(phone_number) == 10) and not username:
            try:
                user = User.objects.get(country_code=country_code, phone_number=phone_number)
                username = user.username
            except User.DoesNotExist:
                raise serializers.ValidationError(_("User with this phone number does not exist."))

        # If email is provided but not username and phone_number, find the user by email
        if email and not username and not phone_number:
            # Validate email format before attempting lookup
            try:
                validated_email = validate_secure_email(email)
                try:
                    user = User.objects.get(email=validated_email)
                    username = user.username
                except User.DoesNotExist:
                    raise serializers.ValidationError(_("User with this email does not exist."))
            except serializers.ValidationError as e:
                # Re-raise validation errors from email validation
                raise e
            except Exception as e:
                raise serializers.ValidationError(_("Invalid email."))
        
        # Authenticate with username and password
        authenticated_user = authenticate(
            request=self.context.get('request'),
            username=username,
            password=password
        )
        
        if not authenticated_user:
            raise serializers.ValidationError(_("Unable to log in with provided credentials."))
        
        attrs['user'] = authenticated_user
        return attrs


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'phone_number', 'country_code', 'address', 'profile_image')
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        if not value:
            return value
        
        # Format validation - exactly 10 digits
        if not re.match(r'^\d{10}$', value):
            raise serializers.ValidationError(
                "Phone number must be exactly 10 digits (without country code)"
            )
        
        return value
    
    def validate(self, attrs):
        """Validate phone number uniqueness with country code for profile updates"""
        phone_number = attrs.get('phone_number')
        country_code = attrs.get('country_code', '+91')
        user = self.instance
        
        # Check for uniqueness of phone number + country code combination (exclude current user)
        if phone_number and User.objects.filter(
            phone_number=phone_number, 
            country_code=country_code
        ).exclude(id=user.id if user else None).exists():
            raise serializers.ValidationError({
                'phone_number': "A user with this phone number already exists for this country."
            })
        
        return attrs
    
    def validate_country_code(self, value):
        """Validate country code format"""
        if not value:
            return '+91'  # Default to India
        
        if not re.match(r'^\+\d{1,4}$', value):
            raise serializers.ValidationError(
                "Country code must start with + and be 1-4 digits (e.g., +91, +1)"
            )
        
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        """Validate email with security checks before password reset"""
        # First, run our secure email validation
        try:
            validated_email = validate_secure_email(value)
        except serializers.ValidationError as e:
            raise e
        except Exception as e:
            raise serializers.ValidationError(f"Email validation error: {str(e)}")
        
        # Check if user exists
        if not User.objects.filter(email=validated_email).exists():
            raise serializers.ValidationError(_("User with this email does not exist."))
        
        return validated_email


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=False)
    otp = serializers.CharField(max_length=6, required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(required=True, validators=[validate_password])
    
    def validate(self, data):
        token = data.get('token')
        otp = data.get('otp')
        email = data.get('email')
        
        # Either token OR (email AND otp) must be provided
        if not token and not (email and otp):
            raise serializers.ValidationError({
                'non_field_errors': [_("Either token or (email and otp) must be provided.")]
            })
        
        if token and (email or otp):
            raise serializers.ValidationError({
                'non_field_errors': [_("Provide either token or (email and otp), not both.")]
            })
            
        return data
    
    def validate_token(self, value):
        if not value:
            return value
        try:
            hashed_token = hashlib.sha256(value.encode()).hexdigest()
            user = User.objects.get(reset_password_token=hashed_token)
            if user.reset_password_expires and user.reset_password_expires < timezone.now():
                raise serializers.ValidationError(_("Reset token has expired."))
        except User.DoesNotExist:
            raise serializers.ValidationError(_("Invalid reset token."))
        return value
    
    def validate_otp(self, value):
        if not value:
            return value
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError(_("OTP must be exactly 6 digits."))
        return value


class SessionSerializer(serializers.ModelSerializer):
    device_info = serializers.SerializerMethodField()
    last_activity = serializers.SerializerMethodField()
    
    class Meta:
        model = ExpiringToken
        fields = ('id', 'device_type', 'device_id', 'created_at', 'last_used', 
                 'expiry', 'ip_address', 'device_info', 'last_activity')
        read_only_fields = ('id', 'created_at', 'last_used', 'expiry')
    
    def get_device_info(self, obj):
        return {
            'type': obj.device_type,
            'id': obj.device_id,
            'user_agent': obj.user_agent[:100] if obj.user_agent else None  # Truncate for security
        }
    
    def get_last_activity(self, obj):
        if obj.last_used:
            return obj.last_used
        return obj.created_at


class JWTSessionSerializer(serializers.ModelSerializer):
    """Serializer for JWT Session data"""
    is_current_session = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = JWTSession
        fields = ('id', 'device_type', 'device_id', 'user_agent', 'ip_address', 
                 'created_at', 'last_activity', 'expires_at', 'is_active', 
                 'is_current_session', 'is_expired')
        read_only_fields = ('id', 'created_at', 'last_activity', 'expires_at')
    
    def get_is_current_session(self, obj):
        """Check if this is the current session based on JWT token"""
        request = self.context.get('request')
        if not request or not hasattr(request, 'auth'):
            return False
        
        # For JWT authentication, check if the JTI matches
        if hasattr(request.auth, 'payload'):
            current_jti = request.auth.payload.get('jti')
            return obj.jti == current_jti
        
        return False
    
    def get_is_expired(self, obj):
        """Check if the session is expired"""
        return obj.is_expired


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)
    device_id = serializers.CharField(required=False)
    all_devices = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        if not attrs.get('refresh_token') and not attrs.get('device_id'):
            raise serializers.ValidationError(
                "Either refresh_token or device_id must be provided"
            )
        return attrs


class SessionTerminateSerializer(serializers.Serializer):
    session_id = serializers.CharField(required=True)
    
    def validate_session_id(self, value):
        user = self.context['request'].user
        try:
            session = ExpiringToken.objects.get(id=value, user=user)
            return value
        except ExpiringToken.DoesNotExist:
            raise serializers.ValidationError("Invalid session ID")
    """Serializer for displaying active user sessions"""
    is_current_session = serializers.SerializerMethodField()
    last_activity = serializers.SerializerMethodField()
    
    class Meta:
        model = ExpiringToken
        fields = (
            'device_type', 'device_id', 'user_agent', 'ip_address', 
            'created_at', 'is_current_session', 'last_activity'
        )
        read_only_fields = ('created_at',)
    
    def get_is_current_session(self, obj):
        """Check if this is the current session token"""
        request = self.context.get('request')
        if request and hasattr(request, 'auth'):
            return request.auth == obj
        return False
    
    def get_last_activity(self, obj):
        """Return the token creation time as last activity"""
        return obj.created_at


class LogoutSerializer(serializers.Serializer):
    """Serializer for logout requests with session management options"""
    logout_type = serializers.ChoiceField(
        choices=['current', 'device_type', 'all'],
        default='current',
        help_text="Type of logout: 'current' session, all sessions for 'device_type', or 'all' sessions"
    )
    device_type = serializers.ChoiceField(
        choices=['ANDROID', 'WEB', 'IOS', 'API'],
        required=False,
        help_text="Required when logout_type is 'device_type'"
    )
    
    def validate(self, attrs):
        logout_type = attrs.get('logout_type')
        device_type = attrs.get('device_type')
        
        if logout_type == 'device_type' and not device_type:
            raise serializers.ValidationError(
                _("device_type is required when logout_type is 'device_type'")
            )
        
        return attrs


class SessionTerminateSerializer(serializers.Serializer):
    """Serializer for terminating specific sessions"""
    device_type = serializers.ChoiceField(
        choices=['ANDROID', 'WEB', 'IOS', 'API'],
        help_text="Device type of session to terminate"
    )
    device_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Specific device ID to terminate (optional)"
    )


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT token serializer with device tracking and enhanced user data
    Supports login with username, email, or phone number
    """
    username_field = 'username'
    
    # Add email and phone fields to accept email/phone-based login
    country_code = serializers.CharField(
        required=False, 
        max_length=4, 
        help_text="Country code for phone number (e.g., +91)"
    )
    phone_number = serializers.CharField(
        required=False, 
        max_length=10,
        help_text="10-digit phone number for login"
    )
    email = serializers.EmailField(required=False, help_text="Email address for login")
    password = serializers.CharField(style={'input_type': 'password'})
    
    device_type = serializers.ChoiceField(
        choices=['ANDROID', 'WEB', 'IOS', 'API'],
        required=False,
        default='API',
        help_text="Device type for session management"
    )
    device_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Unique device identifier for session tracking"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Override the username field to accept username, email, or phone
        self.fields[self.username_field] = serializers.CharField(
            required=False,
            help_text="Username, email address, or phone number"
        )
    
    def validate(self, attrs):
        # Get username, email, phone_number, and password from request
        username = attrs.get(self.username_field)
        country_code = attrs.get('country_code', '+91')  # Default to India
        phone_number = attrs.get('phone_number')
        email = attrs.get('email')
        password = attrs.get('password')        
        # Get device information
        device_type = attrs.get('device_type', 'API')
        device_id = attrs.get('device_id')

        if not username and not email and not phone_number:
            raise serializers.ValidationError(
                _('Must include username, email, or phone_number and password.'),
                code='authorization',
            )
        
        # Validate device_id for mobile platforms
        if device_type in ['ANDROID', 'IOS'] and not device_id:
            raise serializers.ValidationError({
                'device_id': _("device_id is required for mobile platforms (ANDROID/IOS)")
            })

        user = None

        # Find user by username
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    _('No active account found with the given credentials'),
                    code='authorization',
                )

        # If not found by username, check if it's a phone number (10 digits)
        if (phone_number and phone_number.isdigit() and len(phone_number) == 10) and not username:
            try:
                user = User.objects.get(phone_number=phone_number, country_code=country_code)
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    _('No active account found with the given credentials'),
                    code='authorization',
                )
        
        if email and not username and not phone_number:
            # Validate email format before attempting lookup
            try:
                validated_email = validate_secure_email(email)
                try:
                    user = User.objects.get(email=validated_email)
                except User.DoesNotExist:
                    raise serializers.ValidationError(
                        _('No active account found with the given credentials'),
                        code='authorization',
                    )
            except serializers.ValidationError:
                # If email validation fails, don't reveal this - just treat as invalid credentials
                raise serializers.ValidationError(
                    _('No active account found with the given credentials'),
                    code='authorization',
                )
        
        # Check password
        if not user.check_password(password):
            raise serializers.ValidationError(
                _('No active account found with the given credentials'),
                code='authorization',
            )
        
        # Check if user is active
        if not user.is_active:
            raise serializers.ValidationError(
                _('User account is disabled.'),
                code='authorization',
            )
        
        # Set the user for the parent class to use
        self.user = user
        
        # Override the attrs to use the correct username for the parent class
        attrs[self.username_field] = user.username
        
        data = super().validate(attrs)
        
        # Add custom claims to the token
        refresh = self.get_token(self.user)
        refresh['device_type'] = device_type
        refresh['device_id'] = device_id or ''
        refresh['user_email'] = self.user.email
        refresh['user_verified'] = self.user.is_verified
        
        # Store device information for tracking (optional)
        if hasattr(self.context.get('request'), 'META'):
            request = self.context.get('request')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip_address = self.get_client_ip(request)
            
            # You can optionally store this information for session tracking
            # This creates a record but doesn't interfere with JWT auth
            try:
                ExpiringToken.objects.update_or_create(
                    user=self.user,
                    device_type=device_type,
                    device_id=device_id or '',
                    defaults={
                        'user_agent': user_agent,
                        'ip_address': ip_address,
                        'key': str(refresh.access_token),  # Store access token for reference
                        'expiry': timezone.now() + timezone.timedelta(days=30)
                    }
                )
            except Exception:
                # Don't fail JWT creation if session tracking fails
                pass
        
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['user'] = UserSerializer(self.user, context=self.context).data
        data['device_type'] = device_type
        data['device_id'] = device_id
        
        return data
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        token['is_verified'] = user.is_verified
        
        return token


class JWTRefreshSerializer(serializers.Serializer):
    """
    Custom refresh token serializer with additional validation
    """
    refresh = serializers.CharField()
    
    def validate(self, attrs):
        refresh = RefreshToken(attrs['refresh'])
        data = {'access': str(refresh.access_token)}
        
        if hasattr(refresh, 'blacklist'):
            refresh.blacklist()
        
        return data