from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import (
    User, ExpiringToken, UserAddress, PaymentHistory, PaymentTransaction, 
    Cart, CartItem, Order, OrderItem, SearchHistoryGroup, SearchHistory, 
    CustomerSupportTicket, CustomerChat, CardPaymentMethod, UPIPaymentMethod,
    JWTSession
)

class CustomUserAdmin(UserAdmin):
    list_display = (
        'username', 'email', 'full_name', 'phone_number', 'country_code', 
        'is_verified', 'is_staff', 'is_active', 'failed_login_attempts', 
        'is_locked', 'date_joined'
    )
    list_filter = (
        'is_staff', 'is_superuser', 'is_active', 'is_verified', 'is_locked',
        'gender', 'preferred_language', 'country_code', 'date_joined'
    )
    search_fields = ('username', 'first_name', 'last_name', 'email', 'phone_number')
    readonly_fields = ('date_joined', 'last_login', 'updated_at', 'full_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        (_('Personal info'), {
            'fields': (
                'first_name', 'last_name', 'email', 'phone_number', 'country_code',
                'profile_image', 'date_of_birth', 'gender', 'preferred_language'
            )
        }),
        (_('Notification Preferences'), {
            'fields': ('email_notifications', 'sms_notifications', 'push_notifications'),
            'classes': ('collapse',)
        }),
        (_('Verification & Security'), {
            'fields': (
                'is_verified', 'verification_token', 'verification_otp', 'verification_otp_expires',
                'reset_password_token', 'reset_password_otp', 'reset_password_otp_expires'
            ),
            'classes': ('collapse',)
        }),
        (_('Account Security'), {
            'fields': (
                'failed_login_attempts', 'last_failed_login', 'is_locked', 'locked_until'
            )
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        (_('Important dates'), {
            'fields': ('last_login', 'date_joined', 'updated_at')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'phone_number', 'country_code',
                'first_name', 'last_name', 'password1', 'password2'
            ),
        }),
    )
    
    def full_name(self, obj):
        return obj.full_name or '-'
    full_name.short_description = 'Full Name'
    
    # Custom actions
    def mark_as_verified(self, request, queryset):
        count = queryset.update(is_verified=True)
        self.message_user(request, f'{count} users marked as verified.')
    mark_as_verified.short_description = "Mark selected users as verified"
    
    def unlock_accounts(self, request, queryset):
        count = queryset.update(is_locked=False, locked_until=None, failed_login_attempts=0)
        self.message_user(request, f'{count} user accounts unlocked.')
    unlock_accounts.short_description = "Unlock selected user accounts"
    
    actions = ['mark_as_verified', 'unlock_accounts']

class PaymentTransactionInline(admin.TabularInline):
    model = PaymentTransaction
    extra = 0
    readonly_fields = ('created_at',)

@admin.register(PaymentHistory)
class PaymentHistoryAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'transaction_id', 'amount', 'currency', 'status', 'payment_type', 
        'gateway_name', 'is_successful', 'created_at'
    )
    list_filter = (
        'status', 'payment_type', 'currency', 'gateway_name', 'created_at'
    )
    search_fields = (
        'user__username', 'user__email', 'transaction_id', 
        'payment_gateway_order_id', 'gateway_transaction_id'
    )
    readonly_fields = (
        'transaction_id', 'created_at', 'updated_at', 'is_successful', 
        'is_refundable', 'net_amount', 'total_amount', 'can_retry'
    )
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('user', 'transaction_id', 'amount', 'currency', 'status', 'payment_type')
        }),
        (_('Gateway Details'), {
            'fields': (
                'gateway_name', 'payment_gateway_order_id', 'gateway_transaction_id',
                'payment_method_id', 'gateway_response'
            )
        }),
        (_('Financial Details'), {
            'fields': (
                'tax_amount', 'convenience_fee', 'discount_amount', 
                'total_amount', 'net_amount'
            )
        }),
        (_('Refund Information'), {
            'fields': ('refund_amount', 'refund_reason', 'refund_processed_at'),
            'classes': ('collapse',)
        }),
        (_('Additional Details'), {
            'fields': (
                'billing_address', 'description', 'failure_reason', 
                'retry_count', 'expires_at'
            )
        }),
        (_('Status & Timestamps'), {
            'fields': ('is_successful', 'is_refundable', 'can_retry', 'created_at', 'updated_at')
        })
    )
    
    inlines = [PaymentTransactionInline]
    
    def is_successful(self, obj):
        return obj.is_successful
    is_successful.boolean = True
    is_successful.short_description = 'Successful'

@admin.register(CardPaymentMethod)
class CardPaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'card_type', 'last_four', 'card_holder_name', 'is_default', 'is_active')
    list_filter = ('card_type', 'is_active', 'is_default')
    search_fields = ('user__username', 'card_holder_name')

@admin.register(UPIPaymentMethod)
class UPIPaymentMethodAdmin(admin.ModelAdmin):
    list_display = ('user', 'upi_id', 'upi_nickname', 'is_default', 'is_active')
    list_filter = ('is_active', 'is_default')
    search_fields = ('user__username', 'upi_id')

class CartItemInline(admin.TabularInline):
    model = CartItem
    extra = 0
    readonly_fields = ('added_at', 'updated_at', 'total_price', 'subtotal', 'is_in_stock')
    fields = (
        'product_id', 'product_name', 'quantity', 'unit_price', 'discount_amount',
        'is_available', 'is_saved_for_later', 'total_price', 'subtotal'
    )

@admin.register(Cart)
class CartAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'store_name', 'store_id', 'item_count', 'saved_item_count',
        'subtotal', 'total_price', 'applied_coupon', 'is_empty', 'updated_at'
    )
    list_filter = ('created_at', 'updated_at', 'expires_at')
    search_fields = ('user__username', 'user__email', 'store_id', 'store_name', 'applied_coupon')
    readonly_fields = (
        'created_at', 'updated_at', 'total_price', 'subtotal', 
        'item_count', 'saved_item_count', 'total_discount', 'is_empty'
    )
    ordering = ('-updated_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('user', 'store_id', 'store_name', 'session_id')
        }),
        (_('Pricing & Discounts'), {
            'fields': (
                'applied_coupon', 'coupon_discount', 'subtotal', 
                'total_price', 'total_discount'
            )
        }),
        (_('Cart Statistics'), {
            'fields': ('item_count', 'saved_item_count', 'is_empty')
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at', 'expires_at')
        })
    )
    
    inlines = [CartItemInline]
    
    def is_empty(self, obj):
        return obj.is_empty
    is_empty.boolean = True
    is_empty.short_description = 'Empty'

class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0
    readonly_fields = ('total_price', 'subtotal')
    fields = (
        'product_id', 'product_name', 'product_sku', 'quantity', 
        'unit_price', 'discount_amount', 'tax_amount', 'status',
        'subtotal', 'total_price'
    )

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = (
        'order_number', 'user', 'status', 'total_amount', 'item_count',
        'tracking_number', 'order_date', 'estimated_delivery_date'
    )
    list_filter = (
        'status', 'preferred_delivery_time', 'order_date', 
        'estimated_delivery_date', 'carrier_name'
    )
    search_fields = (
        'order_number', 'user__username', 'user__email', 
        'tracking_number', 'coupon_code'
    )
    readonly_fields = (
        'order_number', 'order_date', 'confirmed_at', 'shipped_at', 
        'delivered_at', 'cancelled_at', 'item_count', 'is_complete',
        'can_cancel', 'can_return'
    )
    ordering = ('-order_date',)
    date_hierarchy = 'order_date'
    
    fieldsets = (
        (_('Order Information'), {
            'fields': ('order_number', 'user', 'status', 'order_date')
        }),
        (_('Shipping Details'), {
            'fields': (
                'shipping_address', 'tracking_number', 'carrier_name',
                'estimated_delivery_date', 'actual_delivery_date',
                'delivery_instructions', 'preferred_delivery_time'
            )
        }),
        (_('Financial Details'), {
            'fields': (
                'subtotal', 'tax_amount', 'shipping_cost', 'discount_amount',
                'coupon_code', 'coupon_discount', 'total_amount'
            )
        }),
        (_('Order Status'), {
            'fields': (
                'is_complete', 'can_cancel', 'can_return', 'item_count'
            )
        }),
        (_('Timestamps'), {
            'fields': (
                'confirmed_at', 'shipped_at', 'delivered_at', 
                'cancelled_at', 'cancellation_reason'
            )
        }),
        (_('Additional Information'), {
            'fields': ('notes',)
        })
    )
    
    inlines = [OrderItemInline]
    
    def is_complete(self, obj):
        return obj.is_complete
    is_complete.boolean = True
    is_complete.short_description = 'Complete'
    
    def can_cancel(self, obj):
        return obj.can_cancel
    can_cancel.boolean = True
    can_cancel.short_description = 'Can Cancel'
    
    def can_return(self, obj):
        return obj.can_return
    can_return.boolean = True
    can_return.short_description = 'Can Return'

class SearchHistoryInline(admin.TabularInline):
    model = SearchHistory
    extra = 0
    readonly_fields = ('searched_at',)

@admin.register(SearchHistoryGroup)
class SearchHistoryGroupAdmin(admin.ModelAdmin):
    list_display = ('user', 'search_count', 'updated_at')
    search_fields = ('user__username',)
    readonly_fields = ('created_at', 'updated_at')
    inlines = [SearchHistoryInline]

class CustomerChatInline(admin.TabularInline):
    model = CustomerChat
    extra = 0
    readonly_fields = ('timestamp',)

@admin.register(CustomerSupportTicket)
class CustomerSupportTicketAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'subject', 'priority', 'status', 'created_at')
    list_filter = ('status', 'priority', 'created_at')
    search_fields = ('user__username', 'subject')
    readonly_fields = ('created_at', 'updated_at')
    inlines = [CustomerChatInline]

@admin.register(CustomerChat)
class CustomerChatAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'is_user_message', 'timestamp')
    list_filter = ('is_user_message', 'timestamp')
    search_fields = ('ticket__subject', 'message')
    readonly_fields = ('timestamp',)

@admin.register(JWTSession)
class JWTSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_type', 'device_id', 'created_at', 'last_activity', 'is_active', 'is_expired')
    list_filter = ('device_type', 'is_active', 'created_at', 'expires_at')
    search_fields = ('user__username', 'user__email', 'device_id', 'jti')
    readonly_fields = ('jti', 'created_at', 'last_activity', 'expires_at')
    
    def is_expired(self, obj):
        return obj.is_expired
    is_expired.boolean = True
    is_expired.short_description = 'Expired'


@admin.register(ExpiringToken)
class ExpiringTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_type', 'device_id', 'created_at', 'expiry', 'last_used', 'ip_address')
    list_filter = ('device_type', 'created_at', 'expiry')
    search_fields = ('user__username', 'user__email', 'device_id', 'ip_address')
    readonly_fields = ('key', 'created_at', 'last_used')
    ordering = ('-created_at',)
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(UserAddress)
class UserAddressAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'contact_name', 'address_type', 'city', 'state', 'pin_code', 
        'country', 'phone_number', 'country_code', 'is_default', 'is_verified'
    )
    list_filter = (
        'address_type', 'is_default', 'is_verified', 'country', 'state'
    )
    search_fields = (
        'user__username', 'user__email', 'contact_name', 'city', 
        'pin_code', 'phone_number', 'street_address'
    )
    readonly_fields = ('created_at', 'updated_at', 'full_address')
    ordering = ('-updated_at',)
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('user', 'contact_name', 'address_type')
        }),
        (_('Address Details'), {
            'fields': (
                'street_address', 'street_address_2', 'landmark',
                'city', 'state', 'pin_code', 'country'
            )
        }),
        (_('Contact Information'), {
            'fields': ('phone_number', 'country_code')
        }),
        (_('Location Coordinates'), {
            'fields': ('latitude', 'longitude'),
            'classes': ('collapse',)
        }),
        (_('Status & Settings'), {
            'fields': ('is_default', 'is_verified')
        }),
        (_('Full Address Preview'), {
            'fields': ('full_address',),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at')
        })
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

# Register all models with the admin site
admin.site.register(User, CustomUserAdmin)

@admin.register(CartItem)
class CartItemAdmin(admin.ModelAdmin):
    list_display = (
        'cart', 'product_name', 'product_id', 'quantity', 'unit_price',
        'discount_amount', 'total_price', 'is_available', 'is_saved_for_later'
    )
    list_filter = (
        'is_available', 'is_saved_for_later', 'added_at', 'cart__store_id'
    )
    search_fields = (
        'product_name', 'product_id', 'product_sku', 
        'cart__user__username', 'cart__store_name'
    )
    readonly_fields = ('added_at', 'updated_at', 'total_price', 'subtotal', 'is_in_stock')
    ordering = ('-added_at',)
    
    fieldsets = (
        (_('Product Information'), {
            'fields': (
                'cart', 'product_id', 'product_name', 'product_description',
                'product_image_url', 'product_sku'
            )
        }),
        (_('Pricing & Quantity'), {
            'fields': (
                'quantity', 'unit_price', 'discount_amount', 
                'subtotal', 'total_price'
            )
        }),
        (_('Availability & Status'), {
            'fields': (
                'is_available', 'stock_quantity', 'is_in_stock',
                'is_saved_for_later'
            )
        }),
        (_('Product Variants'), {
            'fields': ('product_variant',),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('added_at', 'updated_at')
        })
    )
    
    def is_in_stock(self, obj):
        return obj.is_in_stock
    is_in_stock.boolean = True
    is_in_stock.short_description = 'In Stock'

@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = (
        'order', 'product_name', 'product_id', 'quantity', 'unit_price',
        'discount_amount', 'tax_amount', 'total_price', 'status'
    )
    list_filter = ('status', 'order__status', 'order__order_date')
    search_fields = (
        'product_name', 'product_id', 'product_sku',
        'order__order_number', 'order__user__username'
    )
    readonly_fields = ('total_price', 'subtotal')
    ordering = ('-order__order_date',)
    
    fieldsets = (
        (_('Order & Product'), {
            'fields': (
                'order', 'product_id', 'product_name', 'product_description',
                'product_image_url', 'product_sku'
            )
        }),
        (_('Pricing Details'), {
            'fields': (
                'quantity', 'unit_price', 'discount_amount', 'tax_amount',
                'subtotal', 'total_price'
            )
        }),
        (_('Item Status & Fulfillment'), {
            'fields': ('status', 'weight', 'dimensions')
        }),
        (_('Product Variants'), {
            'fields': ('product_variant',),
            'classes': ('collapse',)
        })
    )

# Customize admin site
admin.site.site_header = "S2Cart Customer API Administration"
admin.site.site_title = "S2Cart Admin"
admin.site.index_title = "Welcome to S2Cart Customer API Administration"
