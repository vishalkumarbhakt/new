from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, UserDetailView,
    ProfileUpdateView, PasswordResetRequestView,
    PasswordResetConfirmView, VerifyAccountView,
    ResendVerificationEmailView, CartListCreateView, CartDetailView,
    CartByStoreView, CartItemListCreateView, CartItemDetailView,
    ClearCartView, OrderListCreateView, OrderDetailView,
    SearchHistoryGroupDetailView, SearchHistoryListCreateView,
    SearchHistoryDetailView, SearchHistoryClearView,
    CustomerSupportTicketListCreateView, CustomerSupportTicketDetailView,
    CustomerChatListCreateView, api_root, health_check,
    CardPaymentMethodView, UPIPaymentMethodView,
    CardPaymentMethodDetailView, UPIPaymentMethodDetailView,
    PaymentHistoryListView, PaymentHistoryDetailView,
    PaymentTransactionCreateView, 
    # Unified Payment Views
    InitiatePaymentView, CheckPaymentStatusView,
    # Gateway-specific Payment Views (Legacy/Specialized)
    InitiatePaytmPaymentView, InitiatePhonePePaymentView,
    PaytmCallbackView, CheckPaytmTransactionStatusView, CheckPhonePeTransactionStatusView,
    PhonePeCallbackView, PhonePeRedirectView,
    UserAddressListCreateView, UserAddressDetailView, SetDefaultAddressView,
    GetDefaultAddressView, UserSessionsView,
    CustomTokenObtainPairView, CustomTokenRefreshView, JWTLogoutView, JWTUserSessionsView
)
from .payment_views import RetryPaymentView

urlpatterns = [
    # Root and health check
    path('', api_root, name='api-root'),
    path('health/', health_check, name='health_check'),    # Authentication endpoints (Legacy Token Auth - kept for backward compatibility)
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),  # Legacy token-based login
    path('logout/', LogoutView.as_view(), name='logout'),  # Legacy token-based logout
    path('profile/', UserDetailView.as_view(), name='user_detail'),
    path('profile/update/', ProfileUpdateView.as_view(), name='profile_update'),
    
    # Session management endpoints
    path('sessions/', UserSessionsView.as_view(), name='user_sessions'),
    path('sessions/<str:session_id>/', UserSessionsView.as_view(), name='terminate_session'),
    
    # Password reset endpoints
    path('password-reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # Account verification endpoints  
    path('verify/otp/', VerifyAccountView.as_view(), name='verify_account_otp'),
    path('verify/resend/', ResendVerificationEmailView.as_view(), name='resend_verification'),
    path('verify/<str:token>/', VerifyAccountView.as_view(), name='verify_account'),
    
    # Cart endpoints - Updated for multiple store support
    path('carts/', CartListCreateView.as_view(), name='cart_list_create'),
    path('carts/<int:pk>/', CartDetailView.as_view(), name='cart_detail'),
    path('carts/store/<str:store_id>/', CartByStoreView.as_view(), name='cart_by_store'),
    path('cart/items/', CartItemListCreateView.as_view(), name='cart_items'),
    path('cart/items/<int:pk>/', CartItemDetailView.as_view(), name='cart_item_detail'),
    path('cart/clear/', ClearCartView.as_view(), name='clear_cart'),
    
    # Order endpoints
    path('orders/', OrderListCreateView.as_view(), name='orders'),
    path('orders/<int:pk>/', OrderDetailView.as_view(), name='order_detail'),
    
    # Payment method endpoints
    path('payment-methods/cards/', CardPaymentMethodView.as_view(), name='card_payment_methods'),
    path('payment-methods/cards/<int:pk>/', CardPaymentMethodDetailView.as_view(), name='card_payment_method_detail'),
    path('payment-methods/upi/', UPIPaymentMethodView.as_view(), name='upi_payment_methods'),
    path('payment-methods/upi/<int:pk>/', UPIPaymentMethodDetailView.as_view(), name='upi_payment_method_detail'),
    # Payment history endpoints
    path('payments/history/', PaymentHistoryListView.as_view(), name='payment_history'),
    path('payments/history/<int:pk>/', PaymentHistoryDetailView.as_view(), name='payment_history_detail'),
    path('payments/history/<int:payment_id>/transactions/', PaymentTransactionCreateView.as_view(), name='payment_transactions'),
    path('payments/history/<int:pk>/retry/', RetryPaymentView.as_view(), name='retry_payment'),
    
    # Unified Payment endpoints (Recommended for new integrations)
    path('payments/initiate/', InitiatePaymentView.as_view(), name='initiate_payment'),
    path('payments/status/<str:order_id>/', CheckPaymentStatusView.as_view(), name='check_payment_status'),
    
    # Paytm Payment endpoints (Legacy/Specialized)
    path('payments/paytm/initiate/', InitiatePaytmPaymentView.as_view(), name='initiate_paytm_payment'),
    path('payments/paytm/callback/', PaytmCallbackView.as_view(), name='paytm_callback'),
    path('payments/paytm/status/<str:order_id>/', CheckPaytmTransactionStatusView.as_view(), name='check_paytm_status'),
    
    # PhonePe Payment endpoints (Legacy/Specialized)
    path('payments/phonepe/initiate/', InitiatePhonePePaymentView.as_view(), name='initiate_phonepe_payment'),
    path('payments/phonepe/callback/', PhonePeCallbackView.as_view(), name='phonepe_callback'),
    path('payments/phonepe/redirect/', PhonePeRedirectView.as_view(), name='phonepe_redirect'),
    path('payments/phonepe/status/<str:order_id>/', CheckPhonePeTransactionStatusView.as_view(), name='check_phonepe_status'),
    
    # Search history endpoints
    path('search-history-group/', SearchHistoryGroupDetailView.as_view(), name='search_history_group'),
    path('search-history/', SearchHistoryListCreateView.as_view(), name='search_history'),
    path('search-history/<int:pk>/', SearchHistoryDetailView.as_view(), name='search_history_detail'),
    path('search-history/clear/', SearchHistoryClearView.as_view(), name='clear_search_history'),
      # Customer support endpoints
    path('support/tickets/', CustomerSupportTicketListCreateView.as_view(), name='support_tickets'),
    path('support/tickets/<int:pk>/', CustomerSupportTicketDetailView.as_view(), name='support_ticket_detail'),
    path('support/tickets/<int:ticket_id>/messages/', CustomerChatListCreateView.as_view(), name='ticket_messages'),
      # Address management endpoints
    path('addresses/', UserAddressListCreateView.as_view(), name='user_addresses'),
    path('addresses/<int:pk>/', UserAddressDetailView.as_view(), name='user_address_detail'),
    path('addresses/default/', GetDefaultAddressView.as_view(), name='get_default_address'),
    path('addresses/set-default/<int:pk>/', SetDefaultAddressView.as_view(), name='set_default_address'),
]