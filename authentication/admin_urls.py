"""
Admin API URLs for order and user management.
"""
from django.urls import path
from .admin_views import (
    AdminOrderListView, AdminOrderDetailView, AdminOrderStatusUpdateView,
    AdminOrderCancelView, AdminOrderStatsView,
    AdminUserListView, AdminUserDetailView
)

urlpatterns = [
    # Order management
    path('orders/', AdminOrderListView.as_view(), name='admin_order_list'),
    path('orders/stats/', AdminOrderStatsView.as_view(), name='admin_order_stats'),
    path('orders/<int:pk>/', AdminOrderDetailView.as_view(), name='admin_order_detail'),
    path('orders/<int:pk>/status/', AdminOrderStatusUpdateView.as_view(), name='admin_order_status'),
    path('orders/<int:pk>/cancel/', AdminOrderCancelView.as_view(), name='admin_order_cancel'),
    
    # User management
    path('users/', AdminUserListView.as_view(), name='admin_user_list'),
    path('users/<int:pk>/', AdminUserDetailView.as_view(), name='admin_user_detail'),
]
