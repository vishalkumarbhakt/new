"""
Admin API views for order and user management.
"""
import logging
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q, Sum, Count
from rest_framework import generics, status, filters
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser

from .models import Order, OrderItem, User, PaymentHistory
from .serializers import OrderSerializer, OrderItemSerializer, UserSerializer

logger = logging.getLogger(__name__)


class AdminOrderListView(generics.ListAPIView):
    """
    Admin API to list all orders with filtering.
    GET /api/admin/orders/
    
    Query Parameters:
    - status: Filter by order status
    - user: Filter by user ID
    - date_from: Filter orders from date
    - date_to: Filter orders to date
    - search: Search by order number or user email
    """
    permission_classes = [IsAdminUser]
    serializer_class = OrderSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['order_number', 'user__email', 'user__username', 'tracking_number']
    ordering_fields = ['order_date', 'total_amount', 'status']
    ordering = ['-order_date']
    
    def get_queryset(self):
        queryset = Order.objects.all().select_related('user', 'shipping_address')
        
        # Filter by status
        order_status = self.request.query_params.get('status')
        if order_status:
            queryset = queryset.filter(status=order_status.upper())
        
        # Filter by user
        user_id = self.request.query_params.get('user')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by date range
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(order_date__gte=date_from)
        if date_to:
            queryset = queryset.filter(order_date__lte=date_to)
        
        return queryset


class AdminOrderDetailView(generics.RetrieveAPIView):
    """
    Admin API to get order details.
    GET /api/admin/orders/<pk>/
    """
    permission_classes = [IsAdminUser]
    serializer_class = OrderSerializer
    queryset = Order.objects.all().select_related('user', 'shipping_address')


class AdminOrderStatusUpdateView(APIView):
    """
    Admin API to update order status.
    PATCH /api/admin/orders/<pk>/status/
    """
    permission_classes = [IsAdminUser]
    
    VALID_STATUS_TRANSITIONS = {
        'PLACED': ['CONFIRMED', 'CANCELLED'],
        'CONFIRMED': ['PAID', 'PROCESSING', 'CANCELLED'],
        'PAID': ['PROCESSING', 'CANCELLED', 'REFUNDED'],
        'PROCESSING': ['PACKED', 'CANCELLED'],
        'PACKED': ['SHIPPED', 'CANCELLED'],
        'SHIPPED': ['OUT_FOR_DELIVERY', 'DELIVERED'],
        'OUT_FOR_DELIVERY': ['DELIVERED'],
        'DELIVERED': ['RETURNED'],
        'RETURNED': ['REFUNDED'],
        'CANCELLED': [],
        'REFUNDED': []
    }
    
    def patch(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        new_status = request.data.get('status', '').upper()
        notes = request.data.get('notes', '')
        
        if not new_status:
            return Response({
                'status': 'error',
                'message': 'Status is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate status value
        valid_statuses = [
            'PLACED', 'CONFIRMED', 'PAID', 'PROCESSING', 'PACKED',
            'SHIPPED', 'OUT_FOR_DELIVERY', 'DELIVERED', 'RETURNED',
            'CANCELLED', 'REFUNDED'
        ]
        if new_status not in valid_statuses:
            return Response({
                'status': 'error',
                'message': f'Invalid status. Valid values: {", ".join(valid_statuses)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate status transition
        allowed_transitions = self.VALID_STATUS_TRANSITIONS.get(order.status, [])
        if new_status not in allowed_transitions:
            return Response({
                'status': 'error',
                'message': f'Cannot transition from {order.status} to {new_status}. Allowed transitions: {", ".join(allowed_transitions) if allowed_transitions else "None"}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        old_status = order.status
        order.status = new_status
        
        # Update timestamps based on status
        if new_status == 'CONFIRMED':
            order.confirmed_at = timezone.now()
        elif new_status == 'SHIPPED':
            order.shipped_at = timezone.now()
            # Update tracking info if provided
            if 'tracking_number' in request.data:
                order.tracking_number = request.data['tracking_number']
            if 'carrier_name' in request.data:
                order.carrier_name = request.data['carrier_name']
        elif new_status == 'DELIVERED':
            order.delivered_at = timezone.now()
            order.actual_delivery_date = timezone.now()
        elif new_status == 'CANCELLED':
            order.cancelled_at = timezone.now()
            if 'cancellation_reason' in request.data:
                order.cancellation_reason = request.data['cancellation_reason']
        
        if notes:
            order.notes = (order.notes or '') + f"\n[{timezone.now().strftime('%Y-%m-%d %H:%M')}] Status changed from {old_status} to {new_status}. {notes}"
        
        order.save()
        
        logger.info(f"Order {order.order_number} status changed from {old_status} to {new_status} by {request.user.username}")
        
        return Response({
            'status': 'success',
            'message': f'Order status updated to {new_status}',
            'data': OrderSerializer(order, context={'request': request}).data
        })


class AdminOrderCancelView(APIView):
    """
    Admin API to cancel an order.
    POST /api/admin/orders/<pk>/cancel/
    """
    permission_classes = [IsAdminUser]
    
    def post(self, request, pk):
        order = get_object_or_404(Order, pk=pk)
        reason = request.data.get('reason', 'Cancelled by admin')
        
        if not order.can_cancel:
            return Response({
                'status': 'error',
                'message': f'Cannot cancel order in {order.status} status'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        order.cancel_order(reason)
        
        # Restore stock for cancelled orders
        for item in order.items.all():
            try:
                from products.models import Product
                product = Product.objects.get(id=item.product_id)
                product.increment_stock(item.quantity)
            except Exception as e:
                logger.warning(f"Could not restore stock for product {item.product_id}: {e}")
        
        logger.info(f"Order {order.order_number} cancelled by {request.user.username}. Reason: {reason}")
        
        return Response({
            'status': 'success',
            'message': 'Order cancelled successfully',
            'data': OrderSerializer(order, context={'request': request}).data
        })


class AdminOrderStatsView(APIView):
    """
    Admin API to get order statistics.
    GET /api/admin/orders/stats/
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        from django.db.models import Sum, Count, Avg
        from datetime import timedelta
        
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # Overall stats
        total_orders = Order.objects.count()
        total_revenue = Order.objects.filter(status='DELIVERED').aggregate(
            total=Sum('total_amount')
        )['total'] or 0
        
        # Status breakdown
        status_counts = Order.objects.values('status').annotate(count=Count('id'))
        status_breakdown = {item['status']: item['count'] for item in status_counts}
        
        # Recent stats
        today_orders = Order.objects.filter(order_date__date=today).count()
        week_orders = Order.objects.filter(order_date__date__gte=week_ago).count()
        month_orders = Order.objects.filter(order_date__date__gte=month_ago).count()
        
        # Revenue stats
        today_revenue = Order.objects.filter(
            order_date__date=today, status='DELIVERED'
        ).aggregate(total=Sum('total_amount'))['total'] or 0
        
        week_revenue = Order.objects.filter(
            order_date__date__gte=week_ago, status='DELIVERED'
        ).aggregate(total=Sum('total_amount'))['total'] or 0
        
        month_revenue = Order.objects.filter(
            order_date__date__gte=month_ago, status='DELIVERED'
        ).aggregate(total=Sum('total_amount'))['total'] or 0
        
        # Average order value
        avg_order_value = Order.objects.filter(status='DELIVERED').aggregate(
            avg=Avg('total_amount')
        )['avg'] or 0
        
        return Response({
            'status': 'success',
            'data': {
                'overview': {
                    'total_orders': total_orders,
                    'total_revenue': float(total_revenue),
                    'avg_order_value': float(avg_order_value)
                },
                'status_breakdown': status_breakdown,
                'recent_activity': {
                    'today': {
                        'orders': today_orders,
                        'revenue': float(today_revenue)
                    },
                    'week': {
                        'orders': week_orders,
                        'revenue': float(week_revenue)
                    },
                    'month': {
                        'orders': month_orders,
                        'revenue': float(month_revenue)
                    }
                }
            }
        })


class AdminUserListView(generics.ListAPIView):
    """
    Admin API to list users.
    GET /api/admin/users/
    """
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['username', 'email', 'first_name', 'last_name', 'phone_number']
    ordering_fields = ['date_joined', 'last_login', 'username']
    ordering = ['-date_joined']
    
    def get_queryset(self):
        queryset = User.objects.all()
        
        # Filter by verification status
        is_verified = self.request.query_params.get('is_verified')
        if is_verified is not None:
            queryset = queryset.filter(is_verified=is_verified.lower() == 'true')
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Filter by staff status
        is_staff = self.request.query_params.get('is_staff')
        if is_staff is not None:
            queryset = queryset.filter(is_staff=is_staff.lower() == 'true')
        
        return queryset


class AdminUserDetailView(generics.RetrieveAPIView):
    """
    Admin API to get user details.
    GET /api/admin/users/<pk>/
    """
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    queryset = User.objects.all()
