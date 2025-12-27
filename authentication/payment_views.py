from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.utils import timezone
from .models import PaymentHistory, PaymentTransaction
from .paytm_utils import PaytmPayment
import logging
import uuid

logger = logging.getLogger(__name__)

class RetryPaymentView(APIView):
    """
    Retry a failed payment
    """
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self, request, pk):
        try:
            # Get the original payment
            payment = get_object_or_404(
                PaymentHistory, 
                id=pk, 
                user=request.user,
                status='FAILED'
            )
            
            if not payment.order:
                return Response({
                    'error': 'Cannot retry payment without associated order'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate a new secure transaction ID with enhanced randomness
            timestamp = int(timezone.now().timestamp() * 1000)  # milliseconds for uniqueness
            random_part = uuid.uuid4().hex[:12]  # 12 characters from UUID
            transaction_id = f"TXN_{timestamp}_{random_part}"
            
            # Create new payment record based on the failed one
            new_payment = PaymentHistory.objects.create(
                user=request.user,
                amount=payment.amount,
                currency=payment.currency,
                status='INITIATED',
                payment_type=payment.payment_type,
                transaction_id=transaction_id,
                order=payment.order,
                payment_gateway_order_id=f"RETRY_{payment.order.id}_{int(timezone.now().timestamp())}",
                billing_address=payment.billing_address,
                description=f"Retry of payment {payment.id}"
            )
            
            # Create initial transaction record
            PaymentTransaction.objects.create(
                payment=new_payment,
                action='initiate_retry',
                status='pending',
                amount=new_payment.amount,
                gateway_response={"original_payment_id": str(payment.id)}
            )
            
            # Generate Paytm transaction token
            payment_data = PaytmPayment.generate_transaction_token(
                amount=new_payment.amount,
                user_id=request.user.id,
                order_id=new_payment.payment_gateway_order_id
            )
            
            # Add payment ID to response for client reference
            payment_data['payment_id'] = new_payment.id
            
            return Response(payment_data)
            
        except Exception as e:
            logger.error(f"Error retrying payment: {str(e)}")
            return Response({
                'error': 'Failed to initiate payment retry'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
