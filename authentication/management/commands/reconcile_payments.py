from django.core.management.base import BaseCommand
from django.utils import timezone
from authentication.models import PaymentHistory, PaymentTransaction
from authentication.paytm_utils import PaytmPayment
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Reconciles initiated payments that may have been completed but not updated'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Check payments from the last N hours'
        )

    def handle(self, *args, **options):
        hours = options['hours']
        time_threshold = timezone.now() - timezone.timedelta(hours=hours)
        
        # Find payments that are still in INITIATED status
        initiated_payments = PaymentHistory.objects.filter(
            status='INITIATED',
            created_at__gte=time_threshold
        )
        
        self.stdout.write(f"Found {initiated_payments.count()} initiated payments to check")
        
        reconciled = 0
        failed = 0
        
        for payment in initiated_payments:
            self.stdout.write(f"Checking payment {payment.id} with transaction ID {payment.transaction_id}")
            
            if not payment.payment_gateway_order_id:
                self.stdout.write(f"  - No order_id for payment {payment.id}, skipping")
                continue
            
            try:
                # Check the payment status
                response = PaytmPayment.check_transaction_status(payment.payment_gateway_order_id)
                
                if response.get('STATUS') == 'TXN_SUCCESS':
                    payment.status = 'COMPLETED'
                    if payment.order:
                        payment.order.status = 'PAID'
                        payment.order.save()
                    reconciled += 1
                    
                    # Create transaction record if needed
                    PaymentTransaction.objects.create(
                        payment=payment,
                        action='reconcile',
                        status='success',
                        amount=payment.amount,
                        gateway_response=response
                    )
                    
                    self.stdout.write(self.style.SUCCESS(f"  - Payment {payment.id} reconciled as successful"))
                elif response.get('STATUS') in ['TXN_FAILURE', 'PENDING']:
                    if response.get('STATUS') == 'TXN_FAILURE':
                        payment.status = 'FAILED'
                        failed += 1
                        
                        # Create failure transaction
                        PaymentTransaction.objects.create(
                            payment=payment,
                            action='reconcile',
                            status='failed',
                            amount=payment.amount,
                            gateway_response=response,
                            error_message=response.get('RESPMSG', 'Unknown error')
                        )
                        
                        self.stdout.write(self.style.WARNING(f"  - Payment {payment.id} marked as failed"))
                    # For pending, leave as initiated
                
                payment.save()
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  - Error checking payment {payment.id}: {str(e)}"))
                
        self.stdout.write(self.style.SUCCESS(
            f"Reconciliation completed: {reconciled} payments reconciled as successful, {failed} as failed"
        ))
