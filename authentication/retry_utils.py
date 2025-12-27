"""
Retry utilities for handling failed operations with exponential backoff.
"""
import time
import logging
from functools import wraps
from typing import Callable, Any, Tuple, Type
from django.db import transaction, IntegrityError
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)


def retry_on_failure(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator to retry a function on failure with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between attempts in seconds
        backoff: Multiplier for delay after each failure
        exceptions: Tuple of exception types to retry on
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        # Last attempt failed, re-raise the exception
                        logger.error(f"Function {func.__name__} failed after {max_attempts} attempts: {str(e)}")
                        raise
                    
                    logger.warning(f"Function {func.__name__} failed on attempt {attempt + 1}/{max_attempts}: {str(e)}")
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            # This should never be reached, but just in case
            raise last_exception
        
        return wrapper
    return decorator


def retry_db_operation(max_attempts: int = 3, delay: float = 0.5):
    """
    Decorator specifically for database operations that may fail due to locking or integrity issues.
    """
    return retry_on_failure(
        max_attempts=max_attempts,
        delay=delay,
        backoff=1.5,
        exceptions=(IntegrityError, transaction.TransactionManagementError)
    )


def retry_api_call(max_attempts: int = 3, delay: float = 1.0):
    """
    Decorator for external API calls that may fail due to network issues.
    """
    return retry_on_failure(
        max_attempts=max_attempts,
        delay=delay,
        backoff=2.0,
        exceptions=(APIException, ConnectionError, TimeoutError)
    )


class RetryableOperation:
    """
    Context manager for retrying operations with custom logic.
    """
    
    def __init__(self, max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
        self.max_attempts = max_attempts
        self.delay = delay
        self.backoff = backoff
        self.current_attempt = 0
        self.current_delay = delay
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.current_attempt += 1
            
            if self.current_attempt < self.max_attempts:
                logger.warning(f"Operation failed on attempt {self.current_attempt}/{self.max_attempts}: {str(exc_val)}")
                time.sleep(self.current_delay)
                self.current_delay *= self.backoff
                return True  # Suppress the exception to retry
            else:
                logger.error(f"Operation failed after {self.max_attempts} attempts: {str(exc_val)}")
                return False  # Let the exception propagate
    
    def should_retry(self) -> bool:
        """Check if we should attempt another retry."""
        return self.current_attempt < self.max_attempts


# Example usage functions for common retry scenarios

@retry_db_operation()
def safe_create_user_session(user, device_type, device_id=None, **kwargs):
    """
    Safely create a user session with retry logic for database conflicts.
    """
    from .models import ExpiringToken
    return ExpiringToken.get_or_create_token(
        user=user,
        device_type=device_type,
        device_id=device_id,
        **kwargs
    )


@retry_api_call()
def safe_payment_verification(payment_id):
    """
    Safely verify payment status with retry logic for API failures.
    """
    from .paytm_utils import PaytmPayment
    from .models import PaymentHistory
    
    payment = PaymentHistory.objects.get(id=payment_id)
    return PaytmPayment.verify_payment(payment.payment_gateway_order_id)
