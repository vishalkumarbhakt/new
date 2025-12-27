import json
import time
import uuid
import hashlib
import base64
import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class PhonePePayment:
    """
    Secure PhonePe Payment Gateway Integration
    Implements the same security standards as PayTM integration
    """
    
    @staticmethod
    def generate_checksum(payload, salt_key):
        """
        Generate PhonePe checksum for API authentication
        """
        try:
            # PhonePe checksum format: base64(payload) + "/pay" + salt_key
            base64_payload = base64.b64encode(payload.encode()).decode()
            checksum_string = base64_payload + "/pg/v1/pay" + salt_key
            
            # Generate SHA256 hash
            checksum = hashlib.sha256(checksum_string.encode()).hexdigest()
            return checksum + "###1"  # PhonePe format requires ###1 suffix
            
        except Exception as e:
            logger.error(f"Error generating PhonePe checksum: {str(e)}")
            return None
    
    @staticmethod
    def verify_checksum(response_data, salt_key):
        """
        Verify PhonePe response checksum
        """
        try:
            received_checksum = response_data.get('checksum', '')
            if not received_checksum:
                logger.error("No checksum found in PhonePe response")
                return False
            
            # Remove the ###1 suffix
            if received_checksum.endswith('###1'):
                received_checksum = received_checksum[:-4]
            
            # Recreate checksum from response
            response_payload = response_data.get('response', '')
            if not response_payload:
                logger.error("No response payload found")
                return False
            
            checksum_string = response_payload + "/pg/v1/status" + salt_key
            calculated_checksum = hashlib.sha256(checksum_string.encode()).hexdigest()
            
            is_valid = calculated_checksum == received_checksum
            logger.info(f"PhonePe checksum verification: {'SUCCESS' if is_valid else 'FAILED'}")
            return is_valid
            
        except Exception as e:
            logger.error(f"Error verifying PhonePe checksum: {str(e)}")
            return False
    
    @staticmethod
    def generate_secure_transaction_token(amount, user_id, order_id, payment_id):
        """
        Generate secure PhonePe payment request with enhanced validation
        """
        try:
            # Ensure all parameters are properly formatted
            amount = float(amount)
            user_id = str(user_id)
            order_id = str(order_id)
            payment_id = str(payment_id)
            
            # For testing environment
            if getattr(settings, 'PHONEPE_TEST_MODE', False):
                # Create callback and redirect URLs with proper domain
                site_url = f"{getattr(settings, 'SITE_PROTOCOL', 'https')}://{getattr(settings, 'SITE_DOMAIN', 'localhost')}"
                callback_url = f"{site_url}/api/auth/payments/phonepe/callback/"
                redirect_url = f"{site_url}/api/auth/payments/phonepe/redirect/"
                
                # Convert amount to paise (PhonePe expects amount in paise)
                amount_in_paise = int(float(amount) * 100)
                
                # Generate unique merchant transaction ID
                merchant_transaction_id = f"TXN_{payment_id}_{int(time.time())}"
                
                # Create PhonePe payment payload for test mode
                payload = {
                    "merchantId": getattr(settings, 'PHONEPE_MERCHANT_ID', 'PGTESTPAYUAT'),
                    "merchantTransactionId": merchant_transaction_id,
                    "merchantUserId": f"USER_{user_id}",
                    "amount": amount_in_paise,
                    "redirectUrl": redirect_url,
                    "redirectMode": "REDIRECT",
                    "callbackUrl": callback_url,
                    "paymentInstrument": {
                        "type": "PAY_PAGE"
                    }
                }
                
                # Convert payload to JSON string
                payload_json = json.dumps(payload, separators=(',', ':'))
                logger.info(f"PhonePe test payload: {payload_json}")
                
                # Generate base64 encoded payload
                base64_payload = base64.b64encode(payload_json.encode()).decode()
                
                # Generate checksum for test mode
                salt_key = getattr(settings, 'PHONEPE_SALT_KEY', 'test-salt-key')
                checksum_string = base64_payload + "/pg/v1/pay" + salt_key
                checksum = hashlib.sha256(checksum_string.encode()).hexdigest() + "###1"
                
                # PhonePe test/staging API URL
                phonepe_api_url = getattr(settings, 'PHONEPE_STAGING_URL', 'https://api-preprod.phonepe.com/apis/hermes')
                payment_url = f"{phonepe_api_url}/pg/v1/pay"
                
                return {
                    'payment_url': payment_url,
                    'base64_payload': base64_payload,
                    'checksum': checksum,
                    'merchant_transaction_id': merchant_transaction_id,
                    'order_id': order_id,
                    'payment_id': payment_id,
                    'amount': amount_in_paise,
                    'merchant_id': getattr(settings, 'PHONEPE_MERCHANT_ID', 'PGTESTPAYUAT'),
                    'redirect_url': redirect_url,
                    'callback_url': callback_url,
                    'test_mode': True,
                    'staging_api': True
                }

            # Production environment
            merchant_id = settings.PHONEPE_MERCHANT_ID
            if not merchant_id or merchant_id == 'your_merchant_id_here':
                logger.error("PhonePe merchant ID not configured")
                return None

            # Generate unique merchant transaction ID
            merchant_transaction_id = f"TXN_{payment_id}_{int(time.time())}"
            
            # Create callback and redirect URLs
            site_url = f"{getattr(settings, 'SITE_PROTOCOL', 'https')}://{getattr(settings, 'SITE_DOMAIN', 'localhost')}"
            callback_url = f"{site_url}/api/auth/payments/phonepe/callback/"
            redirect_url = f"{site_url}/api/auth/payments/phonepe/redirect/"
            
            # Convert amount to paise (PhonePe expects amount in paise)
            amount_in_paise = int(float(amount) * 100)
            
            # Create payment payload
            payload = {
                "merchantId": merchant_id,
                "merchantTransactionId": merchant_transaction_id,
                "merchantUserId": f"USER_{user_id}",
                "amount": amount_in_paise,
                "redirectUrl": redirect_url,
                "redirectMode": "POST",
                "callbackUrl": callback_url,
                "mobileNumber": "9999999999",  # Will be updated by user during payment
                "paymentInstrument": {
                    "type": "PAY_PAGE"
                }
            }
            
            # Convert payload to JSON string
            payload_json = json.dumps(payload, separators=(',', ':'))
            
            # Generate checksum
            salt_key = settings.PHONEPE_SALT_KEY
            checksum = PhonePePayment.generate_checksum(payload_json, salt_key)
            
            if not checksum:
                logger.error("Failed to generate PhonePe checksum")
                return None
            
            # Encode payload in base64
            base64_payload = base64.b64encode(payload_json.encode()).decode()
            
            # Prepare request headers
            headers = {
                "Content-Type": "application/json",
                "X-VERIFY": checksum,
                "X-MERCHANT-ID": merchant_id,
                "X-CLIENT-ID": settings.PHONEPE_CLIENT_ID,
                "X-CLIENT-VERSION": settings.PHONEPE_CLIENT_VERSION
            }
            
            # Prepare request body
            request_body = {
                "request": base64_payload
            }
            
            # Determine API URL
            if getattr(settings, 'PHONEPE_TEST_MODE', False):
                api_url = f"{settings.PHONEPE_STAGING_URL}/pg/v1/pay"
            else:
                api_url = f"{settings.PHONEPE_PRODUCTION_URL}/pg/v1/pay"
            
            # Make API call to PhonePe
            try:
                response = requests.post(
                    api_url, 
                    json=request_body, 
                    headers=headers, 
                    timeout=30
                )
                
                logger.info(f"PhonePe API response status: {response.status_code}")
                
                if response.status_code != 200:
                    logger.error(f"PhonePe API returned status {response.status_code}: {response.text}")
                    return None
                
                response_data = response.json()
                
                if response_data.get('success') and response_data.get('code') == 'PAYMENT_INITIATED':
                    payment_url = response_data['data']['instrumentResponse']['redirectInfo']['url']
                    
                    return {
                        'order_id': order_id,
                        'payment_id': payment_id,
                        'merchant_transaction_id': merchant_transaction_id,
                        'amount': amount,
                        'payment_url': payment_url,
                        'merchant_id': merchant_id,
                        'redirect_url': redirect_url,
                        'callback_url': callback_url,
                        'test_mode': False,
                        'security_hash': hashlib.sha256(f"{payment_id}{amount}{user_id}".encode()).hexdigest()[:16]
                    }
                else:
                    logger.error(f"PhonePe payment initiation failed: {response_data}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error calling PhonePe API: {str(e)}")
                return None
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response from PhonePe: {str(e)}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error calling PhonePe API: {str(e)}")
                return None
                
        except Exception as e:
            logger.error(f"Error generating secure PhonePe transaction token: {str(e)}")
            return None
    
    @staticmethod
    def verify_payment_checksum(response_data):
        """
        Verify PhonePe payment response checksum
        """
        try:
            # For testing environment
            if getattr(settings, 'PHONEPE_TEST_MODE', False):
                return True, response_data

            salt_key = settings.PHONEPE_SALT_KEY
            is_valid = PhonePePayment.verify_checksum(response_data, salt_key)
            
            if is_valid:
                logger.info("PhonePe checksum verification successful")
                return True, response_data
            else:
                logger.error("PhonePe checksum verification failed")
                return False, {"error": "Checksum verification failed"}

        except Exception as e:
            logger.error(f"Error in PhonePe checksum verification: {str(e)}")
            return False, {"error": str(e)}
    
    @staticmethod
    def verify_transaction_with_phonepe(merchant_transaction_id):
        """
        Independent verification with PhonePe servers
        """
        try:
            # For testing environment
            if getattr(settings, 'PHONEPE_TEST_MODE', False):
                return {
                    "success": True,
                    "status": "PAYMENT_SUCCESS",
                    "amount": 10000,  # Amount in paise
                    "transaction_id": merchant_transaction_id,
                    "message": "Test mode - transaction successful"
                }

            # Production verification
            merchant_id = settings.PHONEPE_MERCHANT_ID
            salt_key = settings.PHONEPE_SALT_KEY
            
            # Create checksum for status check
            checksum_string = f"/pg/v1/status/{merchant_id}/{merchant_transaction_id}" + salt_key
            checksum = hashlib.sha256(checksum_string.encode()).hexdigest() + "###1"
            
            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "X-VERIFY": checksum,
                "X-MERCHANT-ID": merchant_id,
                "X-CLIENT-ID": settings.PHONEPE_CLIENT_ID,
                "X-CLIENT-VERSION": settings.PHONEPE_CLIENT_VERSION
            }
            
            # Determine API URL
            if getattr(settings, 'PHONEPE_TEST_MODE', False):
                api_url = f"{settings.PHONEPE_STAGING_URL}/pg/v1/status/{merchant_id}/{merchant_transaction_id}"
            else:
                api_url = f"{settings.PHONEPE_PRODUCTION_URL}/pg/v1/status/{merchant_id}/{merchant_transaction_id}"
            
            # Make status check API call
            response = requests.get(api_url, headers=headers, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"PhonePe status API returned {response.status_code}: {response.text}")
                return {
                    "success": False,
                    "error": f"Status check failed: {response.status_code}",
                    "message": "Failed to verify with PhonePe"
                }
            
            response_data = response.json()
            
            # Parse PhonePe response
            if response_data.get('success') and response_data.get('data'):
                payment_data = response_data['data']
                status = payment_data.get('state', '')
                amount = payment_data.get('amount', 0)
                transaction_id = payment_data.get('transactionId', '')
                
                success = status == 'COMPLETED'
                
                return {
                    "success": success,
                    "status": status,
                    "amount": amount,
                    "transaction_id": transaction_id,
                    "message": payment_data.get('responseCodeDescription', ''),
                    "raw_response": response_data
                }
            else:
                return {
                    "success": False,
                    "error": "Invalid response format",
                    "message": "Verification failed",
                    "raw_response": response_data
                }

        except Exception as e:
            logger.error(f"Error in independent PhonePe verification: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "message": "Verification service error"
            }
    
    @staticmethod
    def check_transaction_status(merchant_transaction_id):
        """
        Check status of PhonePe transaction (wrapper for verify_transaction_with_phonepe)
        """
        try:
            result = PhonePePayment.verify_transaction_with_phonepe(merchant_transaction_id)
            
            if result.get('success'):
                return {
                    "status": result.get('status'),
                    "amount": result.get('amount'),
                    "transaction_id": result.get('transaction_id'),
                    "message": result.get('message'),
                    "success": True
                }
            else:
                return {
                    "error": result.get('error', 'Unknown error'),
                    "message": result.get('message', 'Status check failed'),
                    "success": False
                }
                
        except Exception as e:
            logger.error(f"Error in PhonePe status check: {str(e)}")
            return {
                "error": str(e),
                "success": False
            }
