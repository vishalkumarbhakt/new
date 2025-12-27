import json
import time
import uuid
import hashlib
import requests
from django.conf import settings
from paytmchecksum import PaytmChecksum
import logging

logger = logging.getLogger(__name__)

class PaytmPayment:
    @staticmethod
    def generate_checksum(params, merchant_key=None):
        """Generate Paytm checksum for given parameters"""
        if merchant_key is None:
            merchant_key = settings.PAYTM_MERCHANT_KEY
        return PaytmChecksum.generateSignature(params, merchant_key)

    @staticmethod
    def verify_checksum(params, merchant_key=None, checksum=None):
        """Verify Paytm checksum for given parameters"""
        if merchant_key is None:
            merchant_key = settings.PAYTM_MERCHANT_KEY
        if checksum is None:
            checksum = params.get('CHECKSUMHASH', '')
            if checksum:
                del params['CHECKSUMHASH']
        return PaytmChecksum.verifySignature(params, merchant_key, checksum)

    @staticmethod
    def generate_secure_transaction_token(amount, user_id, order_id, payment_id):
        """Generate secure transaction token with enhanced validation"""
        try:
            # Ensure all parameters are strings
            amount = str(amount)
            user_id = str(user_id)
            order_id = str(order_id)
            
            # For testing environment
            if getattr(settings, 'PAYTM_TEST_MODE', False):
                test_token = str(uuid.uuid4())
                return {
                    'order_id': order_id,
                    'token': test_token,
                    'mid': str(settings.PAYTM_MERCHANT_ID),
                    'amount': amount,
                    'callback_url': f"{getattr(settings, 'SITE_URL', 'http://localhost:8000')}/api/auth/payments/paytm/callback/",
                    'test_mode': True,
                    'payment_id': payment_id,
                    'security_hash': hashlib.sha256(f"{payment_id}{amount}{user_id}".encode()).hexdigest()[:16]
                }

            # Production environment with enhanced security
            paytm_params = {
                "MID": str(settings.PAYTM_MERCHANT_ID),
                "ORDER_ID": order_id,
                "CUST_ID": user_id,
                "INDUSTRY_TYPE_ID": str(getattr(settings, 'PAYTM_INDUSTRY_TYPE_ID', 'Retail')),
                "CHANNEL_ID": str(getattr(settings, 'PAYTM_CHANNEL_ID', 'WEB')),
                "TXN_AMOUNT": amount,
                "WEBSITE": str(getattr(settings, 'PAYTM_WEBSITE', 'WEBSTAGING')),
                "CALLBACK_URL": f"{getattr(settings, 'SITE_URL', 'http://localhost:8000')}/api/auth/payments/paytm/callback/"
            }

            try:
                checksum = PaytmPayment.generate_checksum(paytm_params)
                if not checksum:
                    logger.error("Failed to generate checksum")
                    return None
                paytm_params["CHECKSUMHASH"] = checksum
            except Exception as e:
                logger.error(f"Error generating checksum: {str(e)}")
                return None

            token_url = getattr(settings, 'PAYTM_TOKEN_URL', 'https://securegw-stage.paytm.in/theia/api/v1/initiateTransaction')
            url = f"{token_url}?mid={settings.PAYTM_MERCHANT_ID}&orderId={order_id}"
            
            headers = {
                "Content-Type": "application/json"
            }

            try:
                response = requests.post(url, data=json.dumps(paytm_params), headers=headers, timeout=30)
                logger.info(f"Paytm API response status: {response.status_code}")
                
                if response.status_code != 200:
                    logger.error(f"Paytm API returned status {response.status_code}: {response.text}")
                    return None
                
                if not response.text.strip():
                    logger.error("Paytm API returned empty response")
                    return None
                
                response_data = response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error calling Paytm API: {str(e)}")
                return None
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response from Paytm: {str(e)}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error calling Paytm API: {str(e)}")
                return None
            
            if response_data.get('head', {}).get('responseCode') == '0000':
                return {
                    'order_id': order_id,
                    'token': response_data['body']['txnToken'],
                    'mid': str(settings.PAYTM_MERCHANT_ID),
                    'amount': amount,
                    'callback_url': paytm_params['CALLBACK_URL'],
                    'test_mode': False,
                    'payment_id': payment_id,
                    'security_hash': hashlib.sha256(f"{payment_id}{amount}{user_id}".encode()).hexdigest()[:16]
                }
            else:
                logger.error(f"Failed to generate Paytm token: {response_data}")
                return None

        except Exception as e:
            logger.error(f"Error generating secure transaction token: {str(e)}")
            return None

    @staticmethod
    def verify_payment_checksum(paytm_params):
        """Verify payment checksum from callback"""
        try:
            # For testing environment
            if getattr(settings, 'PAYTM_TEST_MODE', False):
                return True, paytm_params

            # Extract checksum
            received_checksum = paytm_params.get('CHECKSUMHASH')
            if not received_checksum:
                return False, {"error": "No checksum found in response"}

            # Create params dict without checksum for verification
            params_for_verification = dict(paytm_params)
            if 'CHECKSUMHASH' in params_for_verification:
                del params_for_verification['CHECKSUMHASH']

            # Verify checksum
            is_valid = PaytmPayment.verify_checksum(
                params_for_verification, 
                checksum=received_checksum
            )
            
            if is_valid:
                logger.info("Checksum verification successful")
                return True, paytm_params
            else:
                logger.error("Checksum verification failed")
                return False, {"error": "Checksum verification failed"}

        except Exception as e:
            logger.error(f"Error in checksum verification: {str(e)}")
            return False, {"error": str(e)}

    @staticmethod
    def verify_transaction_with_paytm(order_id):
        """Independent verification with Paytm servers"""
        try:
            # For testing environment
            if getattr(settings, 'PAYTM_TEST_MODE', False):
                return {
                    "success": True,
                    "status": "TXN_SUCCESS",
                    "amount": "100.00",
                    "transaction_id": f"TEST_{order_id}",
                    "message": "Test mode - transaction successful"
                }

            # Call Paytm status check API
            status_response = PaytmPayment.check_transaction_status(order_id)
            
            if status_response.get('error'):
                return {
                    "success": False,
                    "error": status_response['error'],
                    "message": "Failed to verify with Paytm"
                }
            
            # Parse Paytm response
            paytm_status = status_response.get('STATUS', '')
            paytm_amount = status_response.get('TXNAMOUNT', '0')
            paytm_txn_id = status_response.get('TXNID', '')
            paytm_message = status_response.get('RESPMSG', '')
            
            success = paytm_status in ['TXN_SUCCESS', 'SUCCESS']
            
            return {
                "success": success,
                "status": paytm_status,
                "amount": paytm_amount,
                "transaction_id": paytm_txn_id,
                "message": paytm_message,
                "raw_response": status_response
            }

        except Exception as e:
            logger.error(f"Error in independent Paytm verification: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "message": "Verification service error"
            }

    @staticmethod
    def verify_payment(paytm_params):
        """Verify payment response"""
        try:
            # For testing environment
            if getattr(settings, 'PAYTM_TEST_MODE', False):
                return True, paytm_params

            # Verify checksum
            if not PaytmPayment.verify_checksum(paytm_params):
                logger.error("Checksum verification failed")
                return False, {"error": "Checksum verification failed"}

            # Verify transaction status
            response = PaytmPayment.check_transaction_status(paytm_params.get('ORDERID'))
            
            if response.get('STATUS') == 'TXN_SUCCESS':
                return True, response
        except Exception as e:
            logger.error(f"Error in verify_payment: {str(e)}")
            return False, {"error": str(e)}

    @staticmethod
    def check_transaction_status(order_id):
        """Check status of transaction"""
        try:
            # For testing environment
            if getattr(settings, 'PAYTM_TEST_MODE', False):
                return {
                    "ORDERID": order_id,
                    "STATUS": "TXN_SUCCESS",
                    "TXNAMOUNT": "100.00",
                    "TXNID": f"TEST_{order_id}",
                    "RESPCODE": "01",
                    "RESPMSG": "Success",
                    "TXNDATE": time.strftime('%Y-%m-%d %H:%M:%S')
                }

            # Production status check
            paytm_params = {
                "MID": getattr(settings, 'PAYTM_MERCHANT_ID', ''),
                "ORDERID": order_id,
            }

            checksum = PaytmPayment.generate_checksum(paytm_params)
            paytm_params["CHECKSUMHASH"] = checksum

            status_url = getattr(settings, 'PAYTM_STATUS_URL', 'https://securegw-stage.paytm.in/merchant-status/getTxnStatus')
            response = requests.post(status_url, data=paytm_params)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Transaction status check failed: {response.text}")
                return {"error": "Status check failed"}

        except Exception as e:
            logger.error(f"Error in check_transaction_status: {str(e)}")
            return {"error": str(e)}