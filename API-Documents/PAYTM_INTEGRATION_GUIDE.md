# Paytm Integration Guide for S2Cart API

This guide explains how to properly configure the Paytm payment gateway for your S2Cart API in production.

## Prerequisites

1. A registered Paytm business account
2. Paytm Merchant ID and Merchant Key
3. Whitelisted server IP addresses on Paytm dashboard
4. Configured webhook URL in Paytm dashboard

## Configuration Steps

### 1. Obtain Paytm Production Credentials

1. Log in to your Paytm business account at [https://business.paytm.com/](https://business.paytm.com/)
2. Navigate to Developer Settings and locate your:
   - Merchant ID
   - Merchant Key
   - Website Name (usually 'DEFAULT' or a custom identifier provided by Paytm)
   - Industry Type ID (e.g., 'Retail', 'eCommerce', etc.)
   - Channel ID (use 'WAP' for mobile apps)

### 2. Update Environment Variables

Add the following to your `.env` file:

```
PAYTM_TEST_MODE=False
PAYTM_MERCHANT_ID=your_merchant_id_from_paytm
PAYTM_MERCHANT_KEY=your_merchant_key_from_paytm
PAYTM_WEBSITE=DEFAULT
PAYTM_INDUSTRY_TYPE_ID=Retail
PAYTM_CHANNEL_ID=WAP
```

### 3. Configure Webhook URL

1. In your Paytm business dashboard, navigate to the Developer Settings
2. Configure the callback URL to: `https://yourdomain.com/api/auth/payments/paytm/callback/`
3. Make sure the URL is HTTPS and is accessible from the internet

### 4. Testing vs Production Mode

The S2Cart API has built-in support for both testing and production modes:

- **Testing Mode**: Set `PAYTM_TEST_MODE=True` in your `.env` file
  - Uses Paytm staging servers
  - Provides test payment instruments
  - Transaction logs are available in Paytm's staging dashboard

- **Production Mode**: Set `PAYTM_TEST_MODE=False` in your `.env` file
  - Uses Paytm production servers
  - Real transactions are processed
  - Full production security measures are applied

### 5. Verify Integration

To verify your integration is working correctly:

1. Set `PAYTM_TEST_MODE=True` temporarily
2. Process a test order through your application
3. Confirm the payment flow completes successfully
4. Check the transaction status in your Paytm staging dashboard
5. Once verified, set `PAYTM_TEST_MODE=False` for production use

### 6. Common Paytm Error Codes

Here are some common Paytm error codes and their solutions:

| Error Code | Description | Solution |
|------------|-------------|----------|
| 400 | Bad Request | Check your request parameters |
| 401 | Unauthorized | Verify merchant ID and key |
| 402 | Payment Required | The transaction requires payment |
| 403 | Forbidden | Your IP may not be whitelisted |
| 404 | Not Found | Check the API endpoint URL |
| 500 | Internal Server Error | Contact Paytm support |

### 7. Security Best Practices

1. **Never hardcode Paytm credentials** in your source code
2. Always validate the checksum in the callback response
3. Store sensitive data like Merchant Key securely using environment variables
4. Implement proper error handling for payment failures
5. Log all payment transactions for audit purposes
6. Never expose payment details to client-side code

### 8. Testing Tools

- Use Paytm test cards for sandbox testing:
  - Card Number: 4111 1111 1111 1111
  - Expiry: Any future date
  - CVV: Any 3 digits
  - OTP: 489871

- Test UPI: 7777777777@paytm
- Test Mobile Number: 7777777777
- Test OTP: 489871

### 9. Important Notes

- The production Paytm flow requires a valid mobile number and email for customers
- Configure the appropriate transaction fees in your Paytm dashboard
- For international payments, ensure your Paytm account is configured for international transactions
- For recurring payments, you'll need to enable subscription payments in your Paytm dashboard

### 10. Troubleshooting

If you encounter issues with Paytm integration:

1. Check the S2Cart API logs for detailed error information
2. Verify all Paytm credentials are correct
3. Ensure your callback URL is properly configured
4. Check that your server's IP is whitelisted in the Paytm dashboard
5. Verify SSL certificates are valid and not expired
6. Contact Paytm support with your Merchant ID and transaction details
