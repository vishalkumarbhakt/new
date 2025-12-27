# PhonePe Payment Gateway Integration Guide

## Overview
This guide covers how to integrate PhonePe payments into your Android application using our secure server-side API. The integration follows PhonePe's official documentation and implements all security best practices.

## Current Configuration

### Test Mode Settings
```
✅ PhonePe Test Mode: ENABLED
✅ Merchant ID: PGTESTPAYUAT (Official test merchant)
✅ Domain: customer-api.s2cart.me
✅ SSL/HTTPS: Enabled
✅ Server-side verification: Enabled
```

## 🎯 Amount Handling (CRITICAL)

⚠️ **IMPORTANT**: PhonePe expects amounts in **paise** (smallest currency unit).

```json
{
  "amount": "47999.97",           // API shows amount in rupees
  "payment_data": {
    "amount": 4799997            // PhonePe gets amount in paise (×100)
  }
}
```

✅ **Conversion**: ₹47,999.97 × 100 = 4,799,997 paise
❌ **Wrong**: Sending rupees directly would charge 100x more!

## API Endpoints

### 1. Initiate Payment (Unified)
**Recommended for new integrations**
```
POST https://customer-api.s2cart.me/api/auth/payments/initiate/
```

### 2. Initiate PhonePe Payment (Specific)
**For PhonePe-specific features**
```
POST https://customer-api.s2cart.me/api/auth/payments/phonepe/initiate/
```

### 3. Payment Status Check
```
GET https://customer-api.s2cart.me/api/auth/payments/status/{payment_id}/
```

### 4. Callback Endpoints (Server-only)
```
POST https://customer-api.s2cart.me/api/auth/payments/phonepe/callback/
GET https://customer-api.s2cart.me/api/auth/payments/phonepe/redirect/
```

## Android Integration Steps

### Step 1: Create Order
Before initiating payment, create an order:

```http
POST https://customer-api.s2cart.me/api/auth/orders/
Authorization: Bearer {jwt_token}
Content-Type: application/json

{
    "delivery_address": "123 Main St, City",
    "payment_method": "PHONEPE",
    "notes": "Order notes"
}
```

### Step 2: Initiate Payment

```http
POST https://customer-api.s2cart.me/api/auth/payments/phonepe/initiate/
Authorization: Bearer {jwt_token}
Content-Type: application/json

{
    "order_id": 3
}
```

**Response:**
```json
{
    "payment_id": 46,
    "transaction_id": "TXN_PHONEPE_3_37_1751086721_02cb362c",
    "order_id": 3,
    "amount": "47999.97",
    "currency": "INR",
    "payment_method": "PHONEPE",
    "payment_data": {
        "order_id": "ORD_PHONEPE_3_1751086721",
        "payment_id": "46",
        "amount": 4799997,
        "merchant_id": "PGTESTPAYUAT",
        "redirect_url": "https://customer-api.s2cart.me/api/auth/payments/phonepe/redirect/",
        "callback_url": "https://customer-api.s2cart.me/api/auth/payments/phonepe/callback/",
        "test_mode": true,
        "security_hash": "0d3eba1a339fb7ca"
    },
    "expires_at": "2025-06-28T05:13:41.674985+00:00",
    "callback_required": true,
    "security_note": "PHONEPE payment verification will be done server-side"
}
```

### Step 3: Android Payment Flow

#### Option A: WebView Integration (Recommended for Test Mode)
```java
// In your Android Activity
WebView webView = findViewById(R.id.payment_webview);
webView.getSettings().setJavaScriptEnabled(true);

// Create a simple HTML form for PhonePe test mode
String paymentForm = String.format(
    "<!DOCTYPE html>" +
    "<html>" +
    "<head>" +
    "    <title>PhonePe Payment</title>" +
    "    <script>" +
    "        function initiatePayment() {" +
    "            // For test mode, you can simulate payment completion" +
    "            alert('Test Mode: Payment Simulation');" +
    "            " +
    "            // In test mode, you would typically redirect to success/failure page" +
    "            // For production, integrate with PhonePe SDK" +
    "            " +
    "            // Simulate successful payment callback" +
    "            setTimeout(function() {" +
    "                window.location.href = '%s?status=SUCCESS&transactionId=%s';" +
    "            }, 2000);" +
    "        }" +
    "    </script>" +
    "</head>" +
    "<body onload=\"initiatePayment()\">" +
    "    <h2>Processing Payment...</h2>" +
    "    <p>Amount: ₹%.2f</p>" +
    "    <p>Order ID: %s</p>" +
    "    <p>Test Mode: Active</p>" +
    "    " +
    "    <button onclick=\"initiatePayment()\">Simulate Payment</button>" +
    "</body>" +
    "</html>",
    paymentData.getString("redirect_url"),
    paymentData.getString("order_id"),
    paymentData.getInt("amount") / 100.0,
    paymentData.getString("order_id")
);

webView.loadData(paymentForm, "text/html", "UTF-8");
```

#### Option B: PhonePe SDK Integration (For Production)
```java
// Add PhonePe SDK dependency in build.gradle
implementation 'com.phonepe.intent:intent:2.4.1'

// Initialize PhonePe SDK
PhonePe phonepe = PhonePe.getPhonePeInstance();
phonepe.init(getApplicationContext(), PhonePeEnvironment.SANDBOX, "PGTESTPAYUAT", "");

// Create payment request
PhonePePaymentRequest paymentRequest = new PhonePePaymentRequest.Builder()
    .data(paymentData.toString())
    .checksum(generateChecksum(paymentData))
    .build();

// Start payment
phonepe.startPayment(this, paymentRequest);
```

### Step 4: Handle Payment Result

```java
// In your Activity
@Override
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    
    if (requestCode == PHONEPE_REQUEST_CODE) {
        switch (resultCode) {
            case RESULT_OK:
                // Payment completed, verify on server
                verifyPaymentOnServer(paymentId);
                break;
            case RESULT_CANCELED:
                // Payment canceled by user
                showPaymentCanceledMessage();
                break;
            default:
                // Payment failed
                showPaymentFailedMessage();
                break;
        }
    }
}

private void verifyPaymentOnServer(String paymentId) {
    // Always verify payment status on server
    Retrofit retrofit = new Retrofit.Builder()
        .baseUrl("https://customer-api.s2cart.me/")
        .addConverterFactory(GsonConverterFactory.create())
        .build();
    
    val apiService = retrofit.create(ApiService::class.java)
    
    apiService.checkPaymentStatus(paymentId, "Bearer $jwtToken")
        .enqueue(object : Callback<PaymentStatusResponse> {
            override fun onResponse(call: Call<PaymentStatusResponse>, response: Response<PaymentStatusResponse>) {
                if (response.isSuccessful) {
                    val status = response.body()?.status
                    when (status) {
                        "COMPLETED" -> showPaymentSuccessMessage()
                        "FAILED" -> showPaymentFailedMessage()
                        "PENDING" -> checkAgainLater()
                    }
                }
            }
            
            override fun onFailure(call: Call<PaymentStatusResponse>, t: Throwable) {
                showNetworkErrorMessage()
            }
        })
}
```

## Testing Guide

### Manual Testing Steps

1. **Create a test user account**
2. **Login and get JWT token**
3. **Create an order with items**
4. **Initiate PhonePe payment**
5. **Complete the payment flow**
6. **Verify payment status**

### Test Cases

#### 1. Successful Payment Flow
```bash
# Test the complete flow
curl -X POST "https://customer-api.s2cart.me/api/auth/payments/phonepe/initiate/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"order_id": YOUR_ORDER_ID}'
```

#### 2. Payment Status Check
```bash
curl -X GET "https://customer-api.s2cart.me/api/auth/payments/status/PAYMENT_ID/" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 3. Invalid Order ID
```bash
curl -X POST "https://customer-api.s2cart.me/api/auth/payments/phonepe/initiate/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"order_id": 99999}'
```

#### 4. Unauthorized Access
```bash
curl -X POST "https://customer-api.s2cart.me/api/auth/payments/phonepe/initiate/" \
  -H "Content-Type: application/json" \
  -d '{"order_id": 1}'
```

### Expected Test Results

#### ✅ Successful Payment Initiation
```json
{
    "payment_id": 46,
    "transaction_id": "TXN_PHONEPE_3_37_1751086721_02cb362c",
    "order_id": 3,
    "amount": "47999.97",
    "currency": "INR",
    "payment_method": "PHONEPE",
    "test_mode": true,
    "security_note": "PHONEPE payment verification will be done server-side"
}
```

#### ❌ Invalid Order
```json
{
    "error": "Invalid order ID or unauthorized access"
}
```

#### ❌ Unauthorized
```json
{
    "detail": "Authentication credentials were not provided."
}
```

## Security Features

### ✅ Implemented Security Measures

1. **Server-side Amount Validation**: Amount is always calculated on server
2. **JWT Authentication**: All requests require valid JWT token
3. **User Authorization**: Users can only pay for their own orders
4. **Transaction Uniqueness**: Each payment gets unique transaction ID
5. **Payment Verification**: Server-side verification with PhonePe
6. **Anti-replay Protection**: Transaction IDs include timestamps
7. **Secure Callback Handling**: Callbacks are verified cryptographically
8. **Rate Limiting**: Prevents payment spam attempts

### 🔒 Security Guarantees

- ✅ **No client-side amount manipulation possible**
- ✅ **All payments verified server-to-server with PhonePe**
- ✅ **User can only access their own payments**
- ✅ **Duplicate payment protection**
- ✅ **Secure test mode without real money transactions**

## Production Deployment

### Before Going Live

1. **Update .env settings:**
```bash
PHONEPE_TEST_MODE=False
PHONEPE_MERCHANT_ID=YOUR_PRODUCTION_MERCHANT_ID
PHONEPE_SALT_KEY=YOUR_PRODUCTION_SALT_KEY
```

2. **Update Android app:**
   - Change PhonePe SDK to PRODUCTION environment
   - Update merchant ID in Android app
   - Test with small amounts first

3. **Verify SSL certificate** is valid on customer-api.s2cart.me

4. **Monitor logs** for any errors during initial production testing

## Support and Troubleshooting

### Common Issues

1. **Payment stuck in PENDING**: Check PhonePe dashboard for transaction status
2. **Invalid signature errors**: Verify salt key and checksum generation
3. **Network timeouts**: Implement retry logic with exponential backoff
4. **JWT token expired**: Implement automatic token refresh

### Logs Location
```bash
/home/s2cartofficial_gmail_com/Customer-API/logs/django.log
/home/s2cartofficial_gmail_com/Customer-API/logs/gunicorn.error.log
```

### API Rate Limits
- Payment initiation: 10 requests per minute per user
- Status check: 60 requests per minute per user

## Contact

For technical support or integration issues, contact the development team with:
- Complete request/response logs
- Error messages
- Steps to reproduce the issue
- Android app version and device information

---

**Note**: This implementation follows PhonePe's official documentation and includes all recommended security practices for production use.
