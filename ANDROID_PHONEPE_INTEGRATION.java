// Android Integration Example for PhonePe Payment Gateway
// File: PaymentManager.java

package com.s2cart.payments;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import androidx.annotation.NonNull;

import okhttp3.*;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

public class PaymentManager {
    
    private static final String TAG = "PaymentManager";
    private static final String BASE_URL = "https://customer-api.s2cart.me";
    private static final int PHONEPE_REQUEST_CODE = 123;
    
    private final Activity activity;
    private final OkHttpClient client;
    
    public PaymentManager(Activity activity) {
        this.activity = activity;
        this.client = new OkHttpClient();
    }
    
    /**
     * Initiate PhonePe payment for an order
     */
    public void initiatePhonePePayment(int orderId, String jwtToken, PaymentCallback callback) {
        try {
            JSONObject json = new JSONObject();
            json.put("order_id", orderId);
            
            RequestBody requestBody = RequestBody.create(
                json.toString(), 
                MediaType.parse("application/json")
            );
            
            Request request = new Request.Builder()
                .url(BASE_URL + "/api/auth/payments/phonepe/initiate/")
                .post(requestBody)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .addHeader("Content-Type", "application/json")
                .build();
            
            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(@NonNull Call call, @NonNull IOException e) {
                    activity.runOnUiThread(() -> 
                        callback.onError("Network error: " + e.getMessage())
                    );
                }
                
                @Override
                public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                    String responseBody = null;
                    if (response.body() != null) {
                        responseBody = response.body().string();
                    }
                    
                    final String finalResponseBody = responseBody;
                    activity.runOnUiThread(() -> {
                        if (response.isSuccessful() && finalResponseBody != null) {
                            try {
                                JSONObject jsonResponse = new JSONObject(finalResponseBody);
                                JSONObject paymentData = jsonResponse.getJSONObject("payment_data");
                                
                                // For test mode, show a simple payment simulation
                                if (paymentData.getBoolean("test_mode")) {
                                    showTestModePayment(jsonResponse, callback);
                                } else {
                                    // For production, integrate with PhonePe SDK
                                    integrateWithPhonePeSDK(paymentData, callback);
                                }
                            } catch (JSONException e) {
                                callback.onError("Response parsing error: " + e.getMessage());
                            }
                        } else {
                            try {
                                JSONObject errorResponse = new JSONObject(finalResponseBody != null ? finalResponseBody : "{}");
                                String errorMessage = errorResponse.optString("error", "Payment initiation failed");
                                callback.onError(errorMessage);
                            } catch (JSONException e) {
                                callback.onError("Payment initiation failed: " + response.code());
                            }
                        }
                    });
                    response.close();
                }
            });
        } catch (JSONException e) {
            callback.onError("Request creation error: " + e.getMessage());
        }
    }
    
    /**
     * Show test mode payment simulation
     */
    private void showTestModePayment(JSONObject paymentResponse, PaymentCallback callback) {
        try {
            String paymentId = paymentResponse.getString("payment_id");
            String amount = paymentResponse.getString("amount");
            String orderId = paymentResponse.getString("order_id");
            JSONObject paymentData = paymentResponse.getJSONObject("payment_data");
            
            // Check if real PhonePe payment URL is available
            if (paymentData.has("payment_url")) {
                // Real PhonePe test mode - redirect to actual PhonePe payment page
                openRealPhonePePayment(paymentData, callback);
            } else {
                // Fallback to simulation
                openPaymentSimulation(paymentId, amount, orderId, callback);
            }
        } catch (JSONException e) {
            callback.onError("Test payment setup error: " + e.getMessage());
        }
    }
    
    /**
     * Open real PhonePe payment page (recommended for testing)
     */
    private void openRealPhonePePayment(JSONObject paymentData, PaymentCallback callback) {
        try {
            String paymentUrl = paymentData.getString("payment_url");
            String base64Payload = paymentData.getString("base64_payload");
            String checksum = paymentData.getString("checksum");
            String paymentId = paymentData.getString("payment_id");
            
            // Create intent to open PhonePe payment in WebView
            Intent intent = new Intent(activity, PhonePePaymentActivity.class);
            intent.putExtra("payment_url", paymentUrl);
            intent.putExtra("base64_payload", base64Payload);
            intent.putExtra("checksum", checksum);
            intent.putExtra("payment_id", paymentId);
            intent.putExtra("real_phonepe", true);
            
            activity.startActivityForResult(intent, PHONEPE_REQUEST_CODE);
            callback.onPaymentInitiated(paymentId);
            
            Log.i(TAG, "Real PhonePe payment initiated with URL: " + paymentUrl);
        } catch (JSONException e) {
            callback.onError("Real payment setup error: " + e.getMessage());
        }
    }
    
    /**
     * Open payment simulation (fallback)
     */
    private void openPaymentSimulation(String paymentId, String amount, String orderId, PaymentCallback callback) {
        // Create intent for simple simulation
        Intent intent = new Intent(activity, PaymentSimulationActivity.class);
        intent.putExtra("payment_id", paymentId);
        intent.putExtra("amount", amount);
        intent.putExtra("order_id", orderId);
        intent.putExtra("test_mode", true);
        
        activity.startActivityForResult(intent, PHONEPE_REQUEST_CODE);
        callback.onPaymentInitiated(paymentId);
    }
    
    /**
     * Integrate with PhonePe SDK for production
     */
    private void integrateWithPhonePeSDK(JSONObject paymentData, PaymentCallback callback) {
        // TODO: Implement PhonePe SDK integration for production
        // This would involve:
        // 1. Initialize PhonePe SDK with merchant credentials
        // 2. Create payment request
        // 3. Start PhonePe payment flow
        
        Log.d(TAG, "PhonePe SDK integration needed for production");
        callback.onError("PhonePe SDK integration required for production mode");
    }
    
    /**
     * Verify payment status on server
     */
    public void verifyPaymentStatus(String paymentId, String jwtToken, PaymentStatusCallback callback) {
        Request request = new Request.Builder()
            .url(BASE_URL + "/api/auth/payments/status/" + paymentId + "/")
            .get()
            .addHeader("Authorization", "Bearer " + jwtToken)
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                activity.runOnUiThread(() ->
                    callback.onError("Network error: " + e.getMessage())
                );
            }
            
            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                String responseBody = null;
                if (response.body() != null) {
                    responseBody = response.body().string();
                }
                
                final String finalResponseBody = responseBody;
                activity.runOnUiThread(() -> {
                    if (response.isSuccessful() && finalResponseBody != null) {
                        try {
                            JSONObject jsonResponse = new JSONObject(finalResponseBody);
                            String status = jsonResponse.getString("status");
                            String amount = jsonResponse.getString("amount");
                            
                            PaymentStatus paymentStatus = new PaymentStatus(
                                paymentId,
                                status,
                                amount,
                                "COMPLETED".equals(status),
                                "FAILED".equals(status)
                            );
                            
                            callback.onStatusReceived(paymentStatus);
                        } catch (JSONException e) {
                            callback.onError("Status parsing error: " + e.getMessage());
                        }
                    } else {
                        callback.onError("Failed to get payment status: " + response.code());
                    }
                });
                response.close();
            }
        });
    }
    
    /**
     * Handle activity result from payment flow
     */
    public void handleActivityResult(int requestCode, int resultCode, Intent data, 
                                   String jwtToken, PaymentResultCallback callback) {
        if (requestCode == PHONEPE_REQUEST_CODE) {
            switch (resultCode) {
                case Activity.RESULT_OK:
                    String paymentId = data != null ? data.getStringExtra("payment_id") : null;
                    if (paymentId == null) return;
                    
                    // Verify payment status on server
                    verifyPaymentStatus(paymentId, jwtToken, new PaymentStatusCallback() {
                        @Override
                        public void onStatusReceived(PaymentStatus status) {
                            if (status.isCompleted()) {
                                callback.onPaymentSuccess(status);
                            } else if (status.isFailed()) {
                                callback.onPaymentFailed("Payment failed on server verification");
                            } else {
                                callback.onPaymentPending(status);
                            }
                        }
                        
                        @Override
                        public void onError(String error) {
                            callback.onPaymentFailed("Verification failed: " + error);
                        }
                    });
                    break;
                    
                case Activity.RESULT_CANCELED:
                    callback.onPaymentCanceled();
                    break;
                    
                default:
                    callback.onPaymentFailed("Payment failed with result code: " + resultCode);
                    break;
            }
        }
    }
}

// Callback interfaces
interface PaymentCallback {
    void onPaymentInitiated(String paymentId);
    void onError(String error);
}

interface PaymentStatusCallback {
    void onStatusReceived(PaymentStatus status);
    void onError(String error);
}

interface PaymentResultCallback {
    void onPaymentSuccess(PaymentStatus status);
    void onPaymentFailed(String error);
    void onPaymentCanceled();
    void onPaymentPending(PaymentStatus status);
}

// Data class
class PaymentStatus {
    private final String paymentId;
    private final String status;
    private final String amount;
    private final boolean isCompleted;
    private final boolean isFailed;
    
    public PaymentStatus(String paymentId, String status, String amount, 
                        boolean isCompleted, boolean isFailed) {
        this.paymentId = paymentId;
        this.status = status;
        this.amount = amount;
        this.isCompleted = isCompleted;
        this.isFailed = isFailed;
    }
    
    // Getters
    public String getPaymentId() { return paymentId; }
    public String getStatus() { return status; }
    public String getAmount() { return amount; }
    public boolean isCompleted() { return isCompleted; }
    public boolean isFailed() { return isFailed; }
}

/*
Usage Example in Activity:

public class CheckoutActivity extends AppCompatActivity {
    
    private PaymentManager paymentManager;
    private String currentPaymentId;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_checkout);
        
        paymentManager = new PaymentManager(this);
        
        // Handle payment button click
        findViewById(R.id.btn_pay_phonepe).setOnClickListener(v -> initiatePayment());
    }
    
    private void initiatePayment() {
        int orderId = getIntent().getIntExtra("order_id", 0);
        String jwtToken = getJwtToken(); // Get from your auth manager
        
        if (orderId == 0 || jwtToken.isEmpty()) {
            showError("Invalid order or authentication");
            return;
        }
        
        showProgressDialog("Initiating payment...");
        
        paymentManager.initiatePhonePePayment(orderId, jwtToken, new PaymentCallback() {
            @Override
            public void onPaymentInitiated(String paymentId) {
                currentPaymentId = paymentId;
                hideProgressDialog();
                // Payment flow started, wait for result
            }
            
            @Override
            public void onError(String error) {
                hideProgressDialog();
                showError(error);
            }
        });
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        String jwtToken = getJwtToken();
        
        paymentManager.handleActivityResult(requestCode, resultCode, data, jwtToken, 
            new PaymentResultCallback() {
                @Override
                public void onPaymentSuccess(PaymentStatus status) {
                    showSuccess("Payment successful! Amount: ₹" + status.getAmount());
                    // Navigate to order confirmation
                }
                
                @Override
                public void onPaymentFailed(String error) {
                    showError("Payment failed: " + error);
                }
                
                @Override
                public void onPaymentCanceled() {
                    showInfo("Payment was canceled");
                }
                
                @Override
                public void onPaymentPending(PaymentStatus status) {
                    showInfo("Payment is pending verification");
                    // You might want to check status again later
                }
            }
        );
    }
    
    private String getJwtToken() {
        // Return JWT token from your authentication manager
        return "your_jwt_token_here";
    }
    
    // UI helper methods
    private void showProgressDialog(String message) { /* Implementation */ }
    private void hideProgressDialog() { /* Implementation */ }
    private void showError(String message) { /* Implementation */ }
    private void showSuccess(String message) { /* Implementation */ }
    private void showInfo(String message) { /* Implementation */ }
}
*/
