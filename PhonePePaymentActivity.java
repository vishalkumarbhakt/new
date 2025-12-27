// PhonePePaymentActivity.java - Real PhonePe Payment Integration
package com.s2cart.payments;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.webkit.*;
import android.widget.ProgressBar;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

import okhttp3.*;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class PhonePePaymentActivity extends AppCompatActivity {
    
    private static final String TAG = "PhonePePayment";
    private WebView webView;
    private ProgressBar progressBar;
    private String paymentId;
    private String paymentUrl;
    private String base64Payload;
    private String checksum;
    private boolean paymentCompleted = false;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_phonepe_payment);
        
        initializeViews();
        getIntentData();
        setupWebView();
        initiatePhonePePayment();
    }
    
    private void initializeViews() {
        webView = findViewById(R.id.webview_payment);
        progressBar = findViewById(R.id.progress_bar);
    }
    
    private void getIntentData() {
        Intent intent = getIntent();
        paymentUrl = intent.getStringExtra("payment_url");
        base64Payload = intent.getStringExtra("base64_payload");
        checksum = intent.getStringExtra("checksum");
        paymentId = intent.getStringExtra("payment_id");
        
        Log.d(TAG, "Payment URL: " + paymentUrl);
        Log.d(TAG, "Payment ID: " + paymentId);
    }
    
    private void setupWebView() {
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDomStorageEnabled(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setUseWideViewPort(true);
        webSettings.setBuiltInZoomControls(true);
        webSettings.setDisplayZoomControls(false);
        webSettings.setSupportZoom(true);
        webSettings.setDefaultTextEncodingName("utf-8");
        
        // Handle redirects and page loading
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                progressBar.setVisibility(View.VISIBLE);
                Log.d(TAG, "Page started loading: " + url);
                
                // Check if this is a redirect back to our server (payment completion)
                if (url.contains("/api/auth/payments/phonepe/redirect/")) {
                    handlePaymentRedirect(url);
                }
            }
            
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                progressBar.setVisibility(View.GONE);
                Log.d(TAG, "Page finished loading: " + url);
            }
            
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);
                Log.e(TAG, "WebView error: " + error.getDescription());
                
                if (!paymentCompleted) {
                    Toast.makeText(PhonePePaymentActivity.this, 
                        "Payment page loading error", Toast.LENGTH_SHORT).show();
                }
            }
            
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                Log.d(TAG, "URL loading: " + url);
                
                // Allow PhonePe URLs and our redirect URLs
                if (url.contains("phonepe.com") || 
                    url.contains("/api/auth/payments/phonepe/")) {
                    return false; // Let WebView handle it
                }
                
                return super.shouldOverrideUrlLoading(view, request);
            }
        });
        
        // Handle JavaScript alerts and dialogs
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress < 100 && progressBar.getVisibility() == ProgressBar.GONE) {
                    progressBar.setVisibility(ProgressBar.VISIBLE);
                }
                if (newProgress == 100) {
                    progressBar.setVisibility(ProgressBar.GONE);
                }
            }
            
            @Override
            public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
                Log.d(TAG, "JS Alert: " + message);
                return super.onJsAlert(view, url, message, result);
            }
        });
    }
    
    private void initiatePhonePePayment() {
        try {
            // Create the POST request to PhonePe
            OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
            
            // Create form data
            FormBody.Builder formBuilder = new FormBody.Builder();
            formBuilder.add("request", base64Payload);
            formBuilder.add("checksum", checksum);
            
            Request request = new Request.Builder()
                .url(paymentUrl)
                .post(formBuilder.build())
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .addHeader("X-VERIFY", checksum)
                .build();
            
            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    runOnUiThread(() -> {
                        Log.e(TAG, "PhonePe API call failed: " + e.getMessage());
                        Toast.makeText(PhonePePaymentActivity.this, 
                            "Failed to connect to PhonePe: " + e.getMessage(), 
                            Toast.LENGTH_LONG).show();
                        setPaymentResult(Activity.RESULT_CANCELED, "Connection failed");
                    });
                }
                
                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    runOnUiThread(() -> {
                        if (response.isSuccessful()) {
                            try {
                                String responseBody = response.body().string();
                                Log.d(TAG, "PhonePe API response: " + responseBody);
                                
                                // Parse response to get redirect URL
                                JSONObject jsonResponse = new JSONObject(responseBody);
                                
                                if (jsonResponse.getBoolean("success")) {
                                    JSONObject data = jsonResponse.getJSONObject("data");
                                    String instrumentResponse = data.getJSONObject("instrumentResponse").toString();
                                    JSONObject instrument = new JSONObject(instrumentResponse);
                                    String redirectUrl = instrument.getString("redirectInfo");
                                    
                                    // Load the PhonePe payment page
                                    webView.loadUrl(redirectUrl);
                                    Log.i(TAG, "Loading PhonePe payment page: " + redirectUrl);
                                } else {
                                    String message = jsonResponse.optString("message", "Payment initiation failed");
                                    Toast.makeText(PhonePePaymentActivity.this, 
                                        "Payment failed: " + message, Toast.LENGTH_LONG).show();
                                    setPaymentResult(Activity.RESULT_CANCELED, message);
                                }
                            } catch (JSONException | IOException e) {
                                Log.e(TAG, "Error parsing PhonePe response: " + e.getMessage());
                                Toast.makeText(PhonePePaymentActivity.this, 
                                    "Response parsing error", Toast.LENGTH_SHORT).show();
                                setPaymentResult(Activity.RESULT_CANCELED, "Response parsing error");
                            }
                        } else {
                            Log.e(TAG, "PhonePe API error: " + response.code());
                            Toast.makeText(PhonePePaymentActivity.this, 
                                "PhonePe API error: " + response.code(), Toast.LENGTH_SHORT).show();
                            setPaymentResult(Activity.RESULT_CANCELED, "API error: " + response.code());
                        }
                    });
                    response.close();
                }
            });
            
        } catch (Exception e) {
            Log.e(TAG, "Error initiating PhonePe payment: " + e.getMessage());
            Toast.makeText(this, "Error initiating payment: " + e.getMessage(), Toast.LENGTH_LONG).show();
            setPaymentResult(Activity.RESULT_CANCELED, e.getMessage());
        }
    }
    
    private void handlePaymentRedirect(String redirectUrl) {
        Log.i(TAG, "Payment redirect detected: " + redirectUrl);
        
        // Extract status from URL parameters
        if (redirectUrl.contains("status=SUCCESS") || redirectUrl.contains("success=true")) {
            Log.i(TAG, "Payment successful redirect detected");
            setPaymentResult(Activity.RESULT_OK, "Payment successful");
        } else if (redirectUrl.contains("status=FAILURE") || redirectUrl.contains("success=false")) {
            Log.i(TAG, "Payment failed redirect detected");
            setPaymentResult(Activity.RESULT_CANCELED, "Payment failed");
        } else {
            // Wait a bit more to see if we get more info
            Log.i(TAG, "Payment redirect received, checking status...");
            
            // Give PhonePe a moment to process, then check status
            webView.postDelayed(() -> {
                if (!paymentCompleted) {
                    setPaymentResult(Activity.RESULT_OK, "Payment completed");
                }
            }, 2000);
        }
    }
    
    private void setPaymentResult(int resultCode, String message) {
        if (paymentCompleted) return;
        
        paymentCompleted = true;
        Log.i(TAG, "Setting payment result: " + resultCode + ", message: " + message);
        
        Intent result = new Intent();
        result.putExtra("payment_id", paymentId);
        result.putExtra("message", message);
        
        setResult(resultCode, result);
        finish();
    }
    
    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            // User cancelled payment
            if (!paymentCompleted) {
                setPaymentResult(Activity.RESULT_CANCELED, "Payment cancelled by user");
            }
        }
    }
    
    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
