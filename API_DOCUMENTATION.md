# S2Cart Customer API - Complete Reference Documentation

## 📋 Table of Contents
1. [API Overview](#api-overview)
2. [Authentication](#authentication)
3. [Base Response Format](#base-response-format)
4. [Error Codes](#error-codes)
5. [Data Models](#data-models)
6. [User Management](#user-management)
7. [Authentication Endpoints](#authentication-endpoints)
8. [JWT Token Management](#jwt-token-management)
9. [Cart Management](#cart-management)
10. [Order Management](#order-management)
11. [Payment System](#payment-system)
12. [Address Management](#address-management)
13. [Search History](#search-history)
14. [Customer Support](#customer-support)
15. [Rate Limiting](#rate-limiting)
16. [Pagination](#pagination)
17. [Additional Features](#additional-features)

## 🚀 API Overview

### Base Information
- **Base URL**: `https://yourdomain.com/api/auth/`
- **API Version**: 1.0
- **Content Type**: `application/json`
- **Charset**: UTF-8
- **Protocol**: HTTPS (Required in production)

### Supported HTTP Methods
- `GET` - Retrieve data
- `POST` - Create new resources
- `PUT` - Update entire resources
- `PATCH` - Partial resource updates
- `DELETE` - Remove resources

### Required Headers
```http
Content-Type: application/json
Accept: application/json
Authorization: Bearer <jwt_token> # For authenticated endpoints
```

### Optional Headers for Enhanced Tracking
```http
X-Device-Type: ANDROID|WEB|IOS|API
X-Device-ID: unique_device_identifier
X-App-Version: app_version
User-Agent: app_user_agent_string
```

## 🔐 Authentication

S2Cart API supports dual authentication systems:

### 1. JWT Authentication (Recommended)
Modern JWT-based authentication with refresh token support and session management.

**Features:**
- Access tokens (7 days default)
- Refresh tokens (30 days default)
- Token blacklisting
- Device tracking
- Session management

### 2. Legacy Token Authentication
Traditional token-based authentication for backward compatibility.

**Features:**
- Expiring tokens (30 days default)
- Device tracking
- Session management

### Authentication Flow

#### JWT Login Flow
```
1. POST /api/auth/jwt/ → Get access & refresh tokens
2. Use access token for API calls
3. POST /api/auth/jwt/refresh/ → Refresh access token when expired
4. POST /api/auth/jwt/logout/ → Logout and blacklist tokens
```

#### Legacy Login Flow
```
1. POST /api/auth/login/ → Get authentication token
2. Use token for API calls
3. POST /api/auth/logout/ → Logout and invalidate token
```

### Permission Levels
- **AllowAny**: Public endpoints (registration, login)
- **IsAuthenticated**: Requires valid authentication
- **IsOwner**: User can only access their own resources

## 📋 Base Response Format

### Success Response Structure
```json
{
  "status": "success",
  "code": 200,
  "message": "Operation completed successfully",
  "data": {
    // Response data object
  },
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_pages": 5,
    "total_count": 100,
    "has_next": true,
    "has_previous": false
  }
}
```

### Error Response Structure
```json
{
  "status": "error",
  "code": 400,
  "message": "Validation failed",
  "errors": {
    "field_name": ["Error message for this field"],
    "another_field": ["Another error message"]
  },
  "timestamp": "2025-01-20T10:30:00Z"
}
```

## ⚠️ Error Codes

### HTTP Status Codes

| Status Code | Description | Common Causes |
|-------------|-------------|---------------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request data, validation errors |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions, account locked |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Custom Error Codes

| Error Code | Message | Description |
|------------|---------|-------------|
| AUTH_001 | Invalid credentials | Wrong username/password |
| AUTH_002 | Account not verified | Email verification required |
| AUTH_003 | Account locked | Too many failed login attempts |
| AUTH_004 | Token expired | Authentication token has expired |
| AUTH_005 | Invalid token | Malformed or invalid token |
| CART_001 | Cart limit exceeded | Maximum number of carts reached |
| CART_002 | Invalid store ID | Store identifier not found |
| CART_003 | Item out of stock | Product not available |
| PAY_001 | Payment failed | Payment processing error |
| PAY_002 | Invalid payment method | Unsupported payment gateway |
| PAY_003 | Insufficient funds | Payment declined by bank |

### Rate Limiting Errors
```json
{
  "status": "error",
  "code": 429,
  "message": "Rate limit exceeded",
  "retry_after": 60,
  "limit_type": "login",
  "current_usage": "5/3"
}
```

## 📊 Data Models

### User Model
```json
{
  "id": 1,
  "username": "user123",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+91987654321",
  "profile_image": "https://domain.com/media/profile/image.jpg",
  "date_of_birth": "1990-01-01",
  "gender": "MALE",
  "preferred_language": "EN",
  "email_notifications": true,
  "sms_notifications": true,
  "push_notifications": true,
  "is_verified": true,
  "date_joined": "2025-01-01T00:00:00Z",
  "last_login": "2025-01-20T10:30:00Z"
}
```

### Address Model
```json
{
  "id": 1,
  "contact_name": "John Doe",
  "street_address": "123 Main Street",
  "street_address_2": "Apartment 4B",
  "landmark": "Near Central Mall",
  "city": "Mumbai",
  "state": "Maharashtra",
  "pin_code": "400001",
  "country": "India",
  "phone_number": "+91987654321",
  "address_type": "HOME",
  "latitude": 19.0760,
  "longitude": 72.8777,
  "is_default": true,
  "is_verified": false,
  "full_address": "123 Main Street, Apartment 4B, Near Central Mall, Mumbai, Maharashtra 400001, India",
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-20T10:30:00Z"
}
```

### Cart Model
```json
{
  "id": 1,
  "store_id": "store_123",
  "store_name": "SuperMart",
  "total_price": 1250.50,
  "item_count": 3,
  "applied_coupon": "SAVE10",
  "coupon_discount": 125.05,
  "updated_at": "2025-01-20T10:30:00Z",
  "items": [
    {
      "id": 1,
      "product_id": "prod_001",
      "product_name": "Wireless Headphones",
      "product_image_url": "https://domain.com/media/products/headphones.jpg",
      "quantity": 2,
      "unit_price": 500.00,
      "total_price": 1000.00,
      "added_at": "2025-01-20T09:00:00Z"
    }
  ]
}
```

### Order Model
```json
{
  "id": 1,
  "order_number": "ORD-20250120-1234",
  "status": "DELIVERED",
  "order_date": "2025-01-15T10:00:00Z",
  "subtotal": 1000.00,
  "tax_amount": 180.00,
  "shipping_cost": 50.00,
  "discount_amount": 100.00,
  "total_amount": 1130.00,
  "coupon_code": "SAVE10",
  "tracking_number": "TRK123456789",
  "estimated_delivery_date": "2025-01-20T18:00:00Z",
  "shipping_address_details": {
    // Address object
  },
  "items": [
    // OrderItem objects
  ]
}
```

### Payment Model
```json
{
  "id": 1,
  "transaction_id": "TXN_PAYTM_1_123456789",
  "amount": 1130.00,
  "currency": "INR",
  "status": "COMPLETED",
  "payment_type": "UPI",
  "gateway_name": "PAYTM",
  "gateway_transaction_id": "PTM123456789",
  "tax_amount": 180.00,
  "convenience_fee": 10.00,
  "discount_amount": 100.00,
  "created_at": "2025-01-15T10:00:00Z",
  "order_id": 1
}
```

## 👤 User Management

### User Registration

**Endpoint:** `POST /register/`
**Authentication:** Not Required
**Rate Limit:** 5 requests per hour

**Description:** Register a new user account with dual verification methods (email link + OTP).

**Request Parameters:**
```json
{
  "username": "string (required, 3-150 chars)",
  "email": "string (required, valid email)",
  "password": "string (required, min 8 chars)",
  "first_name": "string (optional)",
  "last_name": "string (optional)",
  "phone_number": "string (optional, +91XXXXXXXXXX format)"
}
```

**Request Example:**
```json
{
  "username": "johndoe123",
  "email": "john.doe@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+919876543210"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "data": {
    "user": {
      "id": 1,
      "username": "johndoe123",
      "email": "john.doe@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "phone_number": "+919876543210",
      "is_verified": false,
      "date_joined": "2025-01-20T10:30:00Z"
    },
    "token": "abc123def456...",
    "expires_at": "2025-02-19T10:30:00Z",
    "message": "User registered successfully. Check your email for verification code or link.",
    "verification_method": "Both OTP and Token available",
    "otp_expires_in": "25 minutes",
    "email_sent": true
  }
}
```

**Error Responses:**
- `400` - Validation errors (username taken, weak password, invalid email)
- `429` - Rate limit exceeded

**Notes:**
- Users receive both a verification link and a 6-digit OTP via email
- OTP expires in 25 minutes, token link expires in 24 hours
- Email includes Android deep link for app integration

### User Profile

**Endpoint:** `GET /profile/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get current user's profile information.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    "id": 1,
    "username": "johndoe123",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+919876543210",
    "profile_image": "https://domain.com/media/profile/user1.jpg",
    "date_of_birth": "1990-01-01",
    "gender": "MALE",
    "preferred_language": "EN",
    "email_notifications": true,
    "sms_notifications": true,
    "push_notifications": true,
    "is_verified": true,
    "active_sessions_count": 2,
    "total_carts_count": 1,
    "max_carts_allowed": 5,
    "saved_addresses": [],
    "date_joined": "2025-01-01T00:00:00Z",
    "last_login": "2025-01-20T10:30:00Z"
  }
}
```

### Update Profile

**Endpoint:** `PATCH /profile/update/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Update user profile information.

**Request Example:**
```json
{
  "first_name": "John",
  "last_name": "Smith",
  "phone_number": "+919876543211",
  "date_of_birth": "1990-01-01",
  "gender": "MALE",
  "preferred_language": "HI",
  "email_notifications": false
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Profile updated successfully",
  "data": {
    // Updated user object
  }
}
```

## 🔐 Authentication Endpoints

### Legacy Token Login

**Endpoint:** `POST /login/`
**Authentication:** Not Required
**Rate Limit:** 3 requests per minute

**Description:** Authenticate user and receive authentication token (legacy method).

**Request Parameters:**
```json
{
  "username": "string (required if email not provided)",
  "email": "string (required if username not provided)",
  "password": "string (required)",
  "device_type": "string (optional: ANDROID|WEB|IOS|API)",
  "device_id": "string (optional, required for mobile)"
}
```

**Request Example:**
```json
{
  "email": "john.doe@example.com",
  "password": "SecurePassword123!",
  "device_type": "ANDROID",
  "device_id": "android_device_12345"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Login successful",
  "data": {
    "token": "a1b2c3d4e5f6...",
    "user": {
      // User object
    },
    "device_type": "ANDROID",
    "expires_at": "2025-02-19T10:30:00Z"
  }
}
```

**Error Responses:**
- `400` - Invalid credentials, missing fields
- `403` - Account locked, email not verified
- `429` - Rate limit exceeded

### Legacy Token Logout

**Endpoint:** `POST /logout/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Logout and invalidate current authentication token.

**Request Example:**
```json
{
  "logout_type": "current|all|device_type",
  "device_type": "ANDROID"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Logout successful"
}
```

## 🎫 JWT Token Management

### JWT Login

**Endpoint:** `POST /jwt/`
**Authentication:** Not Required
**Rate Limit:** 3 requests per minute

**Description:** Authenticate user and receive JWT access and refresh tokens.

**Request Parameters:**
```json
{
  "username": "string (required if email not provided)",
  "email": "string (required if username not provided)",
  "password": "string (required)",
  "device_type": "string (optional: ANDROID|WEB|IOS|API)",
  "device_id": "string (required for ANDROID/IOS)"
}
```

**Request Example:**
```json
{
  "email": "john.doe@example.com",
  "password": "SecurePassword123!",
  "device_type": "ANDROID",
  "device_id": "android_device_12345"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Login successful",
  "data": {
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "user": {
      // User object
    },
    "device_type": "ANDROID",
    "device_id": "android_device_12345"
  }
}
```

### JWT Token Refresh

**Endpoint:** `POST /jwt/refresh/`
**Authentication:** Not Required
**Rate Limit:** 50 requests per minute

**Description:** Refresh JWT access token using refresh token.

**Request Example:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

### JWT Token Verification

**Endpoint:** `POST /jwt/verify/`
**Authentication:** Not Required
**Rate Limit:** 100 requests per minute

**Description:** Verify if JWT token is valid.

**Request Example:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Token is valid"
}
```

### JWT Logout

**Endpoint:** `POST /jwt/logout/`
**Authentication:** Required (JWT)
**Rate Limit:** 200 requests per minute

**Description:** Logout and blacklist JWT tokens.

**Request Example:**
```json
{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "logout_type": "current|all|device_type",
  "device_type": "ANDROID"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Successfully logged out from current session"
}
```

### JWT Session Management

**Endpoint:** `GET /jwt/sessions/`
**Authentication:** Required (JWT)
**Rate Limit:** 200 requests per minute

**Description:** List all active JWT sessions for the user.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Found 2 active sessions",
  "data": [
    {
      "id": "session_token_key",
      "device_type": "ANDROID",
      "device_id": "android_device_12345",
      "user_agent": "MyApp/1.0 Android/11",
      "ip_address": "192.168.1.1",
      "created_at": "2025-01-20T10:00:00Z",
      "last_activity": "2025-01-20T10:30:00Z",
      "expires_at": "2025-02-19T10:00:00Z",
      "is_current_session": true
    }
  ]
}
```

**Endpoint:** `DELETE /jwt/sessions/{session_id}/`
**Authentication:** Required (JWT)
**Rate Limit:** 200 requests per minute

**Description:** Terminate a specific JWT session.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Successfully terminated ANDROID session",
  "data": {
    "terminated_session": {
      "device_type": "ANDROID",
      "device_id": "android_device_12345",
      "session_id": "session_token_key"
    }
  }
}
```

## 🛒 Cart Management

### List User Carts

**Endpoint:** `GET /carts/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get all carts for the authenticated user across different stores.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Found 2 carts",
  "data": [
    {
      "id": 1,
      "store_id": "store_123",
      "store_name": "SuperMart",
      "total_price": 1250.50,
      "item_count": 3,
      "applied_coupon": null,
      "coupon_discount": 0,
      "updated_at": "2025-01-20T10:30:00Z",
      "items": [
        {
          "id": 1,
          "product_id": "prod_001",
          "product_name": "Wireless Headphones",
          "product_image_url": "https://domain.com/media/products/headphones.jpg",
          "quantity": 2,
          "unit_price": 500.00,
          "total_price": 1000.00,
          "added_at": "2025-01-20T09:00:00Z"
        }
      ]
    }
  ]
}
```

### Create New Cart

**Endpoint:** `POST /carts/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Create a new cart for a specific store.

**Request Example:**
```json
{
  "store_id": "store_456",
  "store_name": "TechMart"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Cart created successfully",
  "data": {
    "id": 2,
    "store_id": "store_456",
    "store_name": "TechMart",
    "total_price": 0,
    "item_count": 0,
    "items": []
  }
}
```

### Get Cart by Store

**Endpoint:** `GET /carts/store/{store_id}/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get cart for a specific store.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    // Cart object for the specific store
  }
}
```

### Add Item to Cart

**Endpoint:** `POST /cart/items/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Add an item to cart. Automatically creates cart if it doesn't exist for the store.

**Request Example:**
```json
{
  "store_id": "store_123",
  "product_id": "prod_002",
  "product_name": "Bluetooth Speaker",
  "product_image_url": "https://domain.com/media/products/speaker.jpg",
  "quantity": 1,
  "unit_price": 750.00,
  "product_variant": {
    "color": "Black",
    "size": "Medium"
  }
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Item added to cart",
  "data": {
    "id": 2,
    "product_id": "prod_002",
    "product_name": "Bluetooth Speaker",
    "quantity": 1,
    "unit_price": 750.00,
    "total_price": 750.00,
    "added_at": "2025-01-20T11:00:00Z"
  }
}
```

### Update Cart Item

**Endpoint:** `PATCH /cart/items/{item_id}/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Update quantity or other details of a cart item.

**Request Example:**
```json
{
  "quantity": 3
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Cart item updated",
  "data": {
    // Updated cart item object
  }
}
```

### Remove Cart Item

**Endpoint:** `DELETE /cart/items/{item_id}/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Remove an item from cart.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Item removed from cart"
}
```

### Clear Cart

**Endpoint:** `POST /cart/clear/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Remove all items from user's carts.

**Request Example:**
```json
{
  "store_id": "store_123"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Cart cleared successfully"
}
```

**Notes:**
- Users can have maximum 5 carts across different stores
- Cart items are automatically grouped by store
- Quantities are automatically merged for duplicate items
- Cart totals are calculated server-side

## 📦 Order Management

### List Orders

**Endpoint:** `GET /orders/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get all orders for the authenticated user with pagination.

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)
- `status` (optional): Filter by order status
- `ordering` (optional): Sort by field (default: -order_date)

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "order_number": "ORD-20250120-1234",
      "status": "DELIVERED",
      "order_date": "2025-01-15T10:00:00Z",
      "subtotal": 1000.00,
      "tax_amount": 180.00,
      "shipping_cost": 50.00,
      "discount_amount": 100.00,
      "total_amount": 1130.00,
      "coupon_code": "SAVE10",
      "tracking_number": "TRK123456789",
      "carrier_name": "BlueDart",
      "estimated_delivery_date": "2025-01-20T18:00:00Z",
      "actual_delivery_date": "2025-01-19T16:30:00Z",
      "shipping_address_details": {
        // Address object
      },
      "items": [
        {
          "id": 1,
          "product_id": "prod_001",
          "product_name": "Wireless Headphones",
          "quantity": 2,
          "unit_price": 500.00,
          "total_price": 1000.00
        }
      ],
      "payments": [
        {
          "id": 1,
          "transaction_id": "TXN_PAYTM_1_123456789",
          "amount": 1130.00,
          "status": "COMPLETED",
          "payment_type": "UPI"
        }
      ]
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_pages": 1,
    "total_count": 1,
    "has_next": false,
    "has_previous": false
  }
}
```

### Create Order

**Endpoint:** `POST /orders/`
**Authentication:** Required
**Rate Limit:** 10 requests per minute

**Description:** Create a new order from cart items.

**Request Example:**
```json
{
  "cart_id": 1,
  "shipping_address_id": 1,
  "delivery_instructions": "Ring doorbell twice",
  "preferred_delivery_time": "EVENING",
  "coupon_code": "SAVE10"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Order created successfully",
  "data": {
    "id": 1,
    "order_number": "ORD-20250120-5678",
    "status": "PLACED",
    "total_amount": 1130.00,
    "estimated_delivery_date": "2025-01-25T18:00:00Z",
    // Full order object
  }
}
```

### Get Order Details

**Endpoint:** `GET /orders/{order_id}/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get detailed information about a specific order.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    // Complete order object with items and payments
  }
}
```

### Cancel Order

**Endpoint:** `PATCH /orders/{order_id}/`
**Authentication:** Required
**Rate Limit:** 10 requests per minute

**Description:** Cancel an order (only if not shipped).

**Request Example:**
```json
{
  "status": "CANCELLED",
  "cancellation_reason": "Changed mind"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Order cancelled successfully",
  "data": {
    // Updated order object
  }
}
```

## 💳 Payment System

### Initiate Payment (Unified)

**Endpoint:** `POST /payments/initiate/`
**Authentication:** Required
**Rate Limit:** 10 requests per hour

**Description:** Initiate payment for an order using supported payment gateways (Paytm, PhonePe).

**Request Example:**
```json
{
  "order_id": 1,
  "payment_method": "PAYTM"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Payment initiated successfully",
  "data": {
    "payment_id": 1,
    "transaction_id": "TXN_PAYTM_1_123456789",
    "order_id": 1,
    "amount": "1130.00",
    "currency": "INR",
    "payment_method": "PAYTM",
    "payment_data": {
      "order_id": "ORD_PAYTM_1_123456789",
      "token": "payment_token_here",
      "mid": "MERCHANT_ID",
      "amount": "1130.00",
      "callback_url": "https://domain.com/api/auth/payments/paytm/callback/",
      "test_mode": false
    },
    "expires_at": "2025-01-20T11:00:00Z",
    "callback_required": true
  }
}
```

### Check Payment Status

**Endpoint:** `GET /payments/status/{order_id}/`
**Authentication:** Required
**Rate Limit:** 50 requests per minute

**Description:** Check the current status of a payment.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    "payment_id": 1,
    "transaction_id": "TXN_PAYTM_1_123456789",
    "status": "COMPLETED",
    "amount": 1130.00,
    "gateway_transaction_id": "PTM123456789",
    "payment_method": "PAYTM",
    "completed_at": "2025-01-20T10:45:00Z"
  }
}
```

### Retry Failed Payment

**Endpoint:** `POST /payments/history/{payment_id}/retry/`
**Authentication:** Required
**Rate Limit:** 5 requests per hour

**Description:** Retry a failed payment with a new transaction.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Payment retry initiated",
  "data": {
    "payment_id": 2,
    "transaction_id": "TXN_RETRY_1_987654321",
    "payment_data": {
      // New payment gateway data
    }
  }
}
```

### Payment History

**Endpoint:** `GET /payments/history/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get user's payment history with filtering options.

**Query Parameters:**
- `status` (optional): Filter by payment status
- `payment_type` (optional): Filter by payment type
- `from_date` (optional): Start date filter (YYYY-MM-DD)
- `to_date` (optional): End date filter (YYYY-MM-DD)

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "transaction_id": "TXN_PAYTM_1_123456789",
      "amount": 1130.00,
      "currency": "INR",
      "status": "COMPLETED",
      "payment_type": "UPI",
      "gateway_name": "PAYTM",
      "order_id": 1,
      "created_at": "2025-01-15T10:00:00Z",
      "billing_address_details": {
        // Address object
      },
      "transactions": [
        {
          "id": 1,
          "action": "capture",
          "status": "success",
          "amount": 1130.00,
          "created_at": "2025-01-15T10:02:00Z"
        }
      ]
    }
  ]
}
```

### Payment Methods Management

**Endpoint:** `GET /payment-methods/cards/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get user's saved card payment methods.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "card_type": "VISA",
      "last_four": "1234",
      "expiry_month": "12",
      "expiry_year": "2026",
      "card_holder_name": "John Doe",
      "card_nickname": "Primary Card",
      "is_default": true,
      "is_active": true,
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

**Endpoint:** `GET /payment-methods/upi/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get user's saved UPI payment methods.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "upi_id": "john.doe@paytm",
      "upi_nickname": "Primary UPI",
      "is_default": true,
      "is_active": true,
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

**Notes:**
- All payment processing is done server-side for security
- Payment tokens are generated with 15-minute expiry
- Failed payments can be retried up to 3 times
- Payment callbacks are handled automatically
- Supported gateways: Paytm, PhonePe

## 📍 Address Management

### List Addresses

**Endpoint:** `GET /addresses/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get all saved addresses for the user.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "contact_name": "John Doe",
      "street_address": "123 Main Street",
      "street_address_2": "Apartment 4B",
      "landmark": "Near Central Mall",
      "city": "Mumbai",
      "state": "Maharashtra",
      "pin_code": "400001",
      "country": "India",
      "phone_number": "+919876543210",
      "address_type": "HOME",
      "latitude": 19.0760,
      "longitude": 72.8777,
      "is_default": true,
      "is_verified": false,
      "full_address": "123 Main Street, Apartment 4B, Near Central Mall, Mumbai, Maharashtra 400001, India",
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-20T10:30:00Z"
    }
  ]
}
```

### Add New Address

**Endpoint:** `POST /addresses/`
**Authentication:** Required
**Rate Limit:** 20 requests per hour

**Description:** Add a new address to user's address book.

**Request Example:**
```json
{
  "contact_name": "John Doe",
  "street_address": "456 Oak Avenue",
  "street_address_2": "Floor 2",
  "landmark": "Opposite City Hospital",
  "city": "Delhi",
  "state": "Delhi",
  "pin_code": "110001",
  "country": "India",
  "phone_number": "+919876543210",
  "address_type": "WORK",
  "latitude": 28.6139,
  "longitude": 77.2090
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Address added successfully",
  "data": {
    "id": 2,
    // Complete address object
  }
}
```

### Update Address

**Endpoint:** `PATCH /addresses/{address_id}/`
**Authentication:** Required
**Rate Limit:** 20 requests per hour

**Description:** Update an existing address.

**Request Example:**
```json
{
  "street_address": "456 Oak Avenue Updated",
  "landmark": "Near Metro Station"
}
```

### Delete Address

**Endpoint:** `DELETE /addresses/{address_id}/`
**Authentication:** Required
**Rate Limit:** 20 requests per hour

**Description:** Delete an address from user's address book.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Address deleted successfully"
}
```

### Set Default Address

**Endpoint:** `POST /addresses/set-default/{address_id}/`
**Authentication:** Required
**Rate Limit:** 50 requests per minute

**Description:** Set an address as the default address.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Default address updated successfully",
  "data": {
    // Updated address object with is_default: true
  }
}
```

### Get Default Address

**Endpoint:** `GET /addresses/default/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get user's default address.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    // Default address object
  }
}
```

## 🔍 Search History

### Get Search History

**Endpoint:** `GET /search-history/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get user's search history with pagination.

**Query Parameters:**
- `category` (optional): Filter by search category
- `limit` (optional): Limit number of results (default: 20)

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "query": "wireless headphones",
      "category": "electronics",
      "results_count": 25,
      "searched_at": "2025-01-20T10:00:00Z"
    },
    {
      "id": 2,
      "query": "bluetooth speaker",
      "category": "electronics",
      "results_count": 15,
      "searched_at": "2025-01-20T09:30:00Z"
    }
  ]
}
```

### Add Search Query

**Endpoint:** `POST /search-history/`
**Authentication:** Required
**Rate Limit:** 100 requests per minute

**Description:** Add a new search query to history.

**Request Example:**
```json
{
  "query": "smartphone cases",
  "category": "accessories",
  "results_count": 42
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Search query added to history",
  "data": {
    "id": 3,
    "query": "smartphone cases",
    "category": "accessories",
    "results_count": 42,
    "searched_at": "2025-01-20T11:00:00Z"
  }
}
```

### Clear Search History

**Endpoint:** `DELETE /search-history/clear/`
**Authentication:** Required
**Rate Limit:** 10 requests per hour

**Description:** Clear all search history for the user.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Search history cleared successfully"
}
```

### Get Search History Group

**Endpoint:** `GET /search-history-group/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get grouped search history with statistics.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": {
    "id": 1,
    "search_count": 15,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-20T11:00:00Z",
    "recent_searches": [
      {
        "query": "wireless headphones",
        "searched_at": "2025-01-20T10:00:00Z"
      }
    ],
    "searches": [
      // All search history items
    ]
  }
}
```

## 🎧 Customer Support

### List Support Tickets

**Endpoint:** `GET /support/tickets/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get all support tickets for the user.

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "data": [
    {
      "id": 1,
      "subject": "Payment Issue",
      "description": "Payment was deducted but order not confirmed",
      "status": "OPEN",
      "priority": "HIGH",
      "category": "payment",
      "created_at": "2025-01-20T09:00:00Z",
      "updated_at": "2025-01-20T10:30:00Z",
      "messages": [
        {
          "id": 1,
          "message": "Payment was deducted but order not confirmed",
          "is_user_message": true,
          "timestamp": "2025-01-20T09:00:00Z",
          "attachment_url": null
        }
      ]
    }
  ]
}
```

### Create Support Ticket

**Endpoint:** `POST /support/tickets/`
**Authentication:** Required
**Rate Limit:** 10 requests per hour

**Description:** Create a new support ticket.

**Request Example:**
```json
{
  "subject": "Order Delivery Issue",
  "description": "My order was not delivered on the expected date",
  "category": "delivery",
  "priority": "MEDIUM"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Support ticket created successfully",
  "data": {
    "id": 2,
    "subject": "Order Delivery Issue",
    "status": "OPEN",
    "priority": "MEDIUM",
    "created_at": "2025-01-20T11:00:00Z"
  }
}
```

### Get Ticket Details

**Endpoint:** `GET /support/tickets/{ticket_id}/`
**Authentication:** Required
**Rate Limit:** 200 requests per minute

**Description:** Get detailed information about a support ticket.

### Add Message to Ticket

**Endpoint:** `POST /support/tickets/{ticket_id}/messages/`
**Authentication:** Required
**Rate Limit:** 50 requests per hour

**Description:** Add a message to an existing support ticket.

**Request Example:**
```json
{
  "message": "I have checked the tracking and it shows delivered but I haven't received it",
  "attachment_url": "https://domain.com/media/attachments/proof.jpg"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 201,
  "message": "Message added to ticket",
  "data": {
    "id": 2,
    "message": "I have checked the tracking and it shows delivered but I haven't received it",
    "is_user_message": true,
    "timestamp": "2025-01-20T11:30:00Z",
    "attachment_url": "https://domain.com/media/attachments/proof.jpg"
  }
}
```

## 🚀 Rate Limiting

The API implements comprehensive rate limiting to ensure fair usage and system stability.

### Rate Limit Headers
Every API response includes rate limit information:

```http
X-RateLimit-Limit: 200
X-RateLimit-Remaining: 150
X-RateLimit-Reset: 1642680000
```

### Rate Limit Tiers

| User Type | Requests per Minute | Requests per Hour | Requests per Day |
|-----------|-------------------|------------------|------------------|
| Anonymous | 50 | 1,000 | 10,000 |
| Authenticated | 200 | 5,000 | 50,000 |
| Premium | 500 | 10,000 | 100,000 |

### Specific Endpoint Limits

| Endpoint Category | Rate Limit | Window |
|------------------|------------|--------|
| Authentication | 3 requests | per minute |
| Registration | 5 requests | per hour |
| Payment Operations | 10 requests | per hour |
| Cart Operations | 200 requests | per minute |
| Search | 100 requests | per minute |
| File Uploads | 20 requests | per hour |

### Rate Limit Exceeded Response
```json
{
  "status": "error",
  "code": 429,
  "message": "Rate limit exceeded",
  "retry_after": 60,
  "limit_type": "user",
  "current_usage": "201/200"
}
```

## 📄 Pagination

The API uses cursor-based pagination for optimal performance with large datasets.

### Pagination Parameters
- `page`: Page number (1-based, default: 1)
- `page_size`: Items per page (default: 20, max: 100)
- `ordering`: Sort field (prefix with `-` for descending)

### Paginated Response Format
```json
{
  "status": "success",
  "code": 200,
  "data": [
    // Array of items
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_pages": 5,
    "total_count": 100,
    "has_next": true,
    "has_previous": false,
    "next_url": "/api/auth/orders/?page=2",
    "previous_url": null
  }
}
```

### Example Paginated Request
```http
GET /api/auth/orders/?page=2&page_size=10&ordering=-order_date
```

## 🔧 Additional Features

### Health Check

**Endpoint:** `GET /health/`
**Authentication:** Not Required
**Rate Limit:** 100 requests per minute

**Description:** Check API health status.

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-20T11:00:00Z",
  "version": "1.0.0",
  "database": "connected",
  "cache": "operational"
}
```

### API Root

**Endpoint:** `GET /`
**Authentication:** Not Required
**Rate Limit:** 100 requests per minute

**Description:** Get API information and available endpoints.

**Response Example:**
```json
{
  "name": "S2Cart API",
  "description": "Backend API for S2Cart Android App",
  "version": "1.0.0",
  "endpoints": {
    "jwt": {
      "login": "/api/auth/jwt/",
      "refresh": "/api/auth/jwt/refresh/",
      "logout": "/api/auth/jwt/logout/"
    },
    "legacy": {
      "login": "/api/auth/login/",
      "logout": "/api/auth/logout/"
    },
    "user": {
      "profile": "/api/auth/profile/",
      "register": "/api/auth/register/"
    }
  }
}
```

### Password Reset

**Endpoint:** `POST /password-reset/request/`
**Authentication:** Not Required
**Rate Limit:** 5 requests per hour

**Description:** Request password reset email.

**Request Example:**
```json
{
  "email": "john.doe@example.com"
}
```

**Response Example:**
```json
{
  "status": "success",
  "code": 200,
  "message": "Password reset email sent if account exists"
}
```

**Endpoint:** `POST /password-reset/confirm/`
**Authentication:** Not Required
**Rate Limit:** 5 requests per hour

**Description:** Confirm password reset with token.

**Request Example:**
```json
{
  "token": "reset_token_here",
  "password": "NewSecurePassword123!"
}
```

### Account Verification

S2Cart API supports dual verification methods for enhanced user experience.

#### Method 1: Token-Based Verification (Browser/Web)

**Endpoint:** `GET /verify/{token}/`
**Authentication:** Not Required
**Rate Limit:** 10 requests per hour

**Description:** Verify user account using email verification token link.

**URL Parameters:**
- `token` (string): 64-character verification token from email

**Response Example:**
```json
{
  "status": "success",
  "message": "Account verified successfully.",
  "verification_method": "token"
}
```

**Error Responses:**
- `400` - Invalid or expired token

#### Method 2: OTP-Based Verification (Mobile/App)

**Endpoint:** `POST /verify/otp/`
**Authentication:** Not Required
**Rate Limit:** 10 requests per hour

**Description:** Verify user account using 6-digit OTP code.

**Request Parameters:**
```json
{
  "email": "string (required)",
  "otp": "string (required, 6 digits)"
}
```

**Request Example:**
```json
{
  "email": "john.doe@example.com",
  "otp": "123456"
}
```

**Response Example:**
```json
{
  "status": "success",
  "message": "Account verified successfully.",
  "verification_method": "otp"
}
```

**Error Responses:**
- `400` - Email and OTP are required
- `400` - OTP has expired or is invalid
- `400` - Invalid OTP
- `400` - User with this email does not exist

#### Resend Verification

**Endpoint:** `POST /verify/resend/`
**Authentication:** Not Required
**Rate Limit:** 3 requests per hour

**Description:** Resend verification email with new token and OTP.

**Request Example:**
```json
{
  "email": "john.doe@example.com"
}
```

**Response Example:**
```json
{
  "status": "success",
  "message": "Verification email resent successfully",
  "verification_method": "Both OTP and Token available",
  "otp_expires_in": "25 minutes"
}
```

### Password Reset

S2Cart API supports dual password reset methods for enhanced user experience.

#### Request Password Reset

**Endpoint:** `POST /password-reset/request/`
**Authentication:** Not Required
**Rate Limit:** 3 requests per hour

**Description:** Request password reset with dual verification methods.

**Request Example:**
```json
{
  "email": "john.doe@example.com"
}
```

**Response Example:**
```json
{
  "status": "success",
  "message": "If your email exists in our system, password reset instructions will be sent.",
  "reset_method": "Both OTP and Token available",
  "otp_expires_in": "25 minutes"
}
```

#### Method 1: Token-Based Password Reset

**Endpoint:** `POST /password-reset/confirm/`
**Authentication:** Not Required
**Rate Limit:** 10 requests per hour

**Description:** Reset password using email token.

**Request Example:**
```json
{
  "token": "reset_token_from_email",
  "password": "NewSecurePassword123!"
}
```

**Response Example:**
```json
{
  "status": "success",
  "message": "Password has been reset successfully.",
  "verification_method": "token"
}
```

#### Method 2: OTP-Based Password Reset

**Endpoint:** `POST /password-reset/confirm/`
**Authentication:** Not Required
**Rate Limit:** 10 requests per hour

**Description:** Reset password using 6-digit OTP.

**Request Example:**
```json
{
  "email": "john.doe@example.com",
  "otp": "654321",
  "password": "NewSecurePassword123!"
}
```

**Response Example:**
```json
{
  "status": "success",
  "message": "Password has been reset successfully.",
  "verification_method": "otp"
}
```

**Error Responses:**
- `400` - Either token or (email and otp) must be provided
- `400` - OTP has expired or is invalid
- `400` - Invalid OTP or token

### Android Deep Linking

The S2Cart API includes Android deep linking support for seamless app integration.

#### Deep Link Format

**Verification Links:**
- `s2cart://verify?token={token}&otp={otp}`

**Password Reset Links:**
- `s2cart://reset-password?token={token}&otp={otp}`

#### Email Integration

Email templates include two buttons:
1. **"Open in S2Cart App"** - Opens the app if installed, otherwise redirects to Play Store
2. **"Verify in Browser"** - Opens in web browser

#### Implementation Notes

- Deep links are automatically generated in email templates
- If the S2Cart app is not installed, users are prompted to install from Play Store
- App package: `com.s2cart` with activity `com.s2cart.register`
- Deep links include both token and OTP for maximum compatibility

### Security Features

1. **Account Lockout**: Accounts are locked after 5 failed login attempts for 60 minutes
2. **Token Expiry**: JWT tokens expire after 7 days, refresh tokens after 30 days
3. **Device Tracking**: All sessions are tracked by device type and ID
4. **IP Monitoring**: Failed login attempts are monitored by IP address
5. **Session Management**: Users can view and terminate active sessions
6. **Request Validation**: All inputs are validated and sanitized
7. **HTTPS Only**: All API calls must use HTTPS in production

### Error Handling Best Practices

1. **Always check the `status` field** in the response
2. **Handle rate limiting** by implementing exponential backoff
3. **Store and refresh JWT tokens** automatically
4. **Validate user input** before making API calls
5. **Implement proper error messaging** in your client application
6. **Log API errors** for debugging purposes
7. **Handle network failures** gracefully

### SDK Integration Examples

#### Android (Java/Kotlin)
```java
// JWT Authentication
private void loginUser(String email, String password) {
    JSONObject loginData = new JSONObject();
    loginData.put("email", email);
    loginData.put("password", password);
    loginData.put("device_type", "ANDROID");
    loginData.put("device_id", getDeviceId());
    
    // Make API call to /api/auth/jwt/
}
```

#### Web (JavaScript)
```javascript
// Fetch with error handling
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAccessToken()}`,
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (data.status === 'error') {
            throw new Error(data.message);
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}
```

### Performance Optimization Tips

1. **Use pagination** for large datasets
2. **Implement caching** for frequently accessed data
3. **Use appropriate HTTP methods** (GET for retrieval, POST for creation)
4. **Compress request/response data** when possible
5. **Implement request deduplication** to avoid duplicate API calls
6. **Use JWT tokens** for better performance over legacy tokens
7. **Cache user profile data** locally with appropriate TTL

### Troubleshooting Common Issues

#### Authentication Issues
- **401 Unauthorized**: Check if token is valid and not expired
- **403 Forbidden**: Verify account is verified and not locked
- **Token expired**: Use refresh token to get new access token

#### Payment Issues
- **Payment failed**: Check payment method validity and account balance
- **Transaction timeout**: Implement retry mechanism with exponential backoff
- **Callback issues**: Ensure proper webhook handling

#### Cart Issues
- **Cart limit exceeded**: Users can have maximum 5 carts
- **Item not found**: Verify product availability before adding to cart
- **Stock issues**: Check item availability before checkout

This documentation provides a comprehensive reference for integrating with the S2Cart Customer API. For additional support or questions, please contact the development team.
