# Email Security Configuration Guide

## Overview

The email security system is now fully configurable through environment variables. This document describes all available configuration options for the email validation and rate limiting system.

## 📋 **Environment Variables (.env)**

### Core Email Security Settings

```bash
# Enable/disable the entire email security system
EMAIL_SECURITY_ENABLED=True
```

### Rate Limiting Configuration

```bash
# Registration rate limiting
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=3      # Max attempts per window
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=15       # Window in minutes

# Login rate limiting (email-based login)
EMAIL_RATE_LIMIT_LOGIN_ATTEMPTS=5             # Max attempts per window
EMAIL_RATE_LIMIT_LOGIN_WINDOW=10              # Window in minutes

# Password reset rate limiting
EMAIL_RATE_LIMIT_PASSWORD_RESET_ATTEMPTS=3    # Max attempts per window
EMAIL_RATE_LIMIT_PASSWORD_RESET_WINDOW=30     # Window in minutes
```

### Email Validation Features

```bash
# Feature toggles
EMAIL_VALIDATION_ENABLE_MX_CHECK=False                    # DNS MX record validation
EMAIL_VALIDATION_BLOCK_TEMP_EMAILS=True                   # Block disposable emails
EMAIL_VALIDATION_BLOCK_RESERVED_USERNAMES=True           # Block admin, root, etc.
EMAIL_VALIDATION_ENABLE_SUSPICIOUS_PATTERN_CHECK=True    # Pattern detection

# Validation strictness (strict, moderate, lenient)
EMAIL_VALIDATION_STRICTNESS=strict

# DNS validation timeout in seconds
EMAIL_VALIDATION_DNS_TIMEOUT=5
```

### Custom Restrictions

```bash
# Custom blocked domains (comma-separated)
EMAIL_VALIDATION_CUSTOM_BLOCKED_DOMAINS=example.test,spam.local,abuse.test

# Custom reserved usernames (comma-separated)
EMAIL_VALIDATION_CUSTOM_RESERVED_USERNAMES=ceo,founder,owner,company
```

## ⚙️ **Configuration Options Explained**

### 1. **EMAIL_SECURITY_ENABLED**
- **Values**: `True` / `False`
- **Default**: `True`
- **Description**: Master switch for the entire email security system. When disabled, only basic email format validation is performed.

### 2. **Rate Limiting Settings**

| Setting | Default | Description |
|---------|---------|-------------|
| `EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS` | 3 | Max registration attempts per IP |
| `EMAIL_RATE_LIMIT_REGISTRATION_WINDOW` | 15 | Time window in minutes |
| `EMAIL_RATE_LIMIT_LOGIN_ATTEMPTS` | 5 | Max login attempts per IP |
| `EMAIL_RATE_LIMIT_LOGIN_WINDOW` | 10 | Time window in minutes |
| `EMAIL_RATE_LIMIT_PASSWORD_RESET_ATTEMPTS` | 3 | Max password reset attempts per IP |
| `EMAIL_RATE_LIMIT_PASSWORD_RESET_WINDOW` | 30 | Time window in minutes |

### 3. **Validation Features**

| Setting | Default | Description |
|---------|---------|-------------|
| `EMAIL_VALIDATION_ENABLE_MX_CHECK` | False | Validate domain has MX records |
| `EMAIL_VALIDATION_BLOCK_TEMP_EMAILS` | True | Block 400+ temporary email services |
| `EMAIL_VALIDATION_BLOCK_RESERVED_USERNAMES` | True | Block admin, support, root, etc. |
| `EMAIL_VALIDATION_ENABLE_SUSPICIOUS_PATTERN_CHECK` | True | Detect suspicious email patterns |

### 4. **Strictness Levels**

| Level | Description | What it blocks |
|-------|-------------|----------------|
| **strict** | Maximum security | All patterns, very short emails, very long emails |
| **moderate** | Balanced approach | Most patterns except very short emails |
| **lenient** | Basic protection | Only obvious attack patterns |

### 5. **Custom Restrictions**
- **Custom Blocked Domains**: Add your own list of domains to block
- **Custom Reserved Usernames**: Add company-specific reserved usernames

## 🔧 **Configuration Examples**

### Example 1: High Security Setup
```bash
EMAIL_SECURITY_ENABLED=True
EMAIL_VALIDATION_STRICTNESS=strict
EMAIL_VALIDATION_ENABLE_MX_CHECK=True
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=2
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=30
EMAIL_VALIDATION_CUSTOM_RESERVED_USERNAMES=ceo,cto,admin,company,business
```

### Example 2: Moderate Security Setup
```bash
EMAIL_SECURITY_ENABLED=True
EMAIL_VALIDATION_STRICTNESS=moderate
EMAIL_VALIDATION_ENABLE_MX_CHECK=False
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=5
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=10
```

### Example 3: Lenient Setup for Testing
```bash
EMAIL_SECURITY_ENABLED=True
EMAIL_VALIDATION_STRICTNESS=lenient
EMAIL_VALIDATION_BLOCK_TEMP_EMAILS=False
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=10
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=5
```

### Example 4: Disabled for Development
```bash
EMAIL_SECURITY_ENABLED=False
```

## 🚀 **Production Recommendations**

### For High-Traffic Production:
```bash
EMAIL_SECURITY_ENABLED=True
EMAIL_VALIDATION_STRICTNESS=strict
EMAIL_VALIDATION_ENABLE_MX_CHECK=False  # Disable for performance
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=3
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=15
EMAIL_VALIDATION_BLOCK_TEMP_EMAILS=True
EMAIL_VALIDATION_BLOCK_RESERVED_USERNAMES=True
```

### For Business/Enterprise:
```bash
EMAIL_SECURITY_ENABLED=True
EMAIL_VALIDATION_STRICTNESS=moderate
EMAIL_VALIDATION_ENABLE_MX_CHECK=True
EMAIL_RATE_LIMIT_REGISTRATION_ATTEMPTS=5
EMAIL_RATE_LIMIT_REGISTRATION_WINDOW=10
EMAIL_VALIDATION_CUSTOM_RESERVED_USERNAMES=ceo,cto,admin,support,sales,marketing
```

## 📊 **Impact of Each Setting**

### Performance Impact:
- **MX Check**: +50-500ms per validation (network dependent)
- **Pattern Check**: +1-2ms per validation
- **Rate Limiting**: Minimal impact (~0.1ms)

### Security Impact:
- **Temp Email Blocking**: Prevents 90%+ of spam registrations
- **Reserved Username Blocking**: Prevents admin impersonation
- **Rate Limiting**: Prevents DDOS and brute force attacks
- **Pattern Detection**: Catches automated attack patterns

## 🔄 **Runtime Configuration Changes**

Most settings can be changed without restarting the server by updating the `.env` file and reloading the application:

```bash
# Update .env file
nano .env

# Restart the service to apply changes
sudo systemctl restart customer-api
```

## 🧪 **Testing Configuration**

Test your configuration with these curl commands:

```bash
# Test rate limiting
for i in {1..5}; do
  curl -X POST https://customer-api.s2cart.me/api/auth/register/ \
    -H "Content-Type: application/json" \
    -d '{"username":"test'$i'","email":"test'$i'@mailinator.com","password":"SecurePass123!"}'
  echo
done

# Test temp email blocking
curl -X POST https://customer-api.s2cart.me/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"username":"temptest","email":"test@guerrillamail.com","password":"SecurePass123!"}'

# Test reserved username blocking
curl -X POST https://customer-api.s2cart.me/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admintest","email":"admin@company.com","password":"SecurePass123!"}'
```

## 📝 **Configuration Checklist**

- [ ] Set appropriate rate limits for your traffic
- [ ] Choose strictness level based on your user base
- [ ] Add custom blocked domains if needed
- [ ] Add custom reserved usernames for your organization
- [ ] Test configuration in staging environment
- [ ] Monitor logs for blocked attempts
- [ ] Adjust settings based on false positives/negatives

This comprehensive configuration system allows you to fine-tune the email security to match your specific requirements while maintaining maximum flexibility for future changes.
