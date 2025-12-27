# Domain Setup Guide for S2Cart Android API

This guide walks you through the process of configuring your Django application to use a custom domain with proper SSL certificates.

## Prerequisites

1. A registered domain name (e.g., yourdomain.com)
2. Access to your domain's DNS settings
3. Server with proper SSL certificates (Let's Encrypt or commercial)

## Configuration Steps

### 1. Update DNS Records

Point your domain to your server's IP address by creating:
- An A record: `yourdomain.com` → Your server IP
- An A record: `www.yourdomain.com` → Your server IP

### 2. SSL Certificate Setup

#### Using Let's Encrypt (recommended)

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Verify automatic renewal
sudo certbot renew --dry-run
```

### 3. Update Environment Configuration

Edit your `.env.production` file:

```bash
# Server Configuration
SERVER_PORT=8000
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
SITE_PROTOCOL=https
SITE_DOMAIN=yourdomain.com

# SSL/HTTPS Settings
USE_HTTPS=True

# CORS and CSRF Settings
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### 4. Nginx Configuration

Update `/etc/nginx/sites-available/S2Cart.conf`:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect all HTTP requests to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # SSL configurations
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    
    # HSTS (optional but recommended)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Other security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    
    location /static/ {
        alias /home/s2cartofficial_gmail_com/Customer-API/Customer_API/staticfiles/;
    }
    
    location /media/ {
        alias /home/s2cartofficial_gmail_com/Customer-API/Customer_API/media/;
    }
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 5. Test Your Configuration

After applying these changes:

1. Restart Nginx: `sudo systemctl restart nginx`
2. Restart your Django application
3. Test access via https://yourdomain.com
4. Verify SSL certificate is valid (should show the lock icon in browsers)
5. Test API endpoints through the Android application

### 6. Update Android Application

Update your Android application configuration to use the new domain:

```java
// Replace
private static final String BASE_URL = "http://34.47.154.53:8000/api/";

// With
private static final String BASE_URL = "https://yourdomain.com/api/";
```

## Troubleshooting

### SSL Certificate Issues

If you encounter SSL certificate errors:

1. Verify certificate installation: `sudo certbot certificates`
2. Check Nginx configuration syntax: `sudo nginx -t`
3. Check certificate path in Nginx config
4. Ensure ports 80 and 443 are open in your firewall

### Domain Not Resolving

1. Check DNS propagation: `dig yourdomain.com`
2. Verify A records were properly set
3. DNS changes may take up to 48 hours to propagate globally

### Application Errors

1. Verify `ALLOWED_HOSTS` contains your domain
2. Check Django logs for any errors
3. Ensure CORS settings include your domain

## Next Steps

- Set up monitoring for SSL certificate expiration
- Configure automatic certificate renewal
- Consider implementing a Content Delivery Network (CDN) for static assets
