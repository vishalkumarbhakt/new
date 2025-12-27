# S2Cart API Production Deployment Guide

This guide describes how to deploy the S2Cart API to a production environment.

## Prerequisites

1. Linux server (Ubuntu 20.04+ recommended)
2. PostgreSQL 12+
3. Python 3.8+
4. Nginx
5. SSL certificate (Let's Encrypt recommended)

## Deployment Steps

### 1. Verify Production Readiness

Before proceeding with deployment, verify your environment is properly configured:

```bash
# Run the production readiness check tool 
./dev.sh prod-check

# Run Django's built-in deployment checks
cd Customer-API
python manage.py check --deploy
cd ..
```

Address any issues found by these checks before proceeding.

### 2. Clone the Repository

```bash
git clone https://yourgitrepo.com/Customer-API.git
cd Customer-API
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables

1. Copy the `.env.template` to `.env`:
   ```bash
   cp .env.template .env
   ```

2. Edit the `.env` file with your production settings:
   ```bash
   nano .env
   ```

3. Important settings to change:
   - Set `DEBUG=False`
   - Generate a secure `DJANGO_SECRET_KEY`
   - Configure PostgreSQL database credentials
   - Add your domain to `ALLOWED_HOSTS`
   - Configure Paytm production credentials

### 4. Set Up PostgreSQL Database

```bash
sudo -u postgres psql
postgres=# CREATE DATABASE S2Cart_db;
postgres=# CREATE USER S2Cart_user WITH PASSWORD 'secure_password';
postgres=# GRANT ALL PRIVILEGES ON DATABASE S2Cart_db TO S2Cart_user;
postgres=# \q
```

### 5. Run Migrations and Collect Static Files

```bash
python manage.py migrate
python manage.py collectstatic --no-input
```

### 6. Configure Gunicorn

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/S2Cart.service
```

Add the following content:

```
[Unit]
Description=S2Cart API Gunicorn daemon
After=network.target

[Service]
User=your_user
Group=your_group
WorkingDirectory=/path/to/Customer-API
ExecStart=/path/to/Customer-API/Customer-venv/bin/gunicorn \
          --config /path/to/Customer-API/Customer_API/gunicorn_config.py \
          Customer_API.wsgi:application
Restart=on-failure
Environment="PATH=/path/to/Customer-API/Customer-venv/bin"
EnvironmentFile=/path/to/Customer-API/.env

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable S2Cart
sudo systemctl start S2Cart
```

### 7. Configure Nginx

```bash
sudo nano /etc/nginx/sites-available/S2Cart
```

Add:

```
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL configuration
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Static and media files
    location /static/ {
        alias /path/to/Customer-API/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, max-age=31536000";
    }
    
    location /media/ {
        alias /path/to/Customer-API/media/;
        expires 1d;
        add_header Cache-Control "public, max-age=86400";
    }
    
    # Proxy to Gunicorn
    location / {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://127.0.0.1:8000;  # Port should match Gunicorn
        proxy_buffering off;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Increased client_max_body_size for file uploads
    client_max_body_size 10M;
}
```

Enable the site and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/S2Cart /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

### 8. Set Up SSL with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### 9. Configure Rate Limiting and DDoS Protection

Edit your Nginx configuration to add rate limiting:

```
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    # ...existing config...
    
    # Apply rate limiting to API endpoints
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        # ...existing proxy settings...
    }
}
```

### 10. Set Up Database Backups

Create a backup script `/path/to/backup_script.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/path/to/backups"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/S2Cart_db_$DATE.sql"

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Backup PostgreSQL database
pg_dump -U S2Cart_user -d S2Cart_db > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Remove backups older than 7 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete
```

Make it executable:

```bash
chmod +x /path/to/backup_script.sh
```

Add to crontab to run daily:

```bash
crontab -e
# Add this line:
0 2 * * * /path/to/backup_script.sh
```

## Monitoring and Maintenance

### Set Up Error Monitoring with Sentry

Add to your Django settings:

```python
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn="your-sentry-dsn",
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.2,  # Adjust based on your traffic
    send_default_pii=False
)
```

### Regular Maintenance Tasks

1. **Check server logs daily:**
   ```bash
   sudo journalctl -u S2Cart.service
   ```

2. **Monitor server resources:**
   ```bash
   htop
   ```

3. **Update dependencies regularly:**
   ```bash
   pip install -U -r requirements.txt
   ```

4. **Test your backups:**
   Periodically restore a backup to a test environment to verify backup integrity.
