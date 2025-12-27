#!/usr/bin/env python3
"""
Test script for email validation functionality
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
sys.path.append('/home/s2cartofficial_gmail_com/Customer-API')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Customer_API.settings')
django.setup()

from authentication.email_validators import validate_secure_email
from rest_framework import serializers

def test_email_validation():
    """Test various email validation scenarios"""
    
    # Test cases for valid emails
    valid_emails = [
        'user@gmail.com',
        'test.user@domain.com',
        'user123@example.org',
        'valid-email@subdomain.domain.com',
        'a@b.co'
    ]
    
    # Test cases for invalid emails with special characters
    invalid_special_char_emails = [
        'user!@#$%^&*()@domain.com',
        'test!!!@domain.com',
        'user@domain!@#.com',
        'user###@domain.com',
        'test$$$$@domain.com',
        'user@dom@in.com',
        'user..user@domain.com',
        '.user@domain.com',
        'user.@domain.com'
    ]
    
    # Test cases for temporary/disposable emails
    temp_emails = [
        'test@10minutemail.com',
        'user@guerrillamail.com',
        'temp@mailinator.com',
        'throwaway@yopmail.com',
        'test@tempmail.org'
    ]
    
    # Test cases for restricted local parts
    restricted_emails = [
        'admin@company.com',
        'root@server.com',
        'support@business.com',
        'postmaster@mail.com',
        'security@domain.com'
    ]
    
    # Test cases for suspicious patterns
    suspicious_emails = [
        'test123456789012345@domain.com',
        'aaaaaaa@domain.com',
        'test!!!!!@domain.com',
        '123456@domain.com',
        'ab@domain.com',
        'veryveryveryveryveryveryveryveryverylongemaillocalpart@domain.com'
    ]
    
    print("=== EMAIL VALIDATION TEST RESULTS ===\n")
    
    print("1. Testing VALID emails:")
    for email in valid_emails:
        try:
            result = validate_secure_email(email)
            print(f"✅ {email} -> {result}")
        except Exception as e:
            print(f"❌ {email} -> ERROR: {e}")
    
    print("\n2. Testing INVALID emails with special characters:")
    for email in invalid_special_char_emails:
        try:
            result = validate_secure_email(email)
            print(f"❌ {email} -> SHOULD HAVE FAILED but got: {result}")
        except Exception as e:
            print(f"✅ {email} -> CORRECTLY REJECTED: {e}")
    
    print("\n3. Testing TEMPORARY/DISPOSABLE emails:")
    for email in temp_emails:
        try:
            result = validate_secure_email(email)
            print(f"❌ {email} -> SHOULD HAVE FAILED but got: {result}")
        except Exception as e:
            print(f"✅ {email} -> CORRECTLY REJECTED: {e}")
    
    print("\n4. Testing RESTRICTED local parts:")
    for email in restricted_emails:
        try:
            result = validate_secure_email(email)
            print(f"❌ {email} -> SHOULD HAVE FAILED but got: {result}")
        except Exception as e:
            print(f"✅ {email} -> CORRECTLY REJECTED: {e}")
    
    print("\n5. Testing SUSPICIOUS patterns:")
    for email in suspicious_emails:
        try:
            result = validate_secure_email(email)
            print(f"❌ {email} -> SHOULD HAVE FAILED but got: {result}")
        except Exception as e:
            print(f"✅ {email} -> CORRECTLY REJECTED: {e}")
    
    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test_email_validation()
