#!/usr/bin/env python3
"""
Integration test for email validation in serializers
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
sys.path.append('/home/s2cartofficial_gmail_com/Customer-API')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Customer_API.settings')
django.setup()

from authentication.serializers import RegisterSerializer, PasswordResetRequestSerializer
from rest_framework import serializers

def test_register_serializer():
    """Test RegisterSerializer with email validation"""
    print("=== TESTING REGISTER SERIALIZER ===")
    
    # Test valid registration
    valid_data = {
        'username': 'testuser',
        'email': 'valid.user@gmail.com',
        'password': 'SecurePassword123!',
        'first_name': 'Test',
        'last_name': 'User'
    }
    
    serializer = RegisterSerializer(data=valid_data)
    try:
        if serializer.is_valid():
            print("✅ Valid email accepted:", valid_data['email'])
        else:
            print("❌ Valid email rejected:", serializer.errors)
    except Exception as e:
        print("❌ Error with valid email:", str(e))
    
    # Test invalid emails
    invalid_emails = [
        'admin@company.com',  # Reserved username
        'test@mailinator.com',  # Temp email
        'user!@#$@domain.com',  # Special characters
        'test123456789@domain.com',  # Suspicious pattern
    ]
    
    for email in invalid_emails:
        test_data = valid_data.copy()
        test_data['email'] = email
        test_data['username'] = f'user_{email.split("@")[0]}'  # Unique username
        
        serializer = RegisterSerializer(data=test_data)
        try:
            if serializer.is_valid():
                print(f"❌ Invalid email accepted: {email}")
            else:
                print(f"✅ Invalid email rejected: {email} - {serializer.errors.get('email', ['Unknown error'])[0]}")
        except Exception as e:
            print(f"✅ Invalid email rejected: {email} - {str(e)}")

def test_password_reset_serializer():
    """Test PasswordResetRequestSerializer with email validation"""
    print("\n=== TESTING PASSWORD RESET SERIALIZER ===")
    
    # Test invalid emails for password reset
    invalid_emails = [
        'admin@company.com',  # Reserved username
        'test@mailinator.com',  # Temp email
        'fake!@#$@domain.com',  # Special characters
    ]
    
    for email in invalid_emails:
        serializer = PasswordResetRequestSerializer(data={'email': email})
        try:
            if serializer.is_valid():
                print(f"❌ Invalid email accepted for reset: {email}")
            else:
                print(f"✅ Invalid email rejected for reset: {email} - {serializer.errors.get('email', ['Unknown error'])[0]}")
        except Exception as e:
            print(f"✅ Invalid email rejected for reset: {email} - {str(e)}")

if __name__ == "__main__":
    test_register_serializer()
    test_password_reset_serializer()
    print("\n=== INTEGRATION TEST COMPLETE ===")
