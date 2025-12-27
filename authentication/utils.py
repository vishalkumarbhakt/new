import logging
import random
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings

logger = logging.getLogger(__name__)

def send_verification_email(user, verification_url, otp=None):
    """
    Send email verification email to user with both token link and OTP
    """
    subject = 'Verify Your S2Cart Account'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]
    
    # Generate Android deep link URL
    android_deep_link = f"s2cart://verify?token={verification_url.split('/')[-2]}&otp={otp}" if otp else f"s2cart://verify?token={verification_url.split('/')[-2]}"
    
    # HTML content
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            .header {{ background-color: #4CAF50; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
            .button {{ display: inline-block; background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; 
                      text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            .otp-box {{ background-color: #f8f9fa; border: 2px dashed #4CAF50; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px; }}
            .otp-code {{ font-size: 32px; font-weight: bold; color: #4CAF50; letter-spacing: 8px; font-family: monospace; }}
            .footer {{ margin-top: 20px; text-align: center; font-size: 12px; color: #777; }}
            .app-button {{ display: inline-block; background-color: #2196F3; color: white; padding: 10px 20px; text-align: center; 
                          text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Verify Your S2Cart Account</h2>
            </div>
            
            <p>Hello {user.first_name or user.username},</p>
            
            <p>Thank you for registering with S2Cart. You can verify your email address in two ways:</p>
            
            <h3>Option 1: Use the verification code</h3>
            {f'''<div class="otp-box">
                <p style="margin: 0; font-size: 16px;">Your verification code is:</p>
                <div class="otp-code">{otp}</div>
                <p style="margin: 0; font-size: 14px; color: #666;">This code will expire in 25 minutes</p>
            </div>''' if otp else ''}
            
            <h3>Option 2: Click the verification button</h3>
            <p>Click the button below to verify your email address:</p>
            
            <a href="{android_deep_link}" class="app-button">Open in S2Cart App</a>
            <a href="{verification_url}" class="button">Verify in Browser</a>
            
            <p style="font-size: 14px; color: #666;">
                <strong>Note:</strong> The "Open in S2Cart App" button will open the S2Cart app if installed, 
                otherwise it will redirect you to install the app from the Play Store.
            </p>
            
            <p>This verification link will expire in 24 hours.</p>
            
            <p>If you did not create this account, you can safely ignore this email.</p>
            
            <p>Thank you,<br>
            The S2Cart Team</p>
            
            <div class="footer">
                <p>This is an automated email. Please do not reply to this message.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text content
    text_content = f"""
    Hello {user.first_name or user.username},
    
    Thank you for registering with S2Cart. You can verify your email address in two ways:
    
    Option 1: Use this verification code: {otp if otp else 'Not provided'}
    (This code will expire in 25 minutes)
    
    Option 2: Click this link to verify: {verification_url}
    
    This verification link will expire in 24 hours.
    
    If you did not create this account, you can safely ignore this email.
    
    Thank you,
    The S2Cart Team
    """
    
    try:
        # Create email message
        email = EmailMultiAlternatives(
            subject,
            text_content,
            from_email,
            to_email
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
        logger.info(f"Verification email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        return False

def send_password_reset_email(user, reset_url, otp=None):
    """
    Send password reset email to user with both token link and OTP
    """
    subject = 'Reset Your S2Cart Password'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]
    
    # Generate Android deep link URL
    android_deep_link = f"s2cart://reset-password?token={reset_url.split('/')[-2]}&otp={otp}" if otp else f"s2cart://reset-password?token={reset_url.split('/')[-2]}"
    
    # HTML content
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            .header {{ background-color: #2196F3; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
            .button {{ display: inline-block; background-color: #2196F3; color: white; padding: 10px 20px; text-align: center; 
                      text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            .otp-box {{ background-color: #f8f9fa; border: 2px dashed #2196F3; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px; }}
            .otp-code {{ font-size: 32px; font-weight: bold; color: #2196F3; letter-spacing: 8px; font-family: monospace; }}
            .footer {{ margin-top: 20px; text-align: center; font-size: 12px; color: #777; }}
            .app-button {{ display: inline-block; background-color: #FF9800; color: white; padding: 10px 20px; text-align: center; 
                          text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Reset Your S2Cart Password</h2>
            </div>
            
            <p>Hello {user.first_name or user.username},</p>
            
            <p>You requested a password reset for your S2Cart account. You can reset your password in two ways:</p>
            
            <h3>Option 1: Use the reset code</h3>
            {f'''<div class="otp-box">
                <p style="margin: 0; font-size: 16px;">Your password reset code is:</p>
                <div class="otp-code">{otp}</div>
                <p style="margin: 0; font-size: 14px; color: #666;">This code will expire in 25 minutes</p>
            </div>''' if otp else ''}
            
            <h3>Option 2: Click the reset button</h3>
            <p>Click the button below to reset your password:</p>
            
            <a href="{android_deep_link}" class="app-button">Open in S2Cart App</a>
            <a href="{reset_url}" class="button">Reset in Browser</a>
            
            <p style="font-size: 14px; color: #666;">
                <strong>Note:</strong> The "Open in S2Cart App" button will open the S2Cart app if installed, 
                otherwise it will redirect you to install the app from the Play Store.
            </p>
            
            <p>This password reset link will expire in 24 hours.</p>
            
            <p>If you did not request a password reset, you can safely ignore this email.</p>
            
            <p>Thank you,<br>
            The S2Cart Team</p>
            
            <div class="footer">
                <p>This is an automated email. Please do not reply to this message.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text content
    text_content = f"""
    Hello {user.first_name or user.username},
    
    You requested a password reset for your S2Cart account. You can reset your password in two ways:
    
    Option 1: Use this reset code: {otp if otp else 'Not provided'}
    (This code will expire in 25 minutes)
    
    Option 2: Click this link to reset: {reset_url}
    
    This password reset link will expire in 24 hours.
    
    If you did not request a password reset, you can safely ignore this email.
    
    Thank you,
    The S2Cart Team
    """
    
    try:
        # Create email message
        email = EmailMultiAlternatives(
            subject,
            text_content,
            from_email,
            to_email
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
        logger.info(f"Password reset email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        return False