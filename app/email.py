import json
from decimal import Decimal, ROUND_DOWN
from testProject import settings
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMessage
from django.core.mail import EmailMultiAlternatives


#### Email seeding functions #####


# Email notification after signup
def send_email_notification(recipient_list):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Update Notification"
    html_body = f"""
    Hi
    Thank you for choosing TestProject. Your account has been registered successfully!
    Regards, 
    TestProject

    """
    send_mail(subject, html_body, email_from, recipient_list)

    return True


def send_forget_password_mail(user, uid, token):
    reset_password_link = f"http://127.0.0.1:5502/template/pages/samples/change-password.html?uid={uid}&token={token}"
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(
        "Account Password Reset Notification",
        f"""
Hi {user.first_name},

There was a request to change your password! 
Please click this link to change your password: {reset_password_link}

Kind regards,
TestProject Support Team
""",
        email_from,
        [user.email],
        fail_silently=False,
    )
    return True


# Email notification If user changes Profile information
def send_user_profile_delete_notification(recipient_list):
    email_from = settings.DEFAULT_FROM_EMAIL
    subject = "Account Deletion Notification"
    message = f"""
    
Dear {recipient_list.get('first_name')},

We regret to inform you that your account with HeartBeat has been deleted as per your request. This action is irreversible, and all associated data and information have been permanently removed from our systems.
    
If you have any further queries or require assistance, please don't hesitate to reach out to our support team at {email_from}.
Thank you for being a part of HeartBeat. We appreciate your past support and wish you all the best in your future endeavors.

Kind regards,
TestProject Support Team

"""
    send_mail(subject, message, email_from, recipient_list)

    return True
