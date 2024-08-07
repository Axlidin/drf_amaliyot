import re
import threading
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError

check_email = re.compile(r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+")
username_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")

def check_email__(email):
    if re.fullmatch(check_email, email):
        return 'email'
    else:
        data = {
            'status': False,
            'message': "Email manzilingiz noto'g'tri."
        }
        raise ValidationError(data)

def check_user_type(user_input):
    if re.fullmatch(check_email, user_input):
        user_input = 'email'
    elif re.fullmatch(username_regex, user_input):
        user_input = 'username'
    else:
        data = {
            "success": False,
            "message": "Email yoki username noto'g'ri"
        }
        raise ValidationError(data)
    return user_input

class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()

class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentification/activate_account.html',
        {'code': code}
    )
    Email.send_email(
        {
            'subject': "Ro'yxatdan o'tish",
            'to_email': email,
            'body': html_content,
            'content_type': 'html'

        }

    )