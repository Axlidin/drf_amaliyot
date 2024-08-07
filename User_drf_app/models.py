import random
import uuid
from datetime import datetime, timedelta

from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

from shared_drf_app.models import BaseModel

ORDINARY_USER, MANAGER, ADMIN = ('ordinary_user', 'manager', 'admin')
NEW, CODE_VERIFIED, DONE, PHOTO_DONE = ('new', 'code_verified', 'done', 'photo_done')

class User_drf_amaliyot(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN),
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
        (PHOTO_DONE, PHOTO_DONE),
    )
    user_roles = models.CharField(max_length=31, choices=USER_ROLES, default=ORDINARY_USER)
    email = models.CharField(null=True, blank=True, unique=True)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS, default=NEW)
    photo = models.ImageField(upload_to='user_photos/', null=True, blank=True,
          validators=[FileExtensionValidator(
              allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif']
          )]
                              )

    def __str__(self):
        return self.username

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self):
        code = "".join([str(random.randint(0, 9)) for _ in range(4)])  # Tasodifiy 4 xonali kod yaratish
        confirmation, created = UserConfirmation_drf_amaliyot.objects.update_or_create(
            verify_email=self.email,
            defaults={
                'user': self,
                'code': code,
                'expiration_time': datetime.now() + timedelta(minutes=EMAIL_EXPIRE),
                'is_confirmed': False
            }
        )
        return code

    def check_username(self):
        if not self.username:
            temp_username = f'instagram-{uuid.uuid4().__str__().split("-")[-1]}'  # instagram-23324fsdf
            while User_drf_amaliyot.objects.filter(username=temp_username):
                temp_username = f"{temp_username}{random.randint(0, 9)}"
            self.username = temp_username
    def check_email(self):
        if self.email:
            normalize_email = self.email.lower()
            self.email = normalize_email

    def check_pass(self):
        if not self.password:
            temp_password = f"password-{uuid.uuid4.__str__().split('-')[-1]}"
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def token(self):
        refresh_token = RefreshToken.for_user(self)
        return {
            "access": str(refresh_token.access_token),
            "refresh_token": str(refresh_token)
        }

    def save(self, *args, **kwargs):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()
        super(User_drf_amaliyot, self).save(*args, **kwargs)

EMAIL_EXPIRE = 1
class UserConfirmation_drf_amaliyot(BaseModel):
    verify_email = models.EmailField(null=True, blank=True, unique=True)
    code = models.CharField(max_length=4)
    user = models.ForeignKey('User_drf_app.User_drf_amaliyot', on_delete=models.CASCADE,
                             related_name='verify_email_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        if self.verify_email:
            self.expiration_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)
            super(UserConfirmation_drf_amaliyot, self).save(*args, **kwargs)