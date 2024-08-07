from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

from .models import User_drf_amaliyot, CODE_VERIFIED, DONE, PHOTO_DONE, NEW
from shared_drf_app.utility import check_email__, send_email, check_user_type


class SignUp_drf_amaliyotSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUp_drf_amaliyotSerializer, self).__init__(*args, **kwargs)
        self.fields['email_'] = serializers.CharField(required=False)

    class Meta:
        model = User_drf_amaliyot
        fields = (
            'id',
            'email',
            'auth_status'
        )
        extra_kwargs = {
            'auth_status': {'read_only': True, 'required': False},
        }
    def create(self, validated_date):
        user = super(SignUp_drf_amaliyotSerializer, self).create(validated_date)
        code = user.create_verify_code()
        send_email(user.email, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUp_drf_amaliyotSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_')).lower()
        input_type = check_email__(user_input)
        if input_type == "email":
            data = {
                "email": user_input,
            }
        else:
            data = {
                'success': False,
                'message': "You must send only email."
            }
            raise ValidationError(data)
        return data

    def validate_email_(self, value):
        value = value.lower()
        print(value)
        if value and User_drf_amaliyot.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Email allaqachon ma'lumotlar omborida mavjud"
            }
            raise ValidationError(data)
        return value

    def to_representation(self, instance):
        data = super(SignUp_drf_amaliyotSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data

class ChengeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            data = {
                'success': False,
                'message': 'Passwords do not match.'
            }
            raise ValidationError(data)
        if password:
            validate_password(password)
            validate_password(confirm_password)
        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 35:
            raise ValidationError(
                {
                    'message': 'Username uzunligi 5-35 ta belgi orasidabo\'lishi kerak.'
                }
            )
        elif username.isdigit():
            raise ValidationError(
                {
                    'message': 'Usernamening raqamlardan iborat bo\'lishi kerak emas.'
                }
            )
        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.password = validated_data.get('password', instance.password)
        instance.username = validated_data.get('username', instance.username)
        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE
        instance.save()
        return instance

class ChangeUserPhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(
              allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif']
          )])
    def update(self, instance, validated_data):
        photo = validated_data.get('photo')
        if photo:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()
        return instance

class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(read_only=True, required=False)

    def auth_validate(self, data):
        user_input = data.get('userinput')
        if check_user_type(user_input) == 'username':
            username = user_input
        elif check_user_type(user_input) == 'email':
            user = self.get_user(email__iexact=user_input)
            username = user.username
        else:
            data = {
                'success': True,
                'message': "Siz email yoki username kiritishingiz kerak."
            }
            raise ValidationError(data)
        authenticaton_kwargs = {
            self.username_field: username,
            'password': data.get('password')
        }
        current_user = User_drf_amaliyot.objects.filter(username__iexact=username).first()
        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            data = {
                'success': False,
                'message': "Siz ro'yxatdan to'liq o'tmagansiz."
            }
            raise ValidationError(data)
        user = authenticate(**authenticaton_kwargs)
        if user is not None:
            self.user = user
        else:
            data = {
                "success": False,
                'detail': 'Siz kiritgan login yoki parolingiz noto\'g\'ri iltimos qaytadan kiriting.',
            }
            raise ValidationError(data)

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_DONE]:
            raise PermissionDenied("Siz login qila olmaysiz, siz avval ro'yxatdan o'ting!")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['fullname'] = self.user.full_name
        return data
    def get_user(self, **kwargs):
        users = User_drf_amaliyot.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    'detail': 'User not found',
                }
            )
        return users.first()

class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User_drf_amaliyot, id=user_id)
        update_last_login(None, user)
        return data

class LogOutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class ForgotpasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email', None)
        if email is None:
            raise serializers.ValidationError({'success': True,
                                               "message": 'email manzilingiz shart.'})
        user = User_drf_amaliyot.objects.filter(Q(email=email))
        if not user.exists():
            raise NotFound(detail='Not found user.')
        else:
            attrs['user'] = user.first()
            return attrs

class RestpasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(required=True, write_only=True, min_length=8)
    confirm_password = serializers.CharField(required=True, write_only=True, min_length=8)

    class Meta:
        model = User_drf_amaliyot
        fields = ('id', 'password', 'confirm_password')

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise serializers.ValidationError({'success': False,
                                               'message': 'Parollaringiz bir biriga mos emas.'})
        if password:
            validate_password(password)
            validate_password(confirm_password)
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(RestpasswordSerializer, self).update(instance, validated_data)