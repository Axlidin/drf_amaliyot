from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from shared_drf_app.utility import send_email, check_email__
from .serializers import SignUp_drf_amaliyotSerializer, ChengeUserInformation, ChangeUserPhotoSerializer, \
    LoginSerializer, LoginRefreshSerializer, LogOutSerializer, ForgotpasswordSerializer, RestpasswordSerializer
from .models import User_drf_amaliyot, DONE, CODE_VERIFIED, NEW


class CreateUserView(CreateAPIView):
    queryset = User_drf_amaliyot.objects.all()
    serializer_class = SignUp_drf_amaliyotSerializer
    permission_classes = (AllowAny, )


class VerifyApiView(APIView):

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')
        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "auth_status": user.auth_status,
                "access": user.token()['access'],
                "refresh_token": user.token()['refresh_token'],
            }
        )

    @staticmethod
    def check_verify(user, code):
        verify = user.verify_email_codes.filter(expiration_time__gte=timezone.now(), code=code, is_confirmed=False)
        if not verify.exists():
            data = {
                "message": "Tasdiqlash kodingiz xato yoki eskirgan."
            }
            raise ValidationError(data)
        verify.update(is_confirmed=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerification(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.email:
            code = user.create_verify_code()
            send_email(user.email, code)
        else:
            data = {
                "message": 'Email manzilingizning mavjud emas yoki xato kiritdingiz!'
            }
            raise ValidationError(data)
        return Response(
            data={
                "success":True,
                "message": 'Tasdiqlash kodingiz qaytadan yuborildi!'
            }
        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_email_codes.filter(expiration_time__gte=timezone.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": 'Kodingizning ishlatish uchun yaroqli, iltimos biroz kuting!'
            }
            raise ValidationError(data)

class ChengeUserInformationView(UpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ChengeUserInformation
    http_method_names = ['put', 'patch']


    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChengeUserInformationView, self).update(request, *args, **kwargs)
        data = {
            "success":True,
            "message": 'Ma\'lumotlaringiz o\'zgartirildi!',
            "auth_status": self.request.user.auth_status,
        }
        return Response(data, status=200)

    def partial_update(self, request, *args, **kwargs):
        super(ChengeUserInformationView, self).partial_update(request, *args, **kwargs)
        data = {
            "success":True,
            "message": 'Ma\'lumotlaringiz o\'zgartirildi!',
            "auth_status": self.request.user.auth_status,
        }
        return Response(data, status=200)

class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ChangeUserPhotoSerializer

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response(
                {
                    "success": True,
                    "message": 'Rasm muvaffaqiyatli o\'zgartirildi!',
                    "auth_status": self.request.user.auth_status
                }, status=200
            )
        else:
            return Response(serializer.errors, status=400)

class LoginbView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

class LogOutView(APIView):
    serializer_class = LogOutSerializer
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                'message': "You are logged out"
            }
            return Response(data)
        except TokenError as e:
            return Response(status=400)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny, ]
    serializer_class = ForgotpasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        user = serializer.validated_data.get('user')
        if check_email__(email) == 'email':
            code = user.create_verify_code()
            send_email(user.email, code)
        return Response(
            {
                "success": True,
                "message": 'Tasdiqlash kodingiz qaytadan yuborildi!',
                "access": user.token()['access'],
                "refresh_token": user.token()['refresh_token'],
                "auth_status": user.auth_status,
            }, status=200
        )

class RestpasswordView(UpdateAPIView):
    serializer_class = RestpasswordSerializer
    permission_classes = [IsAuthenticated, ]
    http_method_names = ['put', 'patch']


    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super(RestpasswordView, self).update(request, *args, **kwargs)
        try:
            user = User_drf_amaliyot.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist:
            raise NotFound(detail='User not found.')
        return Response(
            {
                "success": True,
                "message": 'Parolingiz o\'zgartirildi!',
                "access": user.token()['access'],
                "refresh_token": user.token()['refresh_token'],
                "auth_status": user.auth_status,
            }
        )