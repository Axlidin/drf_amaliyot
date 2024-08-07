from django.urls import path
from .views import (CreateUserView, VerifyApiView, GetNewVerification, ChengeUserInformationView,
                    ChangeUserPhotoView, LoginbView, LoginRefreshView, LogOutView, ForgotPasswordView,
                    RestpasswordView)

urlpatterns = [
    path('login/', LoginbView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyApiView.as_view()),
    path('code-verify/', GetNewVerification.as_view()),
    path('change-user/', ChengeUserInformationView.as_view()),
    path('change-user-photo/', ChangeUserPhotoView.as_view()),
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('reset-password/', RestpasswordView.as_view()),
]

