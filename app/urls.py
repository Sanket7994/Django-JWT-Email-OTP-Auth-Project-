from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import MyTokenObtainPairView, TokenRefreshView, LogoutView
from .views import LoginView, SignupView, ForgotPasswordView
from .views import (
    ResetPasswordView,
    UserRetrieveUpdateAPIView,
)


urlpatterns = [
    path("token/refresh/", TokenRefreshView.as_view(), name="auto-refresh-acc-token"),
    path("login/", LoginView.as_view(), name="login"),
    path("signup/", SignupView.as_view(), name="signup"),
    path("logout/", LogoutView.as_view(), name="logout"),
    
    path("forgot-password/", ForgotPasswordView.as_view(), name="forget-password"),
    path("reset-password", ResetPasswordView.as_view(), name="reset-password"),
    path("profile/id=<str:id>", UserRetrieveUpdateAPIView.as_view(), name="view"),
    path("profile/<str:id>/update", UserRetrieveUpdateAPIView.as_view(), name="update"),
    path("profile/<str:id>/delete", UserRetrieveUpdateAPIView.as_view(), name="delete"),
    path("api/token/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/logout_token/", LogoutView.as_view(), name="logout_token"),
]
