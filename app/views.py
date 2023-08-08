# Within the project directory
from .models import (
    CustomUser,
)
from .serializer import (
    CustomSerializer,
)

from .email import (
    send_email_notification,
    send_forget_password_mail,
    send_user_profile_delete_notification,
)

from .otp_generator import generate_time_based_otp, is_otp_valid

from .serializer import (
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    VerifyOTPSerializer,
)


# External REST libraries and models
from rest_framework import status
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken


# External Django libraries and modules
import base64
import datetime

from django.core.exceptions import ObjectDoesNotExist
from datetime import timedelta
from django.dispatch import Signal

from django.core.exceptions import ObjectDoesNotExist
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator


# User Account creation API
class SignupView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            email = request.data.get("email")
            first_name = request.data.get("first_name")
            last_name = request.data.get("last_name")
            mobile_number = request.data.get("mobile_number"),
            date_of_birth = request.data.get("date_of_birth"),
            password = request.data.get("password")
            confirm_password = request.data.get("confirm_password")

            is_email_exits = CustomUser.objects.filter(email=email)

            # Error case handling for User
            if is_email_exits.exists():
                return Response(
                    data={"message": "Email already exists"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Password Mismatch Case
            if password != confirm_password:
                return Response(
                    data={"message": "Passwords don't match"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = CustomUser(
                email=email,
                first_name=first_name,
                last_name=last_name,
                mobile_number = mobile_number,
                date_of_birth = date_of_birth,
                password = password,
            )

            # Email OTP verification
            send_email_notification([user])                                                                                                                                                                                                                                                         
            
            # Saving user information 
            user.set_password(password)
            user.is_active = True
            user.save()
            return Response(
                data={
                    "message": "Your account has been registered now."
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Login API
class LoginView(APIView):
    permission_classes = [
        permissions.AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            remember_me = request.data.get("remember_me")

            # Rain check from user database
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                return Response(
                    {"message": "User with this email does not exist."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Authentication
            user = authenticate(request, email=email, password=password)
            # Error Case
            if user is None:
                return Response(
                    data={"message": "Email or Password is incorrect"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            elif password is None:
                return Response(
                    data={"message": "Enter the password to login!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Login the user
            login(request, user)

            # Generate tokens
            refresh_token = RefreshToken.for_user(user)

            if remember_me == True:
                # Set token expiration to a longer duration if "Remember Me" is checked
                refresh_token.set_exp(lifetime=timedelta(days=2))
            else:
                # Set token expiration to a short duration if "Remember Me" is not checked
                refresh_token.set_exp(lifetime=timedelta(days=1))
            # Output dictionary
            user_details = {
                "refresh": str(refresh_token),
                "access": str(refresh_token.access_token),
                "user_id": str(user.id),
            }

            user_logged_in = Signal()
            user_logged_in.send(sender=user.__class__, request=request, user=user)
            return Response(user_details, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# customizing the claims in tokens generated by the TokenObtainPairView
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Adding custom claims
        token["id"] = user.id
        return token


# Token serializer
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# Auto refresh access tokens If user is logged in
class TokenRefreshView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        user = request.user
        # Check if the user is logged in
        if user.is_authenticated:
            access_token = request.auth
            if access_token:
                print(access_token.get("exp"))
                # Get the remaining time until the access token expires
                remaining_time = access_token.get("exp") - datetime.utcnow().timestamp()

                # Set the threshold time for refreshing the token
                refresh_threshold = 60  # 1 minute

                if remaining_time < refresh_threshold:
                    # If the access token is about to expire, generate a new one
                    refresh = RefreshToken(access_token)
                    new_access_token = str(refresh.access_token)
                    # Return the new access token in the response
                    return Response(
                        {"access_token": new_access_token}, status=status.HTTP_200_OK
                    )
        # Return a 401 Unauthorized status if the user is not logged in or the token doesn't require refreshing
        return Response({"detail": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)


# User Account Logout API
# Known Issue:
# So basically every time the server was reloading because the SECRET_KEY had a new value,
# the value of the SIGNING_KEY changed. Hence, the old refresh token became invalid,
# even when it did not expire, as its SIGNING_KEY value was not matching with current one.
class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                raise ValueError("Refresh token not provided in the request data.")
            if RefreshToken(refresh_token).is_expired:
                RefreshToken(refresh_token).blacklist()
                raise ValueError("Refresh token has expired.")
            RefreshToken(refresh_token).blacklist()
            return Response(
                {"message": "Logged out successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(data={"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Forgot Password API
class ForgotPasswordView(APIView):
    permission_classes = [
        permissions.AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=request.data)
        try:
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                try:
                    user = CustomUser.objects.filter(email=email).first()

                except CustomUser.DoesNotExist:
                    return Response(
                        {"message": "User with this email does not exist."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
                print(str(user.pk))
                token = default_token_generator.make_token(user)

                # Calling custom email generator
                send_forget_password_mail(user, uid, token)
                return Response(
                    {"message": "Password reset email has been sent."},
                    status=status.HTTP_200_OK,
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# User Account Reset Password API
class ResetPasswordView(APIView):
    permission_classes = [
        permissions.AllowAny,
    ]

    def post(self, request, *args, **kwargs):
        try:
            token = request.query_params.get("token")
            uidb64 = request.query_params.get("uid")

            # Add padding characters to uidb64
            padding = len(uidb64) % 4
            if padding:
                uidb64 += "=" * (4 - padding)

            uid = base64.urlsafe_b64decode(uidb64).decode("utf-8")
            user = CustomUser.objects.get(pk=uid)

        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist) as e:
            return Response(
                {"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST
            )

        if default_token_generator.check_token(user, token):
            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                new_password = serializer.validated_data["new_password"]
                user.set_password(new_password)
                user.save()

                return Response(
                    {"message": "Password reset successful."}, status=status.HTTP_200_OK
                )
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {"message": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST
        )


# USER PROFILE OPERATIONS
class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    # Allow only authenticated users to access this URL
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomSerializer

    # View user data
    def get(self, request, id, *args, **kwargs):
        try:
            user_profile = CustomUser.objects.get(id=id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = CustomSerializer(user_profile, partial=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Update user data
    def put(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(user__id=id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        data = {
            "first_name": request.data.get("first_name"),
            "last_name": request.data.get("last_name"),
            "email": request.data.get("email"),
            "avatar": request.data.get("avatar"),
            "mobile_number": request.data.get("mobile_number"),
            "date_of_birth": request.data.get("date_of_birth"),
        }
        serializer = CustomSerializer(user_data, data=data, partial=True)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    # Delete user data
    def delete(self, request, id, *args, **kwargs):
        try:
            user_data = CustomUser.objects.get(user__id=id)
        except ObjectDoesNotExist:
            return Response(
                {"error": "User profile not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Send User profile delete notification email
        send_user_profile_delete_notification([user_data])

        # Delete user profile
        user_data.delete()
        return Response(
            data={"message": "User profile deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )
