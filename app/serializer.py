import string
from rest_framework import serializers
from .models import (
    CustomUser,
)

# To convert the Model object to an API-appropriate format like JSON,
# Django REST framework uses the ModelSerializer class to convert any model to serialized JSON objects:


# User
class CustomSerializer(serializers.ModelSerializer):
    created_at = serializers.ReadOnlyField()

    class Meta:
        model = CustomUser
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "avatar",
            "mobile_number",
            "date_of_birth",
            "age",
            "created_at",
            "last_login",
        )
        extra_kwargs = {"password": {"write_only": True}}


# Verify OTP
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=8)

    def validate_otp(self, otp):
        if (
            not all(c in string.ascii_letters + string.digits for c in otp)
            or len(otp) != 6
        ):
            raise serializers.ValidationError("Invalid OTP format.")
        return otp


# Forgot password authentication
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


# Reset password authentication with validation
class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs
