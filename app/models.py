# Imports
import uuid
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
import datetime
from django.db import models
from django.utils import timezone
from datetime import time, date, timedelta
from django.utils.translation import gettext_lazy as _
from django_resized import ResizedImageField
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField


# Custom User Model
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_admin") is not True:
            raise ValueError("Superuser must be Admin")
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must be staff")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser = True")

        return self.create_user(email, password, **extra_fields)


# For Backend Admins
class CustomUser(AbstractBaseUser, PermissionsMixin):
    def validate_date(value):
        if value > timezone.now().date():
            raise ValidationError(_("Invalid date."))

    id = models.CharField(unique=True, primary_key=True, max_length=50, editable=False)
    email = models.EmailField(unique=True, blank=False, null=False)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    avatar = ResizedImageField(
        size=[150, 150],
        default="avatar.jpg",
        upload_to="profile_avatars",
        blank=True,
        null=True,
    )
    mobile_number = models.CharField(max_length=50, blank=True, null=True, default=None)
    date_of_birth = models.DateField(
        blank=True, null=True, validators=[validate_date], default=None
    )
    age = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_super_admin = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.id} - {self.email}"

    def save(self, *args, **kwargs):
        if not self.id:
            while True:
                new_id = str(uuid.uuid4().hex[:10].upper())
                if not CustomUser.objects.filter(id=new_id).exists():
                    self.id = new_id
                    break

        if isinstance(self.date_of_birth, tuple):
            date_format = '%d-%m-%Y'
            self.date_of_birth = datetime.datetime.strptime(str(self.date_of_birth[0]), date_format)     
            
        if isinstance(self.mobile_number, tuple):
            self.mobile_number = str(self.mobile_number[0])
            
        if self.date_of_birth:
            today = date.today()
            user_age = int(today.year - self.date_of_birth.year) - 1
            self.age = user_age

        super().save(*args, **kwargs)
