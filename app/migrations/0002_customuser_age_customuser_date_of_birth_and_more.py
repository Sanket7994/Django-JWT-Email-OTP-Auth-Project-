# Generated by Django 4.2.4 on 2023-08-08 10:08

import app.models
import django.core.validators
from django.db import migrations, models
import django.utils.timezone
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='age',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='customuser',
            name='date_of_birth',
            field=models.DateField(default=django.utils.timezone.now, validators=[app.models.CustomUser.validate_date]),
        ),
        migrations.AddField(
            model_name='customuser',
            name='mobile_number',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, default=None, max_length=128, null=True, region=None, validators=[django.core.validators.RegexValidator('^(\\+\\d{1,3})?,?\\s?\\d{8,15}')]),
        ),
    ]
