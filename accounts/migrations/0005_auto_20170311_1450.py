# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-11 22:50
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_auto_20150209_1512'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='activate_user',
            field=models.BooleanField(default=True, help_text='If true, user.is_active will be set to true when verified.'),
        ),
        migrations.AlterField(
            model_name='emailverification',
            name='email_to_verify',
            field=models.EmailField(max_length=254),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='email_verified',
            field=models.BooleanField(default=False, help_text="Has this user's email been verified?"),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='preferred_name',
            field=models.CharField(default='', max_length=30),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='profile_image',
            field=models.URLField(default='/static/accounts/marco_user.png', help_text="URL to the user's profile image."),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='real_name',
            field=models.CharField(default='', max_length=256),
        ),
    ]
