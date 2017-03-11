# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-03-11 23:24
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_auto_20170311_1450'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
