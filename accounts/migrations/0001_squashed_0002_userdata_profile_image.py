# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailVerification',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('email_to_verify', models.EmailField(max_length=75)),
                ('verification_code', models.CharField(max_length=32, editable=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('activate_user', models.BooleanField(default=True, help_text='If true, user.is_active will be set to true when verified.')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserData',
            fields=[
                ('user', models.OneToOneField(primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.CASCADE)),
                ('email_verified', models.BooleanField(default=False, help_text=b"Has this user's email been verified?")),
                ('profile_image', models.URLField(default='/static/accounts/marco_user.png', help_text=b"URL to the user's profile image.")),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='emailverification',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, unique=True, on_delete=django.db.models.deletion.CASCADE),
            preserve_default=True,
        ),
    ]
