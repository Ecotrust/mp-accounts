# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_auto_20150115_1619'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='passworddictionary',
            options={'verbose_name': 'Password Dictionary', 'verbose_name_plural': 'Password Dictionary'},
        ),
        migrations.AddField(
            model_name='userdata',
            name='preferred_name',
            field=models.CharField(default='', max_length=30),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='userdata',
            name='real_name',
            field=models.CharField(default='', max_length=256),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='userdata',
            name='show_real_name_by_default',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
