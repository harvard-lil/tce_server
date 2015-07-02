# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import main.models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_keypair_elgamal_key_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='keypair',
            name='state',
            field=models.TextField(null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='message',
            name='response',
            field=models.TextField(null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='message',
            name='response_status',
            field=models.CharField(default=b'waiting', max_length=20, choices=[(b'waiting', b'waiting'), (b'success', b'success'), (b'failed', b'failed')]),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='keypair',
            name='g',
            field=main.models.BigIntField(default=5),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='message',
            name='message_type',
            field=models.CharField(max_length=20, choices=[(b'generate_key', b'generate_key'), (b'store_share', b'store_share'), (b'combine_share', b'combine_share'), (b'confirm_share', b'confirm_share'), (b'release_key', b'release_key')]),
            preserve_default=True,
        ),
    ]
