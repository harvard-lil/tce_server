from __future__ import absolute_import

from celery import shared_task
import dateutil.parser

from .models import KeyPair, Trustee


@shared_task
def create_key(release_date):
    release_date = dateutil.parser.parse(release_date)

    keypair = KeyPair(release_date=release_date)
    keypair.save()
    keypair.trustees = list(Trustee.objects.exclude(this_server=True))
    keypair.send_generate_key_messages()