from collections import OrderedDict
from datetime import timedelta
import glob
import json
import subprocess
import time
import gnupg
import os
import shutil
import tempdir
import requests
from fabric.api import *

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tce_server.settings')
import django
django.setup()

from django.conf import settings
from django.utils import timezone
from main.tasks import create_key

@task
def generate_keys(name='', email=''):
    """
        Generate a GPG keypair.
    """
    if '/vagrant/' in __file__:
        print "WARNING: This command does not run well under Vagrant, as it requires random entropy."
    with tempdir.TempDir() as tempdir_path:
        gpg = gnupg.GPG(homedir=tempdir_path)
        gpg_input = gpg.gen_key_input(name_email=email, name_real=name)  # use sensible defaults
        print "Generating keypair with this input: %s" % gpg_input
        key = gpg.gen_key(gpg_input)
        print "\nGPG_PUBLIC_KEY = %s\nGPG_PRIVATE_KEY = %s\nGPG_FINGERPRINT = %s" % (
            repr(gpg.export_keys(key.fingerprint)),  # public key
            repr(gpg.export_keys(key.fingerprint, True)),  # private key
            repr(key.fingerprint)
        )

@task
def run_trustees():
    import trustee.process_message

    # var setup

    server = "http://127.0.0.1:8000/"

    trustees = OrderedDict()

    for trustee_name in ["1", "2", "3"]:
        trustee = {}

        trustee["offline_root_dir"] = os.path.join(os.path.dirname(settings.BASE_DIR), "test/offline_servers", trustee_name)
        trustee["message_archive_dir"] = os.path.join(trustee["offline_root_dir"], "incoming_messages/archive")
        trustee['settings'] = json.loads(open(os.path.join(trustee["offline_root_dir"], "settings.json")).read())
        trustee['settings']['private_key_dir'] = os.path.join(trustee["offline_root_dir"], "private_keys")

        trustees[trustee_name] = trustee

    while True:

        for trustee_name, trustee in trustees.items():

            print "--------- TRUSTEE %s ---------" % trustee_name

            # download new messages to online server inbox
            print "Local server is downloading packets from central server."
            known_messages = [fname for fname in list(os.listdir(trustee["message_archive_dir"])) if fname.endswith('.msg')]
            highest_message_id = max(int(fname.split('.msg')[0]) for fname in known_messages) if known_messages else 0
            try:
                response = requests.post(server+"get_messages/", data={'api_key':trustee_name, 'after_id':str(highest_message_id)})
                assert response.ok
                data = response.content
                if data != "[]":
                    for message_id, message in json.loads(data):
                        print "Processing message."
                        print "\nGot message:\n\n%s\n\n" % (message)
                        try:
                            response = trustee.process_message.process_message(json.loads(message), trustee['settings'])
                            status = 'success'
                        except trustee.process_message.ProcessingError as e:
                            raise
                            response = str(e)
                            status = 'failed'
                        requests.post(server+"send_message/", data={'api_key':trustee_name, 'response':json.dumps(response), 'status':status, 'message_id':message_id})
                        print "\nSending response:\n\n%s\n" % (response)
                        open(os.path.join(trustee["message_archive_dir"], "%s.msg" % message_id), 'w').write(message)
            except (requests.ConnectionError, AssertionError):
                print "Unable to reach central server!"
            time.sleep(.5)

@task
def make_key(release_date=None):
    if not release_date:
        release_date = (timezone.now() + timedelta(0,60)).isoformat()

    create_key(release_date)