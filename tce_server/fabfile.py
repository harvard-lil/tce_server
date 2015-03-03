from collections import OrderedDict
from datetime import datetime, timedelta
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
from main.tasks import create_key


def generate_keys():
    """
        Generate a GPG keypair.
    """
    if '/vagrant/' in __file__:
        print "WARNING: This command does not run well under Vagrant, as it requires random entropy."
    with tempdir.TempDir() as tempdir_path:
        gpg = gnupg.GPG(homedir=tempdir_path)
        gpg_input = gpg.gen_key_input()  # use sensible defaults
        print "Generating keypair with this input: %s" % gpg_input
        key = gpg.gen_key(gpg_input)
        print "\nGPG_PUBLIC_KEY = %s\nGPG_PRIVATE_KEY = %s\nGPG_FINGERPRINT = %s" % (
            repr(gpg.export_keys(key.fingerprint)),  # public key
            repr(gpg.export_keys(key.fingerprint, True)),  # private key
            repr(key.fingerprint)
        )


def run_trustees():
    # helpers

    def glob_copy(src, dst):
        for fname in glob.glob(src):
            shutil.copy(fname, dst)

    def glob_move(src, dst):
        for fname in glob.glob(src):
            shutil.move(fname, dst)

    # var setup

    server = "http://127.0.0.1:8000/"
    script_dir = os.path.join(settings.BASE_DIR, "scripts/offline_processor.py")

    trustees = OrderedDict()

    for trustee_name in ["1", "2", "3"]:
        trustee = {}

        trustee["offline_root_dir"] = os.path.join(os.path.dirname(settings.BASE_DIR), "test/offline_servers", trustee_name)
        trustee["offline_outgoing_dir"] = os.path.join(trustee["offline_root_dir"], "outgoing_messages")
        trustee["offline_outgoing_archive_dir"] = os.path.join(trustee["offline_outgoing_dir"], "archive")
        trustee["offline_incoming_dir"] = os.path.join(trustee["offline_root_dir"], "incoming_messages")

        trustee["online_root_dir"] = os.path.join(os.path.dirname(settings.BASE_DIR), "test/online_servers", trustee_name)
        trustee["online_outgoing_dir"] = os.path.join(trustee["online_root_dir"], 'messages_for_offline_server')
        trustee["online_outgoing_archive_dir"] = os.path.join(trustee["online_outgoing_dir"], 'archive')
        trustee["online_incoming_dir"] = os.path.join(trustee["online_root_dir"], 'messages_for_public_server')
        trustee["online_incoming_archive_dir"] = os.path.join(trustee["online_incoming_dir"], 'archive')

        trustees[trustee_name] = trustee

    while True:

        for trustee_name, trustee in trustees.items():

            print "--------- TRUSTEE %s ---------" % trustee_name

            # download new messages to online server inbox
            print "Local server is downloading messages from central server."
            known_messages = [fname for fname in list(os.listdir(trustee["online_outgoing_dir"]))+list(os.listdir(trustee["online_outgoing_archive_dir"])) if fname.endswith('.msg')]
            highest_message_id = max(int(fname.split('.msg')[0]) for fname in known_messages) if known_messages else 0
            try:
                response = requests.post(server+"get_messages/", data={'api_key':trustee_name, 'after_id':str(highest_message_id)})
                assert response.ok
                data = response.content
                if data != "[]":
                    for message_id, message in json.loads(data):
                        open(os.path.join(trustee["online_outgoing_dir"], "%s.msg" % message_id), 'w').write(message)
            except (requests.ConnectionError, AssertionError):
                print "Unable to reach central server!"
            time.sleep(.5)

            print "Employee is copying messages to the offline laptop for processing."
            # copy messages to offline server inbox
            glob_copy(trustee["online_outgoing_dir"] + '/*.msg', trustee["offline_incoming_dir"])
            # move online messages to online server archive
            glob_move(trustee["online_outgoing_dir"] + '/*.msg', trustee["online_outgoing_archive_dir"])

            # process offline messages
            subprocess.call(["python", script_dir, trustee["offline_root_dir"]])
            time.sleep(.5)

            print "Employee is copying responses back to the local server."
            # copy messages to online server public box
            glob_copy(trustee["offline_outgoing_dir"] + '/*.msg', trustee["online_incoming_dir"])
            # move offline messages to offline server archive
            glob_move(trustee["offline_outgoing_dir"] + '/*.msg', trustee["offline_outgoing_archive_dir"])
            time.sleep(.5)

            print "Local server is copying responses back to the central server."
            # upload messages from online server outbox to public server
            for fname in glob.glob(trustee["online_incoming_dir"]+'/*.msg'):
                print "Loading %s" % fname
                contents = open(fname).read()
                try:
                    response = requests.post(server+"send_message/", data={'api_key':trustee_name, 'message':contents})
                    assert response.ok
                except (requests.ConnectionError, AssertionError):
                    print "Unable to reach central server!"
                shutil.move(fname, trustee["online_incoming_archive_dir"])

            time.sleep(1)

def make_key(release_date=None):
    if not release_date:
        release_date = (datetime.utcnow() + timedelta(0,30)).isoformat()

    create_key(release_date)