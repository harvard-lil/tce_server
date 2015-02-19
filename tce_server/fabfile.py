from datetime import datetime, timedelta
import glob
import json
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


def run_trustee(id):
    # helpers

    def glob_copy(src, dst):
        for fname in glob.glob(src):
            shutil.copy(fname, dst)

    def glob_move(src, dst):
        for fname in glob.glob(src):
            shutil.move(fname, dst)

    # var setup

    server = "http://127.0.0.1:8000/"

    offline_root_dir = os.path.join(os.path.dirname(settings.BASE_DIR), "test/offline_servers", id)
    offline_outgoing_dir = os.path.join(offline_root_dir, "outgoing_messages")
    offline_outgoing_archive_dir = os.path.join(offline_outgoing_dir, "archive")
    offline_incoming_dir = os.path.join(offline_root_dir, "incoming_messages")

    online_root_dir = os.path.join(os.path.dirname(settings.BASE_DIR), "test/online_servers", id)
    online_outgoing_dir = os.path.join(online_root_dir, 'messages_for_offline_server')
    online_outgoing_archive_dir = os.path.join(online_outgoing_dir, 'archive')
    online_incoming_dir = os.path.join(online_root_dir, 'messages_for_public_server')
    online_incoming_archive_dir = os.path.join(online_incoming_dir, 'archive')

    script_dir = os.path.join(settings.BASE_DIR, "scripts/offline_processor.py")

    while True:
        ## simulate online server script ##

        # download new messages to online server inbox
        known_messages = [fname for fname in list(os.listdir(online_outgoing_dir))+list(os.listdir(online_outgoing_archive_dir)) if fname.endswith('.msg')]
        highest_message_id = max(int(fname.split('.msg')[0]) for fname in known_messages) if known_messages else 0
        data = requests.post(server+"get_messages/", data={'api_key':id, 'after_id':str(highest_message_id)}).content
        if data != "[]":
            for message_id, message in json.loads(data):
                open(os.path.join(online_outgoing_dir, "%s.msg" % message_id), 'w').write(message)

        # upload messages from online server outbox to public server
        for fname in glob.glob(online_incoming_dir+'/*.msg'):
            print "Loading %s" % fname
            contents = open(fname).read()
            result = requests.post(server+"send_message/", data={'api_key':id, 'message':contents})
            if result.status_code != 200:
                print "Unexpected result %s: %s" % (result.status_code, result.content)
            shutil.move(fname, online_incoming_archive_dir)

        ## simulate trustee user ##

        # copy messages to offline server inbox
        glob_copy(online_outgoing_dir+'/*.msg', offline_incoming_dir)
        # move online messages to online server archive
        glob_move(online_outgoing_dir+'/*.msg', online_outgoing_archive_dir)
        # process offline messages
        local("python '%s' '%s'" % (script_dir, offline_root_dir))
        # copy messages to online server public box
        glob_copy(offline_outgoing_dir + '/*.msg', online_incoming_dir)
        # move offline messages to offline server archive
        glob_move(offline_outgoing_dir + '/*.msg', offline_outgoing_archive_dir)

        time.sleep(1)

def make_key(release_date=None):
    if not release_date:
        release_date = (datetime.utcnow() + timedelta(0,30)).isoformat()

    create_key(release_date)