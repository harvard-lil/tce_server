from __future__ import print_function

import calendar
import hashlib
import json
import os
from random import SystemRandom
import argparse
from datetime import datetime
import uuid
from lockfile import LockFile
import logging
import peewee

from multielgamal import MultiElGamal
from gpg_utils import init_gpg, destroy_gpg


### global vars ###

random_source = SystemRandom()
db = peewee.SqliteDatabase(None, threadlocals=True, timeout=30000)
settings = other_servers = gpg = logger = None
message_handlers = {}


### helpers ###

def get_timestamp():
    return calendar.timegm(datetime.utcnow().utctimetuple())

def message_handler(f):
    message_handlers[f.__name__] = f
    return f

def package_message(message_type, to_server, key_id, content, timestamp=None):
    timestamp = timestamp or get_timestamp()

    content = json.dumps(content)
    if to_server != 'public':
        content = gpg.encrypt(content, to_server).data

    signed_message = gpg.sign(json.dumps({
        'uuid': str(uuid.uuid4()),
        'message_type': message_type,
        'from': settings['gpg_fingerprint'],
        'to': to_server,
        'timestamp': timestamp,
        'key_id': key_id,
        'content': content,
    }), default_key=settings['gpg_fingerprint']).data
    return (timestamp, signed_message)

def message_other_servers(message_type, key_id, group_package, individual_packages={}):
    messages = []
    for server in other_servers:
        message_content = dict(group_package, **individual_packages.get(server['gpg_fingerprint'], {}))
        messages.append(package_message(message_type, server['gpg_fingerprint'], key_id, message_content))
    return messages


### models ###

class BignumField(peewee.CharField):
    def db_value(self, value):
        return str(value) if value else None

    def python_value(self, value):
        return int(value) if value else None

class BaseModel(peewee.Model):
    class Meta:
        database = db

class Keypair(BaseModel):
    key_id = peewee.CharField()
    status = peewee.CharField()

    x_share = BignumField()
    y_share = BignumField()
    g = BignumField()
    p = BignumField()

    release_date = peewee.IntegerField()

class Share(BaseModel):
    keypair = peewee.ForeignKeyField(Keypair, related_name='shares')
    server_id = peewee.CharField()

    group_message_hash = peewee.CharField()
    group_message = peewee.TextField()  # json

    share_input = peewee.IntegerField()
    share_output = BignumField()


### views ###

message_types = {
    "generate_key":{
        "order": 1,
        "keys": ["release_date"],
    },
    "store_share": {
        "order": 2,
        "keys": ["group_message", "share_input", "share_output"],
    },
}

def handle_messages():
    valid_messages = []
    response_messages = []

    for message_file in os.listdir(settings["incoming_message_dir"]):
        if message_file.endswith('.msg'):

            try:
                signed_message = open(os.path.join(settings["incoming_message_dir"], message_file)).read()
            except IOError as e:
                logger.error("Can't open message file: %s", e)
                continue

            logger.debug("Reading message %s." % message_file)

            verified_message = gpg.decrypt(signed_message)

            if not verified_message.data:
                logger.error("No data read from signed message.")
                continue

            json_data = verified_message.data[:-1]  # strip extra \n that gpg adds

            try:
                message = json.loads(json_data)
            except ValueError:
                logger.error("Can't parse message data.")
                continue

            if not type(message) == dict:
                logger.error("Message is not a dict.")
                continue

            message_key_set = set(message.keys())
            expected_key_set = {'uuid', 'from', 'to', 'message_type', 'content', 'timestamp', 'key_id'}
            if message_key_set - expected_key_set:
                logger.error("Unrecognized message keys: %s." % (message_key_set - expected_key_set))
                continue
            if expected_key_set - message_key_set:
                logger.error("Missing expected message keys: %s." % (expected_key_set - message_key_set))
                continue

            if verified_message.fingerprint != message.get("from"):
                logger.error("Fingerprint does not match 'from' address.")
                continue

            if settings["gpg_fingerprint"] != message.get("to"):
                logger.error("Fingerprint does not match 'to' address.")
                continue

            message_type = message.get("message_type")
            if message_type not in message_types:
                logger.error("Unrecognized message type '%s'." % message_type)
                continue

            decrypted_content = gpg.decrypt(message["content"])

            if not decrypted_content.ok:
                logger.error("Couldn't decrypt message content: %s." % decrypted_content.stderr)
                continue

            try:
                message["content"] = json.loads(decrypted_content.data)
            except Exception as e:
                logger.error("Can't parse message content: %s", e)
                continue

            if set(message["content"].keys()) != set(message_types[message_type]['keys']):
                logger.error("Unrecognized or missing message content keys.")
                continue

            valid_messages.append(message)

    if valid_messages:
        # sort messages by type
        valid_messages.sort(key=lambda message: message_types[message["message_type"]]["order"])

        for message in valid_messages:
            logger.debug("Handling %s for key %s." % (message['message_type'], message['key_id']))
            response = message_handlers[message["message_type"]](message, **message["content"])
            if response:
                response_messages += response

    response_messages += check_for_releasable_keys()

    # write out messages
    for timestamp, message in response_messages:
        counter = 0
        while True:
            fpath = os.path.join(settings["outgoing_message_dir"], "%s-%s.msg" % (timestamp, counter))
            if os.path.exists(fpath):
                counter += 1
            else:
                open(fpath, 'w').write(message)
                break

    # move processed files
    for message_file in os.listdir(settings["incoming_message_dir"]):
        if message_file.endswith('.msg'):
            os.rename(os.path.join(settings["incoming_message_dir"], message_file), os.path.join(settings["processed_message_dir"], message_file))


@message_handler
def generate_key(message, release_date=None):

    key_id = message["key_id"]
    logger.debug("Generating %s", key_id)

    # TODO: Validate inputs
    release_date = int(release_date)

    if Keypair.select().where(Keypair.key_id == key_id).count():
        # key already initialized!
        logger.error("Key_id %s already created." % key_id)
        return

    # generate our portion of the ElGamal private and public keys
    mg = MultiElGamal(p=settings['p_value'], g=settings['g_value'])
    x, y = mg.generate_private_key()

    Keypair.create(
        key_id = key_id,
        status = "public_key_released",

        x_share = x,
        y_share = y,
        g = mg.g,
        p = mg.p,

        release_date = release_date
    )

    logger.debug("Created keypair.")

    # send recovery shares and commitments to the other trustees
    shares, commitments = mg.generate_shares(x, share_count=len(other_servers), recovery_threshold=settings["recovery_count"])

    # we prepare three layers of messages here --
    # the individual messages with private shares for each other trustee,
    # the group message with commitments that goes to all trustees,
    # and the public message that goes to the control server

    # public message
    public_message = {
        'p': mg.p,
        'g': mg.g,
        'y_share': y
    }

    # individual messages
    individual_messages = {}
    share_recipients = {}
    for recipient, share in zip(other_servers, shares):
        individual_messages[recipient['gpg_fingerprint']] = {
            'share_input': share[0],
            'share_output': share[1]
        }
        share_recipients[recipient['gpg_fingerprint']] = share[0]

    # group message
    # double-encode the group_message as a JSON string, so servers can compare the hash to confirm they're looking at the same message
    group_message_mixin = {
        'group_message':json.dumps(dict(public_message, **{
            'share_recipients': share_recipients,
            'commitments': commitments,
        })),
    }

    messages = message_other_servers('store_share', key_id, group_message_mixin, individual_messages)
    messages.append(package_message('public_key', 'public', key_id, public_message))
    return messages


@message_handler
def store_share(message, group_message=None, share_input=None, share_output=None):
    key_id = message["key_id"]
    server_id = message["from"]

    logger.debug("Storing share from %s", server_id)

    # TODO: Validate inputs

    try:
        keypair = Keypair.get(Keypair.key_id == key_id)
    except peewee.DoesNotExist:
        logger.error("Unrecognized keypair: %s." % (key_id))
        return

    if Share.select().where(Share.keypair == keypair, Share.server_id == server_id).count():
        logger.error("Share already received for server %s." % server_id)
        return

    group_message_hash = hashlib.sha256(group_message).hexdigest()
    group_message = json.loads(group_message)

    # confirm that we received the share they claimed in the public message
    if group_message['share_recipients'][settings['gpg_fingerprint']] != share_input:
        valid_share = False

    else:
        # confirm that our share matches the public commitments
        mg = MultiElGamal(p=keypair.p, g=keypair.g)
        valid_share = mg.confirm_share(share_input, share_output, group_message['commitments'])

    logger.debug("Share from %s is %svalid." % (server_id, "" if valid_share else "NOT "))

    # store share
    Share.create(
        keypair=keypair,
        server_id=server_id,

        group_message_hash=group_message_hash,
        group_message=group_message,

        share_input=share_input,
        share_output=share_output,
    )

    return [package_message('confirm_share', 'public', key_id, {
        'server_id':server_id,
        'y_share': group_message['y_share'],
        'share_input':share_input,
        'is_valid':valid_share,
        'message_hash':group_message_hash})]


def check_for_releasable_keys():
    messages = []

    for keypair in Keypair.select().where(Keypair.release_date < get_timestamp(), Keypair.status == 'public_key_released'):
        keypair.status = 'private_key_released'

        recovery_shares = []
        for share in keypair.shares:
            recovery_shares.append({'server_id': share.server_id, 'input':share.share_input, 'output':share.share_output})

        messages.append(package_message('release_key', 'public', keypair.key_id, {
            'x_share': keypair.x_share,
            'recovery_shares': recovery_shares,
        }))

        keypair.save()

    return messages


### controller ###

def main():
    global servers, settings, other_servers, gpg, logger, db

    # command line args
    parser = argparse.ArgumentParser()
    parser.add_argument("server_dir", help="Path to server data.")
    args = parser.parse_args()

    settings = json.load(open(os.path.join(args.server_dir, "settings.json")))
    settings["incoming_message_dir"] = os.path.join(args.server_dir, "incoming_messages")
    settings["outgoing_message_dir"] = os.path.join(args.server_dir, "outgoing_messages")
    settings["processed_message_dir"] = os.path.join(args.server_dir, "incoming_messages/archive")
    other_servers = settings["other_servers"]

    # logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('Server '+(args.server_dir.rsplit('/')[-1])+': %(levelname)s: %(message)s'))
    logger.addHandler(handler)

    # database
    db.init(os.path.join(args.server_dir, 'sqldata.db'))
    db.create_tables([Keypair, Share], safe=True)

    # load GPG keys
    gpg = init_gpg([settings["gpg_key"]]+[settings["control_server"]["gpg_key"]]+[server["gpg_key"] for server in other_servers])

    with LockFile(args.server_dir):
        try:
            handle_messages()
        finally:
            destroy_gpg(gpg)

main()