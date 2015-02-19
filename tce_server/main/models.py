import calendar
from collections import defaultdict
from datetime import datetime
import json
import subprocess
import tempfile
import uuid
import itertools

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.utils.functional import cached_property
from django.utils import dateformat

from scripts.gpg_utils import load_gpg
from scripts.multielgamal import MultiElGamal


### custom model fields ###

class BigIntField(models.TextField):
    __metaclass__ = models.SubfieldBase

    def to_python(self, value):
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def get_prep_value(self, value):
        if value is None:
            return None
        return str(int(value))  # will raise ValueError if not a valid int

class UUIDField(models.CharField):

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 36)
        kwargs.setdefault('unique', True)
        super(UUIDField, self).__init__(*args, **kwargs)

    def pre_save(self, model_instance, add):
        if add and not getattr(model_instance, self.attname):
            new_uuid = str(uuid.uuid4())
            setattr(model_instance, self.attname, new_uuid)
            return new_uuid
        else:
            return super(UUIDField, self).pre_save(model_instance, add)


### models ###

class UserProfile(models.Model):
    user = models.OneToOneField(User, related_name='profile')
    trustee = models.ForeignKey('Trustee', related_name='user_profiles', blank=True, null=True)
    api_key = models.CharField(max_length=255, blank=True, null=True, unique=True)

    def __unicode__(self):
        return unicode(self.user)

def create_user_profile(sender, instance, created, **kwargs):
    if created:
        profile, created = UserProfile.objects.get_or_create(user=instance)
post_save.connect(create_user_profile, sender=User)


class Trustee(models.Model):
    nickname = models.CharField(max_length=255)
    this_server = models.BooleanField(default=False)
    key = models.TextField()
    fingerprint = models.CharField(max_length=255)

    def __unicode__(self):
        return self.nickname

class KeyPair(models.Model):
    uuid = UUIDField()
    status = models.CharField(max_length=20, default='generating', choices=((i,i) for i in ('generating', 'public_key_failed', 'have_public_key', 'have_private_key')))
    status_detail = models.TextField(blank=True)
    created_date = models.DateTimeField(auto_now_add=True)

    trustees = models.ManyToManyField(Trustee)
    recovery_threshold = models.SmallIntegerField(default=settings.RECOVERY_THRESHOLD)
    release_date = models.DateTimeField()
    p = BigIntField(default=settings.P_VALUE)
    g = BigIntField(default=settings.G_VALUE)
    x = BigIntField(blank=True, null=True)
    y = BigIntField(blank=True, null=True)

    public_key_file = models.TextField(blank=True)
    temp_private_key_file = models.TextField(blank=True)
    private_key_file = models.TextField(blank=True)

    def __unicode__(self):
        return self.uuid

    def send_generate_key_messages(self):
        this_trustee = Trustee.objects.get(this_server=True)
        for trustee in self.trustees.exclude(this_server=True):
            message = Message(timestamp=datetime.now(),
                              message_type='generate_key',
                              from_trustee=this_trustee,
                              to_trustee=trustee,
                              keypair=self)
            message.encrypt_content(trustee, {'release_date':calendar.timegm(self.release_date.utctimetuple())})
            message.sign_message()
            message.save()

    def check_confirmations(self):
        if not(self.status == 'generating' or self.status == 'public_key_failed'):
            return

        # check if we have enough confirmations yet
        trustee_count = self.trustees.count()
        expected_share_count = trustee_count*(trustee_count-1)  # each trustee should have a confirmed share for each other trustee
        confirmation_messages = list(self.messages.filter(message_type='confirm_share'))
        if len(confirmation_messages) < expected_share_count:
            return

        errors = defaultdict(list)

        # check if we have all the public key shares
        shares_by_trustee = dict((m.from_trustee, m) for m in self.messages.filter(message_type='public_key'))
        if set(shares_by_trustee.keys()) != set(self.trustees.all()):
            errors['shares'].append("Failed to receive one share from each trustee.")

        # parse the confirmation messages
        confirmations = []
        for message in confirmation_messages:
            confirmations.append({
                'confirming_server': message.from_trustee,
                'confirmed_server': Trustee.objects.get(fingerprint=message.content_dict['server_id']),
                'y_share': message.content_dict['y_share'],
                'share_input': message.content_dict['share_input'],
                'is_valid': message.content_dict['is_valid'],
                'message_hash': message.content_dict['message_hash']})

        # check confirmations grouped by confirmed server
        confirmations.sort(key=lambda c: c['confirmed_server'].pk)
        grouped_confirmations = itertools.groupby(confirmations, lambda c: c['confirmed_server'].pk)  # must be sorted first
        for confirmed_server_id, confirmations in grouped_confirmations:
            confirmations = list(confirmations)
            confirmed_server = confirmations[0]['confirmed_server']
            if len(confirmations) != trustee_count-1:
                errors[confirmed_server.fingerprint].append("Wrong number of confirmations received.")

            if len(set(c['message_hash'] for c in confirmations)) != 1:
                errors[confirmed_server.fingerprint].append("Message hashes do not match.")

            if set(c['share_input'] for c in confirmations) != set(range(1, len(confirmations)+1)):
                errors[confirmed_server.fingerprint].append("Wrong set of share inputs.")

            for c in confirmations:
                if not c['is_valid']:
                    errors[confirmed_server.fingerprint].append("Server %s reports share is invalid." % c['confirming_server'].fingerprint)
                public_share = shares_by_trustee[confirmed_server]
                if public_share:  # to allow a complete error report, we only check this one if we don't already have an error about missing shares
                    if c['y_share'] != public_share.content_dict['y_share']:
                        errors[confirmed_server.fingerprint].append("Server %s reports y share doesn't match." % c['confirming_server'].fingerprint)

        if errors:
            self.status = 'public_key_failed'
            self.status_detail += "Errors generating public key:\n"+json.dumps(errors, indent=4)

        else:
            self.status = 'have_public_key'
            mg = MultiElGamal(p=self.p, g=self.g)
            self.y = mg.combine_public_keys(s.content_dict['y_share'] for s in shares_by_trustee.values())

        self.save()

        self.generate_key_files()

    def check_releases(self):
        if self.status == 'have_private_key':
            return

        # check if we have enough confirmations yet
        release_messages = list(self.messages.filter(message_type='release_key'))
        if len(release_messages) < self.recovery_threshold:
            return

        x_values = {}
        recovery_values = defaultdict(list)

        for message in release_messages:
            x_values[message.from_trustee.fingerprint] = message.content_dict['x_share']
            for recovery_share in message.content_dict['recovery_shares']:
                recovery_values[recovery_share['server_id']] += [(recovery_share['input'], recovery_share['output'])]

        shares = [(x_values.get(id), recovery_values[id]) for id in set(x_values.keys() + recovery_values.keys())]

        mg = MultiElGamal(p=self.p, g=self.g)
        try:
            self.x = mg.recover_private_key(self.y, shares, self.recovery_threshold)
            self.status = 'have_private_key'

        except ValueError as e:
            self.status = 'private_key_failed'
            self.status_detail += 'Private key generation failed:\n%s' % e

        self.save()

        self.generate_private_key_file()

    def generate_key_files(self):
        if self.status != 'have_public_key':
            return

        hex_out = lambda x: hex(x)[2:].rstrip('L')  # Convert int to hex, stripping extra. E.g.:  10 -> '0xaL' -> 'a'

        public_key_file = tempfile.NamedTemporaryFile(delete=False)
        public_key_file.close()
        private_key_file = tempfile.NamedTemporaryFile(delete=False)
        private_key_file.close()
        
        subprocess.check_call(['java', '-jar', settings.CREATE_KEY_FILE_JAR, 'create', hex_out(self.p), hex_out(self.g), hex_out(self.y), private_key_file.name, public_key_file.name, "Time capsule key for %s" % self.release_date_display()])

        self.public_key_file = open(public_key_file.name).read()
        self.temp_private_key_file = open(private_key_file.name).read()

        public_key_file.unlink(public_key_file.name)
        private_key_file.unlink(private_key_file.name)

        self.save()

    def generate_private_key_file(self):
        if self.status != 'have_private_key':
            return

        hex_out = lambda x: hex(x)[2:].rstrip('L')  # Convert int to hex, stripping extra. E.g.:  10 -> '0xaL' -> 'a'

        old_private_key_file = tempfile.NamedTemporaryFile(delete=False)
        old_private_key_file.write(self.temp_private_key_file)
        old_private_key_file.close()
        new_private_key_file = tempfile.NamedTemporaryFile(delete=False)
        new_private_key_file.close()

        subprocess.check_call(['java', '-jar', settings.CREATE_KEY_FILE_JAR,
                               'add',
                               old_private_key_file.name,
                               hex_out(self.x),
                               new_private_key_file.name])

        self.private_key_file = open(new_private_key_file.name).read()

        old_private_key_file.unlink(old_private_key_file.name)
        new_private_key_file.unlink(new_private_key_file.name)

        self.save()

    def release_date_display(self):
        return dateformat.format(self.release_date, "N j, Y gA")

class Message(models.Model):
    uuid = UUIDField()

    from_trustee = models.ForeignKey(Trustee, blank=True, null=True, related_name='messages_sent')
    to_trustee = models.ForeignKey(Trustee, blank=True, null=True, related_name='messages_received')
    timestamp = models.DateTimeField()
    message_type = models.CharField(max_length=20, choices=((i,i) for i in ('generate_key', 'public_key', 'store_share', 'confirm_share', 'release_key')))
    keypair = models.ForeignKey(KeyPair, related_name='messages')
    content = models.TextField()

    signed_message = models.TextField()

    class Meta:
        ordering = ['-timestamp']

    def sign_message(self):
        this_trustee = Trustee.objects.get(this_server=True)
        assert self.from_trustee == this_trustee
        json_message = json.dumps(self.as_json_dict())
        with load_gpg([this_trustee.key]) as gpg:
            self.signed_message = gpg.sign(json_message, default_key=this_trustee.fingerprint)

    def encrypt_content(self, recipient, content):
        json_content = json.dumps(content)
        with load_gpg([recipient.key]) as gpg:
            self.content = gpg.encrypt(json_content, recipient.fingerprint).data

    def as_json_dict(self):
        return {
            "uuid": self.uuid,
            "from": self.from_trustee.fingerprint,
            "to": self.to_trustee.fingerprint or 'public',
            "timestamp": calendar.timegm(self.timestamp.utctimetuple()),
            "message_type": self.message_type,
            "key_id": self.keypair.uuid,
            "content": self.content,
        }

    @classmethod
    def from_json_dict(cls, json_dict):
        expected_keys = ['uuid', 'from', 'to', 'timestamp', 'message_type', 'key_id', 'content']
        if set(json_dict.keys()) != set(expected_keys):
            raise ValueError("Unexpected or missing keys.")

        for expected_key in expected_keys:
            if not json_dict.get(expected_key):
                raise ValueError("Key cannot be blank: %s" % expected_key)

        try:
            fingerprint = json_dict.pop("from")
            json_dict["from_trustee"] = Trustee.objects.get(fingerprint=fingerprint)
        except Trustee.DoesNotExist:
            raise ValueError("Trustee with fingerprint %s not found." % fingerprint)

        try:
            fingerprint = json_dict.pop("to")
            if fingerprint != 'public':
                json_dict["to_trustee"] = Trustee.objects.get(fingerprint=fingerprint)
        except Trustee.DoesNotExist:
            raise ValueError("Trustee with fingerprint %s not found." % fingerprint)

        try:
            json_dict["timestamp"] = datetime.fromtimestamp(json_dict["timestamp"])
        except ValueError:
            raise ValueError("Can't parse timestamp.")

        try:
            key_uuid = json_dict.pop('key_id')
            json_dict['keypair'] = KeyPair.objects.get(uuid=key_uuid)
        except KeyPair.DoesNotExist:
            raise ValueError("KeyPair with uuid %s not found." % key_uuid)

        return Message(**json_dict)

    def process_message(self):
        if self.message_type == 'confirm_share':
            self.keypair.check_confirmations()
        elif self.message_type == 'release_key':
            self.keypair.check_releases()

    @cached_property
    def content_dict(self):
        """
            Try to parse message content as JSON, decrypting first if necessary.
        """
        if self.to_trustee:
            if self.to_trustee.this_server:
                with load_gpg([self.to_trustee.key]) as gpg:
                    decrypted_content = gpg.decrypt(self.content)
                if not decrypted_content.ok:
                    raise ValueError("Couldn't decrypt message content: %s." % decrypted_content.stderr)
                content = decrypted_content.data
            else:
                raise ValueError("Content is encrypted for another server.")
        else:
            content = self.content
        return json.loads(content)
