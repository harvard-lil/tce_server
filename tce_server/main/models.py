import calendar
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import uuid

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.utils.functional import cached_property
from django.utils import dateformat
from pgpdump import AsciiData
from pgpdump.packet import PublicSubkeyPacket
import pgpy

from trustee.utils import int_b64decode
from main.utils import load_gpg, generate_public_elgamal_key, update_private_elgamal_key, apply_certificates
from trustee.multielgamal import MultiElGamal


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
    elgamal_key_id = models.CharField(unique=True, max_length=255, blank=True, null=True)

    state = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.uuid


    def message_trustees(self, message_type, arguments=None):
        this_trustee = Trustee.objects.get(this_server=True)
        for trustee in self.trustees.all():
            message = Message(timestamp=datetime.now(),
                              message_type=message_type,
                              from_trustee=this_trustee,
                              to_trustee=trustee,
                              keypair=self)
            message.set_content(arguments)
            message.save()


    def serialized_release_date(self):
        return self.release_date.isoformat()

    def have_all_messages(self, message_type):
        messages = list(self.messages.filter(message_type=message_type, response_status__in=('success', 'failed')).select_related('to_trustee'))
        all_trustees = list(self.trustees.all())
        if len(messages) != len(all_trustees) or set(message.to_trustee for message in messages) != set(all_trustees):
            # don't have all messages yet
            return None, False

        failures = [m for m in messages if m.response_status == 'failed']
        if failures:
            self.save_errors('public_key_failed', [dict((str(m), m.response)) for m in failures])
            return None, True

        return messages, False

    def save_errors(self, status, details):
        print "Errors!", details
        self.status = status
        self.status_detail += "Errors generating public key:\n" + json.dumps(details, indent=4)
        self.save()

    def send_generate_key_messages(self):
        self.message_trustees('generate_contract_keypair')

    def handle_generate_contract_keypair_response(self):
        if not self.status == 'generating':
            return

        messages, failure = self.have_all_messages('generate_contract_keypair')
        if failure or not messages:
            return

        errors = {}
        contract_public_keys = []
        for message in messages:
            trustee_errors = []
            if message.response_dict.get('uuid') != self.uuid:
                trustee_errors.append("UUID doesn't match.")
            if not message.response_dict.get('contract_public_key'):
                trustee_errors.append("contract_public_key is missing.")

            if trustee_errors:
                errors[str(message.to_trustee)] = trustee_errors
            else:
                contract_public_keys.append(message.response_dict['contract_public_key'])

        if errors:
            self.save_errors('public_key_failed', errors)

        else:
            self.message_trustees('generate_share', {
                'contract_public_keys': contract_public_keys,
                'recovery_threshold': self.recovery_threshold,
            })

    def handle_generate_share_response(self):
        if not self.status == 'generating':
            return

        messages, failure = self.have_all_messages('generate_share')
        if failure or not messages:
            return

        errors = {}
        shares = {}
        for message in messages:
            trustee_errors = []
            if message.response_dict.get('uuid') != self.uuid:
                trustee_errors.append("UUID doesn't match.")

            contract_public_key = self.messages.get(message_type='generate_contract_keypair', to_trustee=message.to_trustee, response_status='success').response_dict['contract_public_key']

            if trustee_errors:
                errors[str(message.to_trustee)] = trustee_errors
            else:
                shares[contract_public_key] = message.response_dict['share']

        if errors:
            self.save_errors('public_key_failed', errors)

        else:
            state = {
                'uuid': self.uuid,
                'contract': self.get_contract(),
                'shares': shares,
            }
            self.state = json.dumps(state)
            mg = MultiElGamal(p=self.p, g=self.g)
            self.y = mg.combine_public_keys(int_b64decode(share['y']) for share in shares.values())
            self.save()
            self.generate_public_key_file()

            self.message_trustees('validate_combined_key', {
                    'state': self.state,
                    'combined_gpg_key': self.public_key_file,
                })

    def handle_validate_combined_key_response(self):
        if not self.status == 'generating':
            return

        messages, failure = self.have_all_messages('validate_combined_key')
        if failure or not messages:
            return

        errors = {}
        certs = []
        for message in messages:
            trustee_errors = []
            if message.response_dict.get('uuid') != self.uuid:
                trustee_errors.append("UUID doesn't match.")

            if trustee_errors:
                errors[str(message.to_trustee)] = trustee_errors
            else:
                certs.append(message.response_dict['certificate'])

        if errors:
            self.save_errors('public_key_failed', errors)

        else:
            self.public_key_file = apply_certificates(self.public_key_file, certs)
            self.status = 'have_public_key'
            self.save()

    def get_contract(self):
        return {
            'release_date': self.serialized_release_date(),
            'recovery_threshold': self.recovery_threshold,
            'share_count': self.trustees.count(),
        }

    def get_gpg_info(self):
        return {
            'uuid': self.uuid,
            'contract': self.get_contract(),
            'state_digest': hashlib.sha256(self.state).hexdigest()
        }

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

    def generate_public_key_file(self):
        if self.public_key_file:
            return

        identity = "Time capsule key for %s (%s)" % (self.release_date_display(), json.dumps(self.get_gpg_info()))
        self.public_key_file, self.temp_private_key_file = generate_public_elgamal_key(self.p, self.g, self.y, identity)

        # get key id
        parsed_key = AsciiData(self.public_key_file)
        elgamal_packet = next(packet for packet in parsed_key.packets() if type(packet)==PublicSubkeyPacket)
        self.elgamal_key_id = elgamal_packet.key_id

        self.save()

    def generate_private_key_file(self):
        if self.status != 'have_private_key':
            return

        self.private_key_file = update_private_elgamal_key(self.temp_private_key_file, self.x)

        self.save()

    def release_date_display(self):
        return dateformat.format(self.release_date, "N j, Y")  # gA")

class Message(models.Model):
    uuid = UUIDField()

    from_trustee = models.ForeignKey(Trustee, blank=True, null=True, related_name='messages_sent')
    to_trustee = models.ForeignKey(Trustee, blank=True, null=True, related_name='messages_received')
    timestamp = models.DateTimeField()
    message_type = models.CharField(max_length=20, choices=((i,i) for i in ('generate_key', 'store_share', 'combine_share', 'confirm_share', 'release_key')))
    keypair = models.ForeignKey(KeyPair, related_name='messages')
    content = models.TextField()

    response_status = models.CharField(default='waiting', max_length=20, choices=((i,i) for i in ('waiting', 'success', 'failed')))
    response = models.TextField(blank=True, null=True)

    signed_message = models.TextField()

    class Meta:
        ordering = ['-timestamp']

    def set_content(self, arguments=None):
        message = {
            'action': self.message_type,
            'uuid': self.keypair.uuid
        }
        if arguments:
            message.update(arguments)
        self.content = json.dumps(message)

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

    def process_message_response(self):
        if self.message_type == 'generate_contract_keypair':
            self.keypair.handle_generate_contract_keypair_response()
        if self.message_type == 'generate_share':
            self.keypair.handle_generate_share_response()
        elif self.message_type == 'validate_combined_key':
            self.keypair.handle_validate_combined_key_response()

    @cached_property
    def content_dict(self):
        return json.loads(self.content)

    @cached_property
    def response_dict(self):
        return json.loads(self.response)