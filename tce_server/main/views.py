from functools import wraps
import json
from pgpdump import AsciiData, BinaryData

from django.contrib.auth.models import User
from django.db import DatabaseError
from django.http import HttpResponseForbidden, HttpResponseBadRequest, HttpResponse, HttpResponseNotAllowed, Http404
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from pgpdump.packet import PublicKeyEncryptedSessionKeyPacket
from pgpdump.utils import PgpdumpException

from .models import Message, KeyPair
from scripts.gpg_utils import load_gpg

### view helpers ###

def get_user_from_api_key(f):
    @wraps(f)
    @csrf_exempt
    def get_user(request, *args, **kwargs):
        api_key = request.POST.get('api_key')
        if not api_key:
            return HttpResponseForbidden("api_key is required")
        try:
            request.user = User.objects.get(profile__api_key=api_key)
        except User.DoesNotExist:
            return HttpResponseForbidden("User not found.")
        return f(request, *args, **kwargs)
    return get_user

_log_function_io_depth = 0
def log_function_io(f):
    """ Decorator to set up conditions for working on remote Django directory (e.g. activate virtualenv if necessary, set DJANGO_SETTINGS_MODULE if necessary) """
    @wraps(f)
    def wrapper(*args, **kwargs):
        global _log_function_io_depth
        def print_tabbed(s):
            print '\n'.join(('\t'*_log_function_io_depth)+part for part in s.split('\n'))
        print_tabbed("Calling %s:\n\targs: %s\n\tkwargs: %s" % (f.__name__, args, kwargs))
        _log_function_io_depth += 1
        try:
            result = f(*args, **kwargs)
            _log_function_io_depth -= 1
            print_tabbed("Return value of %s: >>>%s<<< (%s)" % (f.__name__, result, type(result)))
        except Exception as e:
            _log_function_io_depth -= 1
            print_tabbed("Exception %s raised in %s: %s" % (type(e), f.__name__, e))
            raise
        return result
    return wrapper

def deliver_file(data, content_type, delivery_name):
    response = HttpResponse(data, content_type=content_type)
    response['Content-Disposition'] = 'attachment; filename="%s"' % delivery_name
    return response


### trustee message passing views ###

@get_user_from_api_key
def get_messages(request):
    trustee = request.user.profile.trustee
    if not trustee:
        return HttpResponseForbidden()

    after_id = request.POST.get('after_id', 0)
    try:
        after_id = int(after_id)
    except ValueError:
        return HttpResponseBadRequest("Can't parse after_id.")

    messages = trustee.messages_received.filter(id__gt=after_id)
    out = json.dumps([(message.id, message.signed_message) for message in messages])
    return HttpResponse(out, content_type="application/json")


@get_user_from_api_key
def send_message(request):
    trustee = request.user.profile.trustee
    if not trustee:
        return HttpResponseForbidden()

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    if not request.POST.get("message"):
        return HttpResponseBadRequest("message is required")

    with load_gpg([trustee.key]) as gpg:
        verified_message = gpg.decrypt(request.POST["message"])

    if verified_message.fingerprint != trustee.fingerprint:
        return HttpResponseForbidden("Fingerprint does not match.")

    json_data = verified_message.data[:-1]  # strip extra \n that gpg adds

    try:
        json_dict = json.loads(json_data)
    except ValueError:
        return HttpResponseBadRequest("Can't parse message JSON.")

    if json_dict.get("from") != trustee.fingerprint:
        return HttpResponseBadRequest("Message 'from' does not match signature.")

    try:
        message = Message.from_json_dict(json_dict)
    except ValueError as e:
        return HttpResponseBadRequest(e.args[0])

    message.signed_message = request.POST["message"]

    try:
        message.save()
    except DatabaseError as e:
        return HttpResponseBadRequest(e.args[0])

    message.process_message()

    return HttpResponse("OK")


### keypair download views ###

def public_key_file(request, key_id):
    keypair = get_object_or_404(KeyPair, id=key_id)
    if not keypair.public_key_file:
        raise Http404
    return deliver_file(keypair.public_key_file, 'application/pgp-keys', "Time capsule public key for %s.asc" % keypair.release_date_display())


def private_key_file(request, key_id):
    keypair = get_object_or_404(KeyPair, id=key_id)
    if not keypair.private_key_file:
        raise Http404
    return deliver_file(keypair.private_key_file, 'application/pgp-keys', "Time capsule private key for %s.asc" % keypair.release_date_display())


### server-side encrypt/decrypt views ###

def encrypt(request, key_id):

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    keypair = get_object_or_404(KeyPair, id=key_id)
    if not keypair.public_key_file:
        return HttpResponseBadRequest("Can't encrypt -- no public key available.")

    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return HttpResponseBadRequest("Please supply a file upload.")

    with load_gpg([keypair.public_key_file]) as gpg:
        output = gpg.encrypt(uploaded_file.read(), gpg.list_keys().fingerprints[0])

    return deliver_file(output, 'application/pgp-encrypted', uploaded_file.name+'.gpg')

def decrypt(request):

    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return HttpResponseBadRequest("Please supply a file upload.")

    # parse file for key id
    file_contents = uploaded_file.read()
    try:
        parsed_file = AsciiData(file_contents)
    except PgpdumpException:
        try:
            parsed_file = BinaryData(file_contents)
        except PgpdumpException:
            return HttpResponseBadRequest("Can't parse PGP file.")
    public_key_packet = next(packet for packet in parsed_file.packets() if type(packet)==PublicKeyEncryptedSessionKeyPacket)
    elgamal_key_id = public_key_packet.key_id

    # get key
    try:
        keypair = KeyPair.objects.get(elgamal_key_id=elgamal_key_id)
    except KeyPair.DoesNotExist:
        return HttpResponseBadRequest("No key was found matching this file.")
    if not keypair.private_key_file:
        return HttpResponseBadRequest("We do not yet have a private key to decrypt this file (release date %s)." % keypair.release_date_display())

    # decrypt
    with load_gpg([keypair.private_key_file]) as gpg:
        output = gpg.decrypt(file_contents, always_trust=True)

    if not output.ok:
        return HttpResponseBadRequest("Unable to decrypt file.")

    # deliver
    if output.data_filename:
        output_name = output.data_filename
    else:
        output_name = uploaded_file.name
        if output_name.endswith('.gpg'):
            output_name = output_name[:-4]
    return deliver_file(output.data, 'application/octet-stream', output_name)


### home ###

def index(request):
    public_keys = KeyPair.objects.filter(status='have_public_key').exclude(public_key_file='').order_by('-release_date')
    private_keys = KeyPair.objects.filter(status='have_private_key').exclude(private_key_file='').order_by('-release_date')
    return render(request, 'index.html', {'public_keys':public_keys, 'private_keys':private_keys})