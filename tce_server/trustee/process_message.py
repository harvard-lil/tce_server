# stdlib imports
from __future__ import print_function
from base64 import b64encode, b64decode
import hashlib
import json
import os
import sys

# 3rd party imports
import jsonschema
from lockfile import LockFile
import libnacl.sign, libnacl.public
import pgpy
from pgpy.constants import SignatureType

# local imports
from .multielgamal import MultiElGamal
from . import message_schemas


### helpers ###

class ProcessingError(Exception): pass

def load_key_from_disk(key_path):
    """
        Load a stored keypair, returning the secret key object and the base-64 public key we use for ID.
    """
    try:
        our_secret_key = libnacl.public.SecretKey(b64decode(open(key_path, 'rb').read()))
    except IOError:
        raise ProcessingError("Contract key for UUID not found.")
    except ValueError:
        raise ProcessingError("Unable to load contract key.")
    our_public_key_b64 = b64encode(our_secret_key.pk)
    return our_secret_key, our_public_key_b64

def get_valid_json(json_message, schema):
    # parse json
    try:
        message = json.loads(json_message)
    except ValueError:
        raise ProcessingError("Can't parse json.")

    # validate json
    try:
        jsonschema.validate(message, schema)
    except jsonschema.ValidationError as e:
        print(e)
        raise ProcessingError("Can't validate json: %s." % e.message)

    return message

def int_b64encode(i):
    b = bytearray()
    while i:
        b.append(i & 0xFF)
        i >>= 8
    return b64encode(bytes(b))

def int_b64decode(s):
    b = bytearray(b64decode(s))
    return sum((1 << (bi * 8)) * bb for (bi, bb) in enumerate(b))

### message processing ###

def process_message(message, settings):

    with LockFile(settings["contract_private_key_dir"]):
        # validate message json
        try:
            jsonschema.validate(message, message_schemas.message_schema)
        except jsonschema.ValidationError as e:
            raise ProcessingError("Can't validate json: %s." % e.message)

        # handle message
        uuid = message['uuid']
        key_path = os.path.join(settings["contract_private_key_dir"], uuid)
        mg = MultiElGamal(p=settings['p'], g=settings['g'])

        if message['action'] == 'generate_contract_keypair':
            # Round One: generate contract key
            if os.path.exists(key_path):
                raise ProcessingError("UUID is already taken.")
            contract_secret_key = libnacl.public.SecretKey()
            open(key_path, 'wb').write(b64encode(contract_secret_key.sk))
            out_message = {
                'uuid': uuid,
                'contract_public_key': b64encode(contract_secret_key.pk)
            }

        elif message['action'] == 'generate_share':
            # Round Two: generate our portion of the ElGamal private and public keys

            # load contract key
            our_secret_key, our_public_key_b64 = load_key_from_disk(key_path)

            # validate message
            if our_public_key_b64 not in message['contract_public_keys']:
                raise ProcessingError("Our contract key is missing from contract_keys.")
            other_public_keys = [libnacl.public.PublicKey(b64decode(k)) for k in message['contract_public_keys'] if k != our_public_key_b64]

            # generate ElGamal key, subshares and commitments
            x = mg.generate_private_key()
            y = mg.generate_public_key(x)
            subshares, commitments, _ = mg.generate_shares(x, share_count=len(other_public_keys),
                                                        recovery_threshold=message["recovery_threshold"])
            encrypted_subshares = [b64encode(libnacl.public.Box(our_secret_key.sk, other_public_key.pk).encrypt(int_b64encode(subshare))) for other_public_key, subshare in zip(other_public_keys, subshares)]

            # construct share
            out_message = {
                'uuid': uuid,
                'share': {
                    'contract_public_key': our_public_key_b64,
                    'x': b64encode(libnacl.public.Box(our_secret_key.sk, our_secret_key.pk).encrypt(int_b64encode(x))),
                    'y': int_b64encode(y),
                    'commitments': [int_b64encode(c) for c in commitments],
                    'subshares': encrypted_subshares,
                }
            }

        elif message['action'] == 'validate_combined_key':
            # Round Three: given a complete state and a generated GPG key, verify and sign the GPG key

            # load contract key
            our_secret_key, our_public_key_b64 = load_key_from_disk(key_path)

            # parse and validate state json
            state = get_valid_json(message['state'], message_schemas.state_schema)
            if state['contract']['share_count'] != len(state['shares']):
                raise ProcessingError("Wrong number of shares.")
            if state['uuid'] != uuid:
                raise ProcessingError("UUID doesn't match.")
            # TODO: validate date

            # verify that each share contains either a valid x value or a valid subshare
            mg = MultiElGamal(p=settings['p'], g=settings['g'])
            y_shares = []
            our_share_count = 0
            for share in state['shares']:
                y = int_b64decode(share['y'])
                y_shares.append(y)
                if share['contract_public_key'] == our_public_key_b64:
                    x = int_b64decode(libnacl.public.Box(our_secret_key.sk, b64decode(share['contract_public_key'])).decrypt(b64decode(share['x'])))
                    if y != mg.generate_public_key(x):
                        raise ProcessingError("Invalid x value.")
                    our_share_count += 1
                else:
                    if len(share['commitments']) != state['contract']['recovery_threshold']-1:
                        raise ProcessingError("Invalid number of commitments.")
                    for i, subshare in enumerate(share['subshares']):
                        try:
                            decrypted_subshare = int_b64decode(libnacl.public.Box(our_secret_key.sk, b64decode(share['contract_public_key'])).decrypt(b64decode(subshare)))
                        except ValueError:
                            continue
                        commitments = [int_b64decode(c) for c in share['commitments']]
                        if not mg.confirm_share(i+1, decrypted_subshare, [y]+commitments):
                            raise ProcessingError("Invalid subshare.")
                        break
                    else:
                        raise ProcessingError("No subshare found with our key.")
            if our_share_count != 1:
                raise ProcessingError("Wrong number of shares generated by us.")

            # parse GPG key
            combined_key, _ = pgpy.PGPKey.from_blob(message['combined_gpg_key'])

            # parse and validate gpg json
            if len(combined_key.userids) != 1:
                raise ProcessingError("GPG key must have one user ID.")
            gpg_user_id = combined_key.userids[0]
            gpg_contract = get_valid_json(gpg_user_id.comment, message_schemas.gpg_schema)
            if gpg_contract['state_digest'] != hashlib.sha256(message['state']).hexdigest():
                raise ProcessingError("GPG digest doesn't match.")
            if gpg_contract['contract'] != state['contract']:
                raise ProcessingError("Contract doesn't match.")
            if gpg_contract['uuid'] != state['uuid']:
                raise ProcessingError("UUID doesn't match.")

            # validate elgamal key
            if len(combined_key.subkeys) != 1:
                raise ProcessingError("GPG key must have one encryption key.")
            elgamal_subkey = combined_key.subkeys[combined_key.subkeys.keys()[0]]
            elgamal_keymaterial = elgamal_subkey._key.keymaterial
            if elgamal_subkey.key_algorithm.name != 'ElGamal':
                raise ProcessingError("Invalid key algorithm.")
            if elgamal_keymaterial.p != mg.p:
                raise ProcessingError("Invalid prime.")
            if elgamal_keymaterial.g != mg.g:
                raise ProcessingError("Invalid generator.")
            combined_y_value = mg.combine_public_keys(y_shares)
            if elgamal_keymaterial.y != combined_y_value:
                raise ProcessingError("Invalid public key value.")

            # sign key
            signing_key, _ = pgpy.PGPKey.from_blob(settings['private_signing_key'])
            cert = signing_key.certify(gpg_user_id, SignatureType.Positive_Cert)

            out_message = {
                'uuid': uuid,
                'certificate': str(cert),
            }

        else:
            raise ProcessingError("Unrecognized message type.")

        return out_message


if __name__ == "__main__":

    # load settings
    SCRIPT_DIR = os.path.dirname(__file__)
    settings = json.load(open(os.path.join(SCRIPT_DIR, "settings.json")))
    if not 'contract_private_key_dir' in settings:
        settings["contract_private_key_dir"] = os.path.join(SCRIPT_DIR, "private_keys")

    print(process_message(json.loads(open(sys.argv[0]).read()), settings))