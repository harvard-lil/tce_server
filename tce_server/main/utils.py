from contextlib import contextmanager
import subprocess
import tempfile
from django.conf import settings
import gnupg
import pgpy
import tempdir
from trustee.multielgamal import MultiElGamal


@contextmanager
def load_gpg(keys):
    gpg = init_gpg(keys)
    try:
        yield gpg
    finally:
        destroy_gpg(gpg)


def init_gpg(keys):
    t = tempdir.TempDir()
    gpg = gnupg.GPG(homedir=t.name)
    gpg.temp_dir = t
    for key in keys:
        gpg.import_keys(key)
    return gpg


def destroy_gpg(gpg):
    gpg.temp_dir.dissolve()


def gpg_encrypt(public_key, message):
    with load_gpg([public_key]) as gpg:
        return str(gpg.encrypt(message, gpg.list_keys().fingerprints[0]))


def gpg_decrypt(private_key, message):
    with load_gpg([private_key]) as gpg:
        return str(gpg.decrypt(message, always_trust=True))


hex_out = lambda x: hex(x)[2:].rstrip('L')  # Convert int to hex, stripping extra. E.g.:  10 -> '0xaL' -> 'a'


def generate_public_elgamal_key(p, g, y, identity):

    public_key_file = tempfile.NamedTemporaryFile(delete=False)
    public_key_file.close()
    private_key_file = tempfile.NamedTemporaryFile(delete=False)
    private_key_file.close()

    subprocess.check_call(
        ['java', '-jar', settings.CREATE_KEY_FILE_JAR, 'create', hex_out(p), hex_out(g), hex_out(y), private_key_file.name, public_key_file.name, identity])

    public_key = open(public_key_file.name).read()
    private_key = open(private_key_file.name).read()

    public_key_file.unlink(public_key_file.name)
    private_key_file.unlink(private_key_file.name)

    return public_key, private_key


def update_private_elgamal_key(private_key, x):
    old_private_key_file = tempfile.NamedTemporaryFile(delete=False)
    old_private_key_file.write(private_key)
    old_private_key_file.close()
    new_private_key_file = tempfile.NamedTemporaryFile(delete=False)
    new_private_key_file.close()

    subprocess.check_call(['java', '-jar', settings.CREATE_KEY_FILE_JAR,
                           'add',
                           old_private_key_file.name,
                           hex_out(x),
                           new_private_key_file.name])

    updated_private_key = open(new_private_key_file.name).read()

    old_private_key_file.unlink(old_private_key_file.name)
    new_private_key_file.unlink(new_private_key_file.name)

    return updated_private_key


def apply_certificates(public_key, certificates):
    public_key, _ = pgpy.PGPKey.from_blob(public_key)
    for cert in certificates:
        public_key.userids[0] |= cert
    return str(public_key)



import logging
import itertools
from secretsharing import modular_lagrange_interpolation


class MultiElGamalWithRecovery(MultiElGamal):

    def recover_private_key(self, y, shares, recovery_threshold):
        x_shares = []

        for x_share, polynomial_points in shares:

            x_options = set()

            if x_share is not None:
                x_options.add(x_share)

            if len(polynomial_points) >= recovery_threshold:
                for point_subset in itertools.combinations(polynomial_points, recovery_threshold):
                    x_options.add(modular_lagrange_interpolation(0, list(point_subset), self.q))

            if not x_options:
                raise ValueError("Failed to recover key -- not enough shares available.")
            elif len(x_options) > 1:
                logging.warning("Polynomial points resulted in multiple possible x shares -- checking all.")

            x_shares.append(x_options)

        for x_combo in itertools.product(*x_shares):
            x = self.combine_private_keys(x_combo)
            if pow(self.g, x, self.p) == y:
                return x

        raise ValueError("Failed to recover key -- regenerated x did not match known y value.")

    def combine_private_keys(self, x_list):
        return sum(x_list)
