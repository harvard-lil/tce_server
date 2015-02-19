from contextlib import contextmanager
import gnupg
import tempdir

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