from base64 import b64decode, b64encode

def int_b64decode(s):
    """ Convert a base-64-encoded bytestring to an integer. """
    b = bytearray(b64decode(s))
    return sum((1 << (bi * 8)) * bb for (bi, bb) in enumerate(b))

def int_b64encode(i):
    """ Convert an integer to a base-64-encoded bytestring. """
    b = bytearray()
    while i:
        b.append(i & 0xFF)
        i >>= 8
    return b64encode(bytes(b))


