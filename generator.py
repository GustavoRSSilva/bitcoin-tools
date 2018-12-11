#!/usr/bin/env python
import sys
from binascii import hexlify
from bip32utils import BIP32Key

from transformations import int_to_bin, bin_to_bytes, bytes_to_bin, sha256, str_to_bytes

import hmac
import hashlib
from struct import Struct
from operator import xor
from itertools import starmap

_pack_int = Struct('>I').pack

class InvalidMnemonic(Exception):
    pass

def b2h(b):
    h = hexlify(b)
    return h if sys.version < '3' else h.decode('utf8')


def bytes_(s):
    if isinstance(s, str):
        return str_to_bytes(s)
    return s

# def process(mnemonic):
#     seed = mnemonic_to_seed(mnemonic)
#     xprv = BIP32Key.fromEntropy(seed).ExtendedKey()
#     seed = b2h(seed)
#     key = BIP32Key.fromExtendedKey(xprv).SetPublic()
#     print('mnemonic : %s (%d words)' % (mnemonic, len(mnemonic.split(' '))))
#     print('seed     : %s (%d bits)' % (seed, len(seed) * 4))
#     print('xprv     : %s' % xprv)
#     print('key     : %s' % key)
#
# def mnemonic_to_seed(mnemonic, passphrase=''):
#     return Mnemonic.to_seed(mnemonic)

def validate_mnemonic(mnemonic):
    mnemonic = mnemonic.lower().split()

    # Check if it has 12, 15, 18,21 or 24 words
    if len(mnemonic) not in {12, 15, 18, 21, 24}:
        return False

    return True



def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(bytes_(data), None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(bytes_(x))
        return h.digest()

    buf = []
    for block in range(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(bytes_(salt) + _pack_int(block))
        for i in range(iterations - 1):
            u = _pseudorandom(bytes(u))
            rv = starmap(xor, zip(rv, u))
        buf.extend(rv)

    return bytes(buf)[:keylen]


if __name__ == '__main__':
    mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'
    passphrase = ''

    if not validate_mnemonic(mnemonic):
        raise InvalidMnemonic


    seed = pbkdf2_bin(mnemonic, 'mnemonic' + passphrase, iterations=2048, keylen=64, hashfunc=hashlib.sha512)
    print(seed)
    xprv = BIP32Key.fromEntropy(seed).ExtendedKey()
    print(xprv)
    # process(mnemonic)
