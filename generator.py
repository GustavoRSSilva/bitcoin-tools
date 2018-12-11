#!/usr/bin/env python
import sys
from binascii import hexlify
from bip32utils import BIP32Key

from mnemonic import Mnemonic


def b2h(b):
    h = hexlify(b)
    return h if sys.version < '3' else h.decode('utf8')


def process(mnemonic):
    seed = mnemonic_to_seed(mnemonic)
    xprv = BIP32Key.fromEntropy(seed).ExtendedKey()
    seed = b2h(seed)
    key = BIP32Key.fromExtendedKey(xprv).SetPublic()
    print('mnemonic : %s (%d words)' % (mnemonic, len(mnemonic.split(' '))))
    print('seed     : %s (%d bits)' % (seed, len(seed) * 4))
    print('xprv     : %s' % xprv)
    print('key     : %s' % key)

def mnemonic_to_seed(mnemonic, passphrase=''):
    return Mnemonic.to_seed(mnemonic)



if __name__ == '__main__':
    mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'
    process(mnemonic)
