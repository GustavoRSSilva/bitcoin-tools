from btctools import Xprv

m = Xprv.from_mnemonic('letter advice cage absurd amount doctor acoustic avoid letter advice cage above')
extended_key = m.encode()
print(extended_key)


print(m/44/0/0/0)


print(m/0./123/5.)

print((m/123/456).to_xpub())

address_p2pkh = (m/44./0./0./0/0).address('P2PKH')  # bip44
print(address_p2pkh)

address_p2wpkh = (m/84./0./0./0/0).address('P2WPKH')  # bip84
print(address_p2wpkh)
