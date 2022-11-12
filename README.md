# Hash Block Ciphers

This is an encryption method based on hash functions: <a href="https://github.com/mandrecut/hash_block_ciphers/blob/main/hash_block_ciphers.pdf" target="_blank">Hash Block Ciphers</a>

Warning, "do it yourself encryption" is not encouraged, better use an existing validated approach. 
The method described here was developed only for educational purposes, it is not fully tested and validated, 
in practice use it at your own risk. 

## Basic usage

```python
from hcrypto import Hcrypto

plaintext = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.'''

key = Hcrypto.generate_key()
print('key=', key.decode())

H = Hcrypto(key)

ciphertext = H.sha512_encrypt(plaintext.encode())
print('ciphertext=', ciphertext.decode())

plaintext = H.sha512_decrypt(ciphertext)
print('plaintext=', plaintext.decode())
```

output 

```
key= syjocRzfgJjd9C7hBPtYqUiwB_IctlNy4kErC6OwZJbwfZnSdVmhVmPiVgcXn7rH8WRE-tb2HorNA9hCYgSH1g==

ciphertext= zMqreKWA30pGuS0X3r5BbDBKAyPZLJ-XBnv01vqku09LT3LsT3Oi5tRGmgXPwecMN39-ML4S25EZgJBTvQ1QZzHzl6V3kAXrF0uaVji02ag7cmt81GERWORRp1yCxaqQiFUbAH1h0e1MrKWSeVBXmBgm9QHlH8eAc2G054uRRCDON_T91D7njuGSIRVwAxzFF3HcUmV4x-kmFDPwZT_NMzGyrb9WBAmf6v333IZdU0Ww9Lx9tLsKNsxG_8E7tZ-2IVKLssM_-AYOjBWnF4EVdnh569wE4Kw-fxujmStPAbocQSNgvrmcRjQg5RBfHIopYGgR2nIwE1fpTgk=

plaintext= Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
```
