from hcrypto import Hcrypto

plaintext = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.'''

key = Hcrypto.generate_key()
print('key=', key.decode())

H = Hcrypto(key)

ciphertext = H.sha512_encrypt(plaintext.encode())
print('ciphertext=', ciphertext.decode())

plaintext = H.sha512_decrypt(ciphertext)
print('plaintext=', plaintext.decode())
