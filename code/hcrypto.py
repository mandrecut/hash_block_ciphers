import os
import hmac
import base64
from hashlib import sha512
from hashlib import blake2b

'''
(c) M. Andrecut, 2020.
Warning "do it yourself encryption" is not encouraged, better use an existing validated approach. 
The method described here was developed only for educational purposes, it is not fully tested and validated, 
in practice use at your own risk.
'''

class Hcrypto(object):

    def __init__(self, key):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 64:
            raise ValueError("key must be 64 url-safe base64-encoded bytes!")
        self._block = 64
        self._ekey = key[:32]
        self._skey = key[32:]

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(64))

    def _xor(self, x, y):
        return bytes([a^b for (a,b) in zip(x, y)])

    def sha512_encrypt(self, data):
        if len(data) == 0:
            raise ValueError("data is empty!")
        data = bytearray(data)
        v = os.urandom(self._block)
        h = sha512(self._ekey + v).digest()
        N, R, n = int(len(data)/self._block), len(data) % self._block, 0
        while n < N:
            nB, nBB = n*self._block, (n+1)*self._block
            d = bytes(data[nB:nBB])
            data[nB:nBB] = self._xor(d, h)
            h = sha512(self._ekey + data[nB:nBB] + d).digest()
            n += 1
        if R > 0:
            NBR = N*self._block+R
            data[NBR-R:NBR] = self._xor(data[NBR-R:NBR], h[0:R])
        data = data + v
        h = hmac.new(self._skey, data, sha512)
        data = data + h.digest()
        return base64.urlsafe_b64encode(data)

    def sha512_decrypt(self, data):
        data = base64.urlsafe_b64decode(data)
        h = hmac.new(self._skey, data[:-self._block], sha512)
        if not hmac.compare_digest(data[-self._block:], h.digest()):
            raise ValueError("hmac failed!")
        v = data[-2*self._block:-self._block]
        data = bytearray(data[:-2*self._block])
        h = sha512(self._ekey + v).digest()
        N, R, n = int(len(data)/self._block), len(data) % self._block, 0
        while n < N:
            nB, nBB = n*self._block, (n+1)*self._block
            d = bytes(data[nB:nBB])
            data[nB:nBB] = self._xor(d, h)
            h = sha512(self._ekey + d + data[nB:nBB]).digest()
            n += 1
        if R > 0:
            NBR = N*self._block+R
            data[NBR-R:NBR] = self._xor(data[NBR-R:NBR], h[0:R])
        return bytes(data)

    def blake2b_encrypt(self, data):
        if len(data) == 0:
            raise ValueError("data is empty!")
        data = bytearray(data)
        v = os.urandom(self._block)
        h = blake2b(self._ekey + v).digest()
        N, R, n = int(len(data)/self._block), len(data) % self._block, 0
        while n < N:
            nB, nBB = n*self._block, (n+1)*self._block
            d = bytes(data[nB:nBB])
            data[nB:nBB] = self._xor(d, h)
            h = blake2b(self._ekey + data[nB:nBB] + d).digest()
            n += 1
        if R > 0:
            NBR = N*self._block+R
            data[NBR-R:NBR] = self._xor(data[NBR-R:NBR], h[0:R])
        data = data + v
        h = hmac.new(self._skey, data, blake2b)
        data = data + h.digest()
        return base64.urlsafe_b64encode(data)

    def blake2b_decrypt(self, data):
        data = base64.urlsafe_b64decode(data)
        h = hmac.new(self._skey, data[:-self._block], blake2b)
        if not hmac.compare_digest(data[-self._block:], h.digest()):
            raise ValueError("hmac failed!")
        v = data[-2*self._block:-self._block]
        data = bytearray(data[:-2*self._block])
        h = blake2b(self._ekey + v).digest()
        N, R, n = int(len(data)/self._block), len(data) % self._block, 0
        while n < N:
            nB, nBB = n*self._block, (n+1)*self._block
            d = bytes(data[nB:nBB])
            data[nB:nBB] = self._xor(d, h)
            h = blake2b(self._ekey + d + data[nB:nBB]).digest()
            n += 1
        if R > 0:
            NBR = N*self._block+R
            data[NBR-R:NBR] = self._xor(data[NBR-R:NBR], h[0:R])
        return bytes(data)

