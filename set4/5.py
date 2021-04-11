from typing import Union
from functools import reduce
import math

def blockify(data, blocksize):
    assert(len(data) % blocksize == 0)
    return [int.from_bytes(data[i:i+blocksize], 'big') for i in range(0, len(data), blocksize)]

def left_shift_circular(word: int, shift_amount:int = 1):
    return ((word << shift_amount) | (word >> (32 - shift_amount))) & 0xffffffff

class SHA1:
    BLOCK_SIZE_BYTES = 64
    WORD_SIZE_BYTES = 4
    LONG_SIZE_BYTES = 8
    def __init__(self):
        self.hash = [
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        ]
        self.buffer = b''
        self.length = 0

    def _compress(self, data):
        W = blockify(data, 4)
        W += [0] * (80 - len(W))
        assert(len(W) == 80)
        for t in range(16, 80):
            W[t] = left_shift_circular(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

        A, B, C, D, E = self.hash[0], self.hash[1], self.hash[2], self.hash[3], self.hash[4]
        for t in range(0, 80):
            temp = left_shift_circular(A, 5) + self._f(t, B, C, D) + E + W[t] + self._K(t)
            temp &= 0xffffffff
            A, B, C, D, E = temp, A, left_shift_circular(B, 30), C, D

        self.hash[0] = (self.hash[0] + A) & 0xffffffff
        self.hash[1] = (self.hash[1] + B) & 0xffffffff
        self.hash[2] = (self.hash[2] + C) & 0xffffffff
        self.hash[3] = (self.hash[3] + D) & 0xffffffff
        self.hash[4] = (self.hash[4] + E) & 0xffffffff


    def _K(self, t):
        if 0 <= t < 20:
            return 0x5a827999
        elif 20 <= t < 40:
            return 0x6ed9eba1
        elif 40 <= t < 60:
            return 0x8f1bbcdc
        elif 60 <= t < 80:
            return 0xca62c1d6


    def _f(self, t, B, C, D):
        if 0 <= t < 20:
            return (B & C) | ((~B) & D)
        elif 20 <= t < 40:
            return B ^ C ^ D
        elif 40 <= t < 60:
            return (B & C) | (B & D) | (C & D)
        elif 60 <= t < 80:
            return B ^ C ^ D


    def update(self, data: Union[bytes, str]):
        if isinstance(data, str):
            data = data.encode()

        self.buffer += data


        while len(self.buffer) >= SHA1.BLOCK_SIZE_BYTES:
            block, self.buffer = self.buffer[:SHA1.BLOCK_SIZE_BYTES], self.buffer[SHA1.BLOCK_SIZE_BYTES:]
            self._compress(block)
            self.length += SHA1.BLOCK_SIZE_BYTES

        return self

    def digest(self):
        self.length += len(self.buffer)
        pad_len = 64 - (self.length % 64) - 9
        self.update(b'\x80' + b'\x00' * pad_len + (self.length * 8).to_bytes(SHA1.LONG_SIZE_BYTES, 'big'))
        result = [h.to_bytes(SHA1.WORD_SIZE_BYTES, 'big') for h in self.hash]
        return b''.join(result)

key = 'somebodyoncetoldme'.encode()

def MAC_oracle():
    user_data = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'.encode()
    sha = SHA1()
    sha.update(key + user_data)
    return user_data, sha.digest().hex()

def decode_msg(msg):
    data = {}
    for kv in msg.split(b';'):
        key, val = kv.split(b'=')
        data.update({key: val})
    return data

def verify_oracle(msg, mac):
    if not SHA1().update(key+msg).digest().hex() == mac:
        print("Invalid MAC!")
        return False
    else:
        data = decode_msg(msg)
        if data.get(b'admin', b'false') == b'true':
            print("You're an admin!")
            return True
        else:
            print("You're a normal user")
            return False


def main():
    target = ';admin=true'.encode()
    data, mac = MAC_oracle()
    mac_split = [int(mac[i:i+8], 16) for i in range(0, len(mac), 8)]

    for key_len in range(1, 100):
        print(f"Trying key length {key_len}")

        sha = SHA1()

        # Set current starting state of the hash as the output of the old hash
        sha.hash = list(mac_split)

        # Length of original data with glue padding
        data_len = math.ceil((len(data) + key_len)/64) * 64

        # Length of new message
        new_len = (data_len + len(target)) * 8

        # Length of new padding
        new_pad_len = 64 - (len(target) % 64) - 9

        # Length of old padding
        old_pad_len = 64 - ((len(data) + key_len) % 64) - 9

        # New message
        new_msg = data + b'\x80' + b'\x00' * old_pad_len + ((len(data) + key_len) * 8).to_bytes(8, 'big') + target

        # Update the state with handcrafted padding and manually extract the digest
        # We cannot use digest() because it would add more padding
        sha.update(target + b'\x80' + b'\x00' * new_pad_len + new_len.to_bytes(8, 'big'))
        new_mac = b''.join(h.to_bytes(SHA1.WORD_SIZE_BYTES, 'big') for h in sha.hash)

        if verify_oracle(new_msg, new_mac.hex()):
            break

if __name__ == "__main__":
    main()
