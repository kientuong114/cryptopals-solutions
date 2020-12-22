from Crypto.Cipher import AES
from collections import Counter
import string
import itertools
import base64
import os

BLOCKSIZE = 16
key = os.urandom(16)

def xor_strings(s1, s2):
    return b''.join((x^y).to_bytes(1, 'big') for x, y in zip(s1, s2))

def CTR_encrypt(msg, key, nonce):
    num_keystream_blocks = len(msg) // 16 + 1
    keystream = []
    for i in range(num_keystream_blocks):
        aes = AES.new(key, AES.MODE_ECB)
        input_block = nonce.to_bytes(8, 'little') + i.to_bytes(8, 'little')
        keystream.append(aes.encrypt(input_block))
    keystream = b''.join(keystream)
    return xor_strings(msg, keystream)

def CTR_decrypt(msg, key, nonce):
    return CTR_encrypt(msg, key, nonce)

def solve_xor(cptx):
    c = Counter([x for x in cptx if x])
    for ch in ' etaoinshrdlucmfwygpbvkqjxz':
        key = max(c, key=c.get) ^ ord(' ')
        if all([chr(x^key) in string.ascii_letters for x in cptx if x]):
            return key
    return key

def solve_xor_first(cptx):
    c = Counter([x for x in cptx if x])
    for ch in 'tsamcinbrped':
        key = max(c, key=c.get) ^ ord('S')
        if all([chr(x^key) in string.printable for x in cptx if x]):
            return key
    return key

if __name__ == "__main__":
    with open('3.2.in', 'rb') as f:
        ptxs = [base64.b64decode(x.strip()) for x in f.readlines()]

    cptxs = [CTR_encrypt(x, key, 0) for x in ptxs]

    max_len = 0

    for cptx in cptxs:
        if len(cptx) > max_len:
            max_len = len(cptx)

    cptxs = [x[:max_len] for x in cptxs]
    cptxs_transposed = list(itertools.zip_longest(*cptxs))

    key = b''.join(
        [solve_xor_first(cptxs_transposed[0]).to_bytes(1, 'big')] +
        [solve_xor(x).to_bytes(1, 'big') for x in cptxs_transposed[1:]]
    )

    ptxs = [xor_strings(key, x) for x in cptxs]

    for ptx in ptxs:
        print(ptx)

    #Eh, good enough
