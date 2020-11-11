from Crypto.Cipher import AES
from collections import Counter
import random
import os

BLOCKSIZE = 16
N_RUNS = 1000

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def xor(block1, block2):
    assert(len(block1) == 16)
    assert(len(block2) == 16)
    return b''.join((x^y).to_bytes(1, 'big') for x, y in zip(block1, block2))

def CBC_encrypt(ptx, key, IV):
    ptx = PKCS7_pad(ptx, BLOCKSIZE)
    other = IV
    cptx = []
    for i in range(0, len(ptx), BLOCKSIZE):
        ptx_block = ptx[i:BLOCKSIZE+i]
        aes = AES.new(key, AES.MODE_ECB)
        cptx_block = aes.encrypt(xor(ptx_block, other))
        other = cptx_block
        cptx.append(cptx_block)
    return b''.join(cptx)

def ECB_encrypt(ptx, key):
    ptx = PKCS7_pad(ptx, BLOCKSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(ptx)

def encryption_oracle(ptx):
    key = os.urandom(BLOCKSIZE)
    len_prefix = random.randint(5, 10)
    len_suffix = random.randint(5, 10)
    prefix = os.urandom(len_prefix)
    suffix = os.urandom(len_suffix)
    ptx = prefix + ptx + suffix

    choice = random.randint(0, 1)
    if choice:
        IV = os.urandom(BLOCKSIZE)
        res = yield CBC_encrypt(ptx, key, IV)
    else:
        res = yield ECB_encrypt(ptx, key)

    if res == choice:
        yield True
    else:
        yield False

def oracle_breaker():
    correct = 0
    for _ in range(N_RUNS):
        oracle = encryption_oracle(b'a'*16*5)
        cptx = oracle.__next__()
        c = Counter([cptx[i:i+16] for i in range(0, len(cptx), 16)])
        if c.most_common(1)[0][1] >= 2:
            res = oracle.send(0)
        else:
            res = oracle.send(1)
        if res:
            correct += 1
    print("Correct %: ", 100 * correct / float(N_RUNS))

if __name__ == "__main__":
    oracle_breaker()
