from Crypto.Cipher import AES
from base64 import b64decode
from collections import Counter
import os

BLOCKSIZE =16

unknown = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

key = os.urandom(BLOCKSIZE)

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def PKCS7_unpad(msg):
    return msg[:-msg[-1]]

def ECB_encrypt(ptx, key):
    ptx = PKCS7_pad(ptx, BLOCKSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(ptx)

def encryption_oracle(ptx):
    ptx = ptx + unknown
    return ECB_encrypt(ptx, key)

if __name__ == "__main__":
    cptx_0 = encryption_oracle(b'')
    unknown_len = len(cptx_0)
    for i in range(1, 100):
        cptx_1 = encryption_oracle(b'A'*i)
        if len(cptx_1) != unknown_len:
            found_bsize = len(cptx_1) - unknown_len
            break

    cptx = encryption_oracle(b'a'*16*5)
    c = Counter([cptx[i:i+16] for i in range(0, len(cptx), 16)])
    if c.most_common(1)[0][1] == 1:
        raise Exception("Not using ECB?")

    known = b''
    for i in range(unknown_len):
        if i < found_bsize:
            probe = b'A' * (found_bsize - 1 - i) + known
        else:
            probe = known[-found_bsize+1:]
        to_compare = i // found_bsize + 1
        block = b'A' * ((found_bsize - 1 - i) % 16)
        for probe_ch in range(0, 256):
            probe_ch = probe_ch.to_bytes(1, 'big')
            cptx = encryption_oracle(probe + probe_ch + block)
            if cptx[:found_bsize] == cptx[found_bsize*to_compare:found_bsize*(to_compare+1)]:
                known += probe_ch
                break
    print(PKCS7_unpad(known).decode())
