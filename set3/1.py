from Crypto.Cipher import AES
import os
import sys
import random
import base64

BLOCKSIZE = 16
key = os.urandom(BLOCKSIZE)

ptxs = b"""MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split(b'\n')

class PaddingException(Exception):
    def __init__(self):
        super().__init__("Invalid PKCS#7 Padding")

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def PKCS7_unpad(msg):
    return msg[:-msg[-1]]

def PKCS7_validator(msg):
    pad_ch = msg[-1]
    if not all(map(lambda x: x==pad_ch, msg[-pad_ch:])):
        raise PaddingException()

def xor(block1, block2):
    return b''.join((x^y).to_bytes(1, 'big') for x, y in zip(block1, block2))

def CBC_encrypt(ptx, key):
    iv = os.urandom(BLOCKSIZE)
    ptx = PKCS7_pad(ptx, BLOCKSIZE)
    other = iv
    cptx = []
    for i in range(0, len(ptx), BLOCKSIZE):
        ptx_block = ptx[i:BLOCKSIZE+i]
        aes = AES.new(key, AES.MODE_ECB)
        cptx_block = aes.encrypt(xor(ptx_block, other))
        other = cptx_block
        cptx.append(cptx_block)
    return b''.join(cptx), iv

def CBC_decrypt(cptx, key, IV):
    other = IV
    ptx = []
    for i in range(0, len(cptx), BLOCKSIZE):
        aes = AES.new(key, AES.MODE_ECB)
        cptx_block = cptx[i:BLOCKSIZE+i]
        ptx_block = xor(aes.decrypt(cptx_block), other)
        other = cptx_block
        ptx.append(ptx_block)
    return b''.join(ptx)

def blockify(msg, blocksize):
    return [msg[i:i+blocksize] for i in range(0, len(msg), blocksize)]

def encryption_oracle():
    return CBC_encrypt(base64.b64decode(random.choice(ptxs)), key)

def padding_oracle(msg, iv):
    ptx = CBC_decrypt(msg, key, iv)
    try:
        PKCS7_validator(ptx)
    except PaddingException:
        return False
    else:
        return True

if __name__ == "__main__":
    cptx, iv = encryption_oracle()
    cptx_block = blockify(cptx, BLOCKSIZE)
    prev_block = iv
    ptx = []
    for block in cptx_block:
        found = [b'\x00' for _ in range(BLOCKSIZE)]
        for b in range(BLOCKSIZE):
            for i in range(256):
                prefix_block = b'\x00' * (BLOCKSIZE - b - 1)
                random_block = prefix_block
                probe = i.to_bytes(1, 'big')
                xor_known = [x ^ int.from_bytes(y, 'big') for x, y in zip(prev_block[BLOCKSIZE-b:], found[BLOCKSIZE-b:])]
                known_block = b''.join(map(lambda x: (x ^ (b+1)).to_bytes(1, 'big'), xor_known))
                assert(len(prefix_block+probe+known_block) == 16)
                if padding_oracle(prefix_block + probe + known_block + block, iv):
                    found[BLOCKSIZE-b-1] = ((b+1) ^ i ^ prev_block[-b-1]).to_bytes(1, 'big')
                    break
            else:
                print("Something's wrong...")
                sys.exit(1)
        ptx.append(b''.join(found))
        prev_block = block
    print(PKCS7_unpad(b''.join(ptx)))
