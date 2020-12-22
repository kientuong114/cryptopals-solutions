from Crypto.Cipher import AES
from base64 import b64decode
from collections import Counter
from string import printable
import random
import os

BLOCKSIZE = 16

unknown = b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

key = os.urandom(BLOCKSIZE)
prefix_len = random.randint(0, BLOCKSIZE*3)
prefix = os.urandom(prefix_len)

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
    ptx = prefix + ptx + unknown
    return ECB_encrypt(ptx, key)

def blockify(msg, blocksize):
    return [msg[i:i+blocksize] for i in range(0, len(msg), blocksize)]

if __name__ == "__main__":
    #Find block length
    cptx_0 = encryption_oracle(b'')
    prelim_len = len(cptx_0)
    for i in range(1, 100):
        cptx_1 = encryption_oracle(b'A'*i)
        if len(cptx_1) > prelim_len:
            blocksize = len(cptx_1) - prelim_len
            break

    #We need to find where our attacker-controlled input is, since we don't know the prefix.

    #The idea is to first generate a ciphertext with 47 'A's, so we will find for certain two equal blocks.

    cptx_2 = encryption_oracle(b'A'*47)
    cptx_2 = blockify(cptx_2, blocksize)

    for idx, pair in enumerate(zip(cptx_2, cptx_2[1:])): #We compare pairs of blocks, if we find two equal blocks we can treat that as the start of our input
        if pair[0] == pair[1]:
            A_block = pair[0]
            A_block_start = idx #This will be the block we'll check for the one-byte-at-a-time decryption

    #Next, we'll iterate over all possible inputs between 'A'*16 and 'A'*31 to find when we create a full block of 'A's

    found = False
    for i in range(16, 32):
        cptx_3 = blockify(encryption_oracle(b'A'*i), blocksize)
        for block in cptx_3:
            if block == A_block:
                start_len = i - 1 #We use one less than the number of As required to create a block
                prefix_padding = b'A' * (i-16) #These are the As required to pad the prefix to a block
                found = True
                break
        if found:
            break

    #The schema is now | prefix + prefix_padding |     probe     | AAAAAAAAAAAAAAAc | iphertext... |

    i = 0
    known = b''
    exit = False
    while True:
        for ch in range(256):
            probe = known[-blocksize+1:].rjust(blocksize-1, b'A') + ch.to_bytes(1, 'big')
            block = b'A' * ((blocksize - 1 - i) % 16)
            cptx = encryption_oracle(prefix_padding + probe + block)
            to_check = A_block_start + i // blocksize + 1
            if cptx[A_block_start*blocksize:(A_block_start+1)*blocksize] == cptx[to_check*blocksize:(to_check+1)*blocksize]:
                if chr(ch) not in printable:
                    exit = True
                known += ch.to_bytes(1, 'big')
                break
        if exit:
            break
        i += 1

    print(known.strip().decode())
    print(f"Key was: {key}")
    print(f"Prefix was: {prefix}, with length {prefix_len}")

