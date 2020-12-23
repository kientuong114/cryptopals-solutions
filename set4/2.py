from Crypto.Cipher import AES
import os

BLOCKSIZE = 16

key = os.urandom(BLOCKSIZE)
nonce = int.from_bytes(os.urandom(4), 'big')

def xor_strings(s1, s2):
    return b''.join((x^y).to_bytes(1, 'big') for x, y in zip(s1, s2))

def CTR_encrypt(msg, key, nonce):
    global keystream
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

def check_admin(msg):
    return b';admin=true;' in msg

def encryption_oracle(msg):
    msg = b"comment1=cooking%20MCs;userdata="                \
            + msg.replace(b';', b'";"').replace(b'=', b'"="')   \
            + b";comment2=%20like%20a%20pound%20of%20bacon"
    return CTR_encrypt(msg, key, nonce)

def decryption_oracle(msg):
    ptx = CTR_decrypt(msg, key, nonce)
    if check_admin(ptx):
        print("Success! You're an admin!")
    else:
        print("Hi normal user!")

if __name__ == "__main__":
    cptx = encryption_oracle(b'x'*16)
    to_insert = b';admin=true;'
    to_substitute = b'e%20a%20poun'
    len_insert = len(to_insert)
    cptx = cptx[:64] + xor_strings(xor_strings(cptx[64:64+len_insert], to_substitute), to_insert) + cptx[64+len_insert:]
    decryption_oracle(cptx)

