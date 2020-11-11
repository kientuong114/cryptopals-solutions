from Crypto.Cipher import AES
import json
import os

BLOCKSIZE = 16
key = os.urandom(BLOCKSIZE)

def profile_for(email):
    if isinstance(email, str):
        email = email.encode()
    return {'email': email, 'uid':10, 'role':'user'}

def profile_to_token(profile):
    tokens = []
    for k, v in profile.items():
        if k == 'email':
            v = v.replace(b'=',b'').replace(b'&',b'')
        if isinstance(v, int):
            v = str(v).encode()
        elif isinstance(v, str):
            v = v.encode()
        kv = k.encode() + b'=' + v
        tokens.append(kv)
    return b'&'.join(tokens)

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def PKCS7_unpad(msg):
    return msg[:-msg[-1]]

def ECB_encrypt(ptx, key):
    ptx = PKCS7_pad(ptx, BLOCKSIZE)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(ptx)

def ECB_decrypt(cptx, key):
    aes = AES.new(key, AES.MODE_ECB)
    ptx = aes.decrypt(cptx)
    return PKCS7_unpad(ptx)

# I can only use the following functions

def get_token(email):
    return ECB_encrypt(profile_to_token(profile_for(email)), key)

def parse_enc_token(token):
    ptx_token = ECB_decrypt(token, key)
    profile = {}
    for t in ptx_token.split(b'&'):
        k, v = t.split(b'=')
        profile.update({k.decode(): v})
    if profile['role'] == b'admin':
        print("You win!")
    else:
        print("Hi normal user!")

if __name__ == "__main__":
    """
    email=aaaaaaaaaa
    admin\x0b\x0b\x0b\x0b... <-- Take this block...
    &uid=10&role=use
    r\x0f\x0f\x0f...

    email=aaaaaaaaaa
    aaa&uid=10&role=
    user...                  <-- Paste it here
    """

    tk = get_token(b'a'*10 + b'admin' + b'\x0b'*11)
    admin = tk[BLOCKSIZE:2*BLOCKSIZE]
    tk = get_token(b'a'*13)
    parse_enc_token(tk[:-BLOCKSIZE] + admin)
