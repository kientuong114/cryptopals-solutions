from Crypto.Cipher import AES
import os
import string
import codecs

BLOCKSIZE = 16
key = os.urandom(BLOCKSIZE)

class PaddingException(Exception):
    def __init__(self, msg):
        super().__init__(f"Invalid PKCS#7 Padding in message: {msg}.")

class InvalidByteException(Exception):
    def __init__(self, msg):
        super().__init__(f"High non printable byte detected in: {bytearray(msg)}.")

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def PKCS7_unpad(msg):
    return msg[:-msg[-1]]

def PKCS7_validator(msg):
    pad_ch = msg[-1]
    if not all(map(lambda x: x==pad_ch, msg[-pad_ch:])):
        raise PaddingException(msg)

def byte_validator(msg):
    for ch in msg:
        if ch > 0x7F:
            raise InvalidByteException(msg)

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

def CBC_decrypt(cptx, key, IV):
    other = IV
    ptx = []
    for i in range(0, len(cptx), BLOCKSIZE):
        aes = AES.new(key, AES.MODE_ECB)
        cptx_block = cptx[i:BLOCKSIZE+i]
        ptx_block = xor(aes.decrypt(cptx_block), other)
        other = cptx_block
        ptx.append(ptx_block)
    ptx = b''.join(ptx)
    byte_validator(ptx)
    return PKCS7_unpad(ptx)

def check_admin(msg):
    return b';admin=true;' in msg

def encryption_oracle(msg):
    msg = b"comment1=cooking%20MCs;userdata="                \
            + msg.replace(b';', b'";"').replace(b'=', b'"="')   \
            + b";comment2=%20like%20a%20pound%20of%20bacon"
    return CBC_encrypt(msg, key, key)

def decryption_oracle(msg):
    ptx = CBC_decrypt(msg, key, key)
    byte_validator(ptx)
    if check_admin(ptx):
        print("Success! You're an admin!")
    else:
        print("Hi normal user!")

def blockify(msg, blocksize):
    return [msg[i:i+blocksize] for i in range(0, len(msg), blocksize)]

if __name__ == "__main__":
    cptx = encryption_oracle(b'x'*16)
    cptx = blockify(cptx, BLOCKSIZE)
    cptx = cptx[0] + b'\x00'*16 + cptx[0]
    print(f'Real key: {key}')
    try:
        decryption_oracle(cptx)
    except InvalidByteException as e:
        leak = codecs.escape_decode(e.args[0][49:-3])[0]
    leak = blockify(leak, BLOCKSIZE)
    print(f'Found key {xor(leak[0], leak[2])}')
