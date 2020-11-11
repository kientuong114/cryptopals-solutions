from Crypto.Cipher import AES
from base64 import b64decode

BLOCKSIZE = 16

def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

def PKCS7_unpad(msg):
    return msg[:-msg[-1]]

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
    return PKCS7_unpad(b''.join(ptx))


if __name__ == "__main__":
    with open('2.in', 'rb') as f:
        cptx = b64decode(f.read())
    print(CBC_decrypt(cptx, b'YELLOW SUBMARINE', b'\x00'*16).decode())
