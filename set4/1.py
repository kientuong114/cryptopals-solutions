from Crypto.Cipher import AES
import base64
import os

BLOCKSIZE = 16

key = os.urandom(16)

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

def PKCS7_unpad(ptx):
    val = ptx[-1]
    return ptx[:-val]

def setup_cptx():
    with open('1.in') as f:
        cptx = base64.b64decode(f.read().replace('\n', ''))
    aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB)
    ptx = PKCS7_unpad(aes.decrypt(cptx))
    return CTR_encrypt(ptx, key, 0)

def edit(cptx, offset, new_text):
    return cptx[:offset] + xor_strings(new_text, keystream[offset:offset+len(new_text)]) + cptx[offset+len(new_text):]

if __name__ == "__main__":
    cptx = setup_cptx()
    recovered_keystream = edit(cptx, 0, b'\x00' * len(cptx))
    print(xor_strings(cptx, recovered_keystream))
