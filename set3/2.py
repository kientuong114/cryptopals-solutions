from Crypto.Cipher import AES
import base64

BLOCKSIZE = 16

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

if __name__ == "__main__":
    print(CTR_decrypt(base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='), b'YELLOW SUBMARINE', 0))

