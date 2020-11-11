from Crypto.Cipher import AES
from base64 import b64decode

def ECB_encrypt(ptx, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(ptx)

if __name__ == "__main__":
    key = b'YELLOW SUBMARINE'
    with open('7.in', 'rb') as f:
        inp = b64decode(f.read())
    aes = AES.new(key, AES.MODE_ECB)
    print(aes.decrypt(inp).decode())




