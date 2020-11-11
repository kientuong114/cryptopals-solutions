def PKCS7_pad(msg, blocksize):
    b = blocksize - (len(msg)%blocksize)
    return msg + b.to_bytes(1, byteorder='big') * b

if __name__ == "__main__":
    print(PKCS7_pad(b'YELLOW SUBMARINE', 20))

