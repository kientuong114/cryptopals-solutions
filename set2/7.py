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

if __name__ == "__main__":
    PKCS7_validator(b"ICE ICE BABY\x04\x04\x04\x04")
    print("Ok")
    try:
        PKCS7_validator(b"ICE ICE BABY\x05\x05\x05\x05")
    except:
        print("Ok")
    else:
        raise Exception("Uncaught pad badding")

    try:
        PKCS7_validator(b"ICE ICE BABY\x01\x02\x03\x04")
    except:
        print("Ok")
    else:
        raise Exception("Uncaught pad badding")

