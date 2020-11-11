import base64

def hex_2_str(h):
    if isinstance(h, int):
        h = hex(int)[2:]
    return bytes.fromhex(h)

if __name__ == "__main__":
    h = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64 = base64.b64encode(hex_2_str(h))
    assert(b64 == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
    print(b64.decode())



