from base64 import b64decode
from collections import Counter
import itertools


def hamming_weight(b):
    w = 0
    while b:
        w += 1
        b &= b-1
    return w

def hamming(b1, b2):
    if isinstance(b1, str):
        b1 = b1.encode()
    if isinstance(b2, str):
        b2 = b2.encode()
    return sum([hamming_weight(x^y) for x,y in zip(b1, b2)])

def solve_xor(cptx):
    c = Counter([x for x in cptx if x])
    key = max(c, key=c.get) ^ ord(' ')
    return key

if __name__ == "__main__":
    print(hamming('this is a test', 'wokka wokka!!!'))
    with open('6.in', 'rb') as f:
        inp = b64decode(f.read())

    k = []
    for keysize in range(2, 41):
        hd = sum(hamming(inp[i:i+keysize], inp[keysize+i:2*keysize+i])/float(keysize) for i in range(0, len(inp), keysize*2))
        k.append((hd/(len(inp)/(2*keysize)), keysize))

    k = sorted(k, key=lambda x: x[0])
    true_keysize = k[0][1]

    inp = [inp[i:i+true_keysize] for i in range(0, len(inp), true_keysize)]
    inp = list(itertools.zip_longest(*inp))

    key = ''.join([chr(solve_xor(x)) for x in inp])
    print(key)


