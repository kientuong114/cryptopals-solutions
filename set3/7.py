import sys
sys.path.insert(0, '..')
import time
import os
import random
import tqdm

from string import ascii_lowercase

from utils.mt19937 import MT19937_32

seed = int.from_bytes(os.urandom(2), 'big')

def gen_stream(length):
    mt = MT19937_32()
    mt.seed(seed)
    stream = []
    for _ in range(length):
        stream.append(mt.next() & 0xff)
    return stream


def encrypt(ptx):
    if isinstance(ptx, str):
        ptx = ptx.encode()
    stream = gen_stream(len(ptx))
    cptx = b''.join((ch ^ enc).to_bytes(1, 'big') for ch, enc in zip(ptx, stream))
    return cptx


def decrypt(cptx):
    return encrypt(cptx)


def encrypt_oracle():
    prefix_len = random.randrange(4, 20)
    prefix = ''.join(random.choice(ascii_lowercase) for _ in range(prefix_len))
    ptx = prefix + 'A' * 14
    return encrypt(ptx)

def sol_decrypt(seed, cptx):
    mt = MT19937_32()
    mt.seed(seed)
    ptx = []
    for ch in cptx:
        ptx.append(chr((mt.next() & 0xff) ^ ch))
    ptx = ''.join(ptx)
    if ptx[-14:] == 'A'*14:
        return True
    else:
        return False


def main():
    cptx = encrypt_oracle()
    for i in tqdm.tqdm(range(2**16)):
        if sol_decrypt(i, cptx):
            sol = i
            break
    if sol:
        print(f'Found seed: {sol}')
        print(f'Real seed: {seed}')
    else:
        print(f'No seed found')
    #TODO: understand the second part. I think it can be done in the same way?


if __name__ == "__main__":
    main()

