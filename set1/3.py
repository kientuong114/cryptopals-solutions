from collections import Counter

if __name__ == "__main__":
    inp = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    c = Counter(inp)
    key = max(c, key=c.get) ^ ord(' ')
    print(''.join(map(lambda x: chr(x ^ key), inp)))
