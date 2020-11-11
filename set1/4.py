from collections import Counter

if __name__ == "__main__":
    with open('4.in') as f:
        inps = f.readlines()
    for inp in inps:
        inp = inp.strip()
        inp = [int(inp[i:i+2], 16) for i in range(0, len(inp), 2)]
        c = Counter(inp)
        key = max(c, key=c.get) ^ ord(' ')
        out = ''.join(map(lambda x: chr(x ^ key), inp)).strip()
        if out.isprintable():
            print(out)

