def xor(s1, s2):
    assert(len(s1) == len(s2))
    s1 = bytes.fromhex(s1)
    s2 = bytes.fromhex(s2)
    return ''.join([hex(x^y)[2:] for x,y in zip(s1,s2)])

if __name__ == "__main__":
    res = xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    assert(res == '746865206b696420646f6e277420706c6179')
    print(res)
