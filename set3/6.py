import sys
sys.path.insert(0, '..')

from utils.mt19937 import MT19937_32

w=32
n=624
m=397
r=31
a=0x9908b0df
s=7
b=0x9d2c5680
t=15
c=0xefc60000
u=11
d=0xffffffff
l=18
f=1812433253
w_mask = (1 << w) - 1
lower_mask = (1 << r) - 1
upper_mask = w_mask ^ lower_mask

def right_unshift_xor(val, shift):
    unshifted_val = 0
    for i in range(31, 31-shift, -1):
        unshifted_val |= val & (1 << i)
    for i in range(31-shift, -1, -1):
        unshifted_val |= (val & (1 << i)) ^ ((unshifted_val & (1 << i + shift)) >> shift)
    return unshifted_val

def right_unshift_xor_unmask(val, shift, mask):
    unshifted_val = 0
    for i in range(31, 31-shift, -1):
        unshifted_val |= val & (1 << i)
    for i in range(31-shift, -1, -1):
        unshifted_val |= (val & (1 << i)) ^ (((unshifted_val & (1 << i + shift)) >> shift) & mask)
    return unshifted_val

def left_unshift_xor(val, shift):
    unshifted_val = 0
    for i in range(0, shift):
        unshifted_val |= val & (1 << i)
    for i in range(shift, 32):
        unshifted_val |= (val & (1 << i)) ^ ((unshifted_val & (1 << i - shift)) << shift)
    return unshifted_val

def left_unshift_xor_unmask(val, shift, mask):
    unshifted_val = 0
    for i in range(0, shift):
        unshifted_val |= val & (1 << i)
    for i in range(shift, 32):
        unshifted_val |= (val & (1 << i)) ^ (((unshifted_val & (1 << i - shift)) << shift) & mask)
    return unshifted_val


def invert_temper(val):
    val = right_unshift_xor(val, l)
    val = left_unshift_xor_unmask(val, t, c)
    val = left_unshift_xor_unmask(val, s, b)
    val = right_unshift_xor(val, u)
    return val


def temper(val):
    y = val
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)
    return y & ((1 << w) - 1)


def twist(xs):
    state = list(xs)
    for i in range(0, n):
        y = state[i] & upper_mask | state[(i+1) % n] & lower_mask
        if y % 2 == 0:
            y = y >> 1
        else:
            y = (y >> 1) ^ a
        state[i] = y ^ state[(i+m) % n]
    index = 0
    return state


if __name__ == "__main__":
    mt = MT19937_32()
    xs = [invert_temper(mt.next()) for _ in range(624)]
    ys = twist(xs)
    for i in range(624):
        assert(mt.next() == temper(ys[i]))
