import time

class UninitializedRNGError(Exception):
    def __init__(self):
        super().__init__("RNG hasn't been seeded")

class MersenneTwister:
    def __init__(self, w, n, m, r, a, s, b, t, c, u, d, l, f):
        self.w = w                          # Width of the numbers
        self.w_mask = (1 << self.w) - 1     # Mask with length equal to w
        self.n = n                          # Recurrence degree
        self.m = m                          # Middle word location
        self.a = a                          # Twist matrix coefficients, as a w-bit integer
        self.u = u                          # Tempering bit shift u
        self.s = s                          # Tempering bit shift s
        self.t = t                          # Tempering bit shift t
        self.d = d                          # Tempering bit mask d
        self.b = b                          # Tempering bit mask b
        self.c = c                          # Tempering bit mask c
        self.l = l                          # MT bit shift l
        self.f = f                          # Initialization seed multiplier
        self.r = r                          # Separation point between lower and upper mask
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = self.w_mask ^ self.lower_mask
        self.state = [0 for _ in range(self.n)]
        self.index = None

    def seed(self, seed: int):
        self.state[0] = seed & self.w_mask
        for i in range(1, self.n):
            self.state[i] = (self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w - 2))) + i) & self.w_mask
        #self.index = self.n
        self._twist()

    def next(self):
        if self.index == None:
            self.seed(time.time_ns() & self.w_mask)
        elif self.index == self.n:
            self._twist()
        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return y & self.w_mask

    def _twist(self):
        for i in range(0, self.n):
            y = self.state[i] & self.upper_mask | self.state[(i+1) % self.n] & self.lower_mask
            if y % 2 == 0:
                y = y >> 1
            else:
                y = (y >> 1) ^ self.a
            self.state[i] = y ^ self.state[(i+self.m) % self.n]
        self.index = 0

    def __repr__(self):
        return f'<MersenneTwister: w={self.w}, n={self.n}, m={self.m}, a={self.a}, u={self.u}, s={self.s}, t={self.t}, d={self.d}, b={self.b}, c={self.c}, l={self.l}, f={self.f}, r={self.r}, lower_mask={hex(self.lower_mask)}, upper_mask={hex(self.upper_mask)}>'

class MT19937_32(MersenneTwister):
    def __init__(self):
        super().__init__(w=32, n=624, m=397, r=31, a=0x9908b0df, s=7, b=0x9d2c5680, t=15, c=0xefc60000, u=11, d=0xffffffff, l=18, f=1812433253)

class MT19937_64(MersenneTwister):
    def __init__(self):
        super().__init__(w=64, n=312, m=156, r=31, a=0xB5026F5AA96619E9, u=29, d=0x5555555555555555, s=17, b=0x71D67FFFEDA60000, t=37, c=0xFFF7EEE000000000, l=43, f=1812433253)
