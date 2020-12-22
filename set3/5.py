import sys
sys.path.insert(0, '..')

import time

from utils.mt19937 import MT19937_64, MT19937_32

mt = MT19937_32()
time.sleep(random.randrange(40, 1000))
seed = int(time.time())
mt.seed(seed)
time.sleep(random.randrange(10, 30))
val = mt.next()

for i in range(0, 2000):
    mt = MT19937_32()
    mt.seed(i)
    if mt.next() == val:
        print(f'Found seed: {i}.')
else:
    print(f'Seed not found')

print(f'Real seed: {seed}')
