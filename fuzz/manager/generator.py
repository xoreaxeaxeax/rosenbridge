import random

MAX_INS = 0xffffffff
HALF_INS = 0xffff

def strategy_left_bits():
    i = 0
    while i <= MAX_INS:
        yield int('{:032b}'.format(i)[::-1], 2)
        i = i + 1

def strategy_right_bits():
    i = 0
    while i <= MAX_INS:
        yield i
        i = i + 1

def strategy_edge_bits():
    # this is a good way to evenly explore both sides, with no repeated cases
    # or missing values - iterate over sums equal to incrementing value
    yield 0
    i = 1
    while i <= 2 * HALF_INS:
        for k in xrange(i + 1):
            yield int('{:032b}'.format(i-k)[::-1], 2) | k
        i = i + 1

def strategy_random_bits():
    while True:
        yield random.randint(0, MAX_INS)

def strategy_random_left_bits():
    while True:
        v = 0
        for i in xrange(32):
            b = 0
            if random.random() < .5 * (32 - i) / 32.0:
                b = 1
            v = (v<<1) | b
        yield v

def strategy_random_right_bits():
    while True:
        v = 0
        for i in xrange(32):
            b = 0
            if random.random() < .5 * (32 - i) / 32.0:
                b = 1
            v = (v>>1) | (b<<31)
        yield v

def strategy_random_edge_bits():
    while True:
        v_1 = 0
        for i in xrange(16):
            b = 0
            if random.random() < .5 * (16 - i) / 16.0:
                b = 1
            v_1 = (v_1>>1) | (b<<31)
        v_1 = v_1 >> 16
        v_2 = 0
        for i in xrange(16):
            b = 0
            if random.random() < .5 * (16 - i) / 16.0:
                b = 1
            v_2 = (v_2<<1) | b
        v_2 = v_2 << 16
        yield v_1 ^ v_2

def strategy_all():
    strategies = [
            strategy_left_bits(),
            strategy_right_bits(),
            strategy_edge_bits(),
            strategy_random_bits(),
            strategy_random_right_bits(),
            strategy_random_left_bits(),
            strategy_random_edge_bits(),
        ]
    while True:
        for s in strategies:
            yield s.next()
