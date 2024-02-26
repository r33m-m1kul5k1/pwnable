we are given a service that can set RSA key pair and encrypt or decrypt the a message.
In the help option we are told that the encryption has *multiple exploitable bugs*.

#### RSA equation

`m^e % n = c`
`c^d % n = m`
or:
`m^ed % n = m`

`φ(n) = (p - 1)(q - 1) -> n = p*q becuase φ(p*q) = (p - 1)(q - 1)` 
`1 < e < φ(n) and GCD(e, φ(n)) == 1` GCD stands for greatest common divisor
`ed % φ(n) == 1`


## understanding the challenge
when generating a p = 11, q = 13 and e = 10, d = 12, the program said that they are `wrong parameters for key generation`.

```python
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

p = 17
q = 19
n = p*q # field n = 323
e = 5   # encryption key `e`
φ_n = (p - 1)*(q - 1) # PHI(n=323) = 288
d = mod_inverse(e, φ_n) # 173
```
this script using `GPT-4` get's a valid key pair values.

using the encryption function and passing to it more data then allocated (more then 1024) the program crashes :).

```bash
[*] '/home/reem/Desktop/pwnable/challenges/rsa_calc/rsa_calculator'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```
canary with stack is executable, and no PIE, 64 bit AMD (x86_64), little endian

### main
we get a function array each 8 bytes the first function is `set_key` and in the eighth location we got `system`.
the problem is that
```asm
ADD        EAX,0x1
CMP        EAX,0x6
JBE        IS_VALID_CHOICE # jumps below or equal (unsigned values)
```
if we enter 0 we should pass the check but we will access `-1*8 + func` if we enter -1 we will access `func + -2*8`

`g_pbuf` is 1024 bytes (plain text buff)
`g_ebuf` is 1024 bytes (encrypted buff) 

## goal
call `func + 7*8` (system) with `/bin/sh` as an argument (`rdi`)
## vulnerabilities
* each text byte after encryption is 4 cipher bytes, and because `g_ebuf` is 1024 we can overflow the `bss`. (max of 4096)
* each byte in the `g_ebuf` is 2 chars inside the printed cipher which is only 512 bytes long (so we can write max of 8192 bytes into the local buffer) (`buff_i = 1024, buff_i*4 = 4096 -> 2 char per byte (8192)`)
* I can execute `func - 8` (0) or `func - 16` (-1). which is just above `g_ebuf` ;)

## GDB

```text
b *0x00400e9c - after copying the input to the global plaintext buffer
b *0x00400f0d - after stored the encrypted text inside `g_ebuf`
b *0x00400b04 - after inputting p & q
b *0x00400bce - before calculating N 
0x6020e0 - g_ebuf
0x602500 - func
0x602560 - g_pbuf 
```

## analyzing vulnerabilities
when entered a buffer of 1024 I got the buffer in an offset of 3392. The encrypted bytes are 4 bytes of `0x0000000c`  (if we stopped before the encryption we get it without the offset, and if we don't have an overflow it doesn't get fucked)

If we give it `e` and `d` of 1 we get no encryption! the only problem is that we convert one byte to 4.
If I would create a huge N (larger then 2^32) the encryption is basically `m^ed = c`  so I need a byte (m) that when raised to `ed` gives me the needed address.
```
-SET RSA KEY-
p : 1000000
q : 1000000 
p, q, set to 16960, 16960
-current private key and public keys-
public key : 00 00 00 00 00 00 00 00 
public key : 00 00 00 00 00 00 00 00 
N set to 287641600, PHI set to 287607681
set public key exponent e : 1
set private key exponent d : 1
key set ok
pubkey(e,n) : (1(00000001), 287641600(11251000))
prikey(d,n) : (1(00000001), 287641600(11251000))
```

```
SET RSA KEY-
p : 100000
q : 100000
p, q, set to -31072, -31072
-current private key and public keys-
public key : 00 00 00 00 00 00 00 00 
public key : 00 00 00 00 00 00 00 00 
N set to 965469184, PHI set to 965531329
set public key exponent e : 1
set private key exponent d : 1
key set ok
pubkey(e,n) : (1(00000001), 965469184(398be400))
prikey(d,n) : (1(00000001), 965469184(398be400))
```

### exploit
* overflow `func` with the `g_ebuf` (1056 bytes so (264 plain-text bytes)) change it to point to the start of `g_pbuf` -> `0x602500`
* set `g_pbuf` start to a `shellcode` - (`mov rdi, /bin/sh location (say the end of g_pbuf), call func + 8*8`)

##### Note
the two 8 bytes before `system` are garbage...

## The algorithmic problem
I have one by that I need to convert to 3 bytes. a number `0x0-0xff` -> `0x602500`
```
In [21]: (0x602500)**(1/3)
Out[21]: 184.70054304869913

In [14]: (0x602500)**(1/4)
Out[14]: 50.10154623182822

In [11]: (0x602500)**(1/5)
Out[11]: 22.902395141442064

```

a function that is most close to a root of a number
`f = (0x602500)**(1/x) - (0x602500)**(1/x)(int)

Say x % y = z, if y is bigger than x, z = x... so I need N to be bigger then m^e, easy. Or I can use the modulo to create the number I need (`0x602500`) 

`42**5 % (42**5 - 0x602500) = 0x602500` using the idea that if we get a number `A % A-target = target`  if `A-target > target`
`m^e  %  n                  = 0x602500`
So If I would choose a good `n` I would get the number I want


`n = pq == 42**(e) - 0x602500`
`ed % (p - 1)(q - 1) = 1`

`e = 5 => pq = 42**5 - 0x602500 = 124390304
so `p = 32, q = 3887197`

by calculating d we got = `96402461`

```
-SET RSA KEY-
p : 32
q : 3887197
p, q, set to 32, 20573
-current private key and public keys-
public key : 00 00 00 00 00 00 00 00 
public key : 00 00 00 00 00 00 00 00 
N set to 658336, PHI set to 637732
set public key exponent e : 5
set private key exponent d : 96402461
key set ok
pubkey(e,n) : (5(00000005), 658336(000a0ba0))
prikey(d,n) : (96402461(05befc1d), 658336(000a0ba0))

- select menu -
- 1. : set key pair
- 2. : encrypt
- 3. : decrypt
- 4. : help
- 5. : exit
> 2
how long is your data?(max=1024) : 10
paste your plain text data
*****
-encrypted result (hex encoded) -
e0320500e0320500e0320500e0320500e0320500
```

`e0320500` because `p*q` is not 124390304 its 658336 :(
I need a smaller m that `m^5 - 0x602500 > 0x602500`

I checked and `2**8 & 3887197` are the prime factorization of 124390304. And I double checked it and 3887197 is prime
```python
def is_prime(n: int):
    for i in range(2, math.floor(math.sqrt(n))+1):
        if n % i == 0:
            return False
    return True

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
```

### analyzing `set_key` input
p & q are short (2 bytes), but we input to them an integer...
n = `p*q` sign multiplication, and it's an integer so max value is 2^31 - 1, that's valid because 124390304 is approximately 2^27.
the problem is that p & q are only 2 bytes long and sign, that's the max value 2^15 - 1 = 32767 we can get with those numbers to a number bigger than 124390304
but not exactly to it.. I need a better offset...

