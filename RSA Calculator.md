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