>I made a simple brain-fuck language emulation program written in C. 
>The [ ] commands are not implemented yet. However the rest functionality seems working fine. 
>Find a bug and exploit it to get a shell. 

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
No PIE, 32 bit, and we get it's `libc` with protections. ret2libc / ROP.

# understanding the challenge

## `do_brainfuck`
```
+ | ++(*p) ; adds 1 to the value pointed by `p`
, | *p = getchar() 
- | --(*p)
. | putchar(*p) ; calls putchar with the value of one character of `p` 
< | --p 
> | ++p
[ | puts [ and ] not supported 
```

### main
```
p = &tape
we call do_brainfuck for each character inside the inputted string.
```
because I don't have control on the environment :/
# vulnerability
we have a control pointer with control on its value. 
# Abilities
* I have `libc` leaks 
* I can write to the GOT, and with that jump to execute any line of code I want...

So I can jump between `glibc` function calls.
# ideas of attack
* overwrite `strlen` to `system` and change `s` to start with `/bin/sh` 
    the problem is that each iteration `strlen` is called, so only after it was completely overwritten we can call it.
    if I could loop inside `do_brainfuck` then this could work
* overwrite `puts([ and ] ...)` as one line before `memset` inside main and overwrite `memset` to system, the problem is that `s` is relative to the current ESP.
    if we calculate the location which the `memset` will take as `s` we can see it's inside `s` at an offset of 664.  (`-0x430-44+0x434-0x408 = -0x430`)
    let's check if we changed `memset` address to system and padded 664 bytes then added `/bin/sh` we will get a shell.
* overwrite `putchar` as system p is only one byte so the address is not transferred.

## analyzing `S` access
we write S to -0x404, and upwards. 
`do_brainfuck` does `esp -= 0x2c`
when we jump to main after -0x2c , S was -0x430, which isn't what we wanted. 

but using `fgets` I can overwrite the return address of `do_brainfuck` then I can `ret2system` and specify the string
![[Pasted image 20231224164741.png]]
the problem is that `strlen` cannot be overwritten...
so I can use `memset` as `fgets` then `fgets` to get me back to the ret of `do_brainfuck`. 
1. change `puts` to 0x08048710 (main `memset`) and hope that remotely `esp+4` will be larger then zero.
2. change `fgets` to 0x0804866B (ret of `do_brainfuck`)
3. write the address of `/bin/sh` then the address of `system`
Tada

The problem is that `fgets` supposes to get a stream (stdin) and I cannot supply both S and an stdin stream.
So I can use `gets` :)

I forgot the push EIP when we call `fgets` that exactly enough to fuck us up :).
![[Pasted image 20231224172410.png]]

attack flow
1. jumping to `memset` which will write to `esp+0x2c` the `/bin/sh` and `system` addresses
2. then calling `fgets` pushes EIP (`esp -= 4`) now we 0x30 distance from our input.
3. then inside `do_brainfuck` we `esp += 0x2c` and ret. to 4 bytes before our input.
if I could increase `esp` by 8 bytes then we would returned to system with `/bin/sh`.
GIVE ME A ROP GADGAT :)
`0x0005b980 : xor eax, eax ; add esp, 0x6c ; ret` inside `libc`
YAY now it's time :)

### calculations :)
we write to `esp+0x2c` using `gets`
when calling the gadget we decrease `esp` by 4, we add it `0x6c` and `ret` so `esp+0x68` is where the ret address should lay
that means that we should write 56 padding bytes then the address of `/bin/sh` then `system` at 60.

### The final attack flow
* `fgets`, leak `glibc` base and rerun main
* `fgets`, `memset = gets` , `fgets = gadget` , `putchar = main of memset` rerun main of `memset`
* `fgets (gadget)`, we send to `gets` `X*56 + /bin/sh + system` **the wrong order**

### problem
the gadget address is known only after the command execution
* rerun main.
* search a gadget inside the elf, nope there is none that helpful.

### problem
I called system but it crashed... lets try to pass nulls as the second and third parameters. didn't worked even if I added exit after the call to system.
for some reason the child exited with 127 only on gdb we could see this info. 
https://stackoverflow.com/questions/1763156/127-return-code-from according to this answer it means that `/bin/sh` didn't found the program that I wanted to run.
using `execv` caused the program to exit with 60. let's look at similar challenges...

the problem was the order of arguments and that we called system with a `ret` so we should have padded the argument with EIP.

# tech stuff
patching bf_libc.so to bf. just used `pwninit` :)
`0x0804A080 - p`

# writeups
### easy version
because `memset` and `fgets` write to the same stack location relative to `esp`, `memset` could fill it with `/bin/sh` using `gets` and `fgets` could become `system`.
### `strlen` version
change `strlen` bytes to system that each change will result an address with `ret`. He created a graph from `strlen` address to `ret` locations in `libc`. Then he found a path that will take him to `system` address. Crazy idea.

other people used `stack_ck_fail` and `puts` and `setvbuf`. 

# thinking flow
* I got the ability to change any `libc` function to any address
* the problem is that I need the stack of system to contain `/bin/sh`
* if I overwrite `memset` with `gets` and input the pointer to `/bin/sh`
     I could fill the stack of `esp+0x2c` with that address. 
* `fgets` first argument is also `esp+0x2c` so I can just replace it with `system` :)

## lessons
to preserve
* analyze in depth an idea, **run wild** with your ideas
to improve
* when solving a problem with a new idea think of multiple ideas and explore the best