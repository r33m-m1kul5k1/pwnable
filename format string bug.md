
# `fsb`
we get a random key 8 bytes long. 

`fsb` function get's the `argv` and `envp` of the program 
* we delete `argv` and `anvp` 
* we get to execute FSB 4 times
* we convert the string inputted string to unsigned long long integer  (base 10)
* if it's the same as the key value then we run a shell :)

```bash
fsb@pwnable:~$ checksec ./fsb
[*] '/home/fsb/fsb'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
No PIE and NO canary... NX is enabled

Hints:
* format string gives us the ability to read memory on the stack... and to write to the stack (`alloca`)
* No PIE meaning we can use code addresses to jump to... and the global variables are at constant places
* No canary meaning we can overflow the stack (and we can change the stack location)
* we have **4** times to execute FSB...

To solve the challenge we can 
1. change to GOT 
	1. override `sleep` to `execve` location.
		sleep - `0x8048400`
		success - `0x804869f`
		we can write one byte at a time :) with the 4 format strings.
		
2. understand the key's random value 
	1. find `alloca` chunk size -> on the stack of main :0
	2. `c_size ^ 0x12345 = key` 
	
	```asm
	mov    eax,ds:0x804a060
	mov    edx,DWORD PTR ds:0x804a064
	and    eax,0x12345
	lea    edx,[eax+0xf]
	mov    eax,0x10
	sub    eax,0x1
	add    eax,edx
	mov    DWORD PTR [ebp-0x1c],0x10
	mov    edx,0x0
	div    DWORD PTR [ebp-0x1c]
	imul   eax,eax,0x10
	sub    esp,eax
	```
	`div    DWORD PTR [ebp-0x1c]` is line may cause a write to the stack...
	this doesn't help because it only divides by 16. so the size is not stored on the stack...
	
	directions 
	1. if we could find `esp` before we subtract from it `eax` and find `esp` after we subtract we could get the size. (`ebp` is pushed to the stack). The problem with that is that the previous `ebp` of main is `libc` `ebp`  which is not on the same memory location...
	
	2.  we could read values until we reach a value that we now is before the `alloca` extension then we can count the number of `dw` we read and do the calculation from that 
	
	
	wait a minute... the key size is 8 bytes. when `0x12345 & key`  that's no `xor` ... we only keep the `10010001101000101` bits from key that will not help us...


Writing one byte to address `0x8048400` 
I know that a can pad characters `%[param_on_stack_index]$[pad]x` (or you could just `$[num]x`)
and with `%[param_on_stack_index]$n` I can write to `param_on_stack` value.

note that the format length is only 100 bytes long so little lower then 0x64 is the max byte we can write ... that's a problem. well nope
if we use padding `printf` will add those bytes inside the program, so we can write a value from `0-0xff` 

the problem is that buf is a global var meaning it is inside the `bss`.  so we can't use a location that we specify inside it. so writing to the GOT will not work. but writing to `key`  will. at the main we pass key's location to read. so it's on the stack. the only thing left is to find it's offset from `printf` 
and write to it 4 times with a value we want. then we know the value and can input it.

```asm
mov    DWORD PTR [esp+0x4],0x804a060
mov    eax,DWORD PTR [ebp-0xc]
mov    DWORD PTR [esp],eax
call   80483e0 <read@plt>
```
here we put `0x804a060` on the stack which is the address of key.
0x08048608 - code address before format string bug
0x08048710 - code address before storing key's address on the stack

key's stack address `0xffffcc34` 
vuln `printf` stack location `0xffffa9d0` 
`(0xffffcc34 - 0xffffa9d0) / 4 = 2201`
now `alloca` is problematic because each time the offset will be different...
they knew it :).

I think the idea was to stop as from reading key's value with %s.
But it stopped us from writing to it as well.
(buf is close to key....)

another thing is I know I need to use 4 loops of format strings for writing to the same position plus 1, 2, 3. if buf2 could become our stack then we could return to the location we want.

### What I have:
1. I can read from values on the stack
2. I can write to a pointer that's on the stack 

## hints
* `alloca` makes it harder to read / write to the key
* we have 4 writes so it will be easier to over write one address to a location in memory
* buf is not on the stack so we have to use locations that are on the stack

*  No PIE meaning we can use code addresses to jump to... 
* No canary meaning we can overflow the stack (and we can change the stack location)
* we call sleep with no particular reason... (maybe to stop brut forcing the key, that's not a reason because the key is changing each run)
### ideas
* for loop idea 
	```c
	for(i=0; i<4; i++) {
		printf("Give me some format strings(%d)\n", i+1);
		read(0, buf, 100);
		printf(buf);
	}
	```
	why does we have to print `i`? maybe to help use understand the address we can write to
	I could write to `i` a negative value. that way I would have a lot of writes! I don't have it on the stack..
* reading key's value 
	If we could reach the location on the stack where key's location at, we could read the key using `%s` then inputting the correct value in `pw` the problem is that `alloca` increases the stack about `0x0-0x12345` 4 * bytes, and we don't have the offset.
	solution:
	1. find the offset of the writable stack location the offset should be 14 and it is :)
	2. write the address of key to the stack (a very long operation)
	3. access with  `%[param_on_stack_index]$s` the key's value
	what if the key value contains a null byte? we will run the program again :)
	
* using what we have on the stack
	given ![[20231107201233.png]]
	we can use the format strings to write to addresses on the stack say sleep's GOT address (`0x8048400`)
	then overwriting it's value (%n) with the code that pops a shell at `0x804869f`
	**Problem**
	Idea only uses 2 format strings. 

## Simple Direction
write an address to a pointer in the stack that way we would change the stack layout (like unlink) or write to the GOT entry of sleep somehow.

### problem
where in the stack memory we have 4 addresses that are x, x+1, x+2, x+3. 
I can influence the stack using the inputted key. but is this too late...

I need to change `esp` to point to return address. nope. not like that.

Direction
1. I need 4 consecutive addresses on the stack
2. I need to execute the shell 
	1. we ret2shell - smashing the canary with overflow? we don't have one (we need consecutive addresses on the stack, this is not related)
	2. we overwrite GOT entry (we have `sleep`, and other `fsb` used this technique)
	3. we guess the key - no way (I cannot read / write it  / deduct it from `alloca`) what if I changed read to read to the key's address? too late..

what do I have on the stack?
![[1.png]]
that's all
![[20231107201233.png]]
that's two addresses on the stack just after the RA to the main.
can I use them? they are `ebp+0x8` and `ebp+0xc` they are the `argv` and `environment` variables passed to `fsb`. this is not useable ...

on the stack I don't have much. but I do have `buf`'s address

Why do we have to use 4 `printf`es ? I can write to multiple addresses all at one go.
what's the advantage of using 4 iterations? This is the code of the iterative printf
```asm
mov    eax,DWORD PTR [ebp-0x1c] ; i's location
lea    edx,[eax+0x1]
mov    eax,0x8048878            ; the string location
mov    DWORD PTR [esp+0x4],edx  ; i's value is on the stack...
mov    DWORD PTR [esp],eax      
call   80483f0 <printf@plt>
```
I have an Idea, if `ebp-0x1c`  would hold the key's value we could print it using two loops
one for each 4 bytes integer. This idea would print the key's location...
but the `i++` is cool it will increase every value on the stack by 1. exactly what we need.
but first I need to get the initial address to there. the problem is that i's value must be lower than 4.
I could use negative numbers... the stack is at negative numbers. In this direction writing to the stack byte by byte sounds cool. the problem is that writing to `i` 's stack location will be hard the way I thought before

I can write to `argv` the address of i, then write inside i the location of `sleep` then continue an iteration and write the next byte of `sleep` using i's stack location.
the problem is that the value of `i` will be positive (sleep's address) so it will exit the loop 

So I could use `i` to write to a stack address only if `i`'s value is changed to a stack address.

each iteration I can write values starting at `0`  each write we write a 4 byte value.
each iteration I could use the output of the previous iteration (but that you could do with one format string) can I?.

wait what is that?
![[20231108192548.png]]
why did they used a global var to store the data? it's not a protection from `fsb` ?

There is a simpler solution then writing to the GOT.

`key` is below `buf2` which below `buf` so we can't get from buf to key

## Reading the Key's Value
inside the same `printf` the stack doesn't change...
```text
%134520927x %14$n end                 
```
```text
%20$x             end
```
```text
                  end
```
```text
[%20$s]           end
```
![[20231109102834.png]]
maybe on the remote machine this will work, this was a bug from the `pwntools` lib everything OK now.
![[20231109134533.png]]
but this is problematic, this is not a bug on my machine. it's a bug I can exploit? nope...
fuck.

I can 
1. understand the problem
2. take rest
3. continue with GOT.

let's override the GOT. this crashed `printf` for some reason... And I know it's not the intended solution.
wow know I understand my mistake. after reading the `sar` instruction manual. `sar`  keeps the sign value. meaning that `strtoull` expect me to input negative numbers as well!
It doesn't matter because the lower byte's (saved in `edx`) are deleted in the `mov` instruction.

The GOT solution worked, I just had to write to sleep's got location and not it's `plt` which is code segment. 
## Writeups
another solution is to override the key's value. which I thought of but it seemed more complicated so I forgot it. another writeup used `ebp`'s value to write to the stack.
`%34475c%[offset]$hn` cool idea is that you can put two formats write beside each other. 