
### echo1
if you can jump to any location. You could 
1. reuse functionality inside a function
2.  use ROP gadgets
3.  use global variables (`bss`)

* use `ELF` function in `pwntools` to prevent constants, then do `elf.symbols['main']` or use the `got` and `plt` .
* You can use `libc` and `shellcraft`. 
* You can `sendlineafter` and you don't need to wait for `recv`, you can just send :).
* use `wget`
### fix
[building a shellcode](https://bista.sites.dmi.unipg.it/didattica/sicurezza-pg/buffer-overrun/hacking-book/0x2a0-writing_shellcode.html)
ask what are the causes of the problem?
`ulimit -s unlimited` - extends the stack :) 

### `ascii_easy`
symbolic links and path variables can simplify a problem
use `scp -P 2222 source target` 
`scp -P 2222 user@pwnable.kr:~/* .` or 
`scp -P 2222 ./sol.py user@pwnable.kr:/tmp/myfolder`


### `tiny_easy`
yea you could change `argv[0]` in python
```python
process(["\x11\x11\x88\xff"],executable="./tiny_easy",env=dic)
```

man just run the dam program... remotely!
