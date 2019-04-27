Introduction
------------
Reverse TCP shell consist of three syscalls, one for setting up socket that includes [socket()](http://man7.org/linux/man-pages/man2/socket.2.html), [connect()](http://man7.org/linux/man-pages/man2/connect.2.html) functions. The second syscall is [dup2()](http://man7.org/linux/man-pages/man2/dup.2.html) for file descriptors, and the last syscall [execve()](http://man7.org/linux/man-pages/man2/execve.2.html) is used to spawn shell upon successful TCP connection. Please note that most of the functions mentioned here have already been covered in my previous blog post [TCP Bind](https://ihack4falafel.github.io/Creating-Custom-TCP-Bind-Shell-~-Linux-x86/), hence this post will only focus on [connect()](http://man7.org/linux/man-pages/man2/connect.2.html) function, which is the main difference between bind and reverse shell! The post will then conclude by tying all the pieces together to create working shellcode.

socket()
--------
