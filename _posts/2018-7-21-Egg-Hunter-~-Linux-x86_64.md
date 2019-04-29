Introduction
------------
Egg hunter is a technique used to capture larger payloads in memory by tagging the start of the shellcode with an egg. In most cases, egg hunters are used when you don’t have enough space to host your desired shellcode. In this post we’ll create an egg hunter for Linux x86_64 and couple it with `execve()` shellcode for testing. Please refer to my SLAE32 series of posts for more details about egg hunting.

Shellcode
---------
In efforts to experiment with skape awesome piece of shellcode, we will build a slightly different version of the egg hunter that does the following:

* No hardcoded egg marker which will effectively eliminate the need for the second egg marker check.
* Use a readable memory region as starting address which allow the exclusion of memory access check routine.

As you can see this method is indeed unreliable compared to skape’s but hey it works!

```nasm
global _start
_start:

	inc rdx               ; pop valid address into rdi
	push rdx
	pop rdi
	push 0x30313232       ; push the marker-1 into the stack
	pop rax
	inc eax               ; marker is now 0x30313233 so its not hardcoded
EggHunter:
	inc rdi		          ; increment rdi by one byte
	cmp eax,[rdi]         ; check for egg match
	jnz EggHunter         ; if not found jump to EggHunter label
	inc rdi               ; increment rdi pointer by 4
	inc rdi
	inc rdi
	inc rdi
	jmp rdi               ; jump to the shellcode
```

And as always we follow with a demo.

![](/assets/images/Egg_Hunter_Linux_x86_64/EggHunterDemo.gif)

Closing Thoughts
----------------
On behalf of all the shellcoders out there, I would like to say thank you skape for producing such an elegant shellcode that will remain glorious for years to come. All of the above code are available on my [github](https://github.com/ihack4falafel/SLAE64/tree/master/Assignment%203). Feel free to contact me for questions via Twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certiﬁcation:

[http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html](http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html)

Student ID: SLAE64–1579
