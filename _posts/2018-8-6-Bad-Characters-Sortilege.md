Introduction
------------
In exploit development world there will be times where you find yourself working with an executable that enforces a very limited character set in which you can use to craft your shellcode. This rather short blog post will talk about how you can use bad characters to your advantage and ultimately produce otherwise prohibited instructions in your shellcode.

Synopsis
--------
While prepping to take the OSCE course earlier this year, I discovered 0-day in the register function across Flexense products, see the link [EDB-ID: 44455](https://www.exploit-db.com/exploits/44455/). At the time Structured Exception Handler (SEH) subject was fairly new to me, let alone manual shellcoding. I struggled for days trying to figure out a way to overcome the issue before deciding to craft `WinExec()` shellcode for reasons that are beyond this blog post. Typically the register function will only accept alphanumeric characters for obvious reasons and as such anything beyond `\x7f` character is considered bad, this includes pointers and instructions.

![](/assets/images/Bad_Characters_Sortilege/ascii.png)

During the process of crafting the shellcode, I made sure to stay within the range of allowed characters but then reached a point where I needed `JMP ESP` instruction but couldn’t find a clean pointer that I can use. To overcome this issue I decided to pass previously identified bad characters to the program to see if any gets converted to an opcode that I could use (in this case was looking for `RET` instruction) and ultimately found that `\xff` end up as `\xc3`, bingo! So I manually encoded `JMP ESP` pointer by preforming arithmetic operations on `EAX` register and pushing it onto the stack.

At this point all we need really is place `\xff` at the end of the shellcode which will effectively pop previously pushed onto the stack `JMP ESP` pointer to `EIP` and execute it! The following is a demo of the exploit, please check the above exploit link for more details.

![](/assets/images/Bad_Characters_Sortilege/PoC.gif)

Final Thoughts
--------------
The main takeaway here is always look for ways to circumvent restrictions and don’t take bad characters for granted.. Hopefully this blog post will aid folks who run into similar situations or rather help them come up with more creative ways to solve the problem at hand.
