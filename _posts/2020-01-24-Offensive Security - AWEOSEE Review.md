---
layout: single
title: Offensive Security - AWE/OSEE Review 
date: 2020-1-24
classes: wide
header:
  teaser: /assets/images/AWE/IMG_2949.jpg
---

Introduction
------------
This writeup is aimed at folks who are ~~contemplating~~ preparing to take on the AWE course offered by OffSec at Black Hat but are not quite sure where to start. Although you may think taking the course is just the natural continuation after OSCP and OSCE,  the reasoning behind my decision is the fact that the course is all about Windows exploitation, which is what I personally want to excel at. I have nothing against \*nix, in fact I use it on daily basis, I'm just not interested in it from exploitation standpoint. My interest revolves around logic bugs and kernel exploitation for the most part.

![](/assets/images/AWE/IMG_2949.jpg)

Registration
-------------
In order to get a seat for the course you have to have a game plan, otherwise registration will be full before you know it. In my experience I registered with [Twilio](https://www.twilio.com/) SMS service and then modified a Python script provided in their website to send me text message as soon as `https://www.blackhat.com/us-19/training/` URL goes live using cronjobs. The script can be found [here](https://gist.github.com/ihack4falafel/11387e6ec4e6381802c50cbf0dc58449).

![](/assets/images/AWE/BHReg.PNG)

Pre-course Preparation
----------------------
Below is my preparation based on information provided by OffSec AWE syllabus as well as the course details/prerequisites section in chronological order:

* Completed the course and exercises offered by the SecurityTube Linux Assembly64 Expert (SLAE64). There was nothing new really in terms of content if you had already taken the 32-bit version; however,I thought it was a good place to reinforce assembly basics and, more importantly, familiarize myself with 64-bit architecture.
* Studied and wrote programs in C/C++.
* Attended the Corelan Advanced Exploit Development course instructed by Peter Van Eeckhoutte where I learned great deal about Windows Heap and WinDbg. Yes, it was 32-bit based course, but the arcane knowledge acquired was priceless nonetheless.
* Learned reverse engineering basics using tools like IDA pro, Binary Ninja, and dnSpy.
* Practiced basic reverse engineering concepts by taking apart handful of crackmes written in multiple programming languages.
* Built exploits using ROP chains (Return-oriented Programming) using automated scripts mostly with minor modifications.
* Studied about kernel exploitation and then built exploits for [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
* Followed OJ Reeves two parts YouTube session [Hackingz Ze Komputerz](https://www.youtube.com/watch?v=pJZjWXxUEl4) where he walks thru reversing and exploiting Capcom.sys vulnerable driver.
* Watched this video by OALabs few times [WinDbg Basics for Malware Analysis](https://www.youtube.com/watch?v=QuFJpH3My7A).

Some of my pre-course preparation shenanigans can be found [here](https://github.com/ihack4falafel/OSEE). 

Pre-course Challenge
---------------------
Few months prior to course start date OffSec will email you the pre-course challenge which you need to complete. The challenge represents the minimal technical background required to get the most out of the experience. I found the challenge to be quite entertaining, but if you're having difficulty solving it OffSec suggests either reconsidering taking the course or contacting them explaining the issues you're facing and they'll provide recommendation on study materials that you will want to complete before heading to Vegas.

Course
------
The course consists of 4 modules that gets progressively harder with multiple exercises and extra miles (homework). The first module discusess in-depth custom shellcoding on 64-bits systems and what it adds compared to 32-bits. The second module we take deep dive into VMWare internals and ultimately preforming guest-to-hosts escape. The third module is all about Edge exploitation where we learn about things such as type confusion bugs and sandbox escapes. Lastly, we switch gears to kernel space exploitation. Not to mention learning how to bypass modern protections such as ACG, CFG, and SMEP to name a few and building version independent exploits.

From my experience, I thought the course was quite intense, in the sense that the amount of knowledge dropped was mind blowing but exciting at the same time. The course was mostly hands-on as you'd expect from OffSec and I could tell a lot of effort has been put into making sure the content is well outlined and up-to-date. It's worth mentioning the instructors were always looking to help the students without giving too much information, in fact they offered post course support. I can't believe I'm going to say this, but I truly miss the course now that I'm thinking about it and I'm glad I was able to put names to faces and make new friends just by attending. 

Pre-exam Preparation
---------------------
The game plan for the exam was to thoroughly review the course content again and complete all exercises including extra miles to fully understand the concepts taught during the course. Once done with reviewing the course I studied JavaScript essentials which I felt I was lacking during the course and practiced building ROP gadgets by hand using [rp++](https://github.com/0vercl0k/rp). The following are some of the resources gathered during exam preparation:

* [Windows SMEP bypass: U=S - Nicolas Alejandro Economou & Enrique Nissim](https://www.youtube.com/watch?v=QGf0-jHFulg&vl=en)
* [DEF CON 25 - Morten Schenk - Taking Windows 10 Kernel Exploitation to the next level](https://www.youtube.com/watch?v=Gu_5kkErQ6Y)
* [DEF CON 25 - Saif El Sherei - Demystifying Windows Kernel Exploitation by Abusing GDI Objects](https://www.youtube.com/watch?v=2chDv_wTymc)
* [Part 19: Kernel Exploitation -> Logic bugs in Razer rzpnk.sys](https://www.fuzzysecurity.com/tutorials/expDev/23.html)
* [I Got 99 Problem But a Kernel Pointer Ain’tOne - There’s an info leak party at Ring 0](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf)
* [Bypassing Control Flow Guard in Windows 10](https://improsec.com/tech-blog/bypassing-control-flow-guard-in-windows-10)
* [Bypassing Control Flow Guard in Windows 10 - Part II](https://improsec.com/tech-blog/bypassing-control-flow-guard-on-windows-10-part-ii)
* [Bypass Control Flow Guard Comprehensively](https://www.youtube.com/watch?v=K929gLPwlUs)
* [Windows Code Injection: Bypassing CIG Through KnownDlls](https://tyranidslair.blogspot.com/2019/08/windows-code-injection-bypassing-cig.html?m=1)
* [Bypassing Mitigations by Attacking JIT Server in Microsoft Edge](https://googleprojectzero.blogspot.com/2018/05/bypassing-mitigations-by-attacking-jit.html)
* [Floating-Poison Math in Chakra](https://www.thezdi.com/blog/2018/8/22/floating-poison-math-in-chakra)
* [BlueHat IL 2019 - Bruno Keith - Attacking Edge Through the JavaScript Just-In-Time Compiler](https://www.youtube.com/watch?v=lBL4KGIybWE)
* [VMware Exploitation](https://github.com/xairy/vmware-exploitation)

Additionally, I started researching multiple well-known software drivers (I'm interested in kernel exploitation, remember?) and ultimately found my first kernel bug, that is [CVE-2019-18845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18845). At that point I felt I was ready to take the test which was right around early October however, the only available date was my son's birthday during that month so I ended up booking the exam on November 13, 2019.

Exam
----
The exam consisted of few challenges that you needed to solve within ~3 days and then you were given another 24 hours to write the report. I was able to accumulate enough points to pass the exam by the second day and then used the time left to write the report which took longer than anticipated. I felt the exam was somewhat hard, but if you fully understand the topics discussed during the course you should be fine. I would like to point out that I had issues with my exam VPN connection (well it was mostly my fault to be honest) but the support was very prompt in resolving said issues and I was able to connect after an hour more or less.

![](/assets/images/AWE/IMG_3292.JPG)

Conclusion
----------
This course made me realize how little I knew when it comes to Windows exploitation and how challenging it can be to build exploits on modern Windows. I now not only appreciate what goes behind the scenes to build exploits but also the team at Microsoft who works relentlessly to improve/build new mitigations that makes exploit developers life more difficult. In addition, I have used the knowledge acquired from the course to develop proof-of-concept exploits on multiple occasions while disclosing bugs to vendors which is great. Lastly, I would like to thank OffSec on such life changing experience and [@h0mbre_](https://twitter.com/h0mbre_), [@TJ_Null](https://twitter.com/TJ_Null), and wetw0rk for reviewing this blog post.
