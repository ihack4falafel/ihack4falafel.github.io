<!--
---
layout: single
title: AWE Course Review 
date: 2016-6-23
classes: wide
header:
  teaser: /assets/images/AWE/AWE_BH2019.JPG
--- 
-->

Introduction
------------
This writeup is aimed at folks who are ~~contemplating~~ preparing to take on the AWE course offered by OffSec at Black Hat but not quite sure where to start. Although you may be thinking taking the course was just the natural continuation of OSCP and OSCE however, in my case the real reasoning behind my decision is the fact the course is all about Windows exploitation which is what I personally want to excel at. I have nothing against \*inux in fact I use it on daily bases I'm just not interested in it from exploitation standpoint. My interest revolves around logic bugs and kernel exploitation for the most part.

Registeration
-------------
In order to get a seat for the course you'd have to have gameplan, otherwise they are gone before you know it. In my case I regsitered with [Twilio](https://www.twilio.com/) SMS service and then modififed the Python script provided in thier website to send me text message as soon as `https://www.blackhat.com/us-19/training/` URL goes live. The script can by found [here](https://gist.github.com/ihack4falafel/11387e6ec4e6381802c50cbf0dc58449).

Pre-Course Preparation
----------------------
Here is my reparation based on information provided by OffSec AWE syllabus as well as the course details/prerequisites section in chronological order:
* Completed the course and exercises offered by the SecurityTube Linux Assembly64 Expert (SLAE64). Although there was nothing new really in terms of content if you had already taken the x86 version, I thought it was a good place to reinforce assembly basics and get myself fimilar with x86_64 architecture.
* Studied and written programs in C/C++.
* Attended the Corelan Advanced Exploit Development course instructed by Peter Van Eeckhoutte where I learned great deal about Windows Heap and WinDbg. Yes, it was 32-bit based course but the arcane knowledge acquired was priceless nonetheless.
* Learned reverse engineering basics using tools like IDA pro, Binary Ninja, and dnSpy.
* Practiced basic reverse engineering concepts by taking apart handful of crackmes written in multiple programming languages.
* Built exploits using ROP chaines (Return-oriented Programming).
* Studied about kernel exploitation and then built exploit for [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver).
* Followed OJ Reeves two parts youtube session [Hackingz Ze Komputerz](https://www.youtube.com/watch?v=pJZjWXxUEl4) where he wlaks thru reversing and exploiting Capcom.sys vulnerable driver.

[To be continued]
