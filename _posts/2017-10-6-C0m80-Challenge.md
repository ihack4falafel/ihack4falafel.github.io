Introduction
------------
This post is walk-through of how to root C0m80. The challenge is considered hard or at least it was for me. Shout out to [@3mrgnc3](https://twitter.com/3mrgnc3) for putting it together, I did come out the other end with new tricks up my sleeves. You can download the VM from [here](https://www.vulnhub.com/entry/c0m80-1,198/). Lastly, my apologies for the lengthy post, I tried my best to keep it to minimal.

Walkthrough
-----------
Enumeration is KEY if you plan on conquering c0m80. We’ll start by firing off a quick n’ dirty recon script I made, which consist of nmap, nikto, dirb, and enum4linux. You can download the script from [here](https://github.com/ihack4falafel/OSCP/blob/master/BASH/Recon.sh), I also took the liberty of removing all of the junk output that we don’t care about!

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
1 0.39 ms 192.168.127.141

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

Couple of things stood out for me going through the results, the web server, RPC (possible NFS export), and SMB. Started exploring URL(s) from nikto and dirb results one by one, until I bumped into mantis webpage.




