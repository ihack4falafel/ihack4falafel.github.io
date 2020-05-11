---
layout: single
title: Patch Diffing with Ghidra
date: 2020-5-11
classes: wide
header:
  teaser: /assets/images/PatchDiffingwithGhidra/PatchOverview.PNG
---

Introduction
------------
This blog post is intended for folks who are interested in reverse engineering security patches, but don't have access to expensive tools such as IDA Pro to perform such tasks. First off, we will create a program that introduces a common bug class such as buffer overflow and then patch said bug. Once done, we will use BinExport for Ghidra to export both versions of the program and then use BinDiff to analyze the patch. By the end of this blog post, you should be somewhat comfortable investigating patches using BinDiff.  

Toolage
-------
We will be using the following tools:

* [Microsoft Visual Studio Community 2019](https://visualstudio.microsoft.com/downloads/) version 16.5.1.
* [Kali Linux](https://www.kali.org/downloads/) virtual machine.
* [Ghidra](https://ghidra-sre.org/) version 9.1.2 is software reverse engineering (SRE) suite.
* [BinExport](https://github.com/google/binexport/tree/master/java/BinExport) is the exporter component of BinDiff.
* [BinDiff](https://www.zynamics.com/bindiff.html) version 6 is a comparison tool for binary files, that assists vulnerability researchers and engineers to quickly find differences and similarities in disassembled code.

Vulnerable Program
------------------
The following is C program that is vulnerable to buffer overflow due to the use of unsafe [gets](https://www.tutorialspoint.com/c_standard_library/c_function_gets.htm) function. I'm going to assume the reader is already familiar with C programming and buffer overflows, if not then Google is your friend.

```C
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[14];

    printf("Enter password: ");
    gets(buf);

    if (strcmp(buf, "falafelislife"))
    {
        printf("Wrong password!\n");
    }
    else
    {
        printf("You're good.\n");
    }

    return 0;
}
```

The programmer here (well technically me ;D) is making an assumption that the user already knows the password should be no longer than 13 characters and as such `char buf[14]` null-terminated array is used to store the password. Let's confirm the program work as expected.

![](/assets/images/PatchDiffingwithGhidra/VulnerableProgram.PNG)

As we can see above the program works and we were able to corrupt the stack by providing 14 character password.

Patch
-----
I'm by no means a good programmer, but I believe replacing [gets](https://www.tutorialspoint.com/c_standard_library/c_function_gets.htm) with [fgets](https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm) should mitigate the issue. Let me know if there is a more elegant way to fix it.

```C
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[14];

    printf("Enter password: ");
    //gets(buf);
    fgets(buf, 14, stdin);

    if (strcmp(buf, "falafelislife"))
    {
        printf("Wrong password!\n");
    }
    else
    {
        printf("You're good.\n");
    }

    return 0;
}
```

After applying the fix we no longer get the debug error message when entering passwords with more than 13 character.

![](/assets/images/PatchDiffingwithGhidra/PatchedProgram.PNG)

Setup
------
At this point, we will follow the instructions outlined [here](https://github.com/google/binexport/tree/master/java/BinExport) to set up BinExport for Ghidra inside our Kali Linux VM. First and foremost, we make sure we have all the required dependencies installed and then we build BinExport using `gradle`.

![](/assets/images/PatchDiffingwithGhidra/BuildwithGradle.PNG)

If all goes well you should see .zip file under `dist` folder.

![](/assets/images/PatchDiffingwithGhidra/ZipFile.PNG)

We then install BinExport extension by loading the zip file in Ghidra under `File->Install Extensions...` and then verify installation.

![](/assets/images/PatchDiffingwithGhidra/BinExportExtenstionGhidra.PNG)

Now we should have everything we need to export to BinDiff.

Patch Analysis
--------------
Let's load both vulnerable and patched programs into Ghidra and make sure to run them through initial analysis. I did follow the instruction mentioned [here](https://github.com/google/binexport/tree/master/java/BinExport) and enabled the `aggressive instruction finder` option to get better coverage in the export. Now we export programs using BinExport extension.

![](/assets/images/PatchDiffingwithGhidra/BinExportPrograms.PNG)

And then load them into BinDiff by creating a new workspace.

![](/assets/images/PatchDiffingwithGhidra/NewDiff.PNG)

We get nice overview of both programs that show things like hashes, architecture, etc.

![](/assets/images/PatchDiffingwithGhidra/BinDiffOverview.PNG)

Next we right-click on `Overflow v1.1.exe vs Overflow v1.0.exe` and then hit `Open Diff` which create several tabs. 

![](/assets/images/PatchDiffingwithGhidra/BinDiffTabs.PNG)

I will briefly summarize each tab, but feel free to check BinDiff manual [here](https://www.zynamics.com/bindiff/manual/) for more details:

* **Call Graph:** After initial matches for the two executables are created, call-graphs (graphs which contain information about the calls-to relations between functions) are used to generate more matches.
* **Matched Functions:** There are multiple matching algorithms used to determine whether or not the given function is similar such as hash and edge matching based algorithms. In this view, you can quickly determine what functions were changed based on similarity and confidence values among other factors.
* **Primary Unmatched Functions:** Displays functions that are contained in the currently open database and were not associated with any function of the diffed database.
* **Secondary Unmatched Functions:** Contains functions that are in the diffed database but were not associated to any functions in the first.

Navigating to the `Matched Functions` tab, I noticed quite a few changes considering how small the patch was, however, `FUN_140011840` quickly caught my attention due to the number of basic blocks compared to other functions that were changed.  Please note lines are colored according to how similar the matched functions are where greener colors indicate a high similarity while red tones indicate weak matches.

![](/assets/images/PatchDiffingwithGhidra/MatchedFunctions.PNG)

Before we continue, I would like to touch on similarity and confidence scores:

* **Similarity:** A value between zero and one indicating how similar two matched functions are. A value of exactly one means the two functions are identical (in regard to their instructions, not their memory addresses). Values less than one mean the function has changed parts.
* **Confidence:** A value between zero and one indicating the confidence of the similarity score. Note that this value represents the calculated confidence score for the matching algorithms that are enabled in the configuration file.

Let's double-click on `FUN_140011840` function and see if that's where the patch was applied.

![](/assets/images/PatchDiffingwithGhidra/PatchOverview.PNG)

We can see from the image above this is the main function. The following are all possible colors inside this view and what each color represent:

* **Red:** Indicates basic blocks where BinDiff was unable to find equivalents.
* **Yellow:** Indicates nodes for which the algorithms could find equivalents, but which had some instructions changed between versions.
* **Green:** Indicates basic blocks that have identical instruction mnemonics in both executables.

Now before we go over the changes, here's what `fgets` function looks like and where the arguments should be placed based on `__fastcall` calling convention:

```C
char *fgets(char *str, int n, FILE *stream)
RCX = This is the pointer to an array of chars where the string read is stored.
RDX = This is the maximum number of characters to be read (including the final null-character). Usually, the length of the array passed as str is used.
R8  = This is the pointer to a FILE object that identifies the stream where characters are read from.
```

* `XOR ECX, ECX`- make sure `ECX` is equal to zero.
* `CALL qword ptr[PTR__acrt_iob_func_140020310]` - `__acrt_iob_func` is an internal CRT function referring to `stdin` which is used by default in Visual Studio. The return value will be stored in `RAX`.

![](/assets/images/PatchDiffingwithGhidra/acrt_iob_func.png)

* `MOV R8, RAX` - move the file object pointer from `RAX` to `R8`.
* `MOV EDX, 0xe` - move value of `14` to `EDX`. 

To be complete, I should mention the pointer to the buffer that will hold the data is then stored in `RCX` via `LEA RCX, [RBP, 0x8]` and ultimately a call to `fgets` is made which matches the patch that was put into place. At this point, you might be asking yourself what about `fgets` function call? Why wasn't it marked as a change from the unpatched version? The reason `CALL qword ptr[PTR_fgets_140020308]` was not highlighted, and please correct me if I'm wrong, is due to no changes in the mnemonic itself rather the operand which as far as I know BinDiff does not account for.


Conclusion
----------
Hopefully, this blog post has shed some light on the subject of patch diffing and I highly recommend reading through BinDiff [maunal](https://www.zynamics.com/bindiff/manual/) to fully understand what goes behind the scenes to produce the final changes, in fact most of what you have read was based on information taken from it. Lastly, Huge thanks to [@AdmVonSchneider](https://twitter.com/AdmVonSchneider) for making BinDiff and BinExport available and [@h0mbre_](https://twitter.com/h0mbre_) for reviewing.
