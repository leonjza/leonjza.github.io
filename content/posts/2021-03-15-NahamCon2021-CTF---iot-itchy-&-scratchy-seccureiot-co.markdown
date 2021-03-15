---
title: "NahamCon2021 CTF - IoT Itchy & Scratchy SecureIoT Co"
date: 2021-03-15T18:22:05+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

iot - hard

## solution

*unfortunately the infra was down by the time I got to the writeup*

We're given an IP and credentials, along with a reference to mosquito. There was also a URL that accepted a username, a password and OTP.

I used [MQTT Explorer](http://mqtt-explorer.com/) to connect to the mosquito server. With a bit of patience, an office topic received a message with a "u" and "p" flag, base64 encoded.

```text
YWRtaW5pc3RyYXRvcg==
U2VDVVJlUEA1NVcwckQx
```

Decoded they are:

```text
administrator
SeCUReP@55W0rD1
```

A webcam topic also received some messages, arriving as part 1 and part 2. These were much longer base64 encoded strings, so I copied them and put them in a file. Next, base64 decoding the strings we got from the webcam produced an image.

{{< figure src="/images/nahamcon/webcam.jpg" >}}

I thought I had everything needed to login to the web interface, but the credentials were wrong for some reason. After a while, retracing my steps, I pulled the webcam parts again, and stitching them together I realise the OTP was different this time. OFC! Using the new webcam images faster, I logged in and revealed the flag.
