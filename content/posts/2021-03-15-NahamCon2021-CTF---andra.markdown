---
title: "NahamCon2021 CTF - Andra"
date: 2021-03-15T17:09:53+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

mobile - easy

## solution

We get an `.apk` to download. Open it in [jadx](https://github.com/skylot/jadx). And check the `com.example.hack_the_app.MainActivity` class.

Run the app in a simulator (or a phone whatever you want), enter the credentials and find the flag.

{{< figure src="/images/nahamcon/andra.png" >}}
