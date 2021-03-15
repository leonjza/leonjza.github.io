---
title: "NahamCon2021 CTF - Resourceful"
date: 2021-03-15T17:29:32+02:00
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

We get an `.apk` to download. Open it in [jadx](https://github.com/skylot/jadx). And check the `com.congon4tor.resourceful.FlagActivity` class. There is a reference to the string `flag{` and resource called `md5`.

{{< figure src="/images/nahamcon/resourceful_flag.png" >}}

Checking out the resources section, the `md5` is revealed to complete the flag.

{{< figure src="/images/nahamcon/resourceful_md5.png" >}}
