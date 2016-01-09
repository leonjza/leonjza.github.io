---
categories:
- flick
- ctf
- security
- challenge
comments: true
date: 2015-08-21T06:36:19Z
title: flick II - vuln vm with a mobile twist
---

{{< figure src="/images/flickII_logo.png" >}}

# tl;dr
Flick II just got published on [Vulnhub](https://www.vulnhub.com/entry/flick-2,122/)! You should try it =)

## introduction
After about a year since [Flick I](https://www.vulnhub.com/entry/flick-1,99/), I have finally managed to get Flick II out to VulnHub. I learned a lot from Flick I and as a result applied it to Flick II. The making of Flick II was also a very different story. If I have to compare it to the first one (which took 3 nights to build start to finish), Flick II took *waay* longer. I think the total build / testing time must be over a month.

Originally I had a whole bunch of ideas, and after lots of trial and error, came to what it has become today. I have to give a special shouts to [@s4gi_](https://twitter.com/s4gi_) for the inspiration to go with the mobile app idea and [@barrebas](https://twitter.com/barrebas) for testing the first *really* broken version :P

## preparation
I believe Flick II will be the first Vulnerable VM on [@VulnHub](https://twitter.com/VulnHub) with a mobile twist to it. That means you will need to either install the bundled `.apk` on an Android phone, or run it in an Android emulator in order to progress on the path to root! The `.apk` is self-signed so expect Android to complain about that if you install it on a phone. Don't feel bad if you don’t trust me (aka. some random guy on the internet). If you don’t, your safest bet then is to use an emulator. The only real requirement for the `.apk` is that the mobile app must be able to speak to the VM and be run on a relatively recent Android version.

I hope you get to learn as much as I did making it!

Good luck! :D
