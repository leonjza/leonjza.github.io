---
categories:
- oscp
- try harder
- offensive security
- penetration testing
- certification
comments: true
date: 2014-11-22T06:33:34Z
title: trying harder oscp and me
---

{{< figure src="/images/oscp_logo.png" >}}

As I am writing this post, it's the "morning after" I have received the much awaited email confirming that I have successfully completed the OSCP Certification requirements!

In order to obtain OSCP Certification, one must complete some time in the Penetration Testing with Kali Linux labs followed by a grueling 24 hour exam challenge.

One really big realization that I came to was the fact that one should not attempt to do this if your goal is simply to get the OSCP Certification. Doing PWK is a excellent opportunity to learn and rushing it may cause you to not make it in the exam.

Below is a summary of my experience obtaining OSCP.

<!--more-->

## preperation
Taking OSCP was something I wanted to do for quite some time. I have read a number of blogs and experiences from people that have done it, and the most important take from all of that was the amount of time it took. Considering I had a full time job, it was hard for me to gauge exactly how much lab time I would have needed. So, I decided on getting 3 months to start off with.

I also found a [syllabus](http://www.offensive-security.com/documentation/penetration-testing-with-kali.pdf) online to get an idea about what is covered in the training and prepared myself mentally for what lies ahead.

With the payments and logistics out of the way, I was scheduled to start 8 Aug '14.

## first impressions
On the morning of 8 Aug I receive a email with all of the course material and VPN details. I quickly sifted through the videos and pdf materials and decided to have a early look at the lab machines. My very first reaction was "Where the heck do I start?". Everything was a little bit of a information overflow, and there is no clear "do this, then this, then this.". One is given a overview of what is required from a documentation perspective, but that is about it.

It was clear that I needed a plan of action. After some time, I decided to watch the videos thoroughly and after that, work through the PDF. The PDF detailed a whole bunch of exercises that had to be completed and documented too.

One of the more important points to make here was the fact that 2 reports are required in the end. The exam report is of course compulsory but the lab report is optional. However, should you struggle to meet the requirements for the exam challenge, it *may* be possible to gain some points from your lab report. Of course, if you did not provide one, that chance you have is out the door. With that in mind, I decided to leave the exercises to later when I start to compile the actual lab report and jump right into the labs. In retrospect, I wish I decided to do the exercises first as there were some key elements taught to gear you for the labs.

## meeting the PWK labs
The machines in the lab were of varying difficulty for me. Some of them were almost a little too easy to pwn, while others were way more of a challenge. You are faced with a *public* network, and ultimately have to gain access to the *admin* network that is nested deeper in. Using some pivoting techniques, the *admin* network was definitely the most fun for me.

I learnt a few hard lessons here though. My initial approach was to start at one IP, and work my way through trying to pwn them. Once I reached a machine I could not crack, I decided to move on. This worked ok for a while, until I came to a point where I was not able to progress any further. I had to go back and loot the machines I had already pwnd, and that lead to learning more about the surrounding networks and their vulnerabilities.

Almost all of the lab machines are vulnerable to "known" vulnerabilities. This is not 0day training. However. What I really appreciated about the PWK labs was the fact that even though the vulnerabilities are known, in many cases you have to take proof of concept exploits, and modify them to actually fit your current environment and situation. There are not a lot of *push button, get bacon* scenarios, and quite a few exploits require you to actually understand the vulnerability and be able to bend it to suit your needs. This is where the requirement to be able to script/code a little comes from.

{{< figure src="/images/oscp_try_harder.png" >}}

Offensive Security have a [mantra that many know](http://www.offensive-security.com/when-things-get-tough/). *Try Harder*. This is the classic response a student gets when asking for hints/help. It is probably the worst answer you can get when you have been bashing away at something for such a long time, but also the most rewarding when you *finally* get it.

## pwning lab machines to prepare for the exam
Many of the lab machines have vulnerabilities that have Metasploit modules. You can easily try the *push button, get bacon* technique on them. But, it is important to note that in the exam, you will be restricted to what you can use. In fact, there are very clear Metasploit restrictions. From not being allowed to use Metasploit at all, to only being allowed to use certain features of the meterpreter shell. With this in mind, I will always **highly** recommend you attempt to exploit as much as possible in the labs without the use of Metasploit.

Not being allowed to use Metasploit for me personally was not really such a big deal. Having practiced quite a lot in the labs to *not* use Metasploit, it was easy to find PoC exploits and modify them as required. I did make a lot of use of **msfpayload** to generate shellcode, but other than that, plain bind/netcat shells were in the order of the day.

## last days of the PWK lab
My Lab time was scheduled to end 8 nov 2014. I have spent easily about 4-6 hours a night (where possible) in the labs with even more time on the weekends. With about a week left, I turned my focus to the 3 harder machines in the labs, known as *pain*, *sufferance* and *humble*. These 3 machines definitely were the hardest of the bunch, but I managed to pwn them too. By 7 Nov, I had successfully managed to pwn all of the lab machines and had the first version of my Lab report done.

It was time to book the exam.

## OSCP Exam
I managed to secure 19 November @11am as the date I was going to attempt the OSCP Certification Challenge. This actually worked out great for me, as it gave me enough time to catch up on some lost sleep, as well as polish the lab report I was going to send in with my Exam report.

{{< tweet 534967808619470849>}}

The day before the exam, I stocked up on some [energy drinks](https://twitter.com/leonjza/status/534967808619470849) and made sure I get a good nights sleep while trying to keep my mind off the exam until it was time.

The morning of the exam I was not able to keep the excitement in any longer, and I was up at 8am already getting ready for the challenge. My playlist was ready to jam, distractions such as Skype, Steam, Twitter and IRC were all closed, when finally my email with Exam instructions arrived.

The exam instructions outlined exactly how much points each machine you have to pwn is worth, as well as all the restrictions that apply to each machine. You also have 23hours 45minutes before your exam VPN will expire, whereafter you have another 24hours to submit your documentation. There are 100 points obtainable in the exam, of which you have to get 70 to pass.

Within about 5hours, I had secured roughly 50 points. From there, things were going a lot slower. 10 hours in, I went up to 60 points. At about 2am the next morning, the fatigue was playing a massive role and I decided to go take a power nap. I set the alarm for 3am. Of course, I didn't actually sleep, but just letting your body lie down and rest while you ponder about what your next move will be proved to help a lot.

At about 6am that morning, I was up to 80 points. This is technically already enough to pass (assuming I did not make a mistake and break a rule), but I wanted to try get all of the points I could possibly get. Fast forward to about 9am that morning, I decided to call it and start getting a rough draft of the exam report ready. I wanted to make sure I had all of the screenshots and console output I needed before the VPN expired.

## the reports
At exactly 1045 that morning, the VPN dropped and the challenge was over. I now had 24 hours to submit the report. Considering I have been up for about 28 hours now (with a 1hour power nap), I thought it best to actually get some sleep and finish the report off afterwards.

After about 6 hours of ZZZ's, I had a proper dinner and sat down to complete the exam report. The Lab report took me almost 2 weeks to complete, but the exam is nowhere near as much work and was definitely doable in 24hours. 10pm that evening I submitted both of my reports and went straight to bed :D

## certification
Almost exactly 24 hours later, I get the confirmation email that I have passed:

{{< figure src="/images/oscp_complete.png" >}}

Dem feels were good :D

## oscp faq
I had quite a number of questions before I started the PWK training. So, let me try and answer a few for others that may have similar questions:

**q: I am not really in a Security Role now, will this be helpful?**
a: Yes! I am convinced you will learn about things you maybe never even realized was possible. In fact. Not will you learn about common security flaws, you will have the expertise to identify and exploit them as well.

**q: Is scripting/development experience really required?**
a: I'd definitely say yes. To narrow it down, I would say that you don't necessarily have to have some mad ninja l33t dev skillz, but hacking away and debugging existing code (be it C/C++, Python or Perl) to make it work **your** way is definitely a need.

**q: How much time would I need to set aside for this?**
a: Lots! PWK almost literally ate me up. I was not doing anything else apart from this. I had the odd break for a evening or two, but every chance I had I spent on the labs. Considering I had a full time day job, 3 months was perfect, but I think it may totally be possible to nail it in 1 month assuming you have the free time.

**q: Ok, I got the material, where the heck do I start?**
a: Now that I have completed the training, I would suggest you watch the videos. Then, work through the PDF documentation (actually doing the exercises) while you prepare your report. Finally start hacking away in the labs.

**q: How hard were the Lab machines?**
a: That is a really hard question to answer. If you have never ever seen any of this stuff before, you may be in for a lot of learning and may have quite a rough time in the beginning. The *toughness* I'd say is almost entirely relative to your existing experience. But, its not impossible to learn learn learn! :)

**q: Seriously now, how hard was the exam?**
a: For me? It was hard. Not necessarily just from a technical perspective, but also the time limitation, the rules, the fatigue, the everything! However, I feel the PWK labs are sufficient in gearing you towards it. You won't see the same exploits in the exam as you saw in the lab. So, make sure you understand the fundamental concepts in the labs and you will be fine in the exam!

**q: Anything else?**
a: TRY HARDER.
