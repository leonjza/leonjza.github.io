---
categories:
- python
- infosec
- url expansion
comments: true
date: 2013-07-31T00:00:00Z
published: true
title: URL Expansion - I'm paranoid like that
url: /2013/07/31/url-expansion-im-paranoid-like-that/
---

### So there is a good use
URL Shorteners, as they are most commonly known, are pretty useful in places where you are limited to the amount of characters you are allowed to type. Twitter being the prime example. However, it is not only because of services like that that these URL shortening services exist. Sometimes, URL's are are just plain crazy long, and very error prone when you have to copy and paste/link them someone. I guess we can call this a useful feature?

<!--more-->

### And a bad use
Of course, like most of the stuff you find on the internet, there has to be a way to abuse it too. Many people that consider themselves to be "IT Literate", be it second nature, or they have been burned before, will usually check out the link they are about to click. URL Shortening services take this "check" right out. It is now easier to get someone to click on a url to *somedodywebsite.io/free_trojan_screensaver_no_virus_promise.exe* as by the time the page has loaded, it may very well be too late.

There are also concerns about tracking too. But that is a different debate all together.

### Rise of the URL Expander.
There are tons, and I mean, **tons** of 'URL Expansion' services available online. http://longurl.org/, http://urlex.org/ and http://www.wheredoesthislinkgo.com/ to name a few. All from a simple Google Search. There are even browser plugins that would automatically 'expand' urls  as you hover over them.

This is cool and all. But how do I know that those services are not modifying the URL's? How do I know the browser plugin is not also fooling around somehow? Does that sound pretty paranoid to you? Well... :D

### Time for longurl.py
I wanted something to use on the command line, that would allow me to see **exactly** where I was going. Thus, *longurl.py* came to be.

Get the script with: `$ git clone https://github.com/th3l33k/longurl.git`

With this, I am able to see each 30x type redirect, as well as where it will take me. A sample usage case would be:

```bash longurl.py Usage
% ./longurl.py http://t.co/CHwi0q7DyF
[*] Next stop: 'http://t.co/CHwi0q7DyF'
[*] Got status: 301 with reason: Moved Permanently
[*] Next stop: 'http://bit.ly/14hneHx'
[*] Got status: 301 with reason: Moved
[*] Next stop: 'http://t.co/lqyFnSivpw'
[*] Got status: 301 with reason: Moved Permanently
[*] Next stop: 'http://reg.cx/27nM'
[*] Got status: 302 with reason: Found
[*] Next stop: 'http://www.theregister.co.uk/2013/07/31/department_defence_no_lenovo_ban/'
[*] Got status: 200 with reason: OK

[*] The final looks to be: 'http://www.theregister.co.uk/2013/07/31/department_defence_no_lenovo_ban/'
```

Now you can see each 'hop' it would have taken, as well as have your 'check before click' ability back. Like I said, there are lots of other ways to get the same thing done, but I preferred knowing exactly what is going on, rather than just getting the final URL, missing potential bad URL's in between that could lead to other _interesting_ finding. :)

**EDIT**
A similar effect can be seen with this one curl command:
