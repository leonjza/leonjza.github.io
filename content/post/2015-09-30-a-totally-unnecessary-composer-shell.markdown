---
categories:
- php
- reverse
- shell
- composer
comments: true
date: 2015-09-30T19:39:55Z
title: a totally unnecessary composer shell
---

## background
{{< figure src="/images/composer_shell_logo.png" >}}

A silly reverse shell invoked via the Composer Dependency Manager. [Source here](https://github.com/leonjza/composer-shell)

[Composer](https://getcomposer.org/), which is most probably *the* most popular PHP dependency manager allows for [scripts](https://getcomposer.org/doc/articles/scripts.md) to run as callbacks on based an event.
Callbacks are normally triggered just before or after certain events.

It is possible to provide shell commands to the `scripts` property in the required `composer.json` file (with a few restrictions), but this method echoes the command that it executes.
A slightly more covert approach would be to execute a cleverly named static function in a class included in the codebase. It has to be one that can be autoloaded by composer.
<!--more-->

## why?
I thought a little about which scenarios this may actually be useful in and figured maybe only really strange edge cases where you can only run composer (as root lol?).
I also remembered a bug in [git](https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial) (CVE-2014-9390) that allowed for code execution via 'poisoned' repositories. Well, I guess depending on your perspective, this may be a very similar.

## PoC
As part of a PoC, I just used the popular [pentest-monkey PHP reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell), but really, anything is possible that is possible with PHP at this point.

<script type="text/javascript" src="https://asciinema.org/a/b64qlhadvl7zn1912ihwi09wt.js" id="asciicast-b64qlhadvl7zn1912ihwi09wt" data-size="medium" async></script>

