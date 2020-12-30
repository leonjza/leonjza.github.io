---
categories:
- quick-win
- shell
- tip
comments: true
date: 2013-06-23T00:00:00Z
published: true
title: 'Quick Win: Quickly Execute Last Shell Command'
---

### Work clever, not hard
This will be the first post of a series of quick shell tips for getting things done, fast. Infact, it will probably just serve as a notepad for me on the topic ;)

### Last shell command
If you are using a shell, such as [Bash](http://www.gnu.org/software/bash/bash.html), which is pretty much the default on most Linux distributions, then you probably know that you can just use the **up** arrow to get the last command. But, if you are using a shell such as [Zsh](http://www.zsh.org/) like me, you'd quickly come to realise that the global `~/.histfile` can be a tad frustrating if you are expecting the last command you typed in **that** terminal window to appear when you press **up**. Only to realise, its literally the last command you typed in *another* shell.

### Bang Bang to the rescue!
Simply type ``!!`` and *enter* and the last command that was run in **that** terminal will be either echoed or executed, depending on how your shell is configured to handle the command.
