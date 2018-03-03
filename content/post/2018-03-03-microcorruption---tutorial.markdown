---
title: "microcorruption - tutorial"
date: 2018-03-03T21:28:12+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- tutorial
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

These posts will detail my answers to solving various [microcorruption.com](https://microcorruption.com) ctf challenges. To begin, you should have at least had a look at the [lock manual](https://microcorruption.com/manual.pdf) for a number of helpful hints. These challenges are built to run on a MSP430 microcontroller unit, so if you need any assembly references, that is the architecture your are looking for!

Lets look at the tutorial level first.
<!--more-->

## tutorial level

As expected, the first level is super simple. Most of your time is spent on this level getting to know the web based debugger as well as general tips and tricks for moving around.

When you follow the tutorial, you will notice that the flaw you need to exploit in this challenge is simply a length based one as the `check_password` routine simply checks if the password has a length of `9`.

```asm
4484 <check_password>
4484:  6e4f           mov.b @r15, r14
4486:  1f53           inc   r15
4488:  1c53           inc   r12
448a:  0e93           tst   r14
448c:  fb23           jnz   #0x4484 <check_password+0x0>
448e:  3c90 0900      cmp   #0x9, r12   ; password length check
4492:  0224           jeq   #0x4498 <check_password+0x14>
```

Once you hit the instruction at `0x4484`, the first character of the password you entered is loaded into `r14` (which you can see from the memory layout if you were to browse to `0x439c`) from the memory location pointed to in `r15`. Next, the registers `r12` and `r15` are incremented. This will continue until a null byte (a typical string terminator in C) is reached, causing the jump at `0x448c` not to be followed, making the `cmp` be the next instruction.

If `r12` ends up being `0x0009` (indicating that out passwords was 8 characters long with a null byte), then the jump at `0x4492` will occur, finally calling the interrupt to unlock the lock.

{{< figure src="/images/microcorruption/microcorruption_tutorial.png" >}}   

## solution

Enter any 8 character string, such as `password`.

## next challenge

[New Orleans](https://leonjza.github.io/blog/2018/03/03/microcorruption---new-orleans/)
