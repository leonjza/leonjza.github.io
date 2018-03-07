---
title: "microcorruption - sydney"
date: 2018-03-04T18:20:20+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- sydney
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

The next post in the series of solving the [microcorruption.com](https://microcorruption.com) ctf challenges continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/03/microcorruption---new-orleans/) called _New Orleans_. This challenge is titled _Sydney_.

If you were to read the description when you enter the challenge, one would see the following right at the bottom:

> This is  Software Revision 02.  We have received reports that the prior version of the lock was  bypassable without knowing the password. We have fixed this and removed the password from memory.

Lol. Lets take a closer look.
<!--more-->

## sydney

Performing a static analysis of the code, one can see that this time round there is no silly  `create_password` routine or something similar.

```asm
4438 <main>
4438:  3150 9cff      add   #0xff9c, sp
443c:  3f40 b444      mov   #0x44b4 "Enter the password to continue.", r15
4440:  b012 6645      call  #0x4566 <puts>
4444:  0f41           mov   sp, r15
4446:  b012 8044      call  #0x4480 <get_password>
444a:  0f41           mov   sp, r15
444c:  b012 8a44      call  #0x448a <check_password>
4450:  0f93           tst   r15
```

In fact, just a simple `get_password` and `check_password` routine before the `tst r15` call at `0x4450`. The call to `get_password` just ends up with a syscall, prompting you for a password, so that is not really interesting to us. What is interesting though is `check_password`:

```asm
448a <check_password>
448a:  bf90 4c7e 0000 cmp   #0x7e4c, 0x0(r15)
4490:  0d20           jnz   $+0x1c
4492:  bf90 2142 0200 cmp   #0x4221, 0x2(r15)
4498:  0920           jnz   $+0x14
449a:  bf90 4522 0400 cmp   #0x2245, 0x4(r15)
44a0:  0520           jne   #0x44ac <check_password+0x22>
44a2:  1e43           mov   #0x1, r14
44a4:  bf90 587d 0600 cmp   #0x7d58, 0x6(r15)
44aa:  0124           jeq   #0x44ae <check_password+0x24>
44ac:  0e43           clr   r14
44ae:  0f4e           mov   r14, r15
44b0:  3041           ret
```

At first sight it looks like the code does a number of compares to values at an offset from the memory address at `r15`. Could these be parts of the actual password? Lets inspect with the debugger. Setting a breakpoint at `0x448a` and continuing the CPU (entering a password of _test_ when prompted) until we reach it should help in revealing what is happening.

{{< figure src="/images/microcorruption/sydney_byte_compare.png" >}}

Hah, so after the first `cmp` instruction, the status register is `0x4` (N), meaning the jump 14 bytes onwards to `0x44ac` will be taken, effectively ending the `check_password` routine prematurely. The bytes in `r15` at the time of the first `cmp` instruction was `0x439c`, which in turn pointed to `0x7465` in the memory dump (visualised with `read r15` in the debugger). The bytes in memory is clearly the password (_test_ in this case) that I entered when I was prompted.

```python
>>> ' '.join([hex(ord(x)) for x in 'test'])
'0x74 0x65 0x73 0x74'
```

So, lets take the bytes in the three `cmp` calls and enter that as the password, keeping our breakpoints and seeing what the CPU does then. The six bytes of interest are: `0x7e 0x4c 0x42 0x21 0x22 0x45`.

```python
>>> '7e4c42212245'.decode('hex')
'~LB!"E'
```

Resetting the CPU, entering `~LB!"E` as password and continuing untill we hit the breakpoint at `0x448a` and then stepping past the first `cmp` and `jnz` instructions should now look like this:

{{< figure src="/images/microcorruption/sydney_little_endian_suprise.png" >}}

Hmm. The value `0x7e4c` was at `0x439c` (the address `r15` points to), but the `cmp` call set the status register to `0x4` (N), ending the `check_password` function again. :|

What I think this challenge is supposed to teach you is about the endianness of the CPU which means it stores values in little endian format in memory. What that means for us is that that password values should be provided as `0x4c7e` instead of as `0x7e4c` like we did. So, lets re-arrange the password we enter, and continue to the breakpoint again.

```python
>>> '4c7e21424522'.decode('hex')
'L~!BE"'
```

{{< figure src="/images/microcorruption/sydney_valid_pass.png" >}}

Woohoo. This time the `jnz` instruction is not taken as the status register is now `0x3` (CZ) and the next values provided as part of the password checked. By now you might think you have won and decide to just continue the CPU to unlock the lock.

Well, no. See, we missed the part where another `cmp` happens just after `0x1` is moved into `r14`.

{{< figure src="/images/microcorruption/sydney_missing_bytes.png" >}}

This means that when `cmp    #0x7d58, 0x6(r15)` at `0x44a4` is called, we will be comparing to `0x0` (the bytes at `r15+6`), resulting in the jump at `0x44aa` not being taken, clearing `r14` before the routine finishes.

So, to prevent that adn as a final password, we need to enter those the bytes `0x58` and `0x7d` too to unlock the lock.

```python
>>> '4c7e21424522587d'.decode('hex')
'L~!BE"X}'
```

Continue the CPU and unlock the lock!

## solution

Enter `L~!BE"X}` as ASCII or `4c7e21424522587d` as hex encoded input.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
