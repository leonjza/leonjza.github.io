---
title: "microcorruption - hanoi"
date: 2018-03-05T19:08:33+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- hanoi
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/04/microcorruption---sydney/) called _Sydney_. This challenge is titled _Hanoi_.

If you were to read the description when you enter the challenge, one would see the following towards the bottom:

> LockIT Pro Hardware Security Module 1 stores the login password, ensuring users can not access the password through other means. The LockIT Pro can send the LockIT Pro HSM-1 a password, and the HSM will return if the password is correct by setting a flag in memory.

Ok, so mention of a HSM here. Neat! Lets take a look at how that works!
<!--more-->

## hanoi

This time round, our `main` function is quite a bit shorter than the previous programs we have analysed:

```asm
4438 <main>
4438:  b012 2045      call  #0x4520 <login>
443c:  0f43           clr   r15
```

Just a call to `login` which in turn has a similar flow to that which we saw in the previous `main` functions. A semi-shortened, annotated version of `login` is:

```asm
4520 <login>
4520:  c243 1024      mov.b #0x0, &0x2410
4524:  3f40 7e44      mov   #0x447e "Enter the password to continue.", r15
4528:  b012 de45      call  #0x45de <puts>

; but what if i put in more than 16 characters? ;)
452c:  3f40 9e44      mov   #0x449e "Remember: passwords are between 8 and 16 characters.", r15
4530:  b012 de45      call  #0x45de <puts>

[.. routine to get the password ..]

4544:  b012 5444      call  #0x4454 <test_password_valid>
4548:  0f93           tst   r15
454a:  0324           jz    $+0x8

; erm? what is going on here?
454c:  f240 5000 1024 mov.b #0x50, &0x2410
4552:  3f40 d344      mov   #0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call  #0x45de <puts>

; and what about here?
455a:  f290 6300 1024 cmp.b #0x63, &0x2410
4560:  0720           jne   #0x4570 <login+0x50o>

; grants us access!
4562:  3f40 f144      mov   #0x44f1 "Access granted.", r15
4566:  b012 de45      call  #0x45de <puts>
456a:  b012 4844      call  #0x4448 <unlock_door>
456e:  3041           ret

; failed
4570:  3f40 0145      mov   #0x4501 "That password is not correct.", r15
4574:  b012 de45      call  #0x45de <puts>
4578:  3041           ret
```

Some interesting things happening there it seems. I think the next routine to check out is most definitely `test_password_valid`. Taking a look at that routine looks as follows:

```asm
4454 <test_password_valid>

; move a bunh of stuff around
4454:  0412           push  r4
4456:  0441           mov   sp, r4
4458:  2453           incd  r4
445a:  2183           decd  sp
445c:  c443 fcff      mov.b #0x0, -0x4(r4)  ; 0x2400 at this stage
4460:  3e40 fcff      mov   #0xfffc, r14
4464:  0e54           add   r4, r14
4466:  0e12           push  r14
4468:  0f12           push  r15

; push 0x7d into the stack and prep for a syscall
446a:  3012 7d00      push  #0x7d
446e:  b012 7a45      call  #0x457a <INT>

[.. end this routine ..]
447c:  3041           ret
```

Hmm ok, a bunch of `mov` instructions and other arithmetic and finally syscall with interrupt `0x7d` which is described as _"Interface with the HSM-1. Set a flag in memory if the password passed in is
correct."_ according to the locks [manual](https://microcorruption.com/manual.pdf).

So not _that_ interesting after all. Looking at `login` again, it seems like we would ideally want to have `unlock_door` called from `login` at `0x456a` to win. But how to get there?

### debugging

My static analysis capabilities were pretty much exhausted here, and it was now time for some runtime debugging. I manually stepped through the program, focussing on the `test_password_valid` routine. I noticed the password I entered as `12345678` was stored at offset `0x2400` and referenced when the interrupt for the HSM to check was set up.

{{< figure src="/images/microcorruption/hanoi_password_in_memory.png" >}}

A few steps through this routine with no obvious ways to fool it, I decided to park it for now and see what happens after `test_password_valid` is done. This is now back at `login` once `test_password_valid` has returned:

```asm
; test_password_valid has returned
4552:  3f40 d344      mov   #0x44d3 "Testing if password is valid.", r15
4556:  b012 de45      call  #0x45de <puts>

; what is this cmp doing?
455a:  f290 6300 1024 cmp.b #0x63, &0x2410
4560:  0720           jne   #0x4570 <login+0x50>

; making the jne not get taken will land us at unlock_door
4562:  3f40 f144      mov   #0x44f1 "Access granted.", r15
4566:  b012 de45      call  #0x45de <puts>
456a:  b012 4844      call  #0x4448 <unlock_door>
```

I noticed the `cmp.b #0x63, &0x2410` instruction again and realised that `0x2410` is close to the area where my password buffer was being stored in memory. Infact, this was just 16 bytes away from `0x2400`! Now remember that message telling us passwords are supposed to be 8 to 16 characters long? Well, looks like that is because char 17 and 18 forms part of this `cmp.b` instruction!

If we can make the aforementioned instruction pass the test checking if the value at that memory address is `0x63`, (ASCII character `c`), then we can get past the `jne` instruction at `0x4560`, eventually landing us in `unlock_door` routine.

So given that the distance to `0x2410` is 16 bytes from `0x2400` where our password buffer is stored, lets see if we can overflow the buffer to `0x2410`.

```python
>>> print('A' * 16 + 'c')
AAAAAAAAAAAAAAAAc
```

I set a breakpoint at `0x455a` with `break 455a` in the debugger and continued the CPU entering `AAAAAAAAAAAAAAAAc` as the password when prompted.

{{< figure src="/images/microcorruption/hanoi_jump_little_endian.png" >}}

After hitting the breakpoint and inspecting the contents of memory address `0x2410` with `read 2410` in the debugger reveals that the byte `0x63` is at `0x2410` (thanks to our overflow). This results in the `cmp.b` instruction setting the status register to `0x3` (CZ), which in turn means the jump is not taken!

Turns out `test_password_valid` was just a decoy and the real vulnerability was a simple buffer overflow.

## solution

Enter `AAAAAAAAAAAAAAAAc` as ASCII or `4141414141414141414141414141414163` as hex encoded input.

## other challenges

For my other writes for the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
