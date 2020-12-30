---
title: "microcorruption - cusco"
date: 2018-03-06T07:43:25+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- cusco
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/04/microcorruption---sydney/) called _Hanoi_. This challenge is titled _Cusco_.

If you were to read the description when you enter the challenge, one would see the following towards the bottom:

> This is Software Revision 02. We have improved the security of the lock by removing a conditional  flag that could accidentally get set by passwords that were too long.

Oops :P Lets take a closer look at how this fixed version works.
<!--more-->

## cusco

This challenge, just like the previous has a `main` routine that calls `login`. At first glance, the `login` routine itself was not too interesting either:

```asm
4500 <login>

; get the password from the user
4500:  3150 f0ff      add   #0xfff0, sp
4504:  3f40 7c44      mov   #0x447c "Enter the password to continue.", r15
4508:  b012 a645      call  #0x45a6 <puts>
450c:  3f40 9c44      mov   #0x449c "Remember: passwords are between 8 and 16 characters.", r15
4510:  b012 a645      call  #0x45a6 <puts>
4514:  3e40 3000      mov   #0x30, r14
4518:  0f41           mov   sp, r15
451a:  b012 9645      call  #0x4596 <getsn>
451e:  0f41           mov   sp, r15

; run the test password_valid routine
4520:  b012 5244      call  #0x4452 <test_password_valid>
4524:  0f93           tst   r15
4526:  0524           jz    #0x4532 <login+0x32>

; if r15 is not zero, the previous jump wont be taken
4528:  b012 4644      call  #0x4446 <unlock_door>
452c:  3f40 d144      mov   #0x44d1 "Access granted.", r15
4530:  023c           jmp   #0x4536 <login+0x36>
4532:  3f40 e144      mov   #0x44e1 "That password is not correct.", r15
4536:  b012 a645      call  #0x45a6 <puts>
453a:  3150 1000      add   #0x10, sp
453e:  3041           ret
```

Just a simple `getsn` to get the password using an interrupt, a call to `test_password_valid` and finally a conditional jump at `0x4524` which I suppose is what we would want to get past by having `r15` not be zero (from within `test_password_valid` I assume).

Looking at `test_password_valid`, one would notice pretty much exactly the same logic as was seen in the [hanoi](https://leonjza.github.io/blog/2018/03/05/microcorruption---hanoi/) challenge:

```asm
[ ... snip ... ]

4468:  3012 7d00      push  #0x7d
446c:  b012 4245      call  #0x4542 <INT>

[ ... snip ... ]
```

Effectively just a call to interrupt `0x7d` which asks the HSM to verify the password. Pants. Time to debug this one.

### debugging

I stepped through `test_password_valid` with a password of `0123456789` and as in the previous challenge, found nothing too interesting about it. Unlike the previous challenge though, the password buffer was closer to the stack pointer when read after the syscall this time. Returning from `test_password_valid` back to `login` would leave `r15` with `0x0`, resulting in the jump at `0x4526` being taken.

{{< figure src="/images/microcorruption/cusco_wrong_password.png" >}}

I fuzzed the password input with a number of parameters, and it became evident that there did not seem to be a way (apart knowing the real password) to prevent the jump at `0x4526` from being taken. **However**. Remember that "_passwords can be max 16 characters_" thing? Well, providing a password of more than 16 characters seems to corrupt the stack when `login` wants to return. Something I noticed too late.

{{< figure src="/images/microcorruption/cusco_stack_corruption.png" >}}

Notice how the stack pointer (`sp`) is at `0x43f3`, which is also in the string of `A`'s i provided as a password! In this case, the offset was 17 bytes from the start of the password buffer. Because we corrupted the stack with our user controlled data, the `ret` instruction will redirect to any address we place there. In this case, the `unlock_door`'s routine that starts at `0x4446` would be a good place!

All we need to do now is provide a string of 16 characters, and then 2 (little endian formatted) bytes for the `unlock_door` routine.

{{< figure src="/images/microcorruption/cusco_rewrite_ret.png" >}}

And boom. We have redirected code execution to the `unlock_door` routine.

## solution

Enter `414141414141414141414141414141414644` as hex encoded input.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
