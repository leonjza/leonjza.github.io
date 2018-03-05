---
title: "microcorruption - new orleans"
date: 2018-03-03T22:21:36+02:00
description: "solving the new orleans microcorruption challenge"
categories:
- ctf
- exploit
- assembly
- microcorruption
- new orleans
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

The next post in the series of solving the [microcorruption.com](https://microcorruption.com) ctf challenges continues from the [previous small tutorial challenge](https://leonjza.github.io/blog/2018/03/03/microcorruption---tutorial/) post. This challenge is titled _New Orleans_.
<!--more-->

## new orleans

This challenge no longer holds your hand in terms of a nice and easy to follow tutorial. Instead, you are presented with the machine code and the debugger. Lets get to it!

You will immediately notice that there are a lot of functions in the beginning of the code section that do some setup work. Although important, they are not always that interesting. Instead, we are almost always only really interested in what happens once we hit the `main` function.

```asm
4438 <main>
4438:  3150 9cff      add   #0xff9c, sp
443c:  b012 7e44      call  #0x447e <create_password>
4440:  3f40 e444      mov   #0x44e4 "Enter the password to continue", r15
4444:  b012 9445      call  #0x4594 <puts>
4448:  0f41           mov   sp, r15
444a:  b012 b244      call  #0x44b2 <get_password>
444e:  0f41           mov   sp, r15
4450:  b012 bc44      call  #0x44bc <check_password>
4454:  0f93           tst   r15
4456:  0520           jnz   #0x4462 <main+0x2a>
4458:  3f40 0345      mov   #0x4503 "Invalid password; try again.", r15
445c:  b012 9445      call  #0x4594 <puts>
4460:  063c           jmp   #0x446e <main+0x36>
4462:  3f40 2045      mov   #0x4520 "Access Granted!", r15
4466:  b012 9445      call  #0x4594 <puts>
446a:  b012 d644      call  #0x44d6 <unlock_door>
446e:  0f43           clr   r15
4470:  3150 6400      add   #0x64, sp
```

A quick look at the `call`'s that get made, we can see the flow is pretty simple. First we run a `create_password` routine, then `get_password`, then do a `check_password`. Depending on the contents of `r15` once we have done that, we will jump to unlock the lock or not.

Lets take a closer look at `create_password`. This seems like an odd method to have.

```asm
447e <create_password>
447e:  3f40 0024      mov   #0x2400, r15
4482:  ff40 2e00 0000 mov.b #0x2e, 0x0(r15)
4488:  ff40 6700 0100 mov.b #0x67, 0x1(r15)
448e:  ff40 3700 0200 mov.b #0x37, 0x2(r15)
4494:  ff40 4d00 0300 mov.b #0x4d, 0x3(r15)
449a:  ff40 4700 0400 mov.b #0x47, 0x4(r15)
44a0:  ff40 4800 0500 mov.b #0x48, 0x5(r15)
44a6:  ff40 2f00 0600 mov.b #0x2f, 0x6(r15)
44ac:  cf43 0700      mov.b #0x0, 0x7(r15)
44b0:  3041           ret
```

The `create_password` routine seems to be moving some bytes (using `mov.b`) at incrementing offsets relative to `0x2400`. The final `mov.b` instruction at `0x44ac` moves a null byte into the last memory location before returning the method call. I guess its obvious what is going on here already.

Lets take a look at `check_password` too:

```asm
44bc <check_password>
44bc:  0e43           clr   r14
44be:  0d4f           mov   r15, r13
44c0:  0d5e           add   r14, r13
44c2:  ee9d 0024      cmp.b @r13, 0x2400(r14)
44c6:  0520           jne   #0x44d2 <check_password+0x16>
44c8:  1e53           inc   r14
44ca:  3e92           cmp   #0x8, r14
44cc:  f823           jne   #0x44be <check_password+0x2>
44ce:  1f43           mov   #0x1, r15
44d0:  3041           ret
44d2:  0f43           clr   r15
44d4:  3041           ret
```

A quick read seems like 8 `cmp.b` operations are performed from the same offset we have had when `create_password` started writing those bytes. So, `create_password` writes the password to memory, `check_password` just compares those bytes to the ones entered by the user.

Lets debug this application and see what it looks like. First, set a breakpoint just after `create_password` is done at `0x4440` with `break 4440`. This will let us have a peek at `0x2400` to see what that the memory looks like there. The next break point that might be interesting would be where the character comparisons are occurring in `check_password` at `0x44c2`, so add another break point with `break 44c2`. Finally, hit `c` to continue the CPU.

Right after we hit our first breakpoint, we can see that the bytes `2e67 374d 4748 2f00` were written from `0x2400` onwards.

{{< figure src="/images/microcorruption/new_orleans_create_password.png" >}}

Using a small one-liner, we can convert the bytes that were written to ASCII and confirm it matches the section in memory:

```bash
~ » python -c "print '2e67374d47482f00'.decode('hex')"
.g7MGH/
```

I am pretty sure this is the password, so continue the CPU and enter `.g7MGH/` when the interrupt prompts you for a password. Continue the CPU again until we hit our next breakpoint to see the byte comparisons occur. The CPU should step all the way though the loop for the password and finally hit the `mov` instruction at `0x44ce` which sets `r15` to `0x1` for that `tst` instruction in `main` later.

{{< figure src="/images/microcorruption/new_orleans_win_state.png" >}}

The `tst` instruction on register `r15` should have a non-zero return in the state register `sr`, resulting in a win condition. This means the password is `.g7MGH/`!

## solution

Enter a password of `.g7MGH/` in ASCII or `2e67374d47482f00` as hex.

## other challenges

For my other writes for the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
