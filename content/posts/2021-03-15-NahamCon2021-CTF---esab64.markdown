---
title: "NahamCon2021 CTF - Esab64"
date: 2021-03-15T09:58:51+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

warmups - easy

## solution

The downloaded file contained a string, which looked like it was base64 encoded. The challenge title was also base64 reversed, `esab64`.

```bash
❯ cat esab64
mxWYntnZiVjMxEjY0kDOhZWZ4cjYxIGZwQmY2ATMxEzNlFjNl13X
```

To solve, reverse the string, base64 decode and then reverse it again.

```python
import base64

with open("esab64", "r") as f:
    s = f.readline()

s = s[::-1]
d = base64.b64decode(s)

print(d[::-1][:-1])
```

Running it gives us the flag.

```bash
$ python3 solve.py
b'flag{fb5211b498afe87b1bd0db601117e16e}'
```
