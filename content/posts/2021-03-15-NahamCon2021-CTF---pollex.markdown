---
title: "NahamCon2021 CTF - Pollex"
date: 2021-03-15T09:52:23+02:00
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

The downloaded file you get is an image, when opened looks like this:

{{< figure src="/images/nahamcon/pollex.png" >}}

Output of `exiftool` shows that there is a thumbnail, with a hint to extract it right at the bottom.

```text
❯ exiftool pollex.jpg
ExifTool Version Number         : 12.16
File Name                       : pollex.jpg
Directory                       : .
File Size                       : 37 KiB
File Modification Date/Time     : 2021:03:13 13:40:45+02:00
File Access Date/Time           : 2021:03:15 09:53:11+02:00
File Inode Change Date/Time     : 2021:03:15 09:53:11+02:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Exif Byte Order                 : Little-endian (Intel, II)
Image Description               : Man giving thumb up on dark black background.
Software                        : Google
Artist                          : Stevanovic Igor
Copyright                       : (C)2013 Stevanovic Igor, all rights reserved
Exif Version                    : 0220
Color Space                     : sRGB
Interoperability Index          : R98 - DCF basic file (sRGB)
Interoperability Version        : 0100
Compression                     : JPEG (old-style)
Thumbnail Offset                : 334
Thumbnail Length                : 26693
XMP Toolkit                     : XMP Core 4.4.0-Exiv2
Creator Tool                    : Google
Description                     : Man giving thumb up on dark black background.
Rights                          : (C)2013 Stevanovic Igor, all rights reserved
Creator                         : Stevanovic Igor
Current IPTC Digest             : c7c2ff906c74de09234ddcb2c831803b
Envelope Record Version         : 4
Coded Character Set             : UTF8
Application Record Version      : 4
By-line                         : Stevanovic Igor
Credit                          : igor - Fotolia
Copyright Notice                : (C)2013 Stevanovic Igor, all rights reserved
Caption-Abstract                : Man giving thumb up on dark black background.
IPTC Digest                     : c7c2ff906c74de09234ddcb2c831803b
Image Width                     : 424
Image Height                    : 283
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 424x283
Megapixels                      : 0.120
Thumbnail Image                 : (Binary data 26693 bytes, use -b option to extract)
```

So, extract the thumbnail with: `exiftool -b -ThumbnailImage pollex.jpg > image.png`. The thumbnail has the flag.

{{< figure src="/images/nahamcon/pollex-flag.png" >}}
