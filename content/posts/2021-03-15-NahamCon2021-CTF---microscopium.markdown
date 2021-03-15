---
title: "NahamCon2021 CTF - Microscopium"
date: 2021-03-15T17:45:16+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

mobile - medium

## solution

This was a fun one. We get an `.apk` to download. Open it in [jadx](https://github.com/skylot/jadx) and quickly see this is a React App.

```java
package com.microscopium;

import com.facebook.react.ReactActivity;

public class MainActivity extends ReactActivity {
    /* access modifiers changed from: protected */
    @Override // com.facebook.react.ReactActivity
    public String getMainComponentName() {
        return "Microscopium";
    }
}
```

Being React, I expected a large chunk of the logic to be in a JavaScript file, which could be found in the resources section.

{{< figure src="/images/nahamcon/microscopium_react.png" >}}

The app itsef was simple. Just a field where you could enter a PIN, and an output you'd get when you submitted. Every different PIN you entered produced a different output.

{{< figure src="/images/nahamcon/microscopium_pin.png" >}}

The logic for the PIN could be found in the JavaScript. Searching for the word `pin` would have revealed the relevant line. "Prettifying" the relevant line, and extracting the interesting bits, youd find this:

```javascript
   function b() {
      var t;
      (0, o.default)(this, b);
      for (var n = arguments.length, l = new Array(n), u = 0; u < n; u++) l[u] = arguments[u];
      return (t = v.call.apply(v, [this].concat(l))).state = {
        output: 'Insert the pin to get the flag',
        text: ''
      }, t.partKey = "pgJ2K9PMJFHqzMnqEgL", t.cipher64 = "AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=", t.onChangeText = function (n) {
        t.setState({
          text: n
        })
      }, t.onPress = function () {
        var n = p.Base64.toUint8Array(t.cipher64),
          o = y.sha256.create();
        o.update(t.partKey), o.update(t.state.text);
        for (var l = o.hex(), u = "", c = 0; c < n.length; c++) u += String.fromCharCode(n[c] ^ l.charCodeAt(c));
        t.setState({
          output: u
        })
      }, t
    }
```

The important parts were that the key had an existing part, `pgJ2K9PMJFHqzMnqEgL`, whereafter your pin would be appended. A simple xor operation was being performed over the cipher. Based on this, I wrote a simple brute force script, copying the code from the React app.

```javascript
/*
package.json

{
  "dependencies": {
    "js-base64": "^3.6.0",
    "js-sha256": "^0.9.0"
  }
}

*/
const sha256 = require('js-sha256');
const Base64 = require('js-base64');

const cipher = 'AA9VAhkGBwNWDQcCBwMJB1ZWVlZRVAENW1RSAwAEAVsDVlIAV00=';
const n = Base64.toUint8Array(cipher);

for (var i = 0; i < 9999; i++) {
    var o = sha256.create();
    o.update('pgJ2K9PMJFHqzMnqEgL');
    o.update(i.toString());

    for (var l = o.hex(), u = '', c = 0; c < n.length; c++) {
        u += String.fromCharCode(n[c] ^ l.charCodeAt(c));
    }

    if (u.includes("flag{")) {
        console.log("pin=", i.toString(), "flag= ", u);
    }
}
```

Run it to reveal the flag.

```bash
$ node brute.js
pin= 4784 flag=  flag{06754e57e02b0c505149cd1055ba5e0b}
```
