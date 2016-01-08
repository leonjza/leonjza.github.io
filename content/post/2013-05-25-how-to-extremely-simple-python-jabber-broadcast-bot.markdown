---
categories:
- Python
- Jabber
- Bot
comments: true
date: 2013-05-25T00:00:00Z
published: true
title: 'How To: Extremely simple python Jabber Broadcast Bot'
---

### Bots! Bots! Bots!

Generally speaking, a ''bot'' is something that like *does work for you*. But, for this purpose, the need for a jabber bot came from the fact that I had to deal with a lot of email on a daily basis. This large amount of mail sometimes would cause me to completely miss critical mail alerts. Realising later that I could have prevented a catastrophe if I didn't miss that **one** email was just not on anymore. So, I started investigating ways to get the *important* stuff delivered faster.

As a team at work, we have long gone dropped the whole Skype group chat thing for our own Jabber server. My privacy related concerns back then was recently heightened [here](http://lists.randombit.net/pipermail/cryptography/2013-May/004224.html) when a trap URL received a HEAD request from **65.52.100.214**. The user that received the URL in a chat was under strict instructions not to actually click it... 

<!--more-->

### So, how do we do this?
We implemented a [Openfire Server](http://www.igniterealtime.org/projects/openfire/) that was really easy to setup and get going. Whats really nice about this Jabber server is that it supports plugins, some of which you can simply install via the web interface.

One such plugin that was installed is called the [broadcast](http://www.igniterealtime.org/projects/openfire/plugins/broadcast/readme.html) plugin. This allows you to broadcast a message to all users on the server or those in defined groups.

{{< figure src="/images/openfire_screenshot.png" >}}

Once this plugin is installed, some minor configuration is required to allow the broadcasting feature to work. In no way is this an extensive guide on the power of the plugin, but for the purpose of this post well just quickly rush over it.

Head over to *Server* -> *Server Manager* -> *System Properties*. From here you need to add the fields that are not there with the **plugin.broadcast.** prefix. Don't worry if they are not there, just add them.

{{< figure src="/images/openfire_screenshot2.png" >}}

The above is just a sample of a working configuration. Feel free to play around more with different setups.

With everything configured, you should now be able to send a message to something like *all@broadcast.jabber.server*. In my configuration, *plugin.broadcast.all2offline* is set to **true**. So, when a message is broadcasted and I was offline, I'll receive the broadcast as soon as I'm back :) 

### Introducing jabbersend.py

With our jabber server now configured and working, we are ready to start automating things. From here we need two things. Something that will broadcast for us, and something *to* broadcast. The *what to broadcast* is entirely up to you, as the script will accept a text file to broadcast.

The only dependency you probably need to satisfy will be `xmpp`. This should be easily doable with something like `easy_install xmpp` 

```python
#!/usr/bin/python
import sys,os,xmpp,time

# check the received arguments
if len(sys.argv) < 2:
    print "Syntax: jabbersend.py JID textfile"
    sys.exit(0)

# set the values to work with and read the file
tojid=sys.argv[1]
m = open(sys.argv[2],'r')
array = m.readlines()
m.close()

msg=""
for record in array:
        msg = msg + record

# configure your jabber account for the bot here.
username = 'jabber_bot@jabber.server' # from whom will the message be sent
password = 'jabber_bot_secret_password'

jid=xmpp.protocol.JID(username)

# for debugging purposes, uncomment the below line so that 'debug' is 1.
# This makes the script very verbose though, but its helpful if you stuck ^^
#cl=xmpp.Client(jid.getDomain(),debug=1)
cl=xmpp.Client(jid.getDomain(),debug=[])

# Sadly I don't have a valid certificate for my jabber server, so this had to
# be set to False. I do however recommend, if you can, to get a valid certificate
# and enable this
con=cl.connect(secure=False) # Set this to validate the servers certificate.
if not con:
    print "Could not connect"
    sys.exit()

# authenticate the client
auth=cl.auth(jid.getNode(),password,resource=jid.getResource())
if not auth:
    print "Authentication failed"
    sys.exit()

# send the message
id=cl.send(xmpp.protocol.Message(tojid, msg))

# some older servers will not send the message if you disconnect immediately
time.sleep(1)
```

### We have the code, now use it!

Save this code to something like `jabbersend.py` and execute it like this:
`python jabbersend.py all@broadcast.jabber.server message_file.txt`

If all went OK, you should have received a message from jabber_bot@jabber.server :P

Our internal implementation of this has been used in multiple areas. From broadcasting OSSEC alerts to broadcasting important events from cronjobs.
The OSSEC broadcasting I'll blog a little later, but you can obviously see the value that something like this brings. No more missing emails, if I receive a message from the bot, its important :)

