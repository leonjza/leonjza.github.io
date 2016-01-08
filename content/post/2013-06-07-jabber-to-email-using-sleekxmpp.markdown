---
categories:
- jabber
- sleekxmpp
- bot
comments: true
date: 2013-06-07T00:00:00Z
published: true
title: Jabber to Email using SleekXMPP
url: /2013/06/07/jabber-to-email-using-sleekxmpp/
---

### So, why would you even want this..?
Well, to be honest, I am not really sure of many use cases for this, however maybe someone, somewhere will need to do something like this, and I would have done my deed and saved someone some time ::sun::

### Introducing SleekXMPP
[SleekXMPP](http://sleekxmpp.com/) is a python XMPP framework. It takes a bit to get your head around it, but once you have some basics covered its quite a rewarding library to work with. :) To start, you need to install 2 dependencies. Python Mailer and SleekXMPP itself. Something like `pip install mailer sleekxmpp` or for the older school, `easy_install sleekxmpp mailer` should do the trick. It can't hurt to check if the distro you use has these are packages already too.

<!--more-->

### Configuration and testing time
Once the install completes, do a quick check to see if everything is ok, Try to import the modules. They should return no errors. If they do, check that the installation of the previously mentioned dependencies were successful.

```python Check dependencies
% python2
Python 2.7.5 (default, May 12 2013, 12:00:47)
[GCC 4.8.0 20130502 (prerelease)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sleekxmpp
>>> import mailer
>>>
```

Next, you need a *bot* account to use. Provision a user on your jabber server for the bot and test with a jabber client that it works.

### Ok, code
Next, we take the [sample](http://sleekxmpp.com/#here-s-your-first-sleekxmpp-bot) echobot from the SleekXMPP website, and modify it slightly to handle our incoming message by sending a email, instead of simply replying back what we have sent.

First, we import the mailer requirements with:

```python mailer imports

from mailer import Mailer
from mailer import Message
```

The above can be placed right after the option parser has been imported. Then, we only need to change the `message` method within the `EchoBot` class really:

```python Shameless SleekXMPP modification of the echobot http://sleekxmpp.com/#here-s-your-first-sleekxmpp-bot
#!/usr/bin/env python
if msg['type'] in ('chat', 'normal'):

   print "Received Message:\n%(body)s" % msg

   # Mail the message Received
   message = Message(From="'Jabber Email Service' <someone@domain.com>",
         To=["someone@domain.com"],
         Subject="[Jabber Message Received] From: %s" % msg["from"])
   themessage = msg["body"]
   themessage = themessage.decode('unicode_escape').encode('ascii','ignore')
   message.Body = themessage

   sender = Mailer("127.0.0.1")
   sender.send(message)
```

A complete modified example that includes the above changes:

```python Shameless SleekXMPP modification of the echobot http://sleekxmpp.com/#here-s-your-first-sleekxmpp-bot
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2010  Nathanael C. Fritz
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""

import sys
import logging
import getpass
from optparse import OptionParser

from mailer import Mailer
from mailer import Message

import sleekxmpp

# Python versions before 3.0 do not use UTF-8 encoding
# by default. To ensure that Unicode is handled properly
# throughout SleekXMPP, we will set the default encoding
# ourselves to UTF-8.
if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input


class EchoBot(sleekxmpp.ClientXMPP):

    """
    A simple SleekXMPP bot that will echo messages it
    receives, along with a short thank you message.
    """

    def __init__(self, jid, password):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)

        # The session_start event will be triggered when
        # the bot establishes its connection with the server
        # and the XML streams are ready for use. We want to
        # listen for this event so that we we can initialize
        # our roster.
        self.add_event_handler("session_start", self.start)

        # The message event is triggered whenever a message
        # stanza is received. Be aware that that includes
        # MUC messages and error messages.
        self.add_event_handler("message", self.message)

    def start(self, event):
        """
        Process the session_start event.

        Typical actions for the session_start event are
        requesting the roster and broadcasting an initial
        presence stanza.

        Arguments:
            event -- An empty dictionary. The session_start
                     event does not provide any additional
                     data.
        """
        self.send_presence()
        self.get_roster()
        self.nick = "jabberMailBot"

    def message(self, msg):
        """
        Process incoming message stanzas. Be aware that this also
        includes MUC messages and error messages. It is usually
        a good idea to check the messages's type before processing
        or sending replies.

        Arguments:
            msg -- The received message stanza. See the documentation
                   for stanza objects and the Message stanza to see
                   how it may be used.
        """
        if msg['type'] in ('chat', 'normal'):

            print "Received Message:\n%(body)s" % msg

            # Mail the message Received
            message = Message(From="'Jabber Email Service' <someone@domain.com>",
                  To=["someone@domain.com"],
                  Subject="[Jabber Message Received] From: %s" % msg["from"])
            themessage = msg["body"]
            themessage = themessage.decode('unicode_escape').encode('ascii','ignore')
            message.Body = themessage

            sender = Mailer("127.0.0.1")
            sender.send(message)

if __name__ == '__main__':
    # Setup the command line arguments.
    optp = OptionParser()

    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    # JID and password options.
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')

    if opts.jid is None:
        opts.jid = raw_input("Username: ")
    if opts.password is None:
        opts.password = getpass.getpass("Password: ")

    # Setup the EchoBot and register plugins. Note that while plugins may
    # have interdependencies, the order in which you register them does
    # not matter.
    xmpp = EchoBot(opts.jid, opts.password)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0060') # PubSub
    xmpp.register_plugin('xep_0199') # XMPP Ping

    # If you are working with an OpenFire server, you may need
    # to adjust the SSL version used:
    # xmpp.ssl_version = ssl.PROTOCOL_SSLv3

    # If you want to verify the SSL certificates offered by a server:
    # xmpp.ca_certs = "path/to/ca/cert"

    # Connect to the XMPP server and start processing XMPP stanzas.
    if xmpp.connect():
        # If you do not have the dnspython library installed, you will need
        # to manually specify the name of the server if it does not match
        # the one in the JID. For example, to use Google Talk you would
        # need to use:
        #
        # if xmpp.connect(('talk.google.com', 5222)):
        #     ...
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")
```

### So how do I actually use this thing I just saw?
Take the complete example and save it to a file like `bot.py`. Then, run it!
The complete example will echo the message just before it attempts to mail it. You can comment out line **86** to stop this from happening and run the script with the `-q` argument once you are happy all is working.

```bash sample run
% python bot.py -j "myEmailbot@myJabberServer.local"
Password:
INFO     Negotiating TLS
INFO     Using SSL version: 3
INFO     CERT: Time until certificate expiration: 952 days, 6:46:01.014041

Received Message:
This is a test message that will be mailed :D
```

### Things to note.
- Even though the script allows you to specify a `-p` argument, I would highly discourage the usage of this. Any person that has access to your machine, be it legitimate or not, would then see your bot's process, with the password in the `ps` output!
- Ensure the SMTP server specified in line **96** of the complete example allows yo to relay! Change it if needed.

### Test! :D
Send your bot a message and see if your mail arrives ^^

**EDIT**: Modify the message encoding to ASCII as the utf8 stuff seems to barf out sometimes :|
