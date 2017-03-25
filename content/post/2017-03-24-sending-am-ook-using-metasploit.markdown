+++
date = "2017-03-24T17:55:38+02:00"
categories = [
    'sdr', 'rfcat', 'metasploit', 'remote'
]
keywords = [
    'sdr', 'hacking', 'metasploit', 'rfcat'
]
description = ""
title = "sending am-ook using metasploit and rfstransceiver"
+++

Towards the end of last year, I found myself [playing around](https://leonjza.github.io/blog/2016/10/02/reverse-engineering-static-key-remotes-with-gnuradio-and-rfcat/) with some basic AM/OOK SDR stuff™. That resulted in [ooktools](https://github.com/leonjza/ooktools) being built to help with making some of that work easier and to help me learn. A few days ago, metasploit announced new ['rftransceiver' capabilities](https://community.rapid7.com/community/metasploit/blog/2017/03/21/metasploits-rf-transceiver-capabilities) that were added to the framework with a similar goal of making this research easier.

{{< figure src="/images/sendingookmetasploit/metasploit.jpg" >}}

This post is about me playing with these new toys, and as well as releasing a few small modules I wrote.
<!--more-->

## how things fit together
First things first. I had to try and understand how this new stuff actually works. From the blog post, it is possible to see that the additions allow you to communicate with a RFCat capable device from metasploit and run modules over a session. A session is started by connecting to a small Json API (with a python helper) that bridges HTTP requests to `rflib` methods. All of this stuff is still pretty new/experimental. In fact, not everything seems to be [working 100%](https://github.com/rapid7/metasploit-framework/pull/8143), yet. Regardless, I set out to port some of the signaling features I have in ooktools to pure metasploit modules.

Basically, the setup is:

```
metasploit HWBride Module ---> HTTP API from rfcat_msfrelay ---> rflib methods (and dongle)
```

## the testing setup
For testing the new goodies, I have a [yardstickone](https://greatscottgadgets.com/yardstickone/) (which comes with the `rfcat` firmware out the box). The updated modules were not part of metasploit bundled with Kali yet, so I quickly built a [docker container](https://github.com/leonjza/dockerfiles/tree/master/metasploit) with the latest metasploit cloned and setup in it. To get the api bridge I mentioned earlier, I cloned the [RFCat repository](https://bitbucket.org/atlas0fd00m/rfcat) and ran the [rfcat_msfrelay](https://bitbucket.org/atlas0fd00m/rfcat/src/d96f232f6b262d6a281a32109c33ef072c20e929/rfcat_msfrelay?at=default&fileviewer=file-view-default) script on my laptop (outside of the docker container) as metasploit and the relay script talk using tcp/ip (duhr). This script will also work outside of the repository on its own if you have already installed the rfcat python module. It must just be able to import `rflib`. YMMV.

## rfcat_msfrelay
To start, the relay needs to be up first. You can give it the `--noauth` flag to not ask for credentials. Without it, the defaults are `msf_relay:rfcat_relaypass` (which you can change ofc).

{{< figure src="/images/sendingookmetasploit/rfcat_msfrelay.png" >}}

The output is not very exciting, but alas, port 8080 opens up and we can connect a session from metasploit. Over time, you should see the HTTP requests metasploit makes to the bridge appear much like a web servers access log.

## connecting the hwbridge session
Next, we connect the HWBridge session from metasploit. If you have ever used metasploit, this will feel very familiar. Just `use auxiliary/client/hwbridge/connect`, set the IP where the `rfcat_relay` is running with `set RHOST <ip_address>` and `run` the module.

{{< figure src="/images/sendingookmetasploit/hwbridge.png" >}}

Running `sessions -l` will show you have a new session to your radio. It is possible to interact with the session and send some basic commands. In reality, these are just translated to API calls to the bridge, and the rflib methods called.

{{< figure src="/images/sendingookmetasploit/hwbridge_session.png" >}}

## sending signals
“Out of the box” metasploit released two modules that were supposed to allow for [transmitting](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/hardware/rftransceiver/transmitter.rb) signals and allow for some [brute forcing](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/hardware/rftransceiver/rfpwnon.rb) to happen. I tested out the brute forcing module first just to get a feel for how things work.

{{< figure src="/images/sendingookmetasploit/bruteforce.png" >}}

Hah! Brute forcing from metasploit. Never did I think I would see this day. The `rfcat_relay` output started filling up with the API requests that were made from metasploit to the bride and I could see the signals from the brute force run using gnuradio too.

{{< figure src="/images/sendingookmetasploit/gnuradioplot.png" >}}

Nice! This was enough to convince me to write some modules! Considering there already was a brute force tool, I chose port the following remaining features from ooktools; sending an AM/OOK signal, searching for PWM encoded keys and a frequency jamming module.

## sendook module
Most of the hard work for this was already done in ooktools and I just had to translate them really. The sending of signals module was the first to be built and works quite flawlessly with my lab light I have at home.

{{< figure src="/images/sendingookmetasploit/sendook.png" >}}

My remote sends a long flat line at the start, so I had to set the start padding. If you don't set `RAW` to true, the module will automatically PWM encode the binary you give it.

## searchsignal module
The next was the signal searcher. This one proved to be a bigger pain as it seems like the receiver code has not really been tested yet both in the relay script as well as in metasploit itself. I made a [PR upstream](https://github.com/rapid7/metasploit-framework/pull/8143) to fix up the bugs I encountered in metasploit itself, and had to implement a new metasploit method call and bridge method to `lowball()` to allow for some noise to come through when scanning. Nonetheless, the scanning seems to have worked reasonably ok-ish.

{{< figure src="/images/sendingookmetasploit/searchsignal.png" >}}

## jamsignal module
Lastly, and arguably the easiest module of them all was the signal jammer. All I did here was send crap until the user cancels the module running. With my testing, this makes a valid 433mhz remote on the right frequency (and a little bit off too) useless until the jam is stopped. Obviously range is also a thing.

{{< figure src="/images/sendingookmetasploit/jamsignal.png" >}}

## woohoo!
I am very excited to see what else these new possibilities will bring to metasploit. If you want to play with the modules, I have them on github here: [https://github.com/leonjza/metasploit-modules](https://github.com/leonjza/metasploit-modules). I'll probably create a PR to see if these can be added to mtasploit itself too later.

I don't know much ruby, but there is a lot of power in my ^C ^V.
