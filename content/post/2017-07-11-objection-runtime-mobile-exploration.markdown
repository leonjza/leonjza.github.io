---
title: "objection - runtime mobile exploration"
date: 2017-07-11T14:05:41+02:00
description: "releasing objection, a runtime mobile security exploration toolkit"
categories: 
- ios
- android 
- frida
- objection
- pentest
- security
---

{{< figure src="/images/objection/objection.png" >}}

In this post, I want to introduce you to a toolkit that I have been working on, called [objection](https://github.com/sensepost/objection). The name being a play on the words "object" and "injection". objection is a runtime exploration toolkit powered by Frida, aimed at mobile platforms. objection aims to allow you to perform various security related tasks on unencrypted iOS applications, at runtime, on non-jailbroken iOS devices as well as Android applications on Android devices. Features include inspecting the application specific keychain, as well as inspecting various artifacts left on disk during (or after) execution.
<!--more-->

With jailbreaks for iOS devices becoming increasingly difficult to come by (not to mention the often 'dodgy' utilities out there to perform the exploits that allow you access outside of the iOS jail), the expectation of iOS 11 coming soon and many other operational issues faced when trying to prevent an existing iOS device from updating (and losing the jailbreak), objection will allow you to perform a large portion of the typical mobile security assessment all within the existing constraints of the application sandbox.

# why

Many times, we as analysts find ourselves in a position where we need to explain the "real world relevance" of the epic pwnage you had. Often, admitting to the fact that your device was Jailbroken, leaves much to be questioned about how "real" the attacks you performed are. "But if you had root, its technically over anyways, right?". Yes, but that is not the only way.

Client engagement examples aside, most of the tooling that exists out there rely on the fact that your device is jailbroken (and rightfully so). But what if you simply dont have a Jailbroken device? Well, chances are you only focus on the API endpoints that the application consumes, hoping that the SSL pinning is broken enough for you to get an idea of how it works.

Lets change that.

# examples

Under the hood, objection uses Frida to inject objects into a patched applications runtime and executes them within that applications security context to perform various tasks. Typical tasks may be short lived commands such as ls that will let you browse the mobile devices filesystem from the mobile applications perspective, or longer lived commands such as ios sslpinning disable that hooks common methods that are used to pin SSL certificates, and prevent validations from failing as you use the app.

{{< figure src="/images/objection/objection_ls.png" >}}

While we are talking about the filesystem, it is also possible to download files straight off the device (where you have read access) as well as have the ability to re-upload files where write access is granted, such as the applications Documents directory.

objection also includes an inline SQLite editor to make manipulating random sqlite databases that might exist a breeze.

{{< figure src="/images/objection/objection_sqlite.png" >}}

Connecting to and querying an arbitrary SQLite database within an applications Documents directory.

# sample usage

A sample session where objection is used to explore various parts of a sample iOS application that is already patched and running is shown below:

<script type="text/javascript" size="small" src="https://asciinema.org/a/8O6fjDHOdVKgPYeqITHXPp6HV.js" id="asciicast-8O6fjDHOdVKgPYeqITHXPp6HV" async></script>

# features

While still a work in progress, objection already contains a number of features. A few notable ones are:

- Interact with the remote filesystem to move around, upload and download files where ever access is granted.
- Dump the current processes memory, explore loaded modules and module exports.
- Interact with SQLite databases on the remote filesystem.
- Dump various bits of shared storages such as NSUserDefaults, NSHTTPCookieStorage and .plist files on an iOS devices disk in a human readable format.
- Simulate a jailbroken environment to test an iOS applications behaviour in such an environment.
- An iOS SSL pinning bypass module that implements the widely known SSL-Killswitch2 methods.
- Dump the iOS keychain.
- Perform iOS TouchID bypasses.
- Perform a type of class-dump that will list the available Objective-C classes and class methods.
- Dynamically hook and watch for method invocations of a specific class method. Additionally, objection can try and dump method arguments passed as they are invoked.

... and much more.

# get it

You can get objection right now over at https://github.com/sensepost/objection. Some setup work is needed, as well as a patching process for the IPA you are interested in. Fear not, all of that stuff is documented on the projects wiki that can be found here: https://github.com/sensepost/objection/wiki.
