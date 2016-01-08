---
categories:
- linux
- kvm
- centos
- how to
comments: true
date: 2013-08-03T00:00:00Z
published: true
title: KVM - Redirecting CentOS Kernel and tty output to a virtual serial console
url: /2013/08/03/kvm-redirecting-centos-kernel-and-tty-output-to-a-virtual-serial-console/
---

### Console all the things!
First and foremost, I will start with a warning. Like any other virtualization software, you risk leaving the console open. This is a often overlooked part of securing your infrastructure. An administrator may have been required to do some work on the virtual console, and forget to log out. What if that account that is still logged in, is r00t? Having administrative access to a VM Host gives you access to the consoles, but not necessarily to the guests. Remember to log out! Or, setup shells to auto-logout after a few minutes of inactivity.

<!--more-->

### Example virsh console access

Once setup, accessing consoles can be as easy as connecting via SSH to your server. Firing up the virsh client, and connecting to the console:

```bash a primitive virsh console access example
$ virsh --connect qemu:///system
Welcome to virsh, the virtualization interactive terminal.

Type:  'help' for help with commands
       'quit' to quit

 Id    Name                           State
----------------------------------------------------
 6     console-test                   running

virsh # console console-test
Connected to domain console-test
Escape character is ^]

CentOS release 6.4 (Final)
Kernel 2.6.32-358.el6.x86_64 on an x86_64

localhost.localdomain login: root
Password:
Last login: Sat Aug  3 08:31:13 on ttyS0
[root@localhost ~]$
```

You can escape the console by pressing `^]`, which will drop you back into the virsh shell.

```bash virsh guest console escape
[root@localhost ~]$ echo "testing123"
testing123
[root@localhost ~]$                       # I pressed ^] here  
virsh #
```

### Ok, gimme ze commands already...
This I have tested on CentOS 6.4. The 2 commands to get it setup would be:

```bash Enabling KVM Console access
$ cat > /etc/init/ttyS0.conf << EOL
# ttyS0 - agetty
#
# This service maintains a agetty on ttyS0.

stop on runlevel [S016]
start on runlevel [23]

respawn
exec agetty -h -L -w /dev/ttyS0 115200 vt102
EOL
$ grubby --update-kernel=ALL --args='console=ttyS0,115200n8 console=tty0'
```

Now, you can reboot the server and connect to the domains console via virsh. If all went well, you *should* be seeing kernel messages and eventually service starts up's, followed by a login prompt in the console.

If rebooting is not a option, you can enable it on the fly, after saving `ttyS0.conf` with `$ initctl start ttyS0` as root.

The `grubby` command is not mandatory, however this is what allows you to see the kernel messages as the guest boots. I **highly** recommend it.

### I have console, but can't log in as root
If you followed this guide, then that would in fact be the case. Logging in directly as root is not something I would recommend. Rather log in as a unprivileged user, and su/sudo up to root. In some cases however it is actually necessary. So, to fix this problem, simply add `ttyS0` as a "securetty" in `/etc/securetty` by running: `$ echo "ttyS0" >> /etc/securetty`. This will allow root logins via the virsh console.


### serial.conf has the answers
If you are looking for more in-depth explanations as to how this works, I suggest you take a look at `/etc/init/serial.conf` (again on CentOS 6.4). You'll notice the configuration for `ttyS0.conf` also comes from here :)
