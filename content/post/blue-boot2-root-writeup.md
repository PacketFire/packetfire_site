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
Both attacks are taking place in a fairly flat network consisting of my attack host, a fresh booted livecd of Kali Linux, and the the target host, a freshly booted Windows VM. No other information is known about the host, what it's running or It's versioning, however I would be lying if I said I didn't assume that this would be an eternalblue attack based off the name.

### Attacking Blue With Metasploit
I started the attack by opening a tmux session and starting meterpreter with `msfdb run` to spin up a postgres instance to persist scans and recon data and promptly kicked off an nmap scan.

#### Host Enumeration
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