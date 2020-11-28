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

## Summary
