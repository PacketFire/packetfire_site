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
The Internal host took me almost 24 hours to complete just due to the sheer number of hops required to complete it. Unlike many of the other boot2roots I've completed on THM, this host required review of logs and the host above and beyond the results of automated enumaration tools like linPEAS. I enjoyed this host immensely and I thought it was incredibly brilliant machine. 

## Environment
The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the target host. Information on the host was extremely limited other than that there would be two flags available corresponding to a user and root flag. It was also known that the host contained a web application, and that the host, known by the vhost internal.thm, was the only host in scope.

## Attack 

### Host enumeration

## Summary
