---
title: "High-Availability with BGP using BIRD"
date: 2017-11-02T00:00:00-04:00
author: "Nate Catelli"
tags: ["networking"]
description: "Using BIRD to provide high-availability using routing."
type: "post"
draft: false
---

### Introduction:
There are many techniques to providing high-availability for a service including layer 4 and layer 7 load balancing, DNS round-robin and many others. In this article, we will explore using BGP to provide high-availability directly through routing at layer 3. In achieving this, I will be digging deeper into some concepts from the previous articles, [Intro to BGP with BIRD](/post/intro-to-bgp/), such as announcement filtering, BGP communities and how a best path is decided. If you haven't already read through my original article I'd recommend that you begin there.

In order to complete this tutorial you will need to have vagrant 1.6+, git and rsync installed.

### Setup:
To begin, you will need to clone the repo and all submodules of the [bird_examples](https://github.com/ncatelli/bird_examples.git) project.

```bash
ncatelli@ofet> git clone https://github.com/ncatelli/bird_examples.git
ncatelli@ofet> cd bird_examples
ncatelli@ofet> git submodule init
ncatelli@ofet> git submodule update
ncatelli@ofet> vagrant up
```

This should create three VMs, peer1, peer2 and peer3, all of which have BIRD installed and have peering sessions established. Don't worry if you don't know what this means yet, we will cover it shortly after we have our BGP playground set up and ready to go.

### Login in to your playground:
We will start by connecting to peer1 and checking that everything was setup correctly.

```bash
ncatelli@ofet> vagrant ssh peer1
Linux peer1 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u2 (2017-06-26) x86_64 

The programs included with the Debian GNU/Linux system are free software; the exact distribution terms for each program are described in the individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law. 
vagrant@peer1:~$ sudo su -
root@peer1:~# birdc show protocols
BIRD 1.6.3 ready.
name     proto    table    state  since       info
peer2    BGP      master   up     12:06:07    Established
peer3    BGP      master   up     12:07:07    Established
device1  Device   master   up     12:05:06    
direct1  Direct   master   up     12:05:06    
kernel1  Kernel   master   up     12:05:06    
```

If you see that peer2 and peer3 are "Established", everything is working as expected and we are ready to go. Before we begin working with this playground, in the next section I will begin reviewing how best path selection is accomplished in BGP.

### BGP Path Selection:
#### Best Path Selection Algorithm:
The BGP specification defines an algorithm that is used to determine the best path to a route. Understanding how your paths will be determined is essential for any network engineer and I will briefly review how this is determined below. That being said, I'd urge the reader to read through [Cisco's documentation](https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/13753-25.html) on the best path selection algorithm as this will cover it in much greater detail. 
