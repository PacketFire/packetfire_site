---
title: "Intro to BGP with BIRD"
date: 2017-08-21T13:43:28-04:00
author: "Nate Catelli"
tags: ["networking"]
draft: false
---

### Introduction:
Border Gateway Protocol (BGP) is one of the core technologies involved in making our internet work, allowing networks to communicate their routes among eachother. Understanding how this tool can be used to define the topology of a network will both give you a better understanding of how internetworking and allow you translate this robustness into your own network. 

By the end of this tutorial, you will be familiar with the core concepts of BGP and have the proper vocabulary to communicate this to another network engineer. You will also be able to use a userland routing daemon, BIRD, to establish peering sessions and begin announcing routes.

I plan to achieve this using a virtualized vagrant playground which can be downloaded [here](https://gitlab.packetfire.org/crunchbite/bird_examples.git). In order to complete this tutorial you will need to install vagrant 1.6+, git and rsync.

### Setup:
To begin, you will need to clone the repo and all submodules of the [bird_examples](https://gitlab.packetfire.org/crunchbite/bird_examples.git) project.

```bash
ncatelli@ofet> git clone https://gitlab.packetfire.org/crunchbite/bird_examples.git
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
kernel1  Kernel   master   up     12:05:06    
device1  Device   master   up     12:05:06    
peer2    BGP      master   up     12:06:07    Established   
peer3    BGP      master   up     12:07:07    Established
```

If you see that peer2 and peer3 are "Established", everything is working as expected and we are ready to go. Before we begin playing with this playground, I will provide a brief overview of how BGP works.

### BGP Overview:
#### Terminology:
Border Gateway Protocol ([BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)) is an exterior gateway protocol that is used to exchange routing information between autonomous systems. An autonomous system ([AS](https://en.wikipedia.org/wiki/Autonomous_system_(Internet))) is an organizational unit of routing prefixes and policies. These AS are identified by a unique 16-bit, and later 32-bit, autonomous system number (ASN). For example, Facebook's ASN would be 32934 or as commonly presented AS32934. The power of BGP lies in its ability to communicate routing protocols and policies among tens of thousands of decentralized AS.

The internet, along with many other networks, is composed of many autonomous systems that communicate between each other. This communication is facilitated by a peering session, which allows two AS to exchange policies, routes and link status. All of this information is exchanged between two BGP daemons, which will be listening on TCP port 179.

While BGP is considered an exterior gateway protocol that is used for routing between large organizations on the internet, it can also be used within an AS to enable their network engineers to control the topology of their internal network. This is where the terms exterior BGP (eBGP) and interior BGP (iBGP) stem from. iBGP will be our focus for the rest of this tutorial. We will now start experimenting with these peering sessions using BIRD and its interactive command-line tool, birdc.

### Introduction to BIRD:
BIRD is a fully-functional routing daemon that supports many different routing protocols, including BGP. BIRD provides a simple configuration format and command line utility for interacting with sessions. BIRD also comes with built-in support for both IPv4 and IPv6 and the respective tools to work with both protocols. 

#### Examining Sessions:
Similiar to how we verified that our vagrant environment was provisioned properly, we can view running sessions by running:

```bash
root@peer1:~# birdc show protocols                  
BIRD 1.6.3 ready.         
name     proto    table    state  since       info  
kernel1  Kernel   master   up     00:27:05          
device1  Device   master   up     00:27:05          
peer2    BGP      master   up     00:28:02    Established
peer3    BGP      master   up     00:28:59    Established 
```

This gives us a lot of information. However, let us focus on the last two entries, peer2 and peer3. We can see that they are both BGP protocols and that the info field is Established. Each of these entries correspond to a BGP session that peer1 has open with peer2 and peer3. To demonstrate the relationship of these values to our running sessions, let's stop the bird service on peer2.

```bash
root@peer2:~# systemctl stop bird 
```

```bash
root@peer1:~# birdc show protocols
BIRD 1.6.3 ready.
name     proto    table    state  since       info
kernel1  Kernel   master   up     12:05:06    
device1  Device   master   up     12:05:06    
peer2    BGP      master   up     12:06:07    Active      Socket: Connection refused 
peer3    BGP      master   up     12:07:07    Established
```

By restarting BIRD on peer2, a peering session should be reestablished.

```bash
root@peer2:~# systemctl start bird
```

```bash
root@peer1:~# birdc show protocols
BIRD 1.6.3 ready.
name     proto    table    state  since       info
kernel1  Kernel   master   up     00:27:05    
device1  Device   master   up     00:27:05    
peer2    BGP      master   up     00:42:33    Established   
peer3    BGP      master   up     00:28:59    Established
```

By stopping the bird daemon on peer2, we have made the TCP connection on port 179 close between peer1 and peer2. Doing this changes our peer session from Established to Active. Established and Active correspond to two of many BGP states, however for the sake of this tutorial we will focus only on Established and consider all other values as not-established. For those more curious, more information on session states can be found in the [wikipedia article on BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol#Finite-state_machines).

#### Configuring a BGP Session 
Although we now know how to check whether our session are up in our BGP playground, it's also important to understand how these sessions were configured in the first place. For that, we need to dig into the bird configuration files. Let's look at the configuration files under /etc/bird on peer1.

```bash
root@peer1:~# cat /etc/bird/bird.conf
log syslog all;
router id 10.0.2.15;

include "/etc/bird/bird.conf.d/*.conf";
```

```bash
root@peer1:~# cat /etc/bird/bird.conf.d/kernel.conf
protocol kernel {
  metric 0;
  learn;
  import all;
  export none; 
}
```

```bash
root@peer1:~# cat /etc/bird/bird.conf.d/device.conf
protocol device {
}
```

```bash
root@peer1:~# cat /etc/bird/bird.conf.d/bgp_peer2.conf
protocol bgp peer2 {
  local as 64512;
  neighbor 10.0.0.11 as 64513;
  import all;
  export all;
}
```

We can see that the configuration to establish these initial sessions is very minimal. Let's dig deeper into what actually makes this work. For that, we will focus on one specific block. Our protocol bgp peer2 block:

```bash
protocol bgp peer2 {
  local as 64512;
  neighbor 10.0.0.11 as 64513;
  import all;
  export none;
}
```

Earlier in this tutorial, we discussed the difference between eBGP and iBGP and how large AS identify themselves with a unique ASN. However, a small section of the available ASN have been reserved for private iBGP use. This range is 64512 - 65534. Knowing this, we can see that we have allocated a ASN from the private range to our peer2. This _local as_ statement refers to the ASN of your local machine. In this case, peer1 is assigned the ASN 64512.

Looking at the next statement, we can see a neighbor statement with both an IP and an additional AS. This IP corresponds to the host, or neighbor in BGP lingo, that we are attempting to establish a session with, while the AS 64513 corresponds to the AS we've assigned to the host, peer2. We can confirm this by looking at the configuration file on peer2.

```bash
root@peer2:~# cat /etc/bird/bird.conf.d/bgp_peer1.conf
protocol bgp peer1 {
  local as 64513;
  neighbor 10.0.0.10 as 64512;
  export none;
}
```

It is these two directives in our protocol BGP blocks that handle the initial establishment of sessions.

While establishing and maintaining sessions is crucial to the operation of BGP, established sessions alone will not allow you to route any traffic. In the next section, we will explore some of the other elements of our configuration files and how we can use them to discover and announce routes between our nodes.

### Advertising Routes with BGP:
#### Kernel Protocol:
Before we begin announcing routes between bird daemons, we should first understand how BIRD communicates routes between the linux kernel and the BIRD daemon. This is where that kernel protocol block we saw earlier comes into play.

```
protocol kernel {
  metric 64;
  learn;
  import none;
  export all; 
}
```

There are many options that can be specified in the kernel block, and more information on those can be found [here](http://bird.network.cz/?get_doc&f=bird-6.html#ss6.6), however the bulk of what we want to do is defined by the import/export definitions.

```
import none;
```

Tells BIRD to not read routes in from the kernel routing table into BIRD. We will be obtaining our routes via the direct protocol which we will configure shortly.

```
export all;
``` 

Tells BIRD to export all routes learned by other announcements into the kernel's routing table. This allows us to actually leverage any learned routes on this host.

```
metric 0;
```

The metric value is used by the linux kernel to determine the priority of a route, picking the one with the lowest priority. In this case we have set it to an 0 or undefined so that we prefer local routes.

```
learn;
```

Finally, we will set the _learn_ directive which will allow other daemons to learn about routes from the kernel routing table.

#### Discovering direct routes:
Now that we have configured our BIRD daemons to push routes directly to the kernel routing table, we will need to configure our peers to discover local direct routes. Since we will be adding these routes directly to our loopback interface, let's configure the direct protocol to only use the lo interface.

```bash
root@peer2:~# cat /etc/bird/bird.conf.d/direct.conf
protocol direct {
  interface "lo";
}
```

At this point, we will have no routes learned or announced, which can be verified with birdc.

```bash
root@peer2:~# birdc show route all
BIRD 1.6.3 ready.
```

#### Filtering imports and exports:
Similar to the kernel module, export and import can be used to control what is imported and exported by of a BGP peer. Lets begin by exploring the concept of filtering and how it can be used to control what routes will be announced or exported.

Filters in BIRD are basically functions that execute on routes, returning either _accept_ or _reject_. This allows us to apply a simple programming language to add logic to our routing policies. Filters can contain anything from a single statement to very complex logic. To begin, let's reimplement our none and all directives as filters, adding them to our bird.conf file above the include directive.

```
filter accept_all {
  accept;
};
```

```
filter reject_all {
  reject;
};
```

Now that we have our filters in place, let's implement them in our import/export directives for one of our protocol blocks. On your host, peer1, lets look at the block for protocol bgp peer2.

```
protocol bgp peer2 {
  local as 64512;
  neighbor 10.0.0.11 as 64513;
  import filter accept_all;
  export filter accept_all;
}
```

Functionally, this is identical to our original configuration, however now we can extend these settings with further logic. The power of these filters can be understood by researching the [filter scripting language](http://bird.network.cz/?get_doc&f=bird-5.html) further. To expand on what we have learned, let's create a filter in our bird.conf on peer2 to control routes we want to announce to peer1.

```
filter export_subnets {
  if net ~ [ 192.168.5.5/32 ] then {
    accept;
  }
  reject;
}
```

and finally we will need to update our protocol bgp peer1 on peer2 to use this export filter.

```bash
root@peer2:~# cat /etc/bird/bird.conf.d/bgp_peer1.conf
protocol bgp peer1 {
  local as 64513;
  neighbor 10.0.0.10 as 64512;
  export filter export_subnets;
}
```

#### Announcing Routes with BIRD:
We now have all the building blocks we need to begin announcing routes between peer1 and peer2. Before we do thata, let's recap what we have done. To begin, we've configured the BIRD daemon to communicate between its internal routing tables and the kernel routing tables with our kernel protocol. We've configured the BIRD daemon to learn routes from the loopback interface with the direct protocol. We've also configured peer1 to import routes from the other peers and export those routes. Finally we configured peer2 to only export ```192.168.5.5/32``` to peer1 with our export_subnets filter. However, at this point we have no routes currently announced from peer2 to peer1.

```bash
root@peer1:~# ip route
default viia 10.0.2.2 dev eth0
10.0.0.0/24 dev eth1 proto kernel scope link src 10.0.0.10
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15
```

Since we've set up all the building blocks to learn our routes from from the loopback interface. We should be able to directly announce a route by adding an IP to the loopback on peer2.

```bash
root@peer2:~# ip a add 192.168.5.5/32 dev lo
```

Now if we look at both birdc and the kernel routing table on peer1 we should begin to see routes on peer1 to this new IP.

```bash
root@peer1:~# ip route
default viia 10.0.2.2 dev eth0
10.0.0.0/24 dev eth1 proto kernel scope link src 10.0.0.10
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15
192.168.5.5 via 10.0.0.11 dev eth1 proto bird
```

```bash
root@peer1:~# birdc show route all                                            
BIRD 1.6.3 ready.
192.168.5.5/32     via 10.0.0.11 on eth1 [peer2 14:11:33] * (100) [AS64513i]
        Type: BGP unicast univ
        BGP.origin: IGP
        BGP.as_path: 64513
        BGP.next_hop: 10.0.0.11
        BGP.local_pref: 100
```

A ping will show that we can now send traffic to this host from peer1.

```bash
root@peer1:~# ping -c 1 192.168.5.5
PING 192.168.5.5 (192.168.5.5) 56(84) bytes of data.
64 bytes from 192.168.5.5: icmp_seq=1 ttl=64 time=0.627 ms

--- 192.168.5.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.627/0.627/0.627/0.000 ms
```

We can also see that we can now see that these routes are being forwarded on to peer3 via peer1.

```bash
root@peer3:~# birdc show route all
BIRD 1.6.3 ready.
192.168.5.5/32     via 10.0.0.11 on eth1 [peer1 14:30:34 from 10.0.0.10] * (100) [AS64513i]
        Type: BGP unicast univ
        BGP.origin: IGP
        BGP.as_path: 64512 64513
        BGP.next_hop: 10.0.0.11
        BGP.local_pref: 100
root@peer3:~# ping -c 1 192.168.5.5
PING 192.168.5.5 (192.168.5.5) 56(84) bytes of data.
64 bytes from 192.168.5.5: icmp_seq=1 ttl=64 time=0.176 ms

--- 192.168.5.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.176/0.176/0.176/0.000 ms
```

We can tell this is happening by viewing the AS PATH. By looking at the AS PATH associated with the route in birdc we can see that the route announced from 64513 to 64512 before reaching peer3.

```bash
BGP.as_path: 64512 64513
```

Because peer1 was configured to export routes to peer3, and because peer3 was configured to import routes from peer1, we were able to get this route into the BIRD routing table on peer3. Then, because we have the kernel protocol configured to export routes in BIRD, these routes will make it into the kernel routing table on peer3.

### Next steps:
We've explored many concepts in this simple tutorial, however we've barely scratched the surface of what bird and by extension BGP can do. Feel free to use this playground to further experiement with announcing and filtering routes. In later tutorials, we will dig deeper into how BGP works and the processes it uses to determine routes, including what communities and local preference are and how these can be used by your BGP daemon to choose the best path to a server. We will also explore what an anycasted IP is and how we can configure high-availability with BGP. BGP can give you a significant amount of control over the topology of your network.
