---
title: "Intro to IPTables with Service-Based Firewalls"
date: 2017-09-07T19:57:07-04:00
author: "Nate Catelli"
tags: ["networking", "iptables"]
description: "An introductory tutorial to simple firewalls with iptables."
type: "post"
draft: false
---

### Introduction:
IPTables is a stateful firewall implemented via the netfilter kernel module. To many, learning iptables can be a daunting task, however when stuctured correctly an iptables firewall can be both simple to understand and easily automated. This tutorial will function as the first in a series of articles focused on firewalling with iptables. 

In this tutorial, we will focus on creating a comprehensible firewall focused on filtering out traffic to the localhost. What this tutorial is not is a deep-dive into iptables, this will be reserved for later tutorials after you have become more comfortable working with the tool.

We will be using a Vagrant-based playground to complete this tutorial, you will need vagrant 1.6+, git and rsync installed.

### Setup:
To begin, you will need to clone the [iptables example repo](https://github.com/ncatelli/iptables_examples.git).

```bash
ncatelli@ofet> git clone https://github.com/ncatelli/iptables_examples.git
ncatelli@ofet> cd iptables_examples
ncatelli@ofet> vagrant up
```

If everything worked you should be able to connect to the new environment with the following command:

```bash
ncatelli@ofet> vagrant ssh node1
Linux node1 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u2 (2017-06-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
vagrant@node1:~$ sudo su -
root@node1:~#
```

From here we can verify that the we have an open firewall:

```bash
root@node1:~# iptables -nL
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

Don't worry if the output from the previous iptables command is unfamiliar to you. A quick intro to iptables will be provided in the next section.

### IPTables:
To the user, IPTables exposes kernel-level packet filtering functionality via sequential rules. These rules are logically grouped within chains, allowing different rules to be evaluated based on described conditions. Chains are grouped into larger logical groups called tables. For now this tutorial, we will be focusing exclusively on the filter table and it is enough to understand that other tables exist and provide other functionality.

#### Filter table:
The filter table is used for filtering packets to and from services on the localhost. This can be as simple as blocking access to all ports on a host from all new incoming requests while allowing outbound traffic to a server, or managing whitelists of IPs. However, complex behaviors can also be implemented within the filter table such as port knocking, rate-limiting and many other behaviors. For the purpose of this tutorial, we will attempt to build a firewall that is both powerful, yet simple to read and structured in a way that is conducive to automation. We will limit this to two services running on this host. SSH and HTTP. Let's begin by learning how we can look at the state of our filter table and learning how to read it. 

We can view our filter table using the earlier ```iptables -nL``` command:

```bash
root@node1:~# iptables -nL
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

We've seen two new flags in this command and one that was implied, all of which I will detail below:

- __-L__: Lists the rulechain for a table.
- __-n__: Specifies that we will list only numeric values as oppose to attempting to resolve host names.
- __-t__: Used to specify the table we would like to reference. By default, this references the filter table.

```bash
root@node1:~# iptables t filter -nL
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

The filter table, by default, has 3 predefined chains, INPUT, OUTPUT AND FORWARD. These chains are the entry-points for packets into the filter table depending on the source and destination of a packet. The INPUT chain receives packets that are destined for the localhost. It is here that you will do your common filtering for your services, such as blocking external traffic to ssh or whitelisting HTTP traffic to the world. The OUTPUT chain will be the default entrypoint for any packet that is sourced from the localhost. It is here that an administrator could block outbound connections to VPNs or ratelimit external requests, to give a few example. The FORWARD chain is used for controlling where packets can be routed. This could include adding filters to traffic that is to be NAT'd to hosts behind your firewall or even locally to virtual machines or containers.

#### Targets:
You will also notice that each built-in chain has a policy associated with it. In the case of each of our chains, the default policy is to ACCEPT. The policy of a chain allows an administrator to specify the target that a packet will default to, should a packet not match any rules that direct it to a target.

```
Chain INPUT (policy ACCEPT)
```

A target allows an administrator to specify the end destination of a packet and functions as a tranistion point both between chains within a table as well as an exit point from the filter table for a packet. There are many [built-in targets](http://www.iptables.info/en/iptables-targets-and-jumps.html) and I encourage you to read up on these targets as you become more familiar with iptables, however for the purpose of this article, we will be primarily focusing on the ACCEPT, DROP and REJECT targets. I will provide a brief description of what each of these targets signify below:

- __ACCEPT__: Signifies that the packet will be accepted and passed on from the filter table. No further processing or evaluation for that packet will occur within the filter table.
- __DROP__: Signifies that the packet will be dropped and no futher processing of it will take place.
- __REJECT__: Functions similarly to DROP, however an ICMP error message will be returned to the host that has sent the rejected packet.

By understanding these targets and policies, we can see that our filter table is accepting any packet that is coming to or from our server. It is worth noting that changing these policies without having the correct rules in place can lead to an administrator firewalling themselves out of a host as these policies set the default behavior of the entire chain. We will explore how we can customize our firewalls with more fine grained rules in the next section.

### IPTables Rules:
In this next section we are going to work on adding rules to whitelist necessary services. We will then explore ways that we can limit traffic to other services that we do not explicitly allow. To accomplish this we will execute the following commands to define this rule in the INPUT chain and chang the policy.

```bash
root@node1:~# iptables -A INPUT -p tcp --dport 22 -j ACCEPT
root@node1:~# iptables -P INPUT DROP
```

Let's explore what these commands mean one by one. The first command:

```bash
root@node1:~# iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

The ```-A INPUT``` flag and argument specifies that we want append the rule to the INPUT chain. ```-p tcp``` specifies the protocol that we are defining this rule for, in this case tcp, and ```--dport 22``` specifies that we will be whitelisting this for the destination port 22. Finally, we specify a jump to a target with ```-j ACCEPT```. This jump tells iptables to accept the packet, passing it on for further processessing, and to stop evaluating rules in the filter table for that packet.

We then need to change the policy to default DROP. 

```
root@node1:~# iptables -P INPUT DROP
```

This command changes the default policy for the INPUT chain to DROP. This target will be applied to any incoming packet that does not already reach a terminating target from previous rules. In the case of our firewall, any packet that does not have a destination port of 22 will fall through our first rule in the INPUT chain and be dropped.

We can view our rules by running the our command from earlier. This will allow us to see that our policy has changed and that we now have a new rule under the INPUT chain.

```bash
root@node1:~# iptables -nL
Chain INPUT (policy DROP)
target     prot opt source               destination         
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination  
```

We are still able to SSH into this host for now, however changing our INPUT policy has had an unexpected side effect. We are no longer able to receive inbound packets from other established connections. We can view this issue by attempting to make an outbound ping to google's public DNS.

```bash
root@node1:~# ping 8.8.8.8 -c 1
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms 
```

To resolve this issue, we will make use of IPTables connection state tracking.

#### Connection State Tracking:
IPTables is considered a stateful firewall due to its ability to perform connection tracking. This provides a ton of power and flexibility as packets can be associated with a running connection, allowing matches of previous packets to persist state to later packets. We will use this exact feature to fix the ping problem from before.

```bash
root@node1:~# iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

IPTables supports loadable extension modules for additional matching features. To perform state tracking in a rule, we will need to load the conntrack module, this can be done with the ```-m conntrack``` flag and argument. We need to allow connections that have already been established as well as related connections for our ICMP error messages. This can be specified by allowing packets from connections associated with the ```RELATED``` and ```ESTABLISHED``` states in iptables state machines. This can be accomplished by adding the ```--ctstate RELATED,ESTABLISHED``` flag after our module load. Finally, We will jump to the ACCEPT target to stop all further evaluations.

This rule will satisfy many packets as often a server will have long running tcp connections. Since IPTables evaluates rules sequentially, it's more important to have this rule added to the top of the chain to limit rules that will need to be evaluated. For this, we've used the ```-I``` flag to insert the rule to the top of the chain, in place of appending it to the end of the chain. We can view the newly modified chain with our connection tracking rule using the list flag we learned earlier.

```bash
root@node1:~# iptables -nL
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

Though this firewall is easy to read now, as the ruleset grows this can quickly become complex and unreadable. Being able to break rules up into smaller logical grouping allows the ruleset to grow while still being easily readable. In the next section we will restructure our firewall to use user-defined chains and begin setting up the structure of our service-based firewall.

### User-defined Chains:
Defining our own chains aside from the INPUT, FORWARD and OUTPUT chain will allow us to create logical whitelists based on services and break up our rules into smaller, easily understandable sequences. We will begin by defining an inbound chain for SSH.

```bash
root@node1:~# iptables -N SSH_IN
root@node1:~# iptables -nL
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy ACCEPT)             
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain SSH_IN (0 references)
target     prot opt source               destination
```

The ```-N``` flag takes a single argument for a new chain. However, this new chain has zero references so far. We will move our rule accepting packets for port 22 to this chain. However let's narrow down the rules a little bit to only allow access between our desktop and node1 as well as allow access from node2. We will begin by adding two rules

```bash
root@node1:~# iptables -A SSH_IN -s 10.0.2.0/24 -j ACCEPT
root@node1:~# iptables -A SSH_IN -s 10.0.0.11/32 -j ACCEPT
```

Finally we will need to update the INPUT chain to forward inbound tcp packets destined for port 22 to the ```SSH_IN``` chain. Then remove the old record.

```
root@node1:~# iptables -A INPUT -p tcp --dport 22 -j SSH_IN
root@node1:~# iptables -D INPUT 2
```

In the first rule, much like our original rule for port 22, we've adjusted the jump target from ```ACCEPT``` to instead jump to our newly defined target, the ```SSH_IN``` chain. In the second rule we've encountered a new flag. ```-D``` specifies that we want to delete a rule. In this case we are specifying that we would like to delete the second rule from the INPUT chain. A list command will show our new rules are in place.

```bash
root@node1:~# iptables -nL
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
SSH_IN     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain SSH_IN (1 references)
target     prot opt source               destination
ACCEPT     all  --  10.0.2.0/24          0.0.0.0/0
ACCEPT     all  --  10.0.0.11            0.0.0.0/0
```

This user-defined chain may leave a new admin with additional questions. Like, what happens if no rule matches a packet that is jumped to this target. Any packet sent to the ```SSH_IN``` chain that does not match any rule will be returned to it's calling chain, in this case ```INPUT```. In the next section we will setup an additional service for whitelisting http. 

#### More Services:
Currently we have an instance of nginx listening on port 80 of node1. Lets create a new chain for the http service. and and add a whitelist for all the private subnets on node2. That will be ```10.0.100.0/24``` and ```10.0.0.0/24```. Currently, packets destined for port 80 on node1 will be dropped. This can be verifed by attempting to curl the nginx site from node2.

```bash
root@node2~# curl -sD - 'http://10.0.100.10' -o /dev/null
root@node2~#
```

We will need to create a new inbound chain for http on node one and begin adding the rules.

```bash
root@node1:~# iptables -N HTTP_IN
root@node1:~# iptables -A HTTP_IN -s 10.0.100.0/24 -j ACCEPT
root@node1:~# iptables -A HTTP_IN -s 10.0.0.0/24 -j ACCEPT
root@node1:~# iptables -A INPUT -p tcp --dport 80 -j HTTP_IN
root@node1:~# iptables -nL
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
SSH_IN     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
HTTP_IN    tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain HTTP_IN (1 references)
target     prot opt source               destination
ACCEPT     all  --  10.0.100.0/24        0.0.0.0/0
ACCEPT     all  --  10.0.0.0/24          0.0.0.0/0

Chain SSH_IN (1 references)
target     prot opt source               destination
ACCEPT     all  --  10.0.2.0/24          0.0.0.0/0
ACCEPT     all  --  10.0.0.11            0.0.0.0/0
```

We can then verify that we are able to curl the host from node2:

```bash
root@node2:~# curl -sD - 'http://10.0.100.10' -o /dev/null
HTTP/1.1 200 OK
Server: nginx/1.10.3
Date: Tue, 12 Sep 2017 02:12:54 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Mon, 11 Sep 2017 19:06:24 GMT
Connection: keep-alive
ETag: "59b6deb0-264"
Accept-Ranges: bytes
```

### Next Steps:
Managing firewalls on a service by service basis makes it simple to add and remove access to a service by adding or removing a rule to a chain. An administrator can extend this further by managing the outgoing rules to limit access to internal services on their network and better restrict the network accessibilty of their server to only services they define. This setup also lends itself to the use of [IP Sets](http://ipset.netfilter.org), a fast indexable data structure for storing large sets of IP addresses, which could significantly benefit performance for large chains.

This method also lends itself well to automation, as the structure segregates services into their own chains, allowing a recipe/role/manifest to manage a single chain rather than worrying about the positioning of a rules directly in the input chain.

Bear in mind, this is only scratching the surface of what can be done with IPTables. In the followup articles we will dig deeper into what can be accomplished with this toolchain.