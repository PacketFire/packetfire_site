---
title: "Building a Docker-based Development Environment for Concourse-CI"
date: 2018-03-25T19:57:07-04:00
author: "Nate Catelli"
tags: ["docker", "ci/cd", "concourse"]
description: "A write-up on creating a local development environment for concourse-ci."
type: "post"
draft: false
---

### Introduction:

### Requirements:
In order to proceed with this tutorial you will need to install the following tools:

- [docker 1.13.0+](https://docs.docker.com/install/)
- [docker-compose](https://docs.docker.com/compose/install/)


### Setup:
To begin, you will need to clone the [concourse dev environment repo](https://github.com/ncatelli/concourse-development-environment).

```bash
ncatelli@ofet> git clone https://github.com/ncatelli/concourse-development-environment
ncatelli@ofet> cd iptables_examples
ncatelli@ofet> docker-compose up
```

