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
Jenkins has be been the bread and butter CI/CD tool for years with very few tools that have been able to match the expressiveness of it's groovy-based DSL and the extensibility of its plugin ecosystem. That being said the tool api, is not as straightforward as I wish it could be and its configuration can lends itself to becoming a snowflake server on a teams network. Because of this, I'm always on the lookout for new CI/CD tools to play with and [concourse-ci](https://concourse-ci.org/) caught my eye with it's simple yaml-based configuration DSL and modular architecture. One of the most exciting features was how geared towards integrating every aspect of this tool with VCS, which serves to make this tool much easier to automate.

Concourse-ci offers a few options for turning up a development environment with many of them pointing back to their parent organization, [Cloud Foundry](https://www.cloudfoundry.org/)'s, tool [bosh](https://bosh.io/). They do however include a docker-compose tutorial that is targeted at playing with the UI but I've found that it's missing many core components that prevent it from being completely usable for fulling testing. Below I've detailed some modifications that I've made to their docker-compose environment to make this tool useful for experimenting and deveoping concourse pipelines.

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

