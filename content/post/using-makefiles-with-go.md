---
title: "Using Makefiles with Go"
date: 2017-11-01T00:00:00-00:00
author: "Nate Catelli"
tags: ["make", "golang"]
description: "Using make to wrap golang with extra functionality."
type: "post"
draft: false
---

### Introduction:
One of my favorite features of golang is it's simple toolchain for builds. However at times, I've wished that I could easily add tasks to a build step. Using GNU Make, I've found that I can quickly and easily wrap the go toolchain in a consistent way that leaves plenty of room for customization.
