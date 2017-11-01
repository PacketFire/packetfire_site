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

### Wrapping Common Go Commands:
Primarily I leverage four of the go toolchain's subcommands more than anything else and I begin by wrapping the make in similarly named make blocks. At the top of the file I typically define the package name.

The fmt command is mostly a copy paste of the corresponding go command. with test being is where we leverage one small feature of make, chaining blocks. This allows us to insure that our package is linted prior to running our tests. Finally I also typically implement a block to render the documentation into a README.md.

```
PKG="github.com/ncatelli/examplepkg"

build: | fmt test
  go build $(PKG)

fmt:
  go fmt $(PKG)

test: fmt
  go test $(PKG)

doc:
  godoc $(PKG) > $(GOPATH)/src/$(PKG)/README.md
```

### Use with cGo:

