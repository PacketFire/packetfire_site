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
One of my favorite features of golang is its simple toolchain for builds. However at times, I've wished that I could easily add tasks to a build step. Using GNU Make, I've found that I can quickly and easily wrap the go toolchain in a consistent way that leaves plenty of room for customization.

### Wrapping Common Go Commands:
Primarily I leverage four of the go toolchain's subcommands more than anything else and I begin by defining these subcommands in my Makefile.

The fmt command is mostly a copy paste of the corresponding go command. with test being is where we leverage one small feature of make, chaining blocks. This allows us to insure that our package is linted prior to running our tests. Finally I also typically implement a block to render the documentation into a README.md.

```
PKG="github.com/ncatelli/examplepkg"

build: | test
  go build $(PKG)

fmt:
  go fmt $(PKG)

test: fmt
  go test $(PKG)

doc:
  godoc $(PKG) > $(GOPATH)/src/$(PKG)/README.md
```

### Use With cGo:
Though simply wrapping the go toolchain appears to add very little value while adding additional complexity, we begin to see greater benefit when dealing with additional external C libraries. My first use of makefiles with go was while working with [libfreeipmi](https://www.gnu.org/software/freeipmi/). At the time, I was attempting to implement golang bindings for a limited subset of libfreeipmi which required building the shared objects for libfreeipmi from source. Adding this build process to the makefile simplified the building of the library and was easily defined by adding a few extra blocks:

```
PKG="github.com/ncatelli/examplepkg"
BUILDOPTS=--ldflags '-extldflags "-static"'
DEPSCONFOPTS=--enable-static --without-encryption

build: | test
  go build $(BUILDOPTS) $(PKG)

test: fmt deps
  go test $(BUILDOPTS) $(PKG) -v

fmt:
  go fmt $(PKG)

doc: fmt
  godoc $(PKG) > $(GOPATH)/src/$(PKG)/README.md

deps:
  cd libs/freeipmi; \
  ./autogen.sh && \
  ./configure $(DEPSCONFOPTS) && \
  make

clean:
  cd libs/freeipmi; \
  make clean
```

### Leveraging Docker Environments in Makefiles:
If you are not using cGo, you can still derive benefits from the Makefiles abstraction by wrapping a docker build environment. I've included an example of a Makefile from our pasteclick project that wraps a small docker environment with libmagic installed.

```
PKG="gitlab.packetfire.org/Tiksi/paste-click"
GOENV="ncatelli/golang:1.9.2-libmagic"

build: | test
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go build $(PKG)

fmt:
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go fmt $(PKG)

test: fmt
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go test $(PKG)
```

Leveraging a container and make, one is able to provide a consistent build process in a build environment that is repeatable accross platforms.

### Summary:
While the go toolchain is sufficient for purely go packages, leveraging simple makefiles to augment this toolchain with additional tasks is a simple and viable option for keeping your build processes down to a few concise commands.
