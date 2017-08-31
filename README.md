Current PF site implemented using the static site generator, [Hugo](https://gohubo.io).

### Install
For installation of hugo see the [installation page](https://gohubo.io/getting-started/installing).

### Layout
Posts can be added by adding a new .md file under content/post/. These require a header field.

```
---
title: "Intro to BGP with BIRD"
date: 2017-08-21T13:43:28-04:00
author: "Nate Catelli"
tags: ["networking"]
description: "An introductory tutorial on BGP using BIRD and vagrant."
draft: false
---
```

### Commiting

New posts should be created in a seperate branch, When ready to add, open a merge request to master.
