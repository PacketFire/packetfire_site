#!/bin/bash
set -e
set -x

echo $HUGO_VERSION

curl -sk "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_${HUGO_VERSION}_Linux-64bit.tar.gz" -L -o /tmp/hugo.tar.gz
tar -zxf /tmp/hugo.tar.gz -C /tmp/
mv /tmp/hugo /usr/local/bin/hugo
rm -rf /tmp/*

sh -c "hugo $*"
