FROM debian:10

LABEL maintainer="Nate Catelli <ncatelli@packetfire.org>"
LABEL description="The hugo build environment for the packetfire site."
LABEL "com.github.actions.name"="Hugo Actions"
LABEL "com.github.actions.description"="The hugo build environment for the packetfire site."

RUN apt-get update && \ 
    apt-get install -y curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
