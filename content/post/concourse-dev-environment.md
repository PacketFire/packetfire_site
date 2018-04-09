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
$ git clone https://github.com/ncatelli/concourse-development-environment
$ cd iptables_examples
$ docker-compose up
```

### Services
The [docker-compose.yml](https://github.com/ncatelli/concourse-development-environment/blob/master/docker-compose.yml) in the above repo contains our 3 core services, web, worker and db, along with a sidecar to handle key generation, a service for the [fly](http://concourse-ci.org/fly-cli.html) cli utility and finally a synchronization service to wrap it all up. Below I will detail the purposes of each of these services and review their definitons.

#### Required networks and volumes:
To seperate service access, I've defined both a frontend and backend network to seperate the fly and worker services from postgres. I've also defined a flyrc volume for persisting the fly configurations across runs of the fly service.

```yaml
volumes:
  flyrc:
  web_keys:
  worker_keys:

networks:
  frontend:
  backend:
```

#### Web API/UI Service:
The web api/ui service is a stateless service that handles all the build scheduling, user interation and worker managemement. This service primarily interacts with the the end users, the workers and any polled resources to determine if a build should be scheduled.

```yaml
  web:
    image: concourse/concourse:3.9.2
    command: 
      - web
    ports: 
      - "8080:8080"
    volumes: 
      - "web_keys:/concourse-keys:ro"
    restart: unless-stopped 
    environment:
      CONCOURSE_BASIC_AUTH_USERNAME: concourse
      CONCOURSE_BASIC_AUTH_PASSWORD: changeme
      CONCOURSE_EXTERNAL_URL: "${CONCOURSE_EXTERNAL_URL}"
      CONCOURSE_POSTGRES_HOST: 'db'
      CONCOURSE_POSTGRES_USER: concourse
      CONCOURSE_POSTGRES_PASSWORD: changeme
      CONCOURSE_POSTGRES_DATABASE: concourse
    networks:
      - frontend
      - backend
    depends_on: 
      - db
      - ready
```

This service has been configured to communicate with the postgres database and has been added to both the frontend and backend networks.

#### Worker Service:
The [worker service](https://github.com/ncatelli/concourse-development-environment/blob/master/worker/Dockerfile) handles the bulk of the work of our builds. The worker service continuously polls the web-api (ATC) for jobs. These jobs are configured to run within docker containers and thus it is important that we have access to the docker engine within our worker. The problem with the default docker-compose tutorial is that docker has not been added to our runner. We will extend both the compose file and a wrapper dockerfile to add docker to our worker.

```yaml
  worker:
    build:
      context: ./worker
    privileged: true
    command: worker
    volumes: 
      - "worker_keys:/concourse-keys:ro"
      - "/var/run/docker.sock:/var/run/docker.sock"
    environment:
      CONCOURSE_TSA_HOST: web
    networks:
      - frontend
    depends_on:
      - web
```

We've added the following volume `- "/var/run/docker.sock:/var/run/docker.sock"` to mount our lock host's docker socket into our worker container. Finally we will need to install the docker tooling on the local host.

```dockerfile
FROM concourse/concourse:3.9.2

LABEL maintainer="Nate Catelli <ncatelli@packetfire.org>"
LABEL description="Containerized version of a concourse worker running docker."

VOLUME /var/lib/docker

RUN apt-get update -y && \
    apt-get install curl -yq && \
    curl -sSL https://get.docker.com/ | sh && \
    apt-get clean
```

Since our goal is to invoke the concourse worker, we will simply extend the concourse image by triggering the docker install sh script. We should now be able to invoke builds on our worker.

#### Keygen sidecar:
We've showed both the worker and web containers that have corresponding keys volumes. Before we can start using our containers, we will need to create a sidecar container to generate these keys. This can be very quickly and minimally accomplished with an alpine container and openssh.

```dockerfile
FROM alpine:3.7

LABEL description='Key generation sidecar for concourse-ci'
LABEL maintainer='Nate Catelli <ncatelli@packetfire.org>'

ENV KEY_DIR='/data'

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh && \
    apk add --no-cache openssh

VOLUME ${KEY_DIR}
WORKDIR ${KEY_DIR}

CMD ["/usr/local/bin/start.sh"]
```

We will create a small alpine image to generate our keys. We will then leverage the bash script provided by the concourse team to generate our keys.

```sh
#!/bin/sh

mkdir -p ./web ./worker

ssh-keygen -t rsa -f ./web/tsa_host_key -N ''
ssh-keygen -t rsa -f ./web/session_signing_key -N ''

ssh-keygen -t rsa -f ./worker/worker_key -N ''

cp ./worker/worker_key.pub ./web/authorized_worker_keys
cp ./web/tsa_host_key.pub ./worker
```

Finally we will mount volumes for each servies keys.

```yaml
  keygen_sidecar:
    build:
      context: ./keygen_sidecar
    working_dir: "/data"
    volumes:
      - "worker_keys:/data/worker"
      - "web_keys:/data/web"
```

#### Fly service:
The [fly cli](http://concourse-ci.org/fly-cli.html) is used to interact directly with the web api and will be our main point of interaction with concourse. This tool can be used to create and trigger pipelines, inspect workers and check the state of jobs. Since fly is a static binary, we can simply wrap this in a small alpine image.

```dockerfile
FROM alpine:3.7

ARG VERSION="3.9.2"

LABEL description='Command container for concourse fly cli'
LABEL maintainer='Nate Catelli <ncatelli@packetfire.org>'

VOLUME /root

ADD https://github.com/concourse/concourse/releases/download/v${VERSION}/fly_linux_amd64 /usr/local/bin/fly
RUN chmod +x /usr/local/bin/fly

ENTRYPOINT [ "/usr/local/bin/fly" ]
CMD [ "-h" ]
```

Luckily, our main point of persistence for fly is the .flyrc file. Since our image is run as the root user, we can simply persist the state of our fly service by making the /root directory of our fly service a volume. We can then invoke this service any number of times without fear of losing our login credentials.

```yaml
  fly:
    build:
      context: ./fly
      args:
        VERSION: "3.9.2"
    volumes:
      - flyrc:/root
    networks:
      - frontend
```

### Putting it all together
Using all of these services we can now start our cluster with a `docker-compose up`. This should bring up each of our dependent services followed by the web-ui. This can be viewed by browsing to port 8080 on your localhost which should present you with and empty version of the web ui claiming that no pipelines are configured.

#### Configuring a pipeline
From this point, we can continue on with the concourse tutorial by pushing a simple hello world task to the concourse api using our fly service. We will begin by authenticating fly with the service. the following command connects to our concourse api using the basic auth credentials and under the `main` team name.

```bash
$ docker-compose run --entrypoint sh fly
$ fly login -c http://web:8080 -u concourse -p changeme -t main
$ fly ts
name  url              team  expiry
main  http://web:8080  main  Tue, 10 Apr 2018 01:22:41 UTC
```

We can then create a basic hello world pipeline using the following simple pipeline. Which we should save locally to `test-task.yml`.

```yaml
---
jobs:
- name: job-hello-world
  public: true
  plan:
    - task: hello-world
      config:
        platform: linux
        image_resource:
          type: docker-image
          source:
            repository: ubuntu
        run:
          path: echo
          args:
            - hello world
```

We can finally push it to the concourse api with the following command. This applies our configuration and unpauses the pipeline. After running the following commands you should now see the pipeline in your web ui and you should be able to manually trigger this by clicking the job, and then clicking the `+` symbol in the top right corner.

```bash
$ fly -t main sp -c test-task.yaml -p helloworld
apply configuration? [yN]: y
pipeline created!
you can view your pipeline here: http://web:8080/teams/main/pipelines/helloworld

the pipeline is currently paused. to unpause, either:
  - run the unpause-pipeline command
  - click play next to the pipeline in the web ui
$ fly -t main up -p helloworld
```

Optionally you may run the job via fly with the following trigger job command.

```bash
$ fly -t main gp -p helloworld
groups: []
resources: []
resource_types: []
jobs:
- name: job-hello-world
  public: true
  plan:
  - task: hello-world
    config:
      platform: linux
      image_resource:
        type: docker-image
        source:
          repository: ubuntu
      run:
        path: echo
        args:
        - hello world
$ fly -t main tj -j helloworld/job-hello-world
started helloworld/job-hello-world #2
```

### Conclusion
This simple docker environment should be enough to get you started running your first concourse pipelines. To expand on your pipelines complexity, I'd recommend that you reference the greate tutorials at [concource tutorials](https://concoursetutorial.com/) as well as work your way through the [documentation](https://concourse-ci.org/docs.html) on the various components use to compose a pipeline.
