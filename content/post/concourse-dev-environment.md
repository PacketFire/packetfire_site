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
Jenkins has predominantly been the bread and butter CI/CD tool for technology organizations, where very few tools have been able to compete with the expressiveness of its Groovy-based DSL and the extensibility of its plugin ecosystem. That being said, its tool API is not as straightforward as it could be and its configuration lends itself to eventually becoming a snowflake server on an organization's network. Because of this, I'm always on the lookout for new CI/CD tools to play with and [concourse-ci](https://concourse-ci.org/) caught my eye with its simple YAML-based configuration DSL and modular architecture. One of its most exciting features is how geared towards integrating every aspect of this tool with VCS, which serves to make this tool much easier to automate.

Concourse-ci offers a few options for turning up a development environment. Many of them use a tool written by their parent organization, [Cloud Foundry](https://www.cloudfoundry.org/), called [bosh](https://bosh.io/). There is a docker-compose tutorial that offers an environment to play with the UI, but it's missing many core components that prevent it from being usable for large-scale testing. I've made some modifications to their docker-compose environment to make it useful for experimenting and developing concourse pipelines, detailed below.

### Requirements:
In order to proceed with this tutorial, you will need to install the following tools:

- [docker 1.13.0+](https://docs.docker.com/install/)
- [docker-compose](https://docs.docker.com/compose/install/)


### Setup:
You will need to clone the [concourse dev environment repo](https://github.com/ncatelli/concourse-development-environment).

```bash
$ git clone https://github.com/ncatelli/concourse-development-environment
$ cd concourse-development-environment
$ docker-compose up
```

### Services
The [docker-compose.yml](https://github.com/ncatelli/concourse-development-environment/blob/master/docker-compose.yml) in the repository defines 3 core services: web, worker and db. It also includes a sidecar to handle key generation, a service for the [fly](http://concourse-ci.org/fly-cli.html) cli utility, and a synchronization service to wrap it all together.

#### Network and volumes
I've defined a frontend and backend network in order to separate the fly and worker services from postgres. I've also defined a flyrc volume for persisting the fly configurations across subsequent runs of the fly service.

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
The web API/UI service is a stateless service that handles build scheduling, user interaction, and worker managemement. This service primarily interacts with end users, workers, and any polled resources to determine if a build should be scheduled. In our docker-compose environment, it is configured to communicate with the postgres database and is in both the frontend and backend networks.

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

#### Worker Service:
The [worker service](https://github.com/ncatelli/concourse-development-environment/blob/master/worker/Dockerfile) is responsible for executing builds. It polls the web-api (ATC) for jobs. These jobs are configured to run within Docker containers, so it is important that the worker can access to the Docker engine. The problem with the default docker-compose tutorial is that Docker has not been added to the runner. We will extend both the compose file and the Dockerfile to mount the local host's Docker socket into the worker container.

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

We will need to install Docker on the local host.

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

Since our goal is to invoke the concourse worker, we will simply extend the concourse image by triggering the Docker install shell script. We should now be able to schedule builds on our worker.

#### Keygen sidecar:
Both the worker and web containers that have keys volumes. Before we can start using our containers, we will need to create a sidecar container to generate these keys. This can be accomplished with an alpine container and openssh.

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

We will create a small alpine image to generate our keys. We will then invoke the bash script provided by the concourse team to generate our keys.

```sh
#!/bin/sh

mkdir -p ./web ./worker

ssh-keygen -t rsa -f ./web/tsa_host_key -N ''
ssh-keygen -t rsa -f ./web/session_signing_key -N ''

ssh-keygen -t rsa -f ./worker/worker_key -N ''

cp ./worker/worker_key.pub ./web/authorized_worker_keys
cp ./web/tsa_host_key.pub ./worker
```

Finally, we will mount volumes for each service's keys.

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
The [fly cli](http://concourse-ci.org/fly-cli.html) is used to interact with the web API and will be our main point of interaction with concourse. It can be used to create and trigger pipelines, inspect workers and poll the state of jobs. Since fly is a static binary, we can wrap it in a small alpine image.

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

Our main point of persistence for fly is the .flyrc file. Since our image is run as the root user, we can simply persist the state of our fly service by making the /root directory of our fly service a volume. We can then invoke this service any number of times without losing our login credentials.

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
Using all of these services we can now start our cluster by running `docker-compose up`. This should bring up each of our dependent services followed by the web-ui. This can be viewed by browsing to port 8080 on your localhost which should present you with and empty version of the web UI, showing that no pipelines are configured.

#### Configuring a pipeline
Let's push a simple hello world task to the concourse api using our fly service. We will begin by authenticating fly with the service. The following command connects to our concourse api using the basic auth credentials under the `main` team name.

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

We can finally push it to the concourse api with the following command. This applies our configuration and unpauses the pipeline. After running the following commands you should now see the pipeline in your web UI, which you can manually trigger by clicking the job and clicking the `+` symbol in the top right corner.

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

Optionally, you can run the job via fly with the following trigger job command.

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
This simple docker environment should be enough to get you started running your first concourse pipelines. To expand on your pipeline's complexity, I recommend referencing the great tutorials at [concource tutorials](https://concoursetutorial.com/) as well as working your way through the [documentation](https://concourse-ci.org/docs.html) on the various components involved in creating a pipeline.
