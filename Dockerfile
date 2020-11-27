FROM ubuntu:20.10

# see CLion definition
# https://github.com/JetBrains/clion-remote/blob/master/Dockerfile.remote-cpp-env

ARG SSH_KEY_ARG=
ENV DEBIAN_FRONTEND=noninteractive
RUN perl -pi -e 's/# deb-src/deb-src/' /etc/apt/sources.list
RUN apt-get update && apt-get install -qy \
    cmake g++ \
    build-essential \
    tar python tzdata \
    libpcap0.8-dev \
    libboost-filesystem-dev libboost-system-dev \
    libprotobuf-dev protobuf-compiler \
    gdb openssh-server rsync dpkg-dev clangd \
    && apt-get dist-upgrade -qy \
    && apt-get clean -qy

RUN mkdir -p /docker-pkgs /docker-src
WORKDIR /docker-src
RUN apt-get source libc6 libstdc++6 libc++-dev libpcap0.8-dev

# allow Clion to ssh in
EXPOSE 22

# Authorize SSH Host
RUN mkdir -p  /run/sshd /root/.ssh && \
    chmod 0700 /root/.ssh && \
    echo "${SSH_KEY_ARG}" > /root/.ssh/authorized_keys && \
    chmod 0600 /root/.ssh/authorized_keys && \
    echo 'AddressFamily inet' > /etc/ssh/sshd_config.d/AddressFamily_inet.conf
# https://unix.stackexchange.com/questions/470905/why-addressfamily-needs-to-be-configured-for-x11-forwarding

COPY . /docker-src

ENTRYPOINT /etc/init.d/ssh start && tail -f /dev/null
