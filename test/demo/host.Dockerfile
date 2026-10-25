# Demo only: a systemd host with its own Docker daemon, the stand-in for the Linux server "nmsctl install" expects
# (the same packages as the CI runner needs: docker, compose, iproute2, iptables). Everything of the stand runs inside it.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus docker.io docker-compose-v2 \
      iproute2 ca-certificates curl sudo && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN systemctl enable docker && systemctl mask systemd-resolved systemd-networkd getty@tty1 console-getty
# the install preflight requires published ports to keep the source address (as the CI job sets it)
RUN mkdir -p /etc/docker && echo '{"userland-proxy": false}' > /etc/docker/daemon.json
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
