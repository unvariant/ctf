FROM ubuntu:22.04
ARG USER=ctf
COPY --chown=root:10000 launcher /
COPY --chown=root:10000 flag /chroot/
RUN apt-get update && apt-get -y dist-upgrade strace ruby-dev gcc make
RUN groupadd -g 10000 $USER && useradd -N -u 10000 -g 10000 $USER && chmod 750 /launcher && chmod 440 /chroot/flag
RUN gem install seccomp-tools
# ENTRYPOINT ["/usr/bin/timeout", "-s9", "60", "seccomp-tools", "dump", "/launcher"]
