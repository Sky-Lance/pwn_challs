FROM ubuntu:24.04@sha256:3afff29dffbc200d202546dc6c4f614edc3b109691e7ab4aa23d02b42ba86790
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing && \
    apt-get -y install xinetd qemu-system-x86
RUN groupadd -r pwn && useradd -r -g pwn pwn

RUN echo '#!/bin/bash\n\
service xinetd restart && /bin/sleep infinity' > /etc/init.sh
RUN echo 'service pwn\n\
{\n\
  type = UNLISTED\n\
  disable = no\n\
  socket_type = stream\n\
  protocol = tcp\n\
  wait = no\n\
  user = pwn\n\
  bind = 0.0.0.0\n\
  port = 9999\n\
  server = /home/pwn/run.sh\n\
}' > /etc/xinetd.d/pwn
RUN chmod 500 /etc/init.sh
RUN chmod 444 /etc/xinetd.d/pwn

WORKDIR /home/pwn
ADD --chmod=644 rootfs.cpio .
ADD --chmod=644 bzImage     .
ADD --chmod=550 run.sh      .

RUN chown -R root:pwn /home/pwn
RUN service xinetd restart
