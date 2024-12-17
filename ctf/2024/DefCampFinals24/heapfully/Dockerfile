FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.ustc.edu.cn/g" /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential  \
    net-tools \
    software-properties-common \
    libseccomp-dev \
    ltrace \
    xinetd \
    && \
    rm -rf /var/lib/apt/lists/*

RUN useradd ctf 
RUN mkdir /home/ctf

COPY ./xinetd /etc/xinetd.d/xinetd
COPY ./ /home/ctf

RUN chmod +x /home/ctf/main

RUN chmod +r /home/ctf/flag.txt
RUN chmod +r /home/ctf/checker.txt
RUN chmod +x /home/ctf/start.sh

RUN /etc/init.d/xinetd reload

EXPOSE 1337

CMD service xinetd start && sleep 5 && tail -f 



