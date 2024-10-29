FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    libstdc++6 \
    libgcc-s1 \
    libssl-dev \
    ncat \
    && rm -rf /var/lib/apt/lists/*
    

RUN useradd ctf

RUN mkdir -p /home/ctf
COPY ./main /home/ctf/main

RUN chmod +x /home/ctf/main
WORKDIR /home/ctf

EXPOSE 1337
CMD socat TCP-LISTEN:1337,reuseaddr,fork TCP:localhost:1339 & ./main
