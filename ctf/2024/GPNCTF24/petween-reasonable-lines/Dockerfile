# docker build -t petween-reasonable-lines . && docker run -p 7402:7402 --rm -it petween-reasonable-lines
FROM ubuntu:22.04

RUN useradd --create-home --shell /bin/bash ctf
RUN apt-get update -y && \
apt-get install socat nasm -y --no-install-recommends && \
apt-get clean && rm -rf /var/lib/apt/lists/*

ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /flag
COPY --chown=ctf vuln.pl /home/ctf/vuln.pl

USER ctf
EXPOSE 7402
ENTRYPOINT ["socat", "-v", "tcp-listen:7402,reuseaddr,fork", "EXEC:/home/ctf/vuln.pl,stderr"]
