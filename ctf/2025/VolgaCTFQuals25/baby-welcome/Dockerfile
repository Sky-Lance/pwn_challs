FROM ubuntu:25.04@sha256:008b026f11c0b5653d564d0c9877a116770f06dfbdb36ca75c46fd593d863cbc AS chroot

COPY app /
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM ghcr.io/google/nsjail/nsjail@sha256:03a904cd42b07ecc6e6f318c1ea14bd28339e1411d180d8744b2a5e2929e895f

COPY --from=chroot / /chroot
COPY nsjail.cfg /nsjail.cfg

CMD ["nsjail", "--config", "/nsjail.cfg"]