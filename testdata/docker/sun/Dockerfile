FROM debian:buster

RUN set -x  \
    && apt-get update  \
    && apt-get install -y strongswan-charon strongswan-swanctl  \
    && rm -rf /var/lib/apt/lists/* \
    && set +x

COPY rootfs /

CMD /usr/lib/ipsec/charon
