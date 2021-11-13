FROM debian:bullseye

RUN set -x \
    && apt-get update \
    && apt-get install -y libreswan iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && set +x

RUN mkdir -p /run/pluto

COPY rootfs /

ENTRYPOINT ["/docker-entrypoint.sh"]
