FROM debian:bullseye

RUN set -x \
    && apt-get update \
    && apt-get install -y libreswan \
    && rm -rf /var/lib/apt/lists/* \
    && set +x

RUN mkdir -p /run/pluto

RUN set -x \
    && apt-get update \
    && apt-get install -y iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && set +x

COPY rootfs /

ENTRYPOINT ["/docker-entrypoint.sh"]
