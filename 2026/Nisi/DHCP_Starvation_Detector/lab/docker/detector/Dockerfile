FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make \
        findutils \
        libpcap-dev \
        libnetconf2-dev \
        libyang2-dev \
        libssh-dev \
        libyuma-base \
        rrdtool \
        netcat-openbsd \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/defense/dhcp_starvation_detector/ .

# Default config for standalone container runs. The test suite overwrites this
# with the selected config during sync_code().
COPY src/defense/dhcp_starvation_detector/config/config.yaml /app/config/config.yaml

# Patch yang_dir in config/config.yaml to wherever Debian installed ietf-netconf.yang.
RUN yang_path=$(find /usr/share/yuma/modules/ietf /usr/share/yang/modules /usr \
        -name 'ietf-netconf@*.yang' -exec dirname {} \; 2>/dev/null | head -1); \
    [ -n "$yang_path" ] && sed -i "s|yang_dir:.*|yang_dir: $yang_path|" config/config.yaml || true

RUN rm -rf /app/bin && mkdir -p /app/bin && \
    make all BINDIR=/app/bin

COPY lab/docker/detector/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
