FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        dhcpcd-base iproute2 mawk procps \
    && rm -rf /var/lib/apt/lists/*

COPY lab/docker/client/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
