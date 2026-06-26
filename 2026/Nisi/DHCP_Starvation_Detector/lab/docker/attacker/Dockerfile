FROM kalilinux/kali-rolling

# Disable interactive prompts.
ENV DEBIAN_FRONTEND=noninteractive

# Install deps and clean cache apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        libpcap0.8 \
        procps \
        python3 \
        python3-scapy \
        yersinia \
    && rm -rf /var/lib/apt/lists/*

COPY src/attack/dhcp_starvation_attack.py \
     /usr/local/bin/dhcp_starvation_attack.py
RUN chmod +x /usr/local/bin/dhcp_starvation_attack.py

COPY lab/docker/attacker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
