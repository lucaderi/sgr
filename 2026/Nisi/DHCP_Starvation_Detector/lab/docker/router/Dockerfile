FROM debian:bookworm-slim

# To install the right DHCP backend.
ARG DHCP_TYPE=dnsmasq

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils grep iproute2 mawk openssh-server procps sed sysvinit-utils \
    && if [ "$DHCP_TYPE" = "isc" ]; then \
        apt-get install -y --no-install-recommends isc-dhcp-server; \
    else \
        apt-get install -y --no-install-recommends dnsmasq; \
    fi \
    && rm -rf /var/lib/apt/lists/*

ENV DHCP_TYPE=${DHCP_TYPE}

RUN mkdir -p /var/lib/misc /etc/dnsmasq.d /var/lib/dhcp /etc/dhcp /var/run/sshd

COPY lab/docker/router/dnsmasq.conf        /etc/dnsmasq.conf
COPY lab/docker/router/isc-dhcpd.conf      /etc/dhcp/dhcpd.conf
COPY lab/docker/router/lease-hook.sh       /usr/local/bin/lease-hook.sh
COPY src/defense/dhcp_starvation_detector/netconf_action/netconf-handler-dnsmasq.sh /usr/local/bin/netconf-handler-dnsmasq
COPY src/defense/dhcp_starvation_detector/netconf_action/netconf-handler-isc.sh /usr/local/bin/netconf-handler-isc
COPY lab/docker/router/entrypoint.sh              /entrypoint.sh
RUN chmod +x /usr/local/bin/lease-hook.sh \
    /usr/local/bin/netconf-handler-dnsmasq \
    /usr/local/bin/netconf-handler-isc \
    /entrypoint.sh

# Set password to root.
RUN echo 'root:root' | chpasswd

# Configure OpenSSH for NETFCONF.
RUN printf '%s\n' \
        'Port 830' \
        'PermitRootLogin yes' \
        'PasswordAuthentication yes' \
        'UsePAM no' \
        'Subsystem netconf /usr/local/bin/netconf-handler' \
    > /etc/ssh/sshd_config

# DHCP and NETCONF SSH.
EXPOSE 67/udp 830/tcp

ENTRYPOINT ["/entrypoint.sh"]
