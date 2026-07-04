#!/bin/sh

# Install and configure NETCONF server on OpenWRT router.

# Checks for the dnsmasq NETCONF handler script.
if [ "$(id -u)" -ne 0 ]; then
    echo "usage: sudo $0 /path/to/netconf-handler-dnsmasq.sh" >&2
    exit 1
fi
HANDLER_SRC="${1:-}"
if [ -z "$HANDLER_SRC" ]; then
    echo "usage: $0 /path/to/netconf-handler-dnsmasq.sh" >&2
    exit 1
fi
if [ "${HANDLER_SRC##*/}" != "netconf-handler-dnsmasq.sh" ]; then
    echo "error: handler file must be named netconf-handler-dnsmasq.sh" >&2
    exit 1
fi
if [ ! -f "$HANDLER_SRC" ]; then
    echo "error: file not found: $HANDLER_SRC" >&2
    exit 1
fi

apk update

# NETCONF runs as SSH subsystem.
apk add openssh-server

# FTP server for manual file uploads to the router.
apk add vsftpd
cat > /etc/vsftpd.conf <<'EOF'
listen=YES
background=YES

anonymous_enable=YES
no_anon_password=YES
anon_root=/home/ftp

local_enable=NO
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
anon_umask=000
anon_world_readable_only=NO

pasv_enable=YES
pasv_min_port=50000
pasv_max_port=50100
EOF
mkdir -p /home/ftp/upload
chown root:root /home/ftp
chmod 755 /home/ftp
if id ftp >/dev/null 2>&1; then
    chown ftp:ftp /home/ftp/upload 2>/dev/null || chown ftp /home/ftp/upload
fi
chmod 755 /home/ftp/upload
uci -q batch <<'EOF'
delete vsftpd.global
set vsftpd.global=global
set vsftpd.global.disabled='0'
set vsftpd.global.mdns='0'
set vsftpd.global.conf_file='/etc/vsftpd.conf'
commit vsftpd
EOF

# Install NETCONF SSH subsystem handler.
cat "$HANDLER_SRC" > /usr/bin/netconf-handler
chmod +x /usr/bin/netconf-handler

# Configure OpenSSH NETCONF endpoint.
if ! grep -q '^Subsystem netconf /usr/bin/netconf-handler$' /etc/ssh/sshd_config; then
    cat >> /etc/ssh/sshd_config <<'EOF'
Port 830
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
Subsystem netconf /usr/bin/netconf-handler
EOF
fi

# Restart SSH service to apply changes.
/etc/init.d/sshd enable
/etc/init.d/sshd start

# Start FTP service to allow file uploads.
/etc/init.d/vsftpd enable
/etc/init.d/vsftpd stop 2>/dev/null || true
killall vsftpd 2>/dev/null || true
/etc/init.d/vsftpd start

delete_firewall_rules_by_name() {
    name="$1"
    while :; do
        section="$(uci -q show firewall | sed -n "s/^firewall\.\([^.]*\)\.name='$name'$/\1/p" | head -n 1)"
        [ -n "$section" ] || break
        uci -q delete "firewall.$section" || break
    done
}

# Firewall rule to allow NETCONF over SSH.
delete_firewall_rules_by_name netconf
uci set firewall.netconf=rule
uci set firewall.netconf.name='netconf'
uci set firewall.netconf.src='lan'
uci set firewall.netconf.dest_port='830'
uci set firewall.netconf.proto='tcp'
uci set firewall.netconf.target='ACCEPT'

# Firewall rule to allow FTP from the lab LAN.
delete_firewall_rules_by_name ftp
uci set firewall.ftp=rule
uci set firewall.ftp.name='ftp'
uci set firewall.ftp.src='lan'
uci set firewall.ftp.dest_port='21 50000-50100'
uci set firewall.ftp.proto='tcp'
uci set firewall.ftp.target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
