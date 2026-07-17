# Docker Lab

This directory contains the Docker Compose version of the DHCP starvation
detector lab. It recreates the VM topology with four containers on one isolated
bridge network and is the recommended environment for most development and test
runs.

It was developed after the VM-based lab to make the environment easier to run
and more portable across machines.

For the general lab comparison, see [`../README.md`](../README.md). For the
original VM lab, see [`../vms/README.md`](../vms/README.md).

## Requirements

- Docker CLI
- Docker Compose plugin
- Running Docker daemon

The test runner checks these host dependencies automatically when
`--env-type docker` is selected.

## Topology

Docker Compose creates the `dhcp_lab` bridge network:

| Item | Value |
|---|---|
| Subnet | `192.168.100.0/24` |
| Docker bridge gateway | `192.168.100.254` |
| DHCP pool | `192.168.100.10` - `192.168.100.160` |

The containers have fixed addresses:

| Container | Role | VM lab equivalent | Address |
|---|---|---|---|
| `dhcp_router` | DHCP server/router and NETCONF target | OpenWrt | `192.168.100.1` |
| `dhcp_attacker` | DHCP starvation traffic generator | Kali Linux | `192.168.100.2` |
| `dhcp_detector` | Detector build/runtime environment | Ubuntu | `192.168.100.3` |
| `dhcp_client` | Legitimate DHCP client | Debian | `192.168.100.4` |

The attacker, detector, and client containers run privileged because the tests
need raw packet generation, DHCP client control, and interface manipulation.

## DHCP Backend

The router supports both `dnsmasq` and `ISC DHCP`:

- `dnsmasq` is the default backend.
- `ISC DHCP` is selected by setting `DHCP_TYPE=isc` for manual Docker Compose
  runs, or by setting `dhcp.backend: isc` in `config.yaml` when using the test
  suite.

The router image installs the selected backend at build time and starts the
matching service at container startup. The active NETCONF handler is exposed as
`/usr/local/bin/netconf-handler` and points to the backend-specific handler:

- `netconf-handler-dnsmasq`
- `netconf-handler-isc`

Switching backend requires rebuilding/recreating the router container.

## Running Manually

From the project root:

```bash
# Default dnsmasq backend.
docker compose -f lab/docker/docker-compose.yml up -d --build --force-recreate

# ISC DHCP backend.
DHCP_TYPE=isc docker compose -f lab/docker/docker-compose.yml up -d --build --force-recreate

# Stop the lab.
docker compose -f lab/docker/docker-compose.yml down
```

After the lab is running, use `docker exec` to work inside the individual
containers.

### Detector

Open an interactive shell inside the detector container:

```bash
docker exec -it dhcp_detector /bin/sh
```

The detector binary is built inside the detector container under `/app/bin`.
Run it from there, passing the container config file and the Docker runtime
overrides needed to reach the router. Use `DHCP_BACKEND=isc` instead of
`dnsmasq` when the router container was built with the ISC backend:

```bash
docker exec -it dhcp_detector env RUNTIME_INTERFACE=eth0 NETCONF_HOST=192.168.100.1 NETCONF_PASSWORD=root DHCP_BACKEND=dnsmasq /app/bin/dhcp_starvation_detector /app/config/config.yaml
```

The same binary can also be used in router-message mode. For pool status:

```bash
docker exec -it dhcp_detector env NETCONF_HOST=192.168.100.1 NETCONF_PASSWORD=root DHCP_BACKEND=dnsmasq /app/bin/dhcp_starvation_detector --router-message pool /app/config/config.yaml
```

### Attacker

Open an interactive shell inside the attacker container:

```bash
docker exec -it dhcp_attacker /bin/sh
```

Inside the attacker container, the custom Python attack script is available at
`/usr/local/bin/dhcp_starvation_attack.py`. Launch a manual attack from there,
for example:

```bash
python3 /usr/local/bin/dhcp_starvation_attack.py --count 80 --la mixed --no-wait eth0
```

Yersinia is also available in the attacker container. For example, to launch
its DHCP DISCOVER DoS mode on `eth0`:

```bash
yersinia dhcp -attack 1 -interface eth0
```

### Client

Open an interactive shell inside the legitimate client container:

```bash
docker exec -it dhcp_client /bin/sh
```

To ask the legitimate client container for a DHCP lease manually, run `dhcpcd`:

```bash
docker exec -it dhcp_client dhcpcd -4 -1 -L eth0
```

### Router

Open an interactive shell inside the router container:

```bash
docker exec -it dhcp_router /bin/sh
```

Inside `dhcp_router`, the NETCONF handlers are installed under
`/usr/local/bin`:

```text
/usr/local/bin/netconf-handler
/usr/local/bin/netconf-handler-dnsmasq
/usr/local/bin/netconf-handler-isc
```

`/usr/local/bin/netconf-handler` is the active symlink used by the OpenSSH
NETCONF subsystem. The router entrypoint points it to
`netconf-handler-dnsmasq` when `DHCP_TYPE=dnsmasq`, or to
`netconf-handler-isc` when `DHCP_TYPE=isc`.

Other useful router-side files are:

```text
/usr/local/bin/lease-hook.sh      # dnsmasq lease-view helper used by tests
/entrypoint.sh                    # starts sshd and the selected DHCP backend
/etc/dnsmasq.conf                 # dnsmasq configuration
/etc/dhcp/dhcpd.conf              # ISC DHCP configuration
```

The Docker router does not provide OpenWrt-style `resetpool.sh` or
`statuspool.sh` scripts. Use the detector's router-message mode shown above
instead.

Manual Compose runs are useful for using the lab interactively: inspecting
containers and logs, launching custom DHCP starvation attempts or other traffic
from the attacker container, and watching how the detector, router, and
mitigation react. The automated regression suite should normally be started
through `tests/run_tests.py`.

A manual `docker compose ... up --build` already bakes the normal lab resources
into the images: detector source, the detector binary built during image build,
the default config, the default `db/whitelist.txt` included in the detector
source tree, the attack script, Docker DHCP/router files, and NETCONF handlers.
This is enough for interactive/manual lab use. It does not copy the VM-only
`dhcpget.sh` helper; Docker client operations use `dhcpcd` directly, while
`tests/legit_dhcp_client.sh` is copied only by the test suite sync.

## Running Through the Test Suite

From the project root:

```bash
# Docker with backend from config.yaml.
python3 tests/run_tests.py --env-type docker

# Docker with ISC DHCP backend override.
DHCP_BACKEND=isc python3 tests/run_tests.py --env-type docker

# Single group.
python3 tests/run_tests.py --env-type docker --group K
```

When the test suite runs against Docker, it still performs an explicit sync
after the containers are running. That sync makes the running containers match
the selected test run, including any `--config`/environment overrides and the
current workspace contents, then resets the router state and executes the
selected tests.

During test sync, the suite copies or refreshes:

- detector source into `dhcp_detector:/app`;
- detector binary build output in `dhcp_detector:/app/bin`;
- selected config as `dhcp_detector:/app/config/config.yaml`;
- whitelist as `dhcp_detector:/app/db/whitelist.txt`;
- attack script into `dhcp_attacker`;
- legit DHCP client helper into `dhcp_client`;
- backend-specific NETCONF handlers into `dhcp_router:/usr/local/bin`.

## Containers

Router:

- based on `debian:bookworm-slim`;
- runs either `dnsmasq` or `isc-dhcp-server`;
- exposes DHCP on UDP 67 and NETCONF-over-SSH on TCP 830;
- uses `dnsmasq.conf` or `isc-dhcpd.conf` for the backend DHCP configuration;
- uses `lease-hook.sh` with `dnsmasq` to maintain a normalized lease view used
  by the NETCONF handler and by the test suite.

Detector:

- based on `debian:bookworm-slim`;
- installs detector build/runtime dependencies;
- builds `dhcp_starvation_detector` and NETCONF support;
- remains idle at startup because the test suite launches detector instances.

Attacker:

- based on `kalilinux/kali-rolling`;
- includes Python, Scapy, libpcap runtime, `iproute2`, `procps`, and Yersinia;
- contains `dhcp_starvation_attack.py`;
- remains idle unless `ATTACK_AUTOSTART=1` is set for manual demo runs.

Client:

- based on `debian:bookworm-slim`;
- includes `dhcpcd`, `iproute2`, `awk`, and process tools;
- acts as the legitimate DHCP client during tests.

## Files

```text
lab/docker/
|-- docker-compose.yml
|-- router/
|   |-- Dockerfile
|   |-- dnsmasq.conf
|   |-- entrypoint.sh
|   |-- isc-dhcpd.conf
|   `-- lease-hook.sh
|-- detector/
|   |-- Dockerfile
|   `-- entrypoint.sh
|-- attacker/
|   |-- Dockerfile
|   `-- entrypoint.sh
`-- client/
    |-- Dockerfile
    `-- entrypoint.sh
```
