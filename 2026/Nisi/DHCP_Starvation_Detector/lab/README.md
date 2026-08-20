# Lab Environment

This directory contains the lab environments used to develop and test the project.

## Evolution

Initial development and testing were performed on a set of four virtual machines (see [`vms/README.md`](vms/README.md)). This setup closely mirrors a real network deployment but requires VMware Fusion on ARM/Apple Silicon, since the project was developed on an M2 chip, and manual VM provisioning.

To improve portability and reproducibility, the lab was later replicated as a Docker Compose environment (see [`docker/`](docker/)). The containerised setup requires only Docker and can be started with a single command.

## Structure

- `vms/` — VM utility scripts, configuration notes, and setup instructions for the original four-VM lab.
- `docker/` — Docker Compose environment replicating the same topology (router, attacker, detector, legitimate client) in containers.

## DHCP Server

The VM environment uses OpenWrt's default DHCP server, `dnsmasq`. The Docker environment supports both `dnsmasq` and `ISC DHCP`.

## DHCP Backend Support

Support for `dnsmasq` came first because it is the default DHCP server in the
OpenWrt VM lab. `ISC DHCP` support was added later because the project is meant
to be extensible across DHCP backends, and ISC DHCP is one of the most widely
used DHCP implementations.

## VM vs Docker

| | VMs | Docker |
|---|---|---|
| Startup | Manual, several minutes | `docker compose up`, seconds |
| Portability | VMware Fusion + arm64 images, unless emulation is used | Any machine with Docker |
| DHCP server | OpenWrt `dnsmasq` | `dnsmasq` or `ISC DHCP` |
| Realism | Full OS, real network stack | Shared kernel, bridged network |

The Docker environment is strongly recommended for most development and testing work.
