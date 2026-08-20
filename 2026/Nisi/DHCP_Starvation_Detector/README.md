# DHCP Starvation Detector

This project implements and tests a DHCP starvation detection and mitigation
system. It includes a C-based detector, router-side mitigation through a
NETCONF message-exchange system, a reputation pipeline for legitimate clients
during attacks, RRD statistics, custom and external attack tooling, and two lab
environments for validation.

The documentation about the repository is organized so that the root README stays introductory. The
technical details, setup steps, and test cases live in the dedicated README
files linked below.

## Why

DHCP starvation attacks try to exhaust the DHCP address pool by generating many
lease requests, often with different client identities. If the pool is drained,
legitimate clients can no longer obtain an address and the local network loses
connectivity for new or renewing hosts.

Common production defenses are usually based on enterprise features such as
DHCP snooping, often available on managed switches or enterprise routing
equipment. Those solutions are effective, but they require specific network
hardware and are not always available in small labs, low-cost deployments, or
software-defined test environments.

This project explores a different approach: a configurable detector that can run
on a separate host, observe DHCP traffic, estimate starvation risk, and ask the
router/DHCP server to enable mitigation when needed. It can therefore be a
useful alternative when dedicated enterprise hardware is not available, while
still trying to preserve access for legitimate clients through reputation and
ARP confirmation. On the router side, the solution only requires SSH and a
NETCONF-accessible control handler, rather than DHCP snooping support or
specialized enterprise switching hardware. During the research phase of this
project, no directly
similar open implementation was found that combined detection, router-side
mitigation, legitimate-client reputation, backend adaptability, and automated
end-to-end validation in the same system.

## Project Map

| Area | Purpose | Documentation |
|---|---|---|
| `src/` | Source tree for attack and defense components. | [`src/README.md`](src/README.md) |
| `lab/` | Lab tree for the VM and Docker lab environments. | [`lab/README.md`](lab/README.md) |
| `tests/` | End-to-end test runner, test groups, result layout, and helper scripts. | [`tests/README.md`](tests/README.md) |

## Main Components

- Detector: C-based code that runs on the detector host, monitors DHCP traffic,
  computes attack features to decide if an attack is now running, stores RRD
  statistics, and coordinates mitigation by sending messages to the DHCP server
  on the router.
- Router control: runs on the router host, applies or removes whitelist-only
  DHCP policy through backend-specific NETCONF handlers.
- Reputation pipeline: runs inside the detector process on the detector host
  and lets legitimate clients recover access during mitigation when they follow
  expected DHCP retry behavior and pass ARP confirmation.
- Attack tooling: runs on the attacker host and provides a custom Python DHCP
  starvation generator plus Yersinia support in the lab.
- Test suite: runs on the local host machine, synchronizes the current
  workspace into the selected lab, runs scenario groups, collects logs, and
  generates per-scenario RRD graphs.

## Principles

The project is deliberately modular so that individual areas can be maintained,
replaced, or extended without rewriting the whole system. Packet parsing,
detection logic, router actions, whitelist storage, reputation, RRD statistics,
and configuration are kept as separate responsibilities.

The defense goal is not only to block DHCP starvation attacks. The detector
also tries to preserve service for legitimate clients during mitigation by
using a reputation pipeline that checks DHCP retry behavior and ARP reachability
before admitting clients into the runtime whitelist.
During an ongoing attack, a legitimate client will likely take longer to obtain
access, but it should still be able to complete the reputation path and connect.

The detection strategy aims to cover as many attack shapes as possible,
including fast burst attacks and slower low-and-slow pool exhaustion attempts.

The system is intentionally not designed as an inline firewall that filters
every packet. It acts more like a network watcher: it observes DHCP behavior,
detects suspicious conditions, and then asks the router/DHCP server to apply or
remove mitigation.

The router-control layer is designed to be adaptable across DHCP server
backends. The current labs cover `dnsmasq` and `ISC DHCP`, but the NETCONF
handler structure is intended to make additional backends possible without
changing the detector core.

The project aims to be general enough to run on many different network
topologies while still being adaptable to specific environments. Detection,
mitigation, reputation, NETCONF, RRD, and test-suite behavior can be tuned
through configuration parameters instead of changing source code. This is a
deliberate tradeoff between generality and avoiding overfitting to one lab
topology or one specific attack trace.

## Configuration Entry Point

The default configuration file is:

```text
src/defense/dhcp_starvation_detector/config/config.yaml
```

It contains both detector/runtime parameters and test-suite parameters. The
detector and test runner documentation describe how that file is loaded and how
environment variable overrides work.

## Typical Workflows

For automated validation, use the test suite described in
[`tests/README.md`](tests/README.md). For interactive experimentation, use the
manual Docker or VM lab flows described in the corresponding lab README.

The Docker lab is the usual starting point because it is faster to recreate and
does not require provisioning the original VM disks. The VM lab remains useful
when a full operating-system network stack is desired.

## Future Work

Possible future extensions include:

- distributed deployment support, with detectors running on multiple machines
  for larger networks;
- DHCPv6 support;
- support for more DHCP server backends;
- support for other attack families targeting protocols that can naturally be
  observed on the network, such as ARP.

## Notes

This repository is structured as a controlled lab project. The attack tooling
is intended for testing the detector inside the provided environments or other
authorized networks only.

## Contacts/Author

Giulio Nisi  
g[dot]nisi[at]studenti[dot]unipi[dot]it
