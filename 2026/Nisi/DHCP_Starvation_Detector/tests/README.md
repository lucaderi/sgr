# Test Suite

This directory contains the end-to-end test suite for the DHCP starvation
detector. The suite is driven by `run_tests.py` and can run against both lab
environments described in [`../lab/README.md`](../lab/README.md):

- `--env-type vms`: the original VM lab. The DHCP server is OpenWrt `dnsmasq`.
- `--env-type docker`: the Docker lab. The DHCP backend can be either
  `dnsmasq` or `ISC DHCP`, selected through the global `dhcp.backend` config
  value or the `DHCP_BACKEND` environment variable.

## What `run_tests.py` Does

`run_tests.py` is the orchestration script for the full lab:

- reads the selected YAML configuration and forwards it to the detector runtime
  as `config/config.yaml`;
- applies `test_suite` settings from the selected `config.yaml` and uppercase
  environment variable overrides;
- checks lab connectivity for the selected Docker containers or VMs;
- checks host (VM or Docker container) dependencies;
- synchronizes the current workspace code and runtime resources into the lab:
  detector source, selected config, whitelist, NETCONF handlers, attack script,
  legit DHCP client helper, and VM utility scripts where needed;
- builds the detector in the target detector environment;
- resets the DHCP pool and disables whitelist-only mode before the tests on the
  router;
- runs the selected group, smoke suite, or full suite;
- collects detector, attack, client, router lease, whitelist-state logs, and
  RRD graph images.

## Dependencies

For VMs, the script uses `paramiko` to manage SSH/SFTP connections to OpenWrt,
Ubuntu, Kali, and Debian. Install it on the host with:

```bash
python3 -m pip install paramiko
```

For Docker, the script uses Docker Compose and `docker exec`/`docker cp`.

## VM Pre-Test Setup

Before running `run_tests.py --env-type vms`, start and access each VM once and
run its shared-network setup script so the static test IPs are assigned. With
the provided VM disks, the utility scripts are already available in the `lab/`
directory inside each VM home directory.

Run `shared.sh` on Debian, Ubuntu, and Kali, and `setup-shared.sh` on OpenWrt.
See [`../lab/vms/README.md`](../lab/vms/README.md) for the exact script paths,
interfaces, and static IP addresses.

## Results

By default, results are written under:

```text
tests/results/<run_id>/
```

Use `--output PATH` to change the results root.

`<run_id>` defaults to the current timestamp, unless overridden by
`test_suite.run_id` or the `RUN_ID` environment variable.

If parsing or configuration fails before normal logging is fully initialized,
the script still creates an early result directory and writes the failure to
`summary.txt`.

Each run directory contains:

- `summary.txt`: the console log mirrored to a file;
- one subdirectory per test group, from `A/` to `K/`;
- standard per-scenario files:
  - `<scenario>.defense.log`
  - `<scenario>.attack.log`
  - `<scenario>.client.log`
  - `<scenario>.router.leases`
  - `<scenario>.whitelist-state.txt`
  - `<scenario>.rrd-traffic.png`
  - `<scenario>.rrd-ratios.png`
  - `<scenario>.rrd-bucket.png`
  - `<scenario>.rrd-pool.png`
  - `<scenario>.rrd-pool-growth.png`
  - `<scenario>.rrd-tte.png`

`<scenario>.client.lease.txt` is also saved when the legitimate client has a
lease on the router. It is intentionally absent in control scenarios that do
not run or verify a legitimate client lease.

The RRD images are generated from a fresh per-scenario `dhcp_stats.rrd`
database on the detector host/container. They are grouped by unit: traffic
window counts, percentages, leaky-bucket tokens, current pool lease count,
recent pool lease growth, and time-to-exhaustion projection. The images are
copied into the result directory, then removed from the remote lab so the next
scenario starts with a clean RRD file. If the detector never starts or one graph
cannot be generated, the runner writes `<scenario>.rrd-graph.txt` with the
reason instead.

Some scenarios also save extra evidence files. Group `H` stores attacker lease
snapshots before and after ARP/reputation checks:

- `<scenario>.attacker.lease.before-release.txt`
- `<scenario>.attacker.lease.after-release.txt`

## RRD Pool Graph Legend

The `<scenario>.rrd-pool.png` image shows DHCP lease pressure on the router:

- `pool_used`: number of active DHCP leases currently present in the router
  lease table. In a healthy mitigated test this often stays near `1`, because
  only the legitimate client should keep a lease after whitelist-only mode is
  enabled.

The `<scenario>.rrd-pool-growth.png` image shows the recent lease-growth
signal separately for readability:

- `pool_growth`: positive increase in active leases over the detector pool
  history window, configured by `detector.pool_history_secs`. It is not the
  number of DHCP packets sent by the attacker. It only rises when the router
  actually allocates additional leases, and returns to `0` when there is no
  positive lease growth in the current history window.

In short, `pool_used` is the current pool occupancy, while `pool_growth` is the
recent increase in that occupancy. They can overlap during simple rising
patterns, but they answer different questions: how many leases are currently in
use, and whether the pool is still growing fast enough to suggest exhaustion.

The pool graph also prints `pool_total` in the legend as the total configured
DHCP pool size. Both pool-related graphs use MAX consolidation so short-lived
lease changes are not hidden by RRD averaging.

In `<scenario>.rrd-tte.png`, `pool_tte_min` is the projected time to exhaust the
DHCP pool, in minutes. It is meaningful only when the detector sees positive
pool growth. If `pool_growth` is `0`, `pool_tte_min` stays at `0`: this means
there is no current exhaustion projection, not that the graph failed. This is
expected in control cases such as small DISCOVER-only bursts that do not obtain
router leases.

## Usage

Run from the repository root:

```bash
python3 tests/run_tests.py --env-type docker
python3 tests/run_tests.py --env-type vms
```

### Options

- `--help`: show the script help.
- `--env-type {docker,vms}`: required; selects the target lab.
- `--config PATH`: selects the YAML config file. If omitted, the default is
  `src/defense/dhcp_starvation_detector/config/config.yaml`. The same can be
  selected with `CONFIG_FILE` or `DHCP_DEFENSE_CONFIG`.
- `--output PATH`: selects the results root directory. Default:
  `tests/results`.
- `--verbose`: prints remote command output while commands run.
- `--smoke`: runs one short smoke test per group.
- `--group {A,B,C,D,E,F,G,H,I,J,K}`: runs a single group. `--groups` is an
  alias for the same option.

Tester parameters and detector software parameters are both stored in the
selected `config.yaml`.

`test_suite` config keys can be overridden with uppercase environment variables.
For example, `test_suite.detect_timeout_slow` can be overridden with
`DETECT_TIMEOUT_SLOW`.

Global config keys use their section name in the environment variable. For
example, `dhcp.backend` can be overridden with `DHCP_BACKEND`.

Common examples:

```bash
# Full Docker suite with the backend from config.yaml.
python3 tests/run_tests.py --env-type docker

# Docker suite with ISC DHCP.
DHCP_BACKEND=isc python3 tests/run_tests.py --env-type docker

# VM suite. VMs support only OpenWrt dnsmasq.
python3 tests/run_tests.py --env-type vms

# Run only one group.
python3 tests/run_tests.py --env-type docker --group K

# Alias accepted by the script.
python3 tests/run_tests.py --env-type docker --groups K

# Run the smoke suite.
python3 tests/run_tests.py --env-type docker --smoke

# Use a different config and output directory.
python3 tests/run_tests.py --env-type docker --config ./my-config.yaml --output ./tmp-results
```

## Test Groups

- `A`: unique-MAC DHCP DISCOVER bursts, including large and small burst cases.
  `A1`-`A4` verify legitimate client access after mitigation. `A5` is a
  sub-threshold control: detection is not required and the legitimate client
  loop is not started in `A5`, so the pool is expected to remain at `0/total`.
- `B`: repeated same-MAC DISCOVERs followed by no-delay unique-MAC bursts;
  legitimate client access is verified after detection.
- `C`: slow-and-low full DHCP pressure; detection must verify F6 pool pressure
  and legitimate client access.
- `D`: same-MAC control cases; the router should reuse one lease and the
  detector should stay silent. No legitimate client loop is started.
- `E`: idle/baseline check with only the legitimate DHCP client loop.
- `F`: whitelist evasion attempt; whitelist-only must activate, then the
  attacker sends 6 slow full DHCP attempts from one fixed MAC, and that MAC must
  not be promoted by reputation. Legitimate client access is also verified.
- `G`: adaptive baseline F4 check; a same-MAC warmup builds the baseline, then
  a controlled unique-MAC spike must trigger F4; legitimate client access is
  verified after detection.
- `H`: ARP-failed lease removal; a fake attacker lease must be removed after
  reputation ARP probing fails, while legitimate client access must work.
- `I`: external Yersinia DHCP DISCOVER DoS; legitimate client access is
  verified after mitigation.
- `J`: Ethernet source MAC differs from DHCP `chaddr`/`client-id`; legitimate
  client access is verified, and reputation must discard the mismatch traffic
  as `ethernet-src-mismatch`.
- `K`: legitimate client reputation confirmation; the legit MAC is removed from
  the runtime whitelist, whitelist-only is triggered, and the client must pass
  DHCP backoff plus ARP confirmation to become a final whitelist entry.

In summary, `A1`-`A4`, `B`, `C`, `F`, `G`, `H`, `I`, and `J` include a
legitimate-client access check as part of the scenario. `K` is dedicated to
legitimate-client reputation confirmation. `E` runs only normal legitimate
client traffic as a false-positive baseline. `A5` and `D` do not start the
legitimate client loop.

## Utility Shell Script

`legit_dhcp_client.sh` is the helper used to simulate the legitimate DHCP
client during tests. The Python suite copies it into the legitimate-client
host/container and starts it there with environment variables.

It supports both modes:

- `LEGIT_DHCP_CLIENT_MODE=docker`: runs `dhcpcd` directly inside the Docker
  client container, cleans stale dynamic addresses, and checks for a valid pool
  lease.
- `LEGIT_DHCP_CLIENT_MODE=vms`: calls the VM `dhcpget.sh` helper on Debian at
  `lab/vms/vms-scripts/debian-scripts/dhcpget.sh` relative to the local project
  root, then restores/keeps the management address when needed.

The script writes detailed attempt logs to `LEGIT_DHCP_CLIENT_LOG`, including
the command being executed, `dhcpcd` identity lines, retry state, valid lease
state, and fatal DHCP client command errors.

The suite uses the real interface MAC of the legitimate client, read at
runtime. In the Docker lab this is normally a locally administered MAC
(LA-bit on, usually `02:...`), while in the VM lab the default Debian MAC is
`00:50:56:2d:11:c4` and therefore has LA-bit off. The `la=on/off/mixed`
scenario labels refer to the attack-generated MAC addresses, not necessarily
to the legitimate client MAC.

Normally it should not be run by hand; `run_tests.py` prepares the right
environment variables, copies the script to the lab, starts it, and collects
its logs.
