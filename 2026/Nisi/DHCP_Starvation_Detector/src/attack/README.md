# DHCP Starvation Attack Script

This directory contains the custom Python DHCP starvation traffic generator used
by the lab and by the automated test suite.

The script is:

```text
dhcp_starvation_attack.py
```

It generates DHCP traffic with many spoofed client MAC addresses. It can run in
two main modes:

- full DHCP mode: sends DISCOVER, waits for OFFER, sends REQUEST, and waits for
  ACK/NAK;
- burst mode with `--no-wait`: sends only DHCP DISCOVER packets without waiting
  for router replies.

Use it only inside the provided lab environments or on networks where you are
authorized to test.

## Requirements

The script needs:

- Python 3;
- Scapy;
- `ip` from iproute2;
- privileges/capabilities for raw packet send and packet sniffing.

## Usage

```bash
python3 dhcp_starvation_attack.py [options] iface
```

`iface` is the network interface used to send DHCP traffic, for example `eth0`
or `ens160`.

Show the built-in help:

```bash
python3 dhcp_starvation_attack.py --help
```

## Options

| Option | Meaning |
|---|---|
| `--count COUNT` | Total number of request attempts. Default: `150`. |
| `--la {on,off,mixed}` | Controls the locally-administered bit of generated MACs: `on` sets it for all MACs, `off` clears it, `mixed` randomizes it. Default: `on`. |
| `--seed SEED` | Integer seed for deterministic MAC generation. Reusing the same seed with `--count 1` reuses the same MAC. |
| `--delay DELAY` | Target seconds between request attempts. Default: `0.0`. |
| `--no-wait` | Burst mode: send only DISCOVER packets and do not wait for OFFER/ACK replies. |
| `--repeat-every N` | Reuse one fixed MAC every Nth request. `0` disables this mode. Default: `0`. |
| `--repeat-seed SEED` | Seed for the fixed MAC used by `--repeat-every`. Valid only when `--repeat-every > 0`. |
| `--keep-ether-src` | Keep the interface hardware MAC as Ethernet source instead of spoofing it to match the DHCP client MAC. This creates Ethernet/DHCP MAC mismatch traffic. |

## Examples

Fast DISCOVER burst with locally-administered MACs:

```bash
python3 dhcp_starvation_attack.py --count 90 --la on --no-wait eth0
```

Full DHCP attempts spaced three seconds apart:

```bash
python3 dhcp_starvation_attack.py --count 80 --la mixed --delay 3 eth0
```

Reuse one fixed MAC every tenth request:

```bash
python3 dhcp_starvation_attack.py --count 80 --la off --delay 3 --repeat-every 10 --repeat-seed 1234 eth0
```

Generate Ethernet/DHCP source mismatch traffic:

```bash
python3 dhcp_starvation_attack.py --count 40 --la on --no-wait --keep-ether-src eth0
```

## Notes

Without `--no-wait`, the script tries to complete leases by waiting for DHCP
OFFERs and ACKs. This is slower but useful for pool-pressure scenarios.

With `--no-wait`, the script sends DISCOVER packets as fast as possible unless
`--delay` is also provided. This is useful for rate, unique-MAC, and LA-bit
detector scenarios.

When interrupted with Ctrl+C, the script stops gracefully and prints the attack
summary collected so far.
