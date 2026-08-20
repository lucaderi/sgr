# DHCP Starvation Detector Core

This directory contains the main defense program of the project: a C-based DHCP
starvation detection system with router-side mitigation, runtime whitelist
control, pool pressure analysis, RRD statistics, and a reputation pipeline for
admitting legitimate clients during an attack.

The code here is intentionally split into small modules. The top-level program
coordinates packet capture, detection, NETCONF router control, whitelist state,
and reputation decisions; the subdirectories implement those responsibilities.
This modular architecture improves debugging and maintainability by following
the separation-of-concerns principle.

## Directory Layout

```text
dhcp_starvation_detector/
|-- dhcp_starvation_detector.c     # main program and runtime orchestration
|-- Makefile                       # build rules
|-- config/
|   |-- config.yaml                # detector, mitigation, NETCONF, reputation, test suite config
|   |-- defense_config.c           # config parser module
|   `-- defense_config.h
|-- db/
|   `-- whitelist.txt              # persistent trusted MAC database
|-- detector/
|   |-- detector.c                 # feature/score aggregation and attack detected decision
|   |-- detector.h
|   |-- sliding_window.c/.h        # DISCOVER window, unique MACs, LA-bit ratio
|   |-- leaky_bucket.c/.h          # fast rate threshold
|   |-- adaptive_score.c/.h        # EMA/Z-score adaptive baseline
|   |-- test_detector.c
|   `-- demo_detection.sh          # manual test_detector demonstration helper
|-- dhcp_parser/
|   |-- dhcp_parser.c/.h           # pcap capture wrapper and DHCP parser
|   `-- test_parser.c
|-- netconf_action/
|   |-- dhcp-whitelist.yang        # custom YANG model used by the router handlers
|   |-- netconf_action.c/.h        # libnetconf2 client-side RPC builder/parser
|   |-- netconf_worker.c/.h        # async NETCONF job worker
|   |-- netconf-handler-dnsmasq.sh # router-side handler for OpenWrt/plain dnsmasq
|   |-- netconf-handler-isc.sh     # router-side handler for ISC DHCP
|   `-- test_netconf_action.c
|-- reputation/
|   |-- mac_reputation.c/.h        # legitimate-client reputation pipeline
|   `-- test_reputation.c
|-- rrd/
|   |-- rrd_stats.c/.h             # RRDtool database creation/update
|-- whitelist/
|   |-- whitelist.c/.h             # sorted persistent MAC whitelist parsing module
|   `-- test_whitelist.c
```

## Runtime Model

`dhcp_starvation_detector.c` is the executable entry point and runtime
orchestrator. Its startup/runtime flow is:

1. Parses CLI arguments and records whether the special `--router-message` mode
   was requested.
2. Loads configuration from the selected YAML file or from the default search
   path (`config/defense_config.c`, through `cfg_load()` or
   `cfg_load_default()`). This also happens in `--router-message` mode because
   NETCONF settings and paths still come from config.
3. Reads and validates shared runtime values such as `runtime.interface`,
   `dhcp.backend`, `netconf.host`, NETCONF credentials, port, and whitelist
   path (`config/defense_config.c`, `whitelist_cfg_path()`, and local setup of
   `defense_ctx_t`). If `--router-message` was requested, it executes one
   blocking NETCONF operation through `netconf_action/` and exits here, without
   starting capture or the worker thread.
4. Initializes the detection engine and RRD state (`detector/` through
   `detector_init()`, with RRD flushing handled by `rrd/` through
   `detector_rrd_flush()`).
5. Starts the asynchronous NETCONF worker thread (`netconf_action/`,
   through `nw_start()`).
6. Initializes the reputation pipeline and loads the persistent whitelist
   database (`reputation/` through `mr_init()` and
   `mr_enable_confirmed_whitelist()`, backed by `whitelist/`).
7. Opens a live `libpcap` capture on `runtime.interface` (`dhcp_parser/`,
   through `dhcp_capture_open()`, which wraps `pcap_open_live()`).
8. Installs the configured BPF filter, normally `udp and (port 67 or port 68)`
   (`dhcp_parser/`, through `dhcp_capture_open()`, which wraps
   `pcap_compile()` and `pcap_setfilter()`).
9. Registers `SIGINT` and `SIGTERM` handlers, which request shutdown and break
   the active capture through `dhcp_capture_breakloop()`.
10. Polls DHCP pool state through NETCONF and briefly waits for initial pool
    data (`netconf_action/`, through queued worker jobs consumed by
    `drain_netconf_results()`).
11. Processes DHCP packets in a non-blocking loop (`dhcp_parser/`, through
    `dhcp_capture_dispatch()`, which dispatches packets, parses DHCP data into
    `dhcp_info_t`, and hands parsed messages back to the orchestrator).
12. Advances detector/reputation state once per second (`detector_tick()` in
   `detector/`, `mr_tick()` and lease refresh in `reputation/`).
13. Enables whitelist-only mitigation when an attack is detected
    (`detector_attack_active()` plus `enable_mitigation()`, which queues
    NETCONF whitelist enforcement through `netconf_action/`).
14. Disables mitigation after the configured grace period once the attack
    clears (`disable_mitigation()`, which queues NETCONF whitelist disable
    through `netconf_action/`).
15. During shutdown, disables mitigation if still active, stops the NETCONF
    worker with `nw_stop()`, closes the capture with `dhcp_capture_close()`,
    and exits.

The main loop is deliberately non-blocking. Packet capture is invoked through
`dhcp_capture_dispatch()`, which uses `pcap_dispatch()` internally in
non-blocking mode, while NETCONF calls run in a background worker because
SSH/NETCONF RPCs can take seconds. This keeps packet processing responsive even
when the router is slow.

## CLI Modes

The executable supports two modes.

Normal detection mode:

```bash
./bin/dhcp_starvation_detector [config_file]
```

Router-message mode:

```bash
./bin/dhcp_starvation_detector --router-message MSG [router-message options] [config_file]
```

Router-message mode sends one NETCONF command and exits. It is used by the test
suite and is also useful for manual inspection/control. The optional
`config_file` is the same positional argument used by normal mode; in
router-message mode it is used to read NETCONF settings.

Supported MSG values:

| Message | Purpose |
|---|---|
| `whitelist-on` | Push the whitelist and enable whitelist-only DHCP mode. |
| `whitelist-off` | Disable whitelist-only DHCP mode. |
| `pool` | Read DHCP pool usage and active leases. |
| `lease` | Look up one active lease by MAC; requires `--router-mac`. |
| `release-lease` | Remove a lease by MAC and/or IP; requires `--router-mac`. |
| `reset-pool` | Clear leases and disable mitigation state on the router. |

Aliases are also accepted: `on`, `off`, `release`, and `reset`.

Router-message options:

| Option | Used by | Purpose |
|---|---|---|
| `--router-mac MAC` | `lease`, `release-lease` | Select the client MAC. |
| `--router-ip IP` | `release-lease` | Optionally make lease removal more specific. |
| `--router-whitelist FILE` | `whitelist-on` | Use a whitelist file instead of `paths.whitelist`. |

## Configuration

Configuration is read through `config/defense_config.c`. The default file is
`config/config.yaml`. The parser supports a small YAML subset:

```yaml
section:
  key: value
  subsection:
    key: value
flat.key: value
```

Comments beginning with `#` are ignored.

Search priority:

1. Explicit `config_file` argument.
2. `DHCP_DEFENSE_CONFIG`.
3. `config/config.yaml` relative to the current working directory.
4. `src/defense/dhcp_starvation_detector/config/config.yaml` from project root.

Every key can be overridden by an environment variable by uppercasing the key
and replacing `.` with `_`.

Examples:

```text
runtime.interface -> RUNTIME_INTERFACE
netconf.host      -> NETCONF_HOST
netconf.password  -> NETCONF_PASSWORD
dhcp.backend      -> DHCP_BACKEND
paths.whitelist   -> PATHS_WHITELIST
```

Important config sections:

| Section | Role |
|---|---|
| `runtime` | Capture interface. |
| `dhcp` | Backend type: `dnsmasq` or `isc`. |
| `paths` | Whitelist database and RRD database paths. |
| `pcap` | Capture settings and BPF filter. |
| `netconf` | Router NETCONF-over-SSH endpoint and YANG path. |
| `defense` | Mitigation grace period and lease lookup retries. |
| `detector` | Feature thresholds and detector timing. |
| `rrd` | RRD sampling, retention, heartbeat, and consolidation settings. |
| `reputation` | Legitimate-client backoff, quotas, ARP confirmation, and TTLs. |

Minimum/main values to check before running:

| Key | When it matters | Notes |
|---|---|---|
| `runtime.interface` | Normal detection mode | Interface to sniff, for example `ens160` or `eth0`. Required for live detection. |
| `netconf.host` | Both modes | Router NETCONF endpoint. Required because mitigation, pool checks, and router-message commands use it. |
| `dhcp.backend` | Both modes | Must match the router backend, currently `dnsmasq` or `isc`. Defaults to `dnsmasq`. |
| `netconf.username` / `netconf.password` | Both modes | SSH/NETCONF credentials. Defaults are `root` and empty password. |
| `netconf.port` | Both modes | NETCONF-over-SSH port. Defaults to `830`. |
| `paths.whitelist` | Both modes | MAC whitelist DB. Defaults to `db/whitelist.txt`; can be replaced for one router-message call with `--router-whitelist`. |

The remaining sections tune behavior rather than basic connectivity: `pcap`
controls capture details, `detector` controls thresholds and feature timing,
`defense` controls mitigation timing, and `reputation` controls how unknown
legitimate clients can be promoted during mitigation.

`dhcp.backend` is read by both the test suite and the detector. The detector
validates and logs it, while backend-specific router behavior is implemented by
the active NETCONF handler on the router (`dnsmasq` or `ISC DHCP`).

## Detection Engine

The detector combines multiple independent signals and prints their state once
per second. A tick line contains values such as:

```text
discover/sec=...
discover/<window>s=...
new-macs/<window>s=...
la/<la-window>s=...
bucket=<tokens>/<capacity>
baseline=<ema>+-<deviation>
pool=<used>/<total> <percent>% growth=<leases> tte=<seconds>s
f2=... f3=... f4=... f5=... f6=...
```

`<window>` is `detector.window_secs`, and `<la-window>` is
`detector.la_window_secs`. `bucket` shows the current leaky-bucket token level
and capacity. `baseline` shows the adaptive EMA baseline and deviation used by
F4. `pool` shows current DHCP leases, pool usage, lease growth over
`detector.pool_history_secs`, and estimated time to exhaustion; it is printed as
`pool=off` when pool data is not available.

An attack is active when the configured feature score reaches
`detector.score_threshold`, or when F6 pool pressure is active. Each feature
checks a different aspect of the attack signal and contributes to the total
feature score that triggers attack detection when the configured threshold is
reached. F6 is allowed to force detection because DHCP starvation, slow to low,
can be slow enough to avoid pure packet rate thresholds while still draining the
lease pool.

F1 is intentionally absent from the final score: the raw DISCOVER count was too
sensitive to legitimate traffic and caused false positives.

### F2: Unique MAC Pressure

Implemented in `detector/sliding_window.c` and evaluated in `detector.c`.

The detector tracks DHCP DISCOVERs in a time window, normally 60 seconds. F2
fires only when both conditions are true:

- estimated unique MACs exceed `detector.unique_mac_threshold`;
- total DISCOVERs exceed `detector.unique_min_discovers`.

The implementation uses:

- a Counting Bloom Filter to track whether a MAC is already present in the
  active window;
- one HyperLogLog sketch per time slot to estimate unique MAC cardinality.

This avoids a large open-addressing table and prevents linear-probing behavior
from degrading under attack.

### F3: Leaky Bucket

Implemented in `detector/leaky_bucket.c`.

F3 is the fast absolute-rate check. Each DHCP DISCOVER consumes one token. The
bucket refills every second up to its configured capacity. When the bucket is
exhausted, F3 fires.

This is useful for sudden bursts where no baseline is needed.

### F4: Adaptive Baseline

Implemented in `detector/adaptive_score.c`.

F4 models normal traffic using an Exponential Moving Average plus a deviation
estimate. It is evaluated once per second on the current DISCOVER window rate.
After `detector.adaptive_score.warmup` samples have been collected, and only
once the deviation estimate is meaningful, F4 fires when the current window rate
is above:

```text
ema + delta * deviation
```

When F4 fires, the baseline is not updated for that tick, so the learned normal
traffic level does not chase the attack rate.

This is useful for networks whose DHCP activity is not constant throughout the
day. The baseline is updated continuously, including quiet periods.

### F5: Locally Administered MAC Ratio

Implemented through the sliding-window module and evaluated in `detector.c`.

Most generated attack MACs have the locally administered bit set. F5 examines
the recent DISCOVER traffic and fires when the LA-bit ratio exceeds
`detector.la_threshold` over `detector.la_window_secs`. The ratio is evaluated
only after at least `detector.la_min_discovers` DISCOVER packets have been seen
in that recent window, so one or two packets cannot produce a misleading
percentage.

The code uses a short recent window instead of the full 60-second window so the
signal clears quickly after traffic stops.

### F6: DHCP Pool Pressure

Implemented in `detector.c`, fed by NETCONF pool statistics.

F6 tracks actual pool occupancy instead of packet volume. It stores recent pool
samples, computes lease growth, estimates pool usage, and projects
time-to-exhaustion.

It can fire through several paths:

- high pool usage with enough recent growth;
- projected exhaustion within `detector.pool_tte_secs`;
- slow-and-low growth with enough unique MAC and DISCOVER evidence.

F6 has its own hold timer (`detector.pool_alert_hold_secs`) so mitigation does
not flap immediately when pool growth briefly pauses.

## Sliding Window Data Structures

`detector/sliding_window.c` owns the packet-rate window. Its job is to make
per-second detection cheap under attack.

Key implementation choices:

- fixed-duration slots, one per second;
- Counting Bloom Filter shared across the active window;
- per-slot HyperLogLog sketches;
- per-slot LA-bit and DISCOVER counters;
- window advancement through `sw_tick()`;
- packet updates through `sw_feed()`.

The Counting Bloom Filter supports deletion as slots expire, while HyperLogLog
keeps approximate unique-MAC counts compact.

## DHCP Parser

`dhcp_parser/dhcp_parser.c` owns the packet-capture boundary and parses captured
Ethernet frames into a compact `dhcp_info_t` structure. It exposes
`dhcp_capture_open()`, `dhcp_capture_dispatch()`, `dhcp_capture_loop()`,
`dhcp_capture_breakloop()`, and `dhcp_capture_close()` so the rest of the code
does not need to open capture handles, compile BPF filters, or process raw
capture callbacks directly.

It extracts:

- Ethernet source MAC;
- DHCP `chaddr`;
- DHCP message type;
- `ciaddr`, `yiaddr`, and requested IP option;
- packet timestamp.

The detector feeds only DHCP DISCOVERs into the scoring engine, but the
reputation pipeline also consumes OFFER, REQUEST, and ACK information while
mitigation is active.

The parser intentionally checks protocol boundaries and option lengths before
reading fields, because pcap can deliver truncated or malformed packets.

## Mitigation Flow

When the detector reports an active attack:

1. `enable_mitigation()` marks mitigation as enabled.
2. The current whitelist DB is reloaded from disk.
3. A NETCONF job pushes the whitelist to the router.
4. The router switches to whitelist-only DHCP behavior through the appropriate
   backend handler.
5. The reputation pipeline starts evaluating new clients while mitigation is
   active.

When the attack clears, the detector keeps mitigation active for
`defense.mitigation_grace_secs`. This avoids immediately dropping protection
during short pauses. After the grace period, a NETCONF job disables
whitelist-only mode.

If an enable operation finishes after the attack has already ended, the code
detects the stale completion and queues a disable operation again.

## Whitelist Module

`whitelist/whitelist.c` manages a sorted in-memory MAC set backed by
`db/whitelist.txt` or by the configured `paths.whitelist`.

It supports:

- loading from disk;
- membership checks;
- adding a MAC with an inline label/comment;
- removing a MAC from memory and disk.

The same whitelist structure is used for static trusted clients and for
reputation-confirmed clients.

## File-Based Whitelist DB

The whitelist database is currently a plain text file. This keeps the detector
simple to deploy and inspect, and is a reasonable choice for small or
medium-sized networks where the number of trusted clients and newly promoted
clients is not very large.

For larger networks, high churn, centralized administration, or multi-detector
deployments, it may make sense to migrate this layer to a real database or
another shared persistence system. The current whitelist module is the boundary
where that change would naturally fit.

## Reputation Pipeline

`reputation/mac_reputation.c` exists for the hard case: the detector has
enabled whitelist-only mode, but a real client that was not already trusted
still needs a path to regain DHCP access.

It does not simply trust any MAC seen during mitigation. It uses a staged state
machine:

```text
CANDIDATE -> TRACKING -> READY -> PROVISIONAL -> ARP_PENDING -> CONFIRMED
                                                 |
                                                 v
                                              REJECTED
```

The reputation module runs only while whitelist-only mitigation is active. The
detector still feeds every DHCP DISCOVER to the detection engine, but reputation
uses only traffic that can help decide whether an unknown client deserves access
during mitigation. DISCOVER packets are accepted only when the Ethernet source
MAC matches the DHCP `chaddr`/client MAC; mismatches are logged as
`ethernet-src-mismatch` and ignored by the reputation pipeline. OFFER, REQUEST,
ACK, and lease lookups are used later as lease hints for clients that already
reached the temporary-whitelist phase.

The module stores compact state summaries, not packet payloads. The important
global bounds are:

| Structure | Bound | Pipeline stage | What it protects |
|---|---:|---|---|
| Candidate cache | `MR_CANDIDATES = 256` | `CANDIDATE` | First sightings before a full reputation entry is allocated. |
| Temporal gate | `MR_GATE_SLOTS = 5`, `MR_GATE_BITS = 8192`, `reputation.gate_slot_secs` | `CANDIDATE` and `CANDIDATE -> TRACKING` | Bloom-filter-like memory of recently seen MACs, used to reduce churn from one-shot MACs. |
| Main reputation table | `MR_MAX_ENTRIES = 1024` | `TRACKING -> READY -> PROVISIONAL -> ARP_PENDING -> CONFIRMED` | Hard cap on full per-MAC state entries. |
| Tracking quota | `reputation.max_tracking`, default `256` | `TRACKING` | Maximum MACs simultaneously proving their retry timing. |
| Ready quota | `reputation.max_ready`, default `32` | `READY` | Maximum credible clients waiting for temporary whitelist promotion. |
| Temporary whitelist quota | `reputation.max_temp_whitelist`, default `2` | `PROVISIONAL` and `ARP_PENDING` | Maximum clients simultaneously in `PROVISIONAL` or `ARP_PENDING`. |
| Stored DISCOVER timestamps per MAC | `MR_MAX_DISCOVERS = 8` | `TRACKING`, before `READY` | Enough history to validate retry/backoff behavior without unbounded packet history. |
| Pressure threshold | `reputation.pressure_entries`, default `96` | `TRACKING + READY` pressure before `READY` admission | Switches to stricter READY requirements when `TRACKING + READY` is already crowded. |

### CANDIDATE

`CANDIDATE` is a lightweight first-sighting cache. It is intentionally separate
from the main reputation table so that one-shot random MACs do not immediately
consume full tracking entries.

For each candidate, the module stores only:

```text
used        whether this candidate slot is currently occupied
mac         candidate client MAC address seen in accepted DISCOVER traffic
first_seen  timestamp of the first remembered DISCOVER for this candidate
last_seen   timestamp of the most recent remembered DISCOVER for this candidate
```

On the first accepted DISCOVER from a previously unknown MAC, the MAC is stored
as a candidate and also inserted into the temporal gate. If the candidate cache
is full, the oldest candidate slot is reused; this keeps memory bounded, but it
can discard the lightweight first-sighting record during a flood. That does not
permanently block the client: the temporal gate can still remember that the MAC
was seen recently. If the same MAC sends another DISCOVER while the gate still
remembers it, but its candidate slot was already reused, the module creates a
`TRACKING` entry with `disc_count = 1`. The first timestamp was lost, so the
client may need one extra valid retry before reaching `READY`, but it is not
discarded forever. If a candidate is silent for more than
`reputation.observation_window_secs`, it is cleared by `mr_tick()`.

To leave `CANDIDATE`, the same MAC must send another DISCOVER with a plausible
gap:

```text
reputation.min_interval_secs <= gap <= reputation.max_interval_secs
```

and still be inside `reputation.observation_window_secs`. If the second
DISCOVER is too soon, too late, or outside the observation window, the candidate
does not advance; the current DISCOVER becomes the new first sighting, so the
MAC remains in `CANDIDATE` and must produce another valid retry gap before it
can enter `TRACKING`. If the gap is valid, the module creates a full `TRACKING`
entry with the first two DISCOVER timestamps and removes the lightweight
candidate entry.

### TRACKING

`TRACKING` is the first full entry in the main reputation table. It stores:

```text
mac                   client MAC address tracked by this reputation entry
state                 current lifecycle state for this MAC
assigned_ip           observed DHCP IPv4 address for this MAC, or 0 if unknown
first_seen            timestamp when this full reputation entry was created
last_seen             timestamp of the latest useful event for this MAC
state_since           timestamp when the entry entered its current state
disc_count            number of stored valid DISCOVER timestamps
ts[MR_MAX_DISCOVERS]  bounded DISCOVER timestamp history used for backoff checks
arp_tries             number of failed or completed ARP probe attempts
arp_next              next timestamp at which an ARP probe may be started
arp_pid               child process PID for the currently running ARP probe, or -1
```

In this state, the useful fields are mainly `disc_count` and `ts[]`: the module
keeps only a small list of DISCOVER timestamps, capped by `MR_MAX_DISCOVERS`.
This is used to decide whether the MAC behaves like a real DHCP client retrying
with backoff, rather than like an attacker sending a tight stream of DISCOVERs.

Each new DISCOVER is processed as follows:

- if the entry has been observed longer than
  `reputation.observation_window_secs`, tracking is reset from the new
  DISCOVER;
- if the gap from the previous DISCOVER is below
  `reputation.min_interval_secs`, the packet is ignored as timing evidence
  because it arrived too fast, although `last_seen` is still refreshed;
- if the gap is above `reputation.max_interval_secs`, tracking is reset from
  the new DISCOVER;
- if `disc_count` already reached `reputation.max_discovers`, the MAC becomes
  `REJECTED` with reason `too-many-discovers`;
- otherwise the timestamp is appended to `ts[]`.

After at least `reputation.min_discovers` valid DISCOVERs, the module evaluates
the full heuristic:

- every stored gap must be inside the configured min/max interval;
- the total span from first to last DISCOVER must be at least
  `reputation.backoff_min_span_secs`;
- the sequence must show enough backoff growth, controlled by
  `reputation.backoff_growth_percent` and
  `reputation.backoff_min_growth_steps`;
- when the pipeline is under pressure, meaning
  `TRACKING + READY >= reputation.pressure_entries`, the MAC must satisfy the
  stricter `reputation.pressure_min_discovers` and
  `reputation.pressure_min_age_secs` requirements.

If those checks pass, the MAC moves to `READY`. If it stays in `TRACKING` longer
than `reputation.observation_window_secs`, `mr_tick()` evicts it.

### READY

`READY` means the MAC has a credible retry/backoff pattern, but it is still not
trusted and is not yet whitelisted. The same table entry is kept; `state` and
`state_since` are updated, and the stored DISCOVER timestamps remain available
for ranking.

The `READY` queue is bounded by `reputation.max_ready`. If that quota is full,
the module compares candidates using `ready_score`, based on DISCOVER count and
the total observed span. It is computed as
`disc_count * 100 + (last_discover_ts - first_discover_ts)`, so more valid
DISCOVERs dominate the score and longer observation breaks close cases. If the
new candidate is weaker than the weakest READY entry, it is dropped before
entering `READY`. Otherwise, the weakest READY entry is evicted and the stronger
candidate takes its place.

`READY` entries are promoted only by `mr_tick()`, and promotion is rate-limited:

```text
one READY -> PROVISIONAL promotion every reputation.promote_interval_secs
```

Promotion also stops while the number of temporary whitelist entries is already
at `reputation.max_temp_whitelist`. If a MAC remains in `READY` for more than
`reputation.ready_ttl_secs` without being promoted, it is removed.

### PROVISIONAL

`PROVISIONAL` means the MAC has been temporarily added to the runtime whitelist
so it can attempt real DHCP while whitelist-only mitigation is active. This is
not final trust.

When a READY entry is promoted, the module updates:

```text
state = PROVISIONAL  mark the MAC as temporarily admitted to the runtime whitelist
state_since = now    record when temporary admission started
last_seen = now      refresh the latest activity timestamp for TTL/ranking logic
```

and calls the promotion callback. The main detector callback adds the MAC to the
whitelist with label `reputation-temporary` and pushes the updated whitelist to
the router if whitelist-only mode is active.

The temporary whitelist budget is shared by `PROVISIONAL` and `ARP_PENDING`, and
is capped by `reputation.max_temp_whitelist`. This prevents many unknown clients
from being opened at the same time.

To leave `PROVISIONAL`, the detector must observe an IP for that MAC through an
ACK, OFFER, REQUEST, or router lease lookup. Until that happens, the module is
waiting for evidence that the client actually obtained or requested an address.
If no usable lease hint arrives within `reputation.provisional_ttl_secs`, the
entry is withdrawn from the temporary whitelist and moves to `REJECTED` with
reason `ack-timeout`.

### ARP_PENDING

`ARP_PENDING` starts when a PROVISIONAL MAC has an observed IP address. The
module stores:

```text
assigned_ip  IPv4 address that should answer the ARP probe for this MAC
state_since  timestamp when ARP validation started
last_seen    latest useful DHCP/lease evidence observed for this MAC
arp_tries    number of ARP probes already attempted
arp_next     next timestamp at which another ARP probe may be launched
arp_pid      child process PID for the active ARP probe, or -1 if none is running
```

If the IP came from a DHCP ACK, ARP probing can start immediately. If the IP
came from an OFFER, REQUEST, or router lease lookup, probing is delayed by
`reputation.lease_hint_arp_delay_secs` to give the client time to configure the
address.

ARP is executed asynchronously so the detector does not block packet capture.
Each failed ARP attempt increments `arp_tries`. If there are attempts remaining,
the next probe is scheduled after `reputation.arp_retry_secs`. If
`reputation.arp_retries` attempts fail, the temporary whitelist entry is
withdrawn, the lease is released when an IP is known, and the MAC moves to
`REJECTED` with reason `arp-failed`.

If ARP succeeds and the reply comes from the expected MAC/IP pair, the MAC moves
to `CONFIRMED`.

### CONFIRMED

`CONFIRMED` means the MAC passed the full pipeline:

```text
credible DHCP retry timing -> temporary whitelist -> lease/IP observed -> ARP OK
```

At this point, the MAC is persisted into the file-backed whitelist DB with label
`reputation-confirmed`. The runtime reputation entry still has a TTL:
`reputation.confirmed_ttl_secs`. When that TTL expires, only the runtime
reputation entry is removed; the MAC remains in the whitelist file because it
was persisted.

### REJECTED

`REJECTED` is used for MACs that failed validation. A MAC can reach it because
it sent too many DISCOVERs, timed out while temporarily whitelisted, failed ARP,
or was withdrawn during eviction while still temporary.

Rejected entries stay in the runtime table for `reputation.rejected_ttl_secs`.
During that time, further DISCOVERs from the same MAC do not restart the
pipeline. This is a temporary cooldown, not a permanent ban: after the TTL
expires, the entry is deleted and the MAC can be observed again from the
beginning. If it was a legitimate client that was evicted or rejected under
pressure, it can retry after that cooldown.

### Eviction Under Pressure

Memory is bounded by fixed-size arrays and quotas. When the tracking quota is
full, the module evicts the weakest `TRACKING` entry first: the one with the
least DISCOVER evidence, using older `last_seen` as a tie-breaker.

When the full main table is full, eviction uses state priority:

```text
REJECTED < TRACKING < READY < PROVISIONAL < ARP_PENDING < CONFIRMED
```

Within comparable entries, older or weaker entries are sacrificed first.
Deleting a `PROVISIONAL` or `ARP_PENDING` entry invokes the rejection callback,
so temporary whitelist access is withdrawn instead of being left open.

This design prevents RAM growth during a flood. The trade-off is deliberate:
under a very intelligent attack that fills the reputation pipeline with
plausible clients, legitimate unknown clients may be delayed or evicted. The
detector prefers bounded memory and conservative access over allowing an
attacker to allocate unbounded per-MAC state.

Filling the reputation pipeline with plausible clients is harder than a simple
random-MAC flood. The attacker would need a stateful, long-running spoofing
strategy that keeps many MAC identities alive with realistic DHCP retry/backoff
timing. Knowing or inferring the reputation rules would make that attack more
practical, but naive high-rate floods are intentionally handled as bounded
state and mostly discarded before they can consume the pipeline.

## Asynchronous NETCONF Worker

`netconf_action/netconf_worker.c` is a small producer/consumer layer around the
blocking NETCONF functions. It owns a background POSIX thread started with
`nw_start()`.

The dedicated thread exists because NETCONF-over-SSH operations can block for
network latency, SSH negotiation, router-side script execution, or command
timeouts. The detector cannot afford to wait inside the packet-processing loop:
while DHCP traffic is arriving, capture dispatch, detector ticks, reputation
state, and RRD flushing must keep moving.

The main program therefore enqueues router work as jobs:

- periodic pool polling;
- whitelist push and whitelist-only enable;
- whitelist-only disable;
- lease lookup for reputation confirmation;
- lease release after reputation rejection;
- pool reset in router-message mode.

The worker executes those jobs by calling `netconf_action.c`, then publishes
compact results back to the main loop. `dhcp_starvation_detector.c` periodically
drains the result queue with `drain_netconf_results()` and applies the outcome
to detector state, mitigation state, or reputation state. This keeps all
security decisions in the orchestrator while isolating slow router I/O in one
place.

## NETCONF Control Layer

The detector controls the DHCP router through NETCONF-over-SSH.

Client side:

- `netconf_action.c` builds and sends NETCONF RPCs using `libnetconf2` and
  `libyang`;
- `dhcp-whitelist.yang` defines the minimal DHCP defense model used by the RPCs;
- `netconf_worker.c` runs blocking NETCONF calls in a background thread.

Worker job types:

| Job | Purpose |
|---|---|
| `POOL_STATS` | Read current pool usage and active leases. |
| `ENFORCE_WL` | Push whitelist and enable whitelist-only mode. |
| `DISABLE_WL` | Disable whitelist-only mode. |
| `LOOKUP_LEASE` | Find the lease assigned to one MAC. |
| `RELEASE_LEASE` | Remove one lease by MAC/IP. |
| `RESET_POOL` | Clear DHCP pool state and mitigation state. |

Router side:

- `netconf-handler-dnsmasq.sh` supports OpenWrt/UCI and plain dnsmasq
  containers;
- `netconf-handler-isc.sh` supports ISC DHCP containers.

The handlers expose the same logical operations while translating them into
backend-specific file edits, DHCP service restarts, lease parsing, and whitelist
configuration.

## RRD Statistics

`rrd/rrd_stats.c` stores time-series data using `rrdtool`.

The detector records:

- total DISCOVERs in the window;
- estimated unique MACs;
- LA-bit ratio;
- leaky-bucket token level and capacity;
- adaptive baseline EMA and deviation;
- DHCP pool used/total leases, usage percent, lease growth, and projected
  time-to-exhaustion.

These are stored as fixed RRDtool data sources:

```text
discovers
unique_macs
la_ratio
bucket_tokens
bucket_capacity
baseline_ema
baseline_dev
pool_used
pool_total
pool_usage_pct
pool_growth
pool_tte_secs
```

Sampling and retention are configured in the top-level `rrd` section:
`rrd.step_secs`, `rrd.history_hours`, `rrd.heartbeat_multiplier`, and
`rrd.xfiles_factor`.

RRD files have a fixed schema. If an older `dhcp_stats.rrd` is found without
the extended detector/pool data sources, startup moves it to
`dhcp_stats.rrd.old` and creates a new database with the current schema.

RRD updates are not performed from the detector tick itself. The tick only marks
that a sample is ready; the main loop later calls `detector_rrd_flush()`. This
keeps signal/tick work small and avoids calling `system()` from timing-sensitive
logic.

## Build Targets

The default build target is `all`:

```bash
make
```

It builds:

- `dhcp_starvation_detector`;
- parser/whitelist/detector/reputation/NETCONF test binaries.

The `no-netconf` target builds the parts that do not require
`libnetconf2`/`libyang` and also links `dhcp_starvation_detector` against a
local disabled-NETCONF stub:

```bash
make no-netconf
```

This is useful for compiling the core code and inspecting the main program help
page without installing the NETCONF development libraries. The resulting binary
is not a functional mitigation build: NETCONF operations fail with an explicit
disabled-support error.

## Module Test Binaries

Files named `test_*` are standalone executables used to test one detector module
at a time, for example the parser, whitelist, detector logic, reputation logic,
or NETCONF action layer. They are local module checks for this C codebase.

Current standalone utilities:

- `test_parser [--config FILE] <interface>`: captures DHCP traffic through
  `dhcp_parser/` and prints parsed messages, including both Ethernet source MAC
  and DHCP `chaddr`.
- `test_whitelist [--config FILE] [--file FILE]`: verifies whitelist load, add,
  duplicate handling, lookup, remove, reload, and file persistence using a
  scratch file by default.
- `test_detector [--config FILE] <interface> [router_ip] [user] [password]`:
  captures DHCP traffic, feeds DISCOVERs into `detector/`, writes RRD samples,
  and optionally polls pool state through NETCONF.
- `test_reputation [--config FILE] <interface> [whitelist_file]`: feeds live
  DHCP traffic into the reputation pipeline and exercises backoff tracking,
  Ethernet/DHCP mismatch rejection, temporary whitelist callbacks, ARP probing,
  and confirmed whitelist persistence.
- `test_netconf_action [--config FILE] MSG <router_ip> ...`: sends one
  NETCONF/YANG router message such as `whitelist-on`, `whitelist-off`, `pool`,
  `lease`, `release-lease`, or `reset-pool`.

Run any of them with `--help` for the exact arguments. `make no-netconf` builds
the non-NETCONF standalone tools on machines without NETCONF development
libraries; full `make` builds `test_netconf_action` as well when `libnetconf2`
and `libyang` headers/libraries are installed.

They are not the comprehensive project test suite. The full lab-oriented suite
is the Python runner under the repository `tests/` directory, which starts the
Docker or VM environment, synchronizes runtime resources, launches attacks, and
validates end-to-end detector and mitigation behavior.

Custom output directory:

```bash
make BINDIR=/path/to/bin
```

Cleanup:

```bash
make clean
```

## Main Dependencies

The core detector uses:

- `libpcap` for packet capture;
- `libnetconf2` and `libyang` for NETCONF RPCs and YANG parsing;
- SSH support underneath `libnetconf2` (`libssh` development/runtime packages
  on the supported Debian/Ubuntu environments);
- the `ietf-netconf` YANG modules reachable through `netconf.yang_dir`
  (`libyuma-base` provides them in the Docker/VM setup);
- `rrdtool` for time-series storage;
- POSIX threads for the NETCONF worker;
- the standard math library (`libm`, linked with `-lm`) for HyperLogLog
  cardinality estimation;
- standard Linux networking APIs for ARP reputation probing.

The router-side shell handlers additionally require standard shell tools such
as `sed`, `awk`, `grep`, `wc`, `tr`, `head`, `mktemp`, `pidof`, and backend DHCP
commands (`dnsmasq` or `dhcpd`).

## Extension Points

The design keeps several extension points explicit:

- adding a new DHCP backend should mean writing a new router-side NETCONF
  handler that implements the same YANG/RPC behavior;
- tuning detection should mostly happen in `config/config.yaml`, not by changing
  C constants;
- adding a new detection feature should be done in `detector.c` and, if it
  needs state, in a dedicated module under `detector/`;
- changing persistence format should be isolated mostly to `whitelist/`.

## Design Notes

The implementation favors conservative runtime behavior:

- packet capture must keep moving even if NETCONF is slow;
- router changes are queued and retried rather than performed directly in the
  packet callback;
- pool pressure can force detection because lease exhaustion is the real impact
  of DHCP starvation;
- whitelist-only mitigation is delayed before disabling to avoid flapping;
- legitimate clients are never permanently trusted without ARP confirmation;
- generated/spoofed traffic with Ethernet/DHCP MAC mismatch is ignored by the
  reputation system.
