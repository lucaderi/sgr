#!/usr/bin/env python3

"""
DHCP Starvation Detector test runner.

From the host, prepares Docker or VM labs, syncs detector/config/whitelist,
NETCONF handlers and attack/legit-client scripts, verifies required tools, runs
attack and control scenarios, checks detection/mitigation behavior, and saves
logs/results.
"""

from __future__ import annotations

import argparse
import atexit
import inspect
import logging
import os
import posixpath
import random
import re
import signal
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    paramiko = None
else:
    # Suppress paramiko logging.
    for _paramiko_logger_name in ("paramiko", "paramiko.transport"):
        _paramiko_logger = logging.getLogger(_paramiko_logger_name)
        _paramiko_logger.addHandler(logging.NullHandler())
        _paramiko_logger.propagate = False
        _paramiko_logger.setLevel(logging.CRITICAL + 1)

PATHS = {
    "script_dir": (_script_dir := Path(__file__).resolve().parent),
    "project_root": (_project_root := _script_dir.parent),
    "default_local_defense_dir": (
        _default_local_defense_dir := _project_root / "src/defense/dhcp_starvation_detector"
    ),
    "default_config_file": _default_local_defense_dir / "config/config.yaml",
    "default_config_display": "src/defense/dhcp_starvation_detector/config/config.yaml",
    "default_results_root": _script_dir / "results",
    "default_output_display": "tests/results",
}

EARLY_RUN_ID = os.environ.get("RUN_ID") or datetime.now().strftime("%d-%m-%Y %H_%M_%S")

# Regex to get ENV var from C detector files.
CFG_GETTER_RE = re.compile(
    r'cfg_(?:get_(?:int|u32|double|float|string)|resolve_path)\(\s*"([^"]+)"'
)

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _open_early_summary():

    global _early_summary_fh
    if _early_summary_fh:
        return _early_summary_fh
    try:
        EARLY_RESULT_DIR.mkdir(parents=True, exist_ok=True)
        _early_summary_fh = open(EARLY_SUMMARY, "w")
    except OSError:
        _early_summary_fh = None
    return _early_summary_fh

def _format_log_message(msg: str) -> str:

    if not msg or re.match(r"^\s*\[\d{2}:\d{2}:\d{2}\]\s+", msg):
        return msg
    match = re.match(r"^(\s*)(\[(?:OK|WARN|FAIL|PASS)\]\s+.*)$", msg)
    if not match:
        return msg
    return f"{match.group(1)}[{ts()}] {match.group(2)}"

def _emit_log(msg: str = "", *, early_summary: bool = False) -> None:

    msg = _format_log_message(msg)
    print(msg)

    summary_fh = _current_summary_fh()
    if summary_fh:
        print(msg, file=summary_fh, flush=True)
        return

    if early_summary or _early_summary_fh:
        early_fh = _open_early_summary()
        if early_fh:
            print(msg, file=early_fh, flush=True)

def _current_summary_fh():

    runtime = globals().get("RUNTIME")
    if isinstance(runtime, dict):
        return runtime.get("summary_fh")
    return None

def fail_and_exit(message: str, code: int = 2) -> None:

    global _early_header_written
    if not _current_summary_fh() and not _early_header_written:
        _emit_log("DHCP Starvation Detector — Test Suite", early_summary=True)
        if REQUESTED_TEST_TYPE:
            _emit_log(f"Env Type    : {REQUESTED_TEST_TYPE}", early_summary=True)
        _emit_log(f"Run ID      : {EARLY_RUN_ID}", early_summary=True)
        _emit_log(f"Results     : {EARLY_RESULT_DIR}", early_summary=True)
        _emit_log("", early_summary=True)
        _early_header_written = True

    _emit_log(f"[FAIL] {message}", early_summary=True)
    if _early_summary_fh:
        try:
            _early_summary_fh.close()
        except Exception:
            pass
    sys.exit(code)

def preparse_option(argv: list[str], option: str) -> str | None:

    prefix = f"{option}="
    for index, arg in enumerate(argv[1:], start=1):
        if arg.startswith(prefix):
            return arg[len(prefix):]
        if arg == option and index + 1 < len(argv):
            value = argv[index + 1]
            if not value.startswith("-"):
                return value
    return None

def preparse_output_dir(argv: list[str]) -> str | None:

    return preparse_option(argv, "--output")

def preparse_env_type(argv: list[str]) -> str | None:

    return preparse_option(argv, "--env-type")

def preparse_config_file(argv: list[str]) -> str | None:

    return preparse_option(argv, "--config")

REQUESTED_CONFIG_FILE = (
    preparse_config_file(sys.argv) or
    os.environ.get("CONFIG_FILE") or
    os.environ.get("DHCP_DEFENSE_CONFIG")
)
REQUESTED_OUTPUT_DIR = preparse_output_dir(sys.argv)
REQUESTED_TEST_TYPE = preparse_env_type(sys.argv)
CONFIG_FILE = Path(REQUESTED_CONFIG_FILE or PATHS["default_config_file"])

if REQUESTED_CONFIG_FILE and not CONFIG_FILE.is_file():
    fail_and_exit(f"config file not found: {CONFIG_FILE}")

def _early_project_path(value: str | Path) -> Path:

    path = Path(value).expanduser()
    return path if path.is_absolute() else Path(PATHS["project_root"]) / path

EARLY_RESULTS_ROOT = _early_project_path(REQUESTED_OUTPUT_DIR or PATHS["default_results_root"])
EARLY_RESULT_DIR = EARLY_RESULTS_ROOT / EARLY_RUN_ID
EARLY_SUMMARY = EARLY_RESULT_DIR / "summary.txt"
_early_summary_fh = None
_early_header_written = False

# Minimal parser for the project YAML subset: section: / key: value.
def yaml_get(filepath: Path, section: str, key: str) -> str:

    if not filepath.is_file():
        return ""
    in_sec = False
    try:
        fh = open(filepath)
    except OSError as exc:
        fail_and_exit(f"cannot read config file {filepath}: {exc}")
    with fh:
        for line in fh:
            line = re.sub(r'\s*#.*$', '', line.rstrip())
            if re.match(r'^[a-z_]', line):
                in_sec = line.split(':')[0].strip() == section
                continue
            if in_sec and line.startswith((' ', '\t')):
                stripped = line.strip()
                if ':' not in stripped:
                    continue
                k, _, v = stripped.partition(':')
                if k.strip() != key:
                    continue
                return v.strip().strip('"')
    return ""

# Load settings.
# Priority: env var > config file section > hardcoded default.
def cfg(key: str, default: str, *, section: str = "test_suite") -> str:

    env_name = key.upper() if section == "test_suite" else f"{section}_{key}".upper()
    env_val = os.environ.get(env_name)
    if env_val is not None:
        return env_val
    val = yaml_get(CONFIG_FILE, section, key)
    return val if val else default

def project_path(value: str | Path) -> Path:

    path = Path(value).expanduser()
    return path if path.is_absolute() else Path(PATHS["project_root"]) / path

def cfg_int(key: str, default: int, min_value: int | None = None) -> int:

    raw = cfg(key, str(default))
    try:
        value = int(raw)
    except ValueError:
        fail_and_exit(
            f"invalid integer for test_suite.{key} / {key.upper()}: {raw!r}"
        )
    if min_value is not None and value < min_value:
        fail_and_exit(
            f"test_suite.{key} / {key.upper()} must be >= {min_value}: {value}"
        )
    return value

PATHS.update({
    "local_defense_dir": (
        _local_defense_dir := project_path(cfg(
            "local_defense_dir",
            "src/defense/dhcp_starvation_detector",
        ))
    ),
    "local_attack_script": project_path(cfg(
        "local_attack_script",
        "src/attack/dhcp_starvation_attack.py",
    )),
    "local_legit_dhcp_client_script": project_path(cfg(
        "local_legit_dhcp_client_script",
        "tests/legit_dhcp_client.sh",
    )),
    "local_debian_scripts": project_path(cfg(
        "local_debian_scripts",
        "lab/vms/vms-scripts/debian-scripts",
    )),
    "local_whitelist_file": _local_defense_dir / "db/whitelist.txt",
    "remote_config_path": "config/config.yaml",
    "suite_wl_remote": cfg("suite_wl_remote", "db/whitelist_ct.txt"),
    "remote_tmp_dir": cfg("remote_tmp_dir", "/tmp").rstrip("/") or "/tmp",
})

SUITE = {
    "detect_timeout_burst": cfg_int("detect_timeout_burst", 120, 0),
    "detect_timeout_slow": cfg_int("detect_timeout_slow", 360, 0),
    "legit_timeout": cfg_int("legit_timeout", 130, 0),
    "baseline_duration": cfg_int("baseline_duration", 120, 0),
    "post_detect_secs": cfg_int("post_detect_secs", 10, 0),
    "remote_retries": cfg_int("ssh_retries", 3, 1),
}

DHCP_LAB = {
    "router_lease_file": cfg("router_lease_file", "/tmp/dhcp.leases"),
    "ipv4_prefix": cfg("dhcp_ipv4_prefix", "192.168.42."),
    "pool_start_host": cfg_int("dhcp_pool_start_host", 100, 0),
    "pool_total_default": cfg_int("dhcp_pool_total_default", 150, 1),
    "legit_client_path": cfg("legit_dhcp_client_path", "/tmp/legit_dhcp_client.sh"),
    "legit_client_attempts": cfg_int("legit_dhcp_client_attempts", 50, 1),
    "legit_client_valid_sleep_secs": cfg_int("legit_dhcp_client_valid_sleep_secs", 30, 0),
    "legit_client_retry_sleep_secs": cfg_int("legit_dhcp_client_retry_sleep_secs", 8, 0),
}

RUN_ID       = cfg("run_id", EARLY_RUN_ID)
RESULTS_ROOT = project_path(REQUESTED_OUTPUT_DIR or PATHS["default_results_root"])
RESULT_DIR   = RESULTS_ROOT / RUN_ID
SUMMARY    = RESULT_DIR / "summary.txt"

RUNTIME = {
    "debian_lease_ip": "",
    "debian_mac": "",
    "pool_total": DHCP_LAB['pool_total_default'],
    "pool_limit": DHCP_LAB['pool_total_default'],
    "pass_count": 0,
    "fail_count": 0,
    "total_count": 0,
    "current_test": "",
    "current_defense_pid": "",
    "current_attack_pid": "",
    "attack_failed": False,
    "rrd_start_times": {},
    "rrd_graph_collected": set(),
    "interrupted": False,
    "verbose": False,
    "test_type": REQUESTED_TEST_TYPE or "",
    "summary_fh": None,
    "exit_called": False,
}

DOCKER = {
    "compose_file": project_path(cfg("docker_compose_file", "lab/docker/docker-compose.yml")),
    "router_container": cfg("docker_router_container", "dhcp_router"),
    "detector_container": cfg("docker_detector_container", "dhcp_detector"),
    "attacker_container": cfg("docker_attacker_container", "dhcp_attacker"),
    "client_container": cfg("docker_client_container", "dhcp_client"),
    "router_ip": cfg("docker_router_ip", "192.168.100.1"),
    "detector_iface": cfg("docker_detector_iface", "eth0"),
    "attacker_iface": cfg("docker_attacker_iface", "eth0"),
    "client_iface": cfg("docker_client_iface", "eth0"),
    "attack_script": cfg("docker_attack_script", "/usr/local/bin/dhcp_starvation_attack.py"),
    "detector_dir": cfg("docker_detector_dir", "/app"),
    "detector_bin_dir": cfg("docker_detector_bin_dir", "/app/bin"),
    "dhcp_type": cfg("backend", "dnsmasq", section="dhcp").lower(),
    "netconf_yang_dir": cfg("docker_netconf_yang_dir", "/usr/share/yuma/modules/ietf"),
    "router_lease_file": cfg("docker_router_lease_file", "/var/lib/misc/dnsmasq.leases"),
    "isc_router_lease_file": cfg("docker_isc_router_lease_file", "/var/lib/dhcp/dhcpd.leases"),
    "dhcp_ipv4_prefix": cfg("docker_dhcp_ipv4_prefix", "192.168.100."),
    "dhcp_pool_start_host": cfg_int("docker_dhcp_pool_start_host", 10, 0),
    "dhcp_pool_total_default": cfg_int("docker_dhcp_pool_total_default", 151, 1),
    "client_log_dir": cfg("docker_client_log_dir", "/tmp/ct-logs"),
    "legit_dhcp_client_path": cfg("docker_legit_dhcp_client_path", "/tmp/legit_dhcp_client.sh"),
}

DOCKER_BY_ROLE = {
    "router":   DOCKER['router_container'],
    "detector": DOCKER['detector_container'],
    "attacker": DOCKER['attacker_container'],
    "client":   DOCKER['client_container'],
}

# Used by VMs and Docker.
LAB = {
    "openwrt_ip": cfg("openwrt_ip", "192.168.42.4"),
    "openwrt_user": cfg("openwrt_user", "root"),
    "openwrt_pass": cfg("openwrt_pass", ""),
    "openwrt_netconf_handler": cfg("openwrt_netconf_handler", "/usr/bin/netconf-handler"),

    "ubuntu_ip": cfg("ubuntu_ip", "192.168.42.6"),
    "ubuntu_user": cfg("ubuntu_user", "giulio"),
    "ubuntu_pass": cfg("ubuntu_pass", "test123"),
    "ubuntu_iface": cfg("ubuntu_iface", "ens160"),
    "ubuntu_def_dir": cfg("ubuntu_def_dir", "/home/giulio/progettogestionereti/src/defense/dhcp_starvation_detector"),
    "ubuntu_bin_dir": cfg("ubuntu_bin_dir", "/home/giulio/progettogestionereti/bin"),

    "kali_ip": cfg("kali_ip", "192.168.42.5"),
    "kali_user": cfg("kali_user", "giulio"),
    "kali_pass": cfg("kali_pass", "test123"),
    "kali_iface": cfg("kali_iface", "eth0"),
    "kali_attack_dir": cfg("kali_attack_dir", "/home/giulio/progettogestionereti/src/attack"),

    "debian_ip": cfg("debian_ip", "192.168.42.3"),
    "debian_static_ip": cfg("debian_static_ip", "192.168.42.3"),
    "debian_user": cfg("debian_user", "giulio"),
    "debian_pass": cfg("debian_pass", "test123"),
    "debian_iface": cfg("debian_iface", "ens160"),
    "debian_mac_hint": cfg("debian_mac_hint", "00:50:56:2d:11:c4"),
    "debian_dhcpget": cfg("debian_dhcpget", "/home/giulio/progettogestionereti/lab/vms/vms-scripts/debian-scripts/dhcpget.sh"),
    "debian_log_dir": cfg("debian_log_dir", "/home/giulio/ct-logs"),
}

def run_smoke() -> None:
    
    log()
    log("════════ SMOKE MODE (one test per group) ════════════════════════════")

    run_case("SA_smoke_burst_la_on",  "burst_unique",      "on",  50, 0.0, 9001, 100, 120, True, require_f5=True)
    run_case("SB_smoke_mixed_la_off", "mixed_same_unique", "off", 100, 0.2, 9101, 120, 120, True)
    run_case("SC_smoke_slow_pool_same_unique_la_on", "slow_mixed", "on", 80, 3.0, 9201,
             360, max(SUITE['legit_timeout'], 180), True, require_f6=True)
    run_case("SD_smoke_same_mac",     "same_mac_burst",    "on",  30, 0.3, 9301,  80,  80, False, expect_silent=True)
    run_baseline("SE_smoke_baseline")
    run_case("SF_smoke_burst_then_flat", "burst_then_same_flat", "on", 50, 2.0, 9401,
             120, max(SUITE['legit_timeout'], 180), True, check_attacker_rep=True, require_whitelist=True)
    run_case("SG_smoke_adaptive_f4", "adaptive_f4_spike", "on", 130, 1.0, 9501,
             220, max(SUITE['legit_timeout'], 180), True, require_f4=True)
    run_lease_reap("SH_smoke_arp_failed_lease_reap")
    run_case("SI_smoke_yersinia_dhcp_dos", "yersinia_dhcp_discover", "external",
             10, 0.0, 0, 90, max(SUITE['legit_timeout'], 180), True, require_whitelist=True)
    
    run_ethernet_mismatch("SJ_smoke_ethernet_src_mismatch")
    run_reputation_confirm("SK_smoke_legit_reputation_confirmed")

# Check in remote logs.
def wait_for_ethernet_src_mismatch(name: str, timeout: int) -> bool:

    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if detector_ok(
            "grep -q 'reason=ethernet-src-mismatch' "
            f"{shlex.quote(def_log)} 2>/dev/null"
        ):
            return True
        time.sleep(1)
    return False

# Check in local logs.
def defense_log_has_ethernet_src_mismatch(name: str) -> bool:

    try:
        content = (result_group_dir(name) / f"{name}.defense.log").read_text(errors="replace")
    except OSError:
        return False
    return "reason=ethernet-src-mismatch" in content

# Special baseline scenario: detector must log Ethernet/DHCP MAC mismatch discards and ignore them for reputation.
def _run_ethernet_mismatch_impl(name: str) -> None:


    la = "on"
    trigger_count = 90
    mismatch_count = 12
    seed = 8101
    detect_timeout = 120
    mismatch_timeout = 45
    legit_timeout = max(SUITE['legit_timeout'], 180)
    trigger_name = f"{name}_trigger"
    legit_ok = False

    RUNTIME['current_test'] = name
    RUNTIME['current_defense_pid'] = ""
    RUNTIME['current_attack_pid'] = ""

    log()
    log(f"── {ts()}  {name} ──────────────────────────────────────────")
    log("  scenario=ethernet_src_mismatch  trigger=unique-MAC burst  mismatch=12 no-wait DISCOVERs")
    log("  DHCP chaddr/client-id differs from Ethernet source; reputation must ignore it.")
    log()

    cleanup_all()
    reset_router()
    time.sleep(1)
    resolve_client_ip()

    if not start_defense(name):
        kill_remote_attack(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "defense_start_failed")
        return

    record_pre_attack_rrd_baseline()

    if not start_attack(trigger_name, "burst_unique", la, trigger_count, 0.0, seed + 1000):
        kill_remote_attack(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "trigger_attack_start_failed")
        return

    log("  trigger burst running…")
    detected = wait_for_attack_detected(name, detect_timeout, attack_name=trigger_name)
    if detected:
        log(f"  [{ts()}] [OK] ATTACK DETECTED")
    else:
        log(f"  [{ts()}] [FAIL] trigger burst NOT detected within {detect_timeout}s")

    whitelist_ok = False
    if detected:
        whitelist_ok = wait_for_whitelist_applied(name)
        if whitelist_ok:
            log(f"  [{ts()}] [OK] whitelist-only applied")
    else:
        log("  [FAIL] whitelist-only apply confirmation not seen before mismatch phase")

    attack_status_failed(trigger_name)
    kill_remote_attack()

    mismatch_seen = False
    if whitelist_ok:
        log("  starting legitimate DHCP client…")
        if not start_client_loop(name):
            log("  [FAIL] legit client loop start failed")
        else:
            log("  checking legitimate client access…")
            if wait_for_legit_client(name, legit_timeout):
                legit_ok = True
                log(f"  [{ts()}] [OK] legit client access verified ({RUNTIME['debian_lease_ip'] or LAB['debian_ip']})")
            else:
                log(f"  [{ts()}] [FAIL] legit client lease/reputation confirmation NOT found within {legit_timeout}s")
            kill_client_loop()

        if not start_attack(name, "ethernet_src_mismatch", la, mismatch_count, 0.0, seed):
            kill_remote_attack(); stop_defense(name)
            collect_logs(name)
            reset_router()
            mark(name, False, "mismatch_attack_start_failed")
            return

        log("  sending Ethernet/DHCP MAC mismatch traffic…")
        mismatch_seen = wait_for_ethernet_src_mismatch(name, mismatch_timeout)
        if mismatch_seen:
            log(f"  [{ts()}] [OK] detector logged ethernet-src-mismatch discard")
        else:
            log(f"  [{ts()}] [FAIL] detector did NOT log ethernet-src-mismatch within {mismatch_timeout}s")
        attack_status_failed(name)
        kill_remote_attack()

    time.sleep(SUITE['post_detect_secs'])
    used = pool_used()
    pool_ok = used < RUNTIME['pool_limit']
    if pool_ok:
        log(f"  [{ts()}] [OK] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")
    else:
        log(f"  [{ts()}] [FAIL] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")

    wait_for_post_pool_rrd_sample()
    collect_router_state(name)
    stop_defense(name)
    collect_logs(name)
    reset_router()

    if not mismatch_seen:
        mismatch_seen = defense_log_has_ethernet_src_mismatch(name)

    attack_ok = not RUNTIME['attack_failed']
    if detected and whitelist_ok and legit_ok and mismatch_seen and pool_ok and attack_ok:
        mark(name, True, f"detected=yes  whitelist=yes  legit=yes  mismatch_discard=yes  pool={used}/{RUNTIME['pool_total']}")
    else:
        mark(
            name,
            False,
            f"detected={int(detected)}  whitelist={int(whitelist_ok)}  "
            f"legit={int(legit_ok)}  mismatch_discard={int(mismatch_seen)}  "
            f"pool_ok={int(pool_ok)}({used}/{RUNTIME['pool_total']})  "
            f"attack_failed={int(not attack_ok)}",
        )

def run_ethernet_mismatch(name: str) -> None:
    
    try:
        _run_ethernet_mismatch_impl(name)
    except Exception as exc:
        log(f"  [FAIL] unexpected ethernet-mismatch error: {exc}")
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            collect_logs(name)
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass
        mark(name, False, f"unexpected_error={type(exc).__name__}")

def run_group_j() -> None:
    log()
    log("════════ GROUP J: Ethernet/DHCP MAC mismatch ══════════════════════")
    log("  A 90-packet unique-MAC burst must trigger detection and whitelist-only mode.")
    log("  Then 12 no-wait DISCOVERs keep the real Ethernet source but spoof DHCP chaddr/client-id.")
    log("  PASS requires detection, whitelist-only, legit access, ethernet-src-mismatch discard, and pool intact.")

    run_ethernet_mismatch("J1_ethernet_src_mismatch")

def run_client_dhcp_attempt(
    name: str,
    *,
    dhcpcd_timeout_secs: int = 30,
) -> bool:

    client_log = f"{LAB['debian_log_dir']}/{RUN_ID}.{name}.client.log"
    client_script_path = DHCP_LAB['legit_client_path']
    client_script_path_q = shlex.quote(client_script_path)
    mode = "docker" if RUNTIME['test_type'] == "docker" else "vms"
    env_args = _legit_dhcp_client_env(
        mode,
        client_log,
        attempts=1,
        valid_sleep_secs=0,
        retry_sleep_secs=0,
        dhcpcd_timeout_secs=dhcpcd_timeout_secs,
    )
    cmd = f"env {env_args} sh {client_script_path_q}"

    try:
        rc, out, err = client_run(f"test -x {client_script_path_q}", timeout=10)
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [WARN] legit DHCP client script missing for foreground attempt: {detail or f'exit {rc}'}")
            return False

        if RUNTIME['test_type'] == "docker":
            rc, out, err = client_run(cmd, timeout=dhcpcd_timeout_secs + 30)
        else:
            rc, out, err = client_run(
                f"printf '%s\\n' {shlex.quote(LAB['debian_pass'])} | "
                f"su -c {shlex.quote(cmd)}",
                timeout=dhcpcd_timeout_secs + 40,
            )
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [WARN] foreground DHCP client attempt failed: {detail or f'exit {rc}'}")
            return False
        return True
    except Exception as exc:
        log(f"  [WARN] foreground DHCP client attempt error: {exc}")
        return False

def wait_for_reputation_confirmed(name: str, mac: str, timeout: int) -> bool:

    return wait_for_defense_log_text(
        name,
        f"reputation: confirmed {mac.lower()}",
        timeout,
    )

def remote_whitelist_has_mac(mac: str) -> bool:

    remote_wl = runtime_whitelist_path()
    mac_arg = shlex.quote(mac.lower())
    return detector_ok(
        f"awk -v mac={mac_arg} "
        "'{sub(/#.*/, \"\"); if (tolower($1)==tolower(mac)) found=1} "
        "END{exit found ? 0 : 1}' "
        f"{shlex.quote(remote_wl)} 2>/dev/null"
    )

def wait_for_defense_log_text(name: str, text: str, timeout: int) -> bool:

    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    pattern = shlex.quote(text)
    elapsed = 0
    while elapsed < timeout:
        if detector_ok(
            f"grep -qi {pattern} {shlex.quote(def_log)} 2>/dev/null"
        ):
            return True
        time.sleep(2)
        elapsed += 2
    return False

def wait_for_reputation_temp_whitelist(name: str, mac: str, timeout: int) -> bool:

    return wait_for_defense_log_text(
        name,
        f"reputation: temporary whitelist entry {mac.lower()}",
        timeout,
    )

# Special scenario: a legit client not in the whitelist should pass the reputation pipeline and get access.
def _run_reputation_confirm_impl(name: str) -> None:

    la = "on"
    count = 70
    seed = 10001
    detect_timeout = 180
    temp_timeout = 240
    confirm_timeout = max(SUITE['legit_timeout'], 300)

    RUNTIME['current_test'] = name
    RUNTIME['current_defense_pid'] = ""
    RUNTIME['current_attack_pid'] = ""
    RUNTIME['debian_lease_ip'] = ""

    log()
    log(f"── {ts()}  {name} ──────────────────────────────────────────")
    log("  scenario=legit_reputation_confirm  la=on  burst_count=70  client_backoff=5,10,20s  clean_attempt_after_temp=yes  seed=10001")
    log("  Legit client MAC is removed from the runtime whitelist before detector start.")
    log("  PASS requires whitelist-only, temporary promotion, clean DHCP, ARP OK/confirmation, and MAC present in runtime whitelist.")
    log()

    cleanup_all()
    reset_router()
    time.sleep(1)
    resolve_client_ip()
    client_mac = RUNTIME['debian_mac'].lower()

    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", client_mac):
        mark(name, False, "legit_client_mac_unavailable")
        return

    log(f"  [{ts()}] legit client MAC under test: {client_mac}")

    if not start_defense(
        name,
        include_vm_legit_client=False,
        exclude_whitelist_macs=[client_mac],
    ):
        kill_remote_attack(); kill_client_loop(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "defense_start_failed")
        return

    removed_from_initial_wl = not remote_whitelist_has_mac(client_mac)
    if removed_from_initial_wl:
        log(f"  [{ts()}] [OK] legit client MAC absent from initial runtime whitelist")
    else:
        log(f"  [FAIL] legit client MAC {client_mac} is still present in initial runtime whitelist")
        kill_remote_attack(); kill_client_loop(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "legit_client_initial_whitelist_present")
        return

    record_pre_attack_rrd_baseline()

    if not start_attack(name, "burst_unique", la, count, 0.0, seed):
        kill_remote_attack(); kill_client_loop(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "attack_start_failed")
        return

    log("  attack burst running…")
    detected = wait_for_attack_detected(name, detect_timeout)
    if detected:
        log(f"  [{ts()}] [OK] ATTACK DETECTED")
    else:
        log(f"  [{ts()}] [FAIL] attack NOT detected within {detect_timeout}s")

    whitelist_ok = False
    if detected:
        whitelist_ok = wait_for_whitelist_applied(name)
    if whitelist_ok:
        log(f"  [{ts()}] [OK] whitelist-only mode applied")
    else:
        log("  [FAIL] whitelist-only apply confirmation not seen before reputation-confirm phase")

    attack_status_failed(name)
    kill_remote_attack()

    client_started = False
    temp_ok = False
    confirmed = False
    lease_ok = False
    whitelist_final = False

    if whitelist_ok:
        log("  starting legit client DHCP backoff/reputation attempt…")
        client_started = start_client_loop(
            name,
            attempts=10,
            valid_sleep_secs=120,
            retry_backoff_secs="5 10 20 20 20 20 20",
            dhcpcd_timeout_secs=12,
        )
        if not client_started:
            log("  [FAIL] legit client reputation loop start failed")
        else:
            temp_ok = wait_for_reputation_temp_whitelist(name, client_mac, temp_timeout)
            if temp_ok:
                log(f"  [{ts()}] [OK] legit client temporarily promoted to whitelist")
                time.sleep(3)
                kill_client_loop()
                log("  forcing one clean DHCP attempt while temporary whitelist is active…")
                client_started = run_client_dhcp_attempt(name, dhcpcd_timeout_secs=30)
                if client_started:
                    log(f"  [{ts()}] [OK] clean DHCP attempt completed")
                else:
                    log("  [FAIL] clean DHCP attempt failed")
            else:
                log(f"  [FAIL] legit client was not temporarily promoted within {temp_timeout}s")

            confirmed = wait_for_reputation_confirmed(name, client_mac, confirm_timeout)
            if confirmed:
                log(f"  [{ts()}] [OK] legit client reputation confirmed by ARP")
            else:
                log(f"  [FAIL] legit client was not reputation-confirmed within {confirm_timeout}s")

            lease = legit_client_lease_on_router()
            if lease:
                lease_ok = True
                parts = lease.split()
                if len(parts) >= 3:
                    RUNTIME['debian_lease_ip'] = parts[2]
                log(f"  [{ts()}] [OK] legit client lease after confirmation: {describe_router_lease(lease)}")
            else:
                log(f"  [{ts()}] [FAIL] legit client lease not visible on router after confirmation wait")

            whitelist_final = remote_whitelist_has_mac(client_mac)
            if whitelist_final:
                log(f"  [{ts()}] [OK] legit client MAC present in runtime whitelist after confirmation")
            else:
                log(f"  [FAIL] legit client MAC {client_mac} missing from runtime whitelist after confirmation")

    used = pool_used()
    pool_ok = used < RUNTIME['pool_limit']
    if pool_ok:
        log(f"  [{ts()}] [OK] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")
    else:
        log(f"  [{ts()}] [FAIL] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")

    wait_for_post_pool_rrd_sample()
    kill_client_loop()
    collect_router_state(name)
    stop_defense(name)
    collect_logs(name)
    reset_router()

    attack_ok = not RUNTIME['attack_failed']
    if detected and whitelist_ok and client_started and temp_ok and confirmed and lease_ok and whitelist_final and pool_ok and attack_ok:
        mark(name, True, f"detected=yes  whitelist=yes  temp_wl=yes  confirmed=yes  lease=yes  runtime_wl=yes  pool={used}/{RUNTIME['pool_total']}")
    else:
        mark(
            name,
            False,
            f"detected={int(detected)}  whitelist={int(whitelist_ok)}  "
            f"client_started={int(client_started)}  temp_wl={int(temp_ok)}  "
            f"confirmed={int(confirmed)}  lease={int(lease_ok)}  runtime_wl={int(whitelist_final)}  "
            f"pool_ok={int(pool_ok)}({used}/{RUNTIME['pool_total']})  "
            f"attack_failed={int(not attack_ok)}",
        )

def run_reputation_confirm(name: str) -> None:
    try:
        _run_reputation_confirm_impl(name)
    except Exception as exc:
        log(f"  [FAIL] unexpected reputation-confirm error: {exc}")
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            collect_logs(name)
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass
        mark(name, False, f"unexpected_error={type(exc).__name__}")

def run_group_k() -> None:
    log()
    log("════════ GROUP K: Reputation-confirmed whitelist entry ════════════")
    log("  Removes the legit client MAC from the runtime whitelist before detector start.")
    log("  A 70-packet unique-MAC burst must trigger detection and whitelist-only mode.")
    log("  The legit client uses DHCP backoff to reach temporary whitelist, then one clean DHCP attempt that answers ARP.")
    log("  temp_wl means temporary reputation promotion; runtime_wl means final active whitelist entry.")
    log("  PASS requires temporary promotion, reputation confirmation, and final runtime whitelist entry.")

    run_reputation_confirm("K1_legit_reputation_confirmed")

def run_group_i() -> None:
    
    log()
    log("════════ GROUP I: Yersinia DHCP DoS ═══════════════════════════════")
    log("  External-tool attack: yersinia sends DHCP DISCOVER DoS traffic for 10s.")
    log("  PASS requires detection, whitelist-only, legit client access, and pool intact.")

    run_case("I1_yersinia_dhcp_discover_dos", "yersinia_dhcp_discover", "external",
             10, 0.0, 0, 90, max(SUITE['legit_timeout'], 180), True, require_whitelist=True)

def wait_for_router_lease_removed(mac: str, timeout: int) -> bool:

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not router_lease_for_mac(mac):
            return True
        time.sleep(2)
    return False

def wait_for_router_lease(mac: str, timeout: int) -> str:

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lease = router_lease_for_mac(mac)
        if lease:
            return lease
        time.sleep(2)
    return ""

# Prepare the env for the legit_dhcp_client.sh.
def _legit_dhcp_client_env(
    mode: str,
    client_log: str,
    *,
    attempts: int | None = None,
    valid_sleep_secs: int | None = None,
    retry_sleep_secs: int | None = None,
    retry_backoff_secs: str | None = None,
    dhcpcd_timeout_secs: int | None = None,
) -> str:

    env = {
        "LEGIT_DHCP_CLIENT_MODE": mode,
        "LEGIT_DHCP_CLIENT_IFACE": LAB['debian_iface'],
        "LEGIT_DHCP_CLIENT_LOG": client_log,
        "LEGIT_DHCP_CLIENT_ATTEMPTS": str(attempts if attempts is not None else DHCP_LAB['legit_client_attempts']),
        "LEGIT_DHCP_CLIENT_IPV4_PREFIX": DHCP_LAB['ipv4_prefix'],
        "LEGIT_DHCP_CLIENT_VALID_SLEEP_SECS": str(valid_sleep_secs if valid_sleep_secs is not None else DHCP_LAB['legit_client_valid_sleep_secs']),
        "LEGIT_DHCP_CLIENT_RETRY_SLEEP_SECS": str(retry_sleep_secs if retry_sleep_secs is not None else DHCP_LAB['legit_client_retry_sleep_secs']),
    }
    if retry_backoff_secs:
        env["LEGIT_DHCP_CLIENT_RETRY_BACKOFF_SECS"] = retry_backoff_secs
    if dhcpcd_timeout_secs is not None:
        env["LEGIT_DHCP_CLIENT_DHCPCD_TIMEOUT_SECS"] = str(dhcpcd_timeout_secs)

    if mode == "vms":
        env.update({
            "LEGIT_DHCP_CLIENT_DHCPGET": LAB['debian_dhcpget'],
            "LEGIT_DHCP_CLIENT_STATIC_CIDR": f"{LAB['debian_static_ip']}/24",
            "LEGIT_DHCP_CLIENT_STATIC_IP": LAB['debian_static_ip'],
        })

    return " ".join(f"{key}={shlex.quote(value)}"
                    for key, value in env.items())

# Starts the legitimate client DHCP loop to check if a legitimate client can obtain a lease and maintain it during the attack and defense phases.
def start_client_loop(
    name: str,
    *,
    attempts: int | None = None,
    valid_sleep_secs: int | None = None,
    retry_sleep_secs: int | None = None,
    retry_backoff_secs: str | None = None,
    dhcpcd_timeout_secs: int | None = None,
) -> bool:

    client_log = f"{LAB['debian_log_dir']}/{RUN_ID}.{name}.client.log"
    client_script_path = DHCP_LAB['legit_client_path']
    client_script_path_q = shlex.quote(client_script_path)

    if RUNTIME['test_type'] == "docker":
        try:
            client_run(f"mkdir -p {shlex.quote(LAB['debian_log_dir'])}", timeout=10)
            client_run(f": > {shlex.quote(client_log)}", timeout=10)
            rc, out, err = client_run(f"test -x {client_script_path_q}", timeout=10)
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [WARN] Docker legit DHCP client script missing: {detail or f'exit {rc}'}")
                return False
            env_args = _legit_dhcp_client_env(
                "docker",
                client_log,
                attempts=attempts,
                valid_sleep_secs=valid_sleep_secs,
                retry_sleep_secs=retry_sleep_secs,
                retry_backoff_secs=retry_backoff_secs,
                dhcpcd_timeout_secs=dhcpcd_timeout_secs,
            )
            launch = (
                f"nohup env {env_args} sh {client_script_path_q} "
                f">/dev/null 2>&1 &"
            )
            rc, out, err = client_run(launch, timeout=20)
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [WARN] Docker client loop launch failed: {detail or f'exit {rc}'}")
                return False
            time.sleep(2)
            return True
        except Exception as exc:
            log(f"  [WARN] Docker client loop start error: {exc}")
            return False

    # Map the active lab role settings to Docker containers and paths.
    try:
        client_run(f"mkdir -p {shlex.quote(LAB['debian_log_dir'])}", timeout=10)
        client_run(f": > {shlex.quote(client_log)}", timeout=10)
        rc, out, err = client_run(f"test -x {client_script_path_q}", timeout=10)
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [WARN] Debian legit DHCP client script missing: {detail or f'exit {rc}'}")
            return False
        env_args = _legit_dhcp_client_env(
            "vms",
            client_log,
            attempts=attempts,
            valid_sleep_secs=valid_sleep_secs,
            retry_sleep_secs=retry_sleep_secs,
            retry_backoff_secs=retry_backoff_secs,
            dhcpcd_timeout_secs=dhcpcd_timeout_secs,
        )
        root_cmd = (
            f"nohup env {env_args} sh {client_script_path_q} "
            f">/dev/null 2>&1 &"
        )
        launch = (
            f"printf '%s\\n' {shlex.quote(LAB['debian_pass'])} | "
            f"su -c {shlex.quote(root_cmd)}"
        )
        rc, out, err = client_run(launch, timeout=20)
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [WARN] Client DHCP loop launch failed: {detail or f'exit {rc}'}")
            return False
        time.sleep(2)
        return True
    except Exception as exc:
        log(f"  [WARN] Client DHCP loop start error: {exc}")
        return False

# Format a raw router lease line into a more readable form.
def describe_router_lease(lease: str) -> str:

    parts = lease.split()
    if len(parts) < 3:
        return lease

    expires_raw, mac, ip = parts[:3]
    host = parts[3] if len(parts) > 3 and parts[3] != "*" else ""
    client_id = parts[4] if len(parts) > 4 and parts[4] != "*" else ""
    fields = [f"ip={ip}", f"mac={mac}"]

    if host:
        fields.append(f"host={host}")
    if client_id:
        fields.append(f"client_id={client_id}")
    if expires_raw and expires_raw != "0":
        try:
            expires = datetime.fromtimestamp(int(expires_raw)).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            expires = expires_raw
        fields.append(f"expires={expires}")

    return "  ".join(fields)

# Search a lease in the router for a specifc MAC.
def router_lease_for_mac(mac: str) -> str:
    mac_arg = shlex.quote(mac.lower())
    _, out, _ = router_run(
        f"{router_active_leases_cmd()} | "
        f"awk -v mac={mac_arg} 'tolower($2)==tolower(mac){{print}}'"
    )
    return out.strip()

def clean_num(s) -> int:
    
    d = re.sub(r'[^0-9]', '', str(s))
    return int(d) if d else 0

def pool_used() -> int:

    try:
        _, out, _ = router_run(f"{router_active_leases_cmd()} | wc -l")
        return clean_num(out.strip().splitlines()[-1] if out.strip() else "0")
    except Exception:
        return 0

def defense_log_has_arp_reject(name: str, mac: str) -> tuple[bool, bool]:
    
    try:
        content = (result_group_dir(name) / f"{name}.defense.log").read_text(errors="replace").lower()
    except OSError:
        return False, False
    arp_failed = "arp-failed" in content
    rejected = f"reputation: rejected {mac.lower()}" in content
    return arp_failed, rejected

# Special baseline scenario: attacker with fixed MAC must obtain a lease, then be removed after ARP failure.
def _run_lease_reap_impl(name: str) -> None:

    la = "on"
    count = 70
    delay = 4.0
    seed = 7001
    detect_timeout = 180
    lease_timeout = 180
    removal_timeout = 180
    legit_timeout = max(SUITE['legit_timeout'], 180)
    atk_mac = mac_from_seed(seed, la)
    legit_ok = False
    whitelist_ok = False

    RUNTIME['current_test'] = name
    RUNTIME['current_defense_pid'] = ""
    RUNTIME['current_attack_pid'] = ""

    log()
    log(f"── {ts()}  {name} ──────────────────────────────────────────")
    log("  scenario=lease_reap_fixed_mac  la=on  burst_count=70  backoff_discovers=4  fixed_attempts=10  delay=4.0s  seed=7001")
    log(f"  attacker fixed MAC={atk_mac}; must obtain lease, then be removed after ARP failure")

    log()

    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", atk_mac):
        mark(name, False, "attacker_mac_unavailable")
        return

    cleanup_all()
    reset_router()
    time.sleep(1)
    resolve_client_ip()

    if not start_defense(name):
        kill_remote_attack(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "defense_start_failed")
        return

    record_pre_attack_rrd_baseline()

    if not start_attack(name, "lease_reap_fixed_mac", la, count, delay, seed):
        kill_remote_attack(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "attack_start_failed")
        return

    log("  attack running…")

    detected = wait_for_attack_detected(name, detect_timeout)
    if detected:
        log(f"  [{ts()}] [OK] ATTACK DETECTED")
    else:
        log(f"  [{ts()}] [FAIL] attack NOT detected within {detect_timeout}s")

    whitelist_ok = wait_for_whitelist_applied(name)
    if whitelist_ok:
        log(f"  [{ts()}] [OK] whitelist-only applied")
    else:
        log("  [FAIL] whitelist-only apply confirmation not seen before lease-reap phase")

    log("  starting legitimate DHCP client…")
    if not start_client_loop(name):
        log("  [FAIL] legit client loop start failed")
    else:
        log("  checking legitimate client access…")
        if wait_for_legit_client(name, legit_timeout):
            legit_ok = True
            log(f"  [{ts()}] [OK] legit client access verified ({RUNTIME['debian_lease_ip'] or LAB['debian_ip']})")
        else:
            log(f"  [{ts()}] [FAIL] legit client lease/reputation confirmation NOT found within {legit_timeout}s")

    lease_before = wait_for_router_lease(atk_mac, lease_timeout)
    out_dir = result_group_dir(name)
    (out_dir / f"{name}.attacker.lease.before-release.txt").write_text(
        (lease_before + "\n") if lease_before else ""
    )

    if lease_before:
        log(f"  [{ts()}] [OK] attacker fake lease obtained: {describe_router_lease(lease_before)}")
    else:
        log(f"  [{ts()}] [FAIL] attacker fake MAC did NOT obtain a lease within {lease_timeout}s")

    attack_status_failed(name)
    kill_remote_attack()
    kill_client_loop()

    removed = False
    if lease_before:
        removed = wait_for_router_lease_removed(atk_mac, removal_timeout)
    lease_after = router_lease_for_mac(atk_mac)
    (out_dir / f"{name}.attacker.lease.after-release.txt").write_text(
        (lease_after + "\n") if lease_after else ""
    )

    if removed:
        log(f"  [{ts()}] [OK] attacker fake lease removed after ARP/reputation failure")
    elif lease_before:
        log(f"  [{ts()}] [FAIL] attacker fake lease still present after {removal_timeout}s: {describe_router_lease(lease_after)}")

    used = pool_used()
    pool_ok = used < RUNTIME['pool_limit']
    if pool_ok:
        log(f"  [{ts()}] [OK] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")
    else:
        log(f"  [{ts()}] [FAIL] pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")

    wait_for_post_pool_rrd_sample()
    collect_router_state(name)
    stop_defense(name)
    collect_logs(name)
    reset_router()

    arp_failed, rejected = defense_log_has_arp_reject(name, atk_mac)
    if arp_failed:
        log(f"  [{ts()}] [OK] reputation removal reason verified: arp-failed")
    else:
        log("  [FAIL] defense log did not show arp-failed removal reason")
    if rejected:
        log(f"  [{ts()}] [OK] reputation rejection verified for {atk_mac}")
    else:
        log(f"  [FAIL] defense log did not show reputation rejection for {atk_mac}")

    attack_ok = not RUNTIME['attack_failed']
    if detected and whitelist_ok and legit_ok and bool(lease_before) and removed and arp_failed and rejected and pool_ok and attack_ok:
        mark(name, True, f"detected=yes  whitelist=yes  legit=yes  lease_obtained=yes  lease_removed=yes  pool={used}/{RUNTIME['pool_total']}")
    else:
        mark(
            name,
            False,
            f"detected={int(detected)}  whitelist={int(whitelist_ok)}  legit={int(legit_ok)}  "
            f"lease_obtained={int(bool(lease_before))}  "
            f"lease_removed={int(removed)}  arp_failed={int(arp_failed)}  "
            f"rejected={int(rejected)}  pool_ok={int(pool_ok)}({used}/{RUNTIME['pool_total']})  "
            f"attack_failed={int(not attack_ok)}",
        )

def run_lease_reap(name: str) -> None:
    try:
        _run_lease_reap_impl(name)
    except Exception as exc:
        log(f"  [FAIL] unexpected lease-reap error: {exc}")
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            collect_logs(name)
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass
        mark(name, False, f"unexpected_error={type(exc).__name__}")

def run_group_h() -> None:
    log()
    log("════════ GROUP H: ARP-failed lease removal ════════════════════════")
    log("  A 70-packet unique-MAC burst must trigger detection and whitelist-only mode.")
    log("  One fixed fake MAC then follows reputation backoff and obtains a DHCP lease.")
    log("  The fake MAC stops responding; ARP probing must reject it and remove the lease.")
    log("  PASS requires detection, whitelist-only, legit access, fake lease removal, arp-failed, and rejection.")

    run_lease_reap("H1_arp_failed_lease_reap")

def run_group_g() -> None:
    log()
    log("════════ GROUP G: Adaptive baseline F4 ═════════════════════════════")
    log("  Warmup sends 130 same-MAC no-wait DISCOVERs with target delay=1s.")
    log("  The warmup uses repeat-every=1 to avoid the unique-MAC F2 signal.")
    log("  Then 25 no-wait unique-MAC DISCOVERs create a controlled spike.")
    log("  PASS requires detection, legit client access, pool intact, and f4=1.")

    f4_legit_timeout = max(SUITE['legit_timeout'], 180)
    run_case("G1_adaptive_f4_spike_la_on", "adaptive_f4_spike", "on", 130, 1.0, 6001,
             220, f4_legit_timeout, True, require_f4=True)

def run_group_f() -> None:
    log()
    log("════════ GROUP F: Whitelist evasion ════════════════════════════════")
    log("  F1-F3 start with 70 no-wait unique-MAC DISCOVERs to trigger detection.")
    log("  After detection, whitelist-only confirmation is required; missing confirmation fails.")
    log("  Then 6 full DHCP attempts reuse one fixed MAC with 4s gaps to probe reputation.")
    log("  PASS requires detection, whitelist-only, legit client access, pool intact, and attacker_rep=ok (not promoted).")

    evasion_legit_timeout = max(SUITE['legit_timeout'], 240)
    run_case("F1_burst_then_flat_la_on",  "burst_then_same_flat", "on",  70, 4.0, 5001,
             180, evasion_legit_timeout, True, check_attacker_rep=True, require_whitelist=True)
    run_case("F2_burst_then_flat_la_off", "burst_then_same_flat", "off", 70, 4.0, 5101,
             180, evasion_legit_timeout, True, check_attacker_rep=True, require_whitelist=True)
    run_case("F3_burst_then_flat_la_mixed", "burst_then_same_flat", "mixed", 70, 4.0, 5201,
             180, evasion_legit_timeout, True, check_attacker_rep=True, require_whitelist=True)

# Special baseline scenario: no attack, only the legitimate DHCP client loop runs for a while — verify no false positive and pool intact.
def _run_baseline_impl(name: str) -> None:
    

    RUNTIME['current_test'] = name
    RUNTIME['current_defense_pid'] = ""

    log()
    log(f"── {ts()}  {name} ──────────────────────────────────────────")
    log(f"  baseline: no attack, {SUITE['baseline_duration']}s with legitimate client DHCP loop — verify no false positive.")
    log()

    cleanup_all()
    reset_router()
    time.sleep(1)
    resolve_client_ip()
    start_client_loop(name)

    if not start_defense(name):
        kill_client_loop()
        stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "defense_start_failed")
        return

    log(f"  running {SUITE['baseline_duration']}s with only legitimate client traffic…")
    time.sleep(SUITE['baseline_duration'])

    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    false_positive = detector_ok(
        f"grep -qE '\\*\\*\\* ATTACK \\*\\*\\*|ATTACK detected' "
        f"{shlex.quote(def_log)} 2>/dev/null"
    )
    if false_positive:
        log("  [FAIL] false positive: defense triggered without any attack")
    else:
        log(f"  [{ts()}] [OK] no false positive detected")

    bl_ip = ""
    client_ok_flag = False
    lease = legit_client_lease_on_router()
    if lease:
        parts = lease.split()
        if len(parts) >= 3 and parts[2].startswith(DHCP_LAB['ipv4_prefix']):
            bl_ip = parts[2]
        client_ok_flag = True
        log(f"  [{ts()}] [OK] legit client holds DHCP lease at {bl_ip}")
    if not client_ok_flag:
        log("  [WARN] No DHCP lease found for legit client on router")

    used = pool_used()
    pool_ok = used < RUNTIME['pool_limit']
    if pool_ok:
        log(f"  [{ts()}] [OK] pool used = {used} / {RUNTIME['pool_total']}")
    else:
        log(f"  [{ts()}] [FAIL] pool used = {used} / {RUNTIME['pool_total']}")

    wait_for_post_pool_rrd_sample()
    kill_client_loop()
    stop_defense(name)
    collect_logs(name)
    reset_router()

    if not false_positive and pool_ok:
        mark(name, True,  f"no_false_positive  pool={used}/{RUNTIME['pool_total']}  client_ip={bl_ip or 'none'}")
    else:
        mark(name, False, f"false_positive={int(false_positive)}  pool_ok={int(pool_ok)}({used}/{RUNTIME['pool_total']})")

def run_baseline(name: str) -> None:
    try:
        _run_baseline_impl(name)
    except Exception as exc:
        log(f"  [FAIL] unexpected baseline error: {exc}")
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            collect_logs(name)
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass
        mark(name, False, f"unexpected_error={type(exc).__name__}")

def run_group_e() -> None:
    log()
    log("════════ GROUP E: IDLE check ═══════════════════════════════════════")
    log(f"  No attack is launched; only the legitimate DHCP client loop runs for {SUITE['baseline_duration']}s.")
    log("  Checks false positives while normal DHCP traffic is present.")
    log("  The client lease is reported if present; missing lease is logged as WARN.")
    log("  PASS requires no false positive and pool intact.")

    run_baseline("E1_baseline_no_attack")

def run_group_d() -> None:
    log()
    log("════════ GROUP D: Same-MAC control cases ════════════════════════════")
    log("  D1-D3 send 45 full DHCP attempts from one fixed MAC with la=on/off/mixed.")
    log("  Each attempt uses --count 1 with the same seed, then sleeps 0.3s.")
    log("  Control case: repeated same-MAC traffic must not drain the DHCP pool.")
    log("  PASS requires pool intact and no attack detection within 90s.")

    run_case("D1_same_mac_la_on",    "same_mac_burst", "on",    45, 0.3, 4001, 90, 80, False, expect_silent=True)
    run_case("D2_same_mac_la_off",   "same_mac_burst", "off",   45, 0.3, 4101, 90, 80, False, expect_silent=True)
    run_case("D3_same_mac_la_mixed", "same_mac_burst", "mixed", 45, 0.3, 4201, 90, 80, False, expect_silent=True)

def run_group_c() -> None:
    log()
    log("════════ GROUP C: Slow-and-low pool pressure ═══════════════════════")
    log("  Full DHCP attempts use target delay=3s (C1-C3) or 4s (C4) between attempts.")
    log("  Every 10th attempt reuses one fixed MAC; the other attempts use unique MACs.")
    log("  PASS requires detection, legit client access, pool intact, and f6=1.")
    log(f"  Detection timeout uses detect_timeout_slow={SUITE['detect_timeout_slow']}s.")

    slow_legit_timeout = max(SUITE['legit_timeout'], 180)
    run_case("C1_slow_pool_same_unique_la_off", "slow_mixed", "off", 80, 3.0, 3001,
             SUITE['detect_timeout_slow'], slow_legit_timeout, True, require_f6=True)
    run_case("C2_slow_pool_same_unique_la_on",  "slow_mixed", "on",  80, 3.0, 3101,
             SUITE['detect_timeout_slow'], slow_legit_timeout, True, require_f6=True)
    run_case("C3_slow_pool_same_unique_la_mixed", "slow_mixed", "mixed", 80, 3.0, 3278,
             SUITE['detect_timeout_slow'], slow_legit_timeout, True, require_f6=True)
    run_case("C4_very_slow_pool_same_unique_la_on", "slow_mixed", "on", 60, 4.0, 3301,
             SUITE['detect_timeout_slow'], slow_legit_timeout, True, require_f6=True)

def run_group_b() -> None:

    log()
    log("════════ GROUP B: Same-MAC then unique burst ═══════════════════════")
    log("  B1-B3 send 80/100/100 DISCOVERs with la=on/off/mixed.")
    log("  The first 26/33/33 reuse one MAC with 0.2s gaps; the remaining 54/67/67 are no-wait/no-delay unique-MAC bursts.")
    log("  Checks that the repeated-MAC prefix does not hide the F2/F3 unique-burst signal.")

    run_case("B1_mixed_la_on",    "mixed_same_unique", "on",    80,  0.2, 2001, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True)
    run_case("B2_mixed_la_off",   "mixed_same_unique", "off",   100, 0.2, 2101, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True)
    run_case("B3_mixed_la_mixed", "mixed_same_unique", "mixed", 100, 0.2, 2201, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True)

def docker_exec_detached(container: str, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    
    args = ["docker", "exec", "-d", container, "sh", "-lc", cmd]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError("'docker' command not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"detached docker exec {container} timed out after {timeout}s") from exc
    if RUNTIME['verbose']:
        if proc.stdout:
            sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
    return proc.returncode, proc.stdout, proc.stderr

def attack_status_path(name: str) -> str:

    return remote_tmp(f"ct.{RUN_ID}.{name}.attack.status")

def read_attack_status(name: str) -> int | None:

    status_q = shlex.quote(attack_status_path(name))
    try:
        rc, out, _ = attacker_run(f"test -s {status_q} && cat {status_q} || true", timeout=10)
    except Exception:
        return None
    if rc != 0:
        return None
    text = out.strip().splitlines()
    if not text:
        return None
    try:
        return int(text[-1].strip())
    except ValueError:
        return None

def attack_status_failed(name: str) -> bool:

    rc = read_attack_status(name)
    if rc is None or rc == 0:
        return False
    RUNTIME['attack_failed'] = True
    log(f"  [{ts()}] [FAIL] attack scenario exited with rc={rc}; see attack log")
    return True

def _build_attack_script(scenario: str, iface: str, la: str,
                         count: int, delay: float, seed: int,
                         password: str, attack_script: str, log_path: str,
                         status_path: str, use_sudo: bool = True) -> str:
    
    if use_sudo:
        run = (
            f"printf '%s\\n' {shlex.quote(password)} | sudo -S -p '' "
            f"python3 -u {shlex.quote(attack_script)} {shlex.quote(iface)}"
        )
    else:
        run = f"python3 -u {shlex.quote(attack_script)} {shlex.quote(iface)}"

    if scenario == "burst_unique":
        body = (
            f'echo "[burst-unique] count={count} la={la} seed={seed}"\n'
            f'{run} --count {count} --la {la} --seed {seed} --no-wait\n'
        )
    elif scenario == "slow_unique":
        body = (
            f'echo "[slow-unique] count={count} seed={seed} la={la} delay={delay}"\n'
            f'{run} --count {count} --la {la} --seed {seed} --delay {delay}\n'
        )
    elif scenario == "slow_mixed":
        body = (
            f'echo "[slow-mixed] full DHCP attempts count={count} seed={seed} la={la} delay={delay} repeated_mac_every=10"\n'
            f'{run} --count {count} --la {la} --seed {seed} --delay {delay} '
            f'--repeat-every 10 --repeat-seed {seed}\n'
        )
    elif scenario == "same_mac_burst":
        body = (
            f'i=1\n'
            f'while [ "$i" -le {count} ]; do\n'
            f'    echo "[same-mac] full DHCP attempt $i/{count} seed={seed} la={la}"\n'
            f'    {run} --count 1 --la {la} --seed {seed}\n'
            f'    sleep {delay}\n'
            f'    i=$((i + 1))\n'
            f'done\n'
        )
    elif scenario == "mixed_same_unique":
        repeated = count // 3
        unique   = count - repeated
        body = (
            f'i=1\n'
            f'while [ "$i" -le {repeated} ]; do\n'
            f'    echo "[mixed] repeated same-MAC DISCOVER $i/{repeated} seed={seed} la={la}"\n'
            f'    {run} --count 1 --la {la} --seed {seed} --no-wait\n'
            f'    sleep {delay}\n'
            f'    i=$((i + 1))\n'
            f'done\n'
            f'echo "[mixed] unique-MAC DISCOVER burst count={unique} la={la} seed={seed + 1000}"\n'
            f'{run} --count {unique} --la {la} --seed {seed + 1000} --no-wait\n'
        )
    elif scenario == "burst_then_same_flat":
        body = (
            f'echo "[burst-then-same-flat] trigger unique-MAC DISCOVER burst count={count} la={la} seed={seed + 1000}"\n'
            f'{run} --count {count} --la {la} --seed {seed + 1000} --no-wait\n'
            f'i=1\n'
            f'while [ "$i" -le 6 ]; do\n'
            f'    echo "[burst-then-same-flat] fixed-MAC full DHCP attempt $i/6 seed={seed} la={la} delay={delay}"\n'
            f'    {run} --count 1 --la {la} --seed {seed}\n'
            f'    sleep {delay}\n'
            f'    i=$((i + 1))\n'
            f'done\n'
        )
    elif scenario == "lease_reap_fixed_mac":
        fixed_attempts = 10
        body = (
            f'echo "[lease-reap] trigger unique-MAC DISCOVER burst count={count} la={la} seed={seed + 1000}"\n'
            f'{run} --count {count} --la {la} --seed {seed + 1000} --no-wait\n'
            f'echo "[lease-reap] fixed-MAC reputation backoff DISCOVERs gaps=5,10,20s seed={seed}"\n'
            f'i=1\n'
            f'for pause in 5 10 20 0; do\n'
            f'    echo "[lease-reap] fixed-MAC backoff DISCOVER $i/4 seed={seed}"\n'
            f'    {run} --count 1 --la {la} --seed {seed} --no-wait\n'
            f'    if [ "$pause" != "0" ]; then sleep "$pause"; fi\n'
            f'    i=$((i + 1))\n'
            f'done\n'
            f'echo "[lease-reap] waiting for reputation temporary whitelist"\n'
            f'sleep 8\n'
            f'i=1\n'
            f'while [ "$i" -le {fixed_attempts} ]; do\n'
            f'    echo "[lease-reap] fixed-MAC full DHCP attempt $i/{fixed_attempts} seed={seed} delay={delay}"\n'
            f'    {run} --count 1 --la {la} --seed {seed}\n'
            f'    sleep {delay}\n'
            f'    i=$((i + 1))\n'
            f'done\n'
        )
    elif scenario == "adaptive_f4_spike":
        spike_count = 25
        body = (
            f'echo "[adaptive-f4] warmup same-MAC DISCOVERs count={count} la={la} seed={seed} delay={delay}"\n'
            f'{run} --count {count} --la {la} --seed {seed} --delay {delay} --no-wait '
            f'--repeat-every 1 --repeat-seed {seed}\n'
            f'echo "[adaptive-f4] spike unique-MAC DISCOVERs count={spike_count} la={la} seed={seed + 1000}"\n'
            f'{run} --count {spike_count} --la {la} --seed {seed + 1000} --no-wait\n'
        )
    elif scenario == "ethernet_src_mismatch":
        body = (
            f'echo "[ethernet-src-mismatch] mismatched Ethernet/DHCP DISCOVERs count={count} la={la} seed={seed}"\n'
            f'{run} --count {count} --la {la} --seed {seed} --no-wait --keep-ether-src\n'
        )
    elif scenario == "yersinia_dhcp_discover":
        duration = max(5, int(count))
        y_cmd = f"yersinia dhcp -attack 1 -interface {shlex.quote(iface)}"
        y_run = f"tail -f /dev/null | {y_cmd}"
        y_cleanup = "pkill -f '[y]ersinia' >/dev/null 2>&1 || true"
        if use_sudo:
            y_run = (
                f"printf '%s\\n' {shlex.quote(password)} | sudo -S -p '' "
                f"sh -c {shlex.quote(y_run)}"
            )
            y_cleanup = (
                f"printf '%s\\n' {shlex.quote(password)} | sudo -S -p '' "
                f"sh -c {shlex.quote(y_cleanup)}"
            )
        body = (
            f'echo "[yersinia-dhcp] attack=discover-dos interface={iface} duration={duration}s"\n'
            f'if ! command -v yersinia >/dev/null 2>&1; then\n'
            f'    echo "[FAIL] [yersinia-dhcp] yersinia not found"\n'
            f'    exit 127\n'
            f'fi\n'
            f'set +e\n'
            f'timeout {duration} sh -c {shlex.quote(y_run)}\n'
            f'rc=$?\n'
            f'set -e\n'
            f'{y_cleanup}\n'
            f'echo "[yersinia-dhcp] finished rc=$rc"\n'
            f'case "$rc" in 0|124) exit 0 ;; *) exit "$rc" ;; esac\n'
        )
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    status_q = shlex.quote(status_path)
    log_q = shlex.quote(log_path)
    header = (
        "#!/bin/sh\n"
        "set -u\n"
        f"status_file={status_q}\n"
        'rm -f "$status_file"\n'
        "finish() {\n"
        "    rc=$?\n"
        '    printf "%s\\n" "$rc" > "$status_file" 2>/dev/null || true\n'
        "}\n"
        "trap finish EXIT\n"
        f"exec > {log_q} 2>&1\n"
        "set -e\n"
    )
    return f"{header}{body}"

def start_attack(name: str, scenario: str, la: str,
                 count: int, delay: float, seed: int) -> bool:
    
    RUNTIME['attack_failed'] = False
    atk_log = remote_tmp(f"ct.{RUN_ID}.{name}.attack.log")
    atk_status = attack_status_path(name)

    # Static resources are installed once by sync_code(); each test only verifies them.
    try:
        attack_script = remote_attack_script_path()
        rc, out, err = attacker_run(f"test -x {shlex.quote(attack_script)}", timeout=10)
        if rc != 0:
            detail = (err or out).strip()
            target = "Docker attacker" if RUNTIME['test_type'] == "docker" else "Kali"
            log(f"  [FAIL] attack script missing on {target}: {detail or f'exit {rc}'}")
            return False
    except Exception as exc:
        log(f"  [FAIL] attack script check failed: {exc}")
        return False

    # Build and upload the scenario shell script.
    remote_script = remote_tmp(f"ct.{RUN_ID}.{name}.sh")
    try:
        content = _build_attack_script(
            scenario, LAB['kali_iface'], la, count, delay, seed,
            LAB['kali_pass'], attack_script, atk_log, atk_status,
            use_sudo=(RUNTIME['test_type'] != "docker"),
        )
        if RUNTIME['test_type'] == "docker":
            docker_write(DOCKER['attacker_container'], remote_script, content)
        else:
            _pool.write_remote(LAB['kali_ip'], LAB['kali_user'], LAB['kali_pass'], remote_script, content)
    except Exception as exc:
        log(f"  [FAIL] failed to write scenario script: {exc}")
        return False

    remote_script_q = shlex.quote(remote_script)
    if RUNTIME['test_type'] == "docker":
        try:
            rc, out, err = attacker_run(f"chmod +x {remote_script_q}", timeout=30)
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] attack chmod failed: {detail or f'exit {rc}'}")
                return False
            rc, out, err = docker_exec_detached(
                DOCKER['attacker_container'],
                f"sh {remote_script_q}",
                timeout=30,
            )
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] attack start command failed: {detail or f'exit {rc}'}")
                return False
            RUNTIME['current_attack_pid'] = "docker-detached"
            time.sleep(2)
            if attack_status_failed(name):
                return False
            return True
        except Exception as exc:
            log(f"  [FAIL] attack start error: {exc}")
            return False

    launch = f"chmod +x {remote_script_q}; nohup sh {remote_script_q} >/dev/null 2>&1 & echo $!"
    try:
        rc, out, _ = _pool.run(LAB['kali_ip'], LAB['kali_user'], LAB['kali_pass'], launch, timeout=30)
        if rc != 0:
            log(f"  [FAIL] attack start command failed: exit {rc}")
            return False
        last_line = (out.strip().splitlines() or [""])[-1].strip()
        if not re.fullmatch(r"[0-9]+", last_line):
            log("  [FAIL] attack PID not obtained")
            return False
        RUNTIME['current_attack_pid'] = last_line
        time.sleep(2)
        if attack_status_failed(name):
            return False
        return True
    except Exception as exc:
        log(f"  [FAIL] attack start error: {exc}")
        return False

def detector_start_env() -> dict[str, str]:

    env = detector_forwarded_env()
    lab_defaults = {
        "RUNTIME_INTERFACE": LAB['ubuntu_iface'],
        "DHCP_BACKEND": DOCKER['dhcp_type'],
        "NETCONF_HOST": LAB['openwrt_ip'],
        "PATHS_WHITELIST": PATHS['suite_wl_remote'],
    }
    if RUNTIME['test_type'] == "docker":
        lab_defaults.update({
            "NETCONF_YANG_DIR": DOCKER['netconf_yang_dir'],
            "NETCONF_USERNAME": "root",
            "NETCONF_PASSWORD": "root",
        })
    for key, value in lab_defaults.items():
        env.setdefault(key, value)
    return env

# Prepare the environment for the detector.
def detector_env_args(env: dict[str, str]) -> str:
    
    return " ".join(
        f"{key}={shlex.quote(value)}"
        for key, value in sorted(env.items())
    )

# Write a memory string in a docker file.
def docker_write(container: str, remote_path: str, content: str) -> None:

    rc, out, err = docker_exec(
        container,
        f"mkdir -p {shlex.quote(posixpath.dirname(remote_path) or '/')} && "
        f"cat > {shlex.quote(remote_path)}",
        stdin_data=content.encode(),
        timeout=30,
        retries=1,
    )
    if rc != 0:
        detail = (err or out).strip()
        raise RuntimeError(f"docker write failed for {container}:{remote_path}: {detail or f'exit {rc}'}")

# Returns the whitelist with removed MAC.
def whitelist_content_without_macs(content: str, macs: list[str] | tuple[str, ...] | set[str]) -> str:

    targets = {mac.strip().lower() for mac in macs if mac and mac.strip()}
    if not targets:
        return content

    kept = []
    for line in content.splitlines():
        entry = line.split("#", 1)[0].strip().split()
        if entry and entry[0].lower() in targets:
            continue
        kept.append(line)

    result = "\n".join(kept)
    if result and content.endswith("\n"):
        result += "\n"
    return result

def whitelist_content_has_mac(content: str, mac: str) -> bool:

    target = mac.strip().lower()
    if not target:
        return False
    for line in content.splitlines():
        entry = line.split("#", 1)[0].strip().split()
        if entry and entry[0].lower() == target:
            return True
    return False

def ensure_vm_legit_client_whitelisted(content: str) -> str:

    if RUNTIME['test_type'] == "docker" or not RUNTIME['debian_mac']:
        return content
    if whitelist_content_has_mac(content, RUNTIME['debian_mac']):
        return content
    suffix = "" if content.endswith("\n") or not content else "\n"
    return f"{content}{suffix}{RUNTIME['debian_mac'].lower()}   # debian legit client (test-suite VM)\n"

def runtime_whitelist_path() -> str:

    return posixpath.join(LAB['ubuntu_def_dir'].rstrip("/"), PATHS['suite_wl_remote'])

def remote_config_base_dir() -> str:

    config_path = PATHS['remote_config_path']
    config_dir = posixpath.dirname(config_path) or "."
    if posixpath.basename(config_dir) == "config":
        base = posixpath.dirname(config_dir) or "."
    else:
        base = config_dir
    if base.startswith("/"):
        return base
    if base == ".":
        return LAB['ubuntu_def_dir'].rstrip("/")
    return posixpath.normpath(posixpath.join(LAB['ubuntu_def_dir'].rstrip("/"), base))

def remote_rrd_path() -> str:

    rrd_file = (
        os.environ.get("PATHS_RRD_FILE") or
        yaml_get(CONFIG_FILE, "paths", "rrd_file") or
        "db/dhcp_stats.rrd"
    )
    if rrd_file.startswith("/"):
        return rrd_file
    return posixpath.normpath(posixpath.join(remote_config_base_dir(), rrd_file))

def rrd_step_secs() -> int:

    raw = os.environ.get("RRD_STEP_SECS") or yaml_get(CONFIG_FILE, "rrd", "step_secs") or "10"
    try:
        value = int(raw)
    except ValueError:
        return 10
    return value if value > 0 else 10

def record_pre_attack_rrd_baseline() -> None:

    wait_secs = rrd_step_secs() + 2
    log(f"  recording pre-attack RRD baseline ({wait_secs}s)…")
    time.sleep(wait_secs)

def wait_for_post_pool_rrd_sample() -> None:

    wait_secs = rrd_step_secs() + 2
    log(f"  waiting {wait_secs}s for final RRD pool sample...")
    time.sleep(wait_secs)

def detector_privileged_run(cmd: str, **kw) -> tuple[int, str, str]:

    if RUNTIME['test_type'] == "docker":
        return detector_run(cmd, **kw)
    return detector_run(
        f"printf '%s\\n' {shlex.quote(LAB['ubuntu_pass'])} | "
        f"sudo -S -p '' sh -c {shlex.quote(cmd)}",
        **kw,
    )

def detector_epoch_secs() -> int:

    try:
        rc, out, _ = detector_run("date +%s", timeout=10, retries=1)
        if rc == 0:
            return int(out.strip().splitlines()[-1])
    except Exception:
        pass
    return int(time.time())

def prepare_rrd_for_test(name: str) -> None:

    rrd_path = remote_rrd_path()
    graph_paths = " ".join(shlex.quote(path) for path in remote_rrd_graph_paths(name))
    RUNTIME['rrd_start_times'][name] = detector_epoch_secs()
    RUNTIME['rrd_graph_collected'].discard(name)
    try:
        detector_privileged_run(
            f"mkdir -p {shlex.quote(posixpath.dirname(rrd_path) or '.')} && "
            f"rm -f {shlex.quote(rrd_path)} {shlex.quote(rrd_path + '.old')} "
            f"{graph_paths}",
            timeout=20,
            retries=1,
        )
    except Exception as exc:
        log(f"  [WARN] RRD cleanup before test failed: {exc}")

def rrd_graph_specs() -> list[dict[str, object]]:

    return [
        {
            "suffix": "traffic",
            "title": "DHCP traffic and adaptive baseline",
            "vertical_label": "window count",
            "extra": ["--units-exponent", "0"],
            "items": [
                f"DEF:disc={{rrd}}:discovers:AVERAGE",
                f"DEF:uniq={{rrd}}:unique_macs:AVERAGE",
                f"DEF:ema={{rrd}}:baseline_ema:AVERAGE",
                f"DEF:dev={{rrd}}:baseline_dev:AVERAGE",
                "LINE2:disc#1F77B4:discovers_window",
                "GPRINT:disc:LAST: last\\:%6.0lf",
                "GPRINT:disc:MAX: max\\:%6.0lf\\l",
                "LINE2:uniq#2CA02C:unique_macs_window",
                "GPRINT:uniq:LAST: last\\:%6.0lf",
                "GPRINT:uniq:MAX: max\\:%6.0lf\\l",
                "LINE2:ema#D62728:baseline_ema",
                "GPRINT:ema:LAST: last\\:%6.1lf\\l",
                "LINE2:dev#E377C2:baseline_dev",
                "GPRINT:dev:LAST: last\\:%6.1lf\\l",
            ],
        },
        {
            "suffix": "ratios",
            "title": "Ratios and percentages",
            "vertical_label": "percent",
            "extra": ["--upper-limit", "100", "--rigid"],
            "items": [
                f"DEF:la={{rrd}}:la_ratio:AVERAGE",
                f"DEF:pool_pct={{rrd}}:pool_usage_pct:AVERAGE",
                "CDEF:la_pct=la,100,*",
                "LINE2:la_pct#FF7F0E:la_ratio_pct",
                "GPRINT:la_pct:LAST: last\\:%6.1lf%%",
                "GPRINT:la_pct:MAX: max\\:%6.1lf%%\\l",
                "LINE2:pool_pct#17BECF:pool_usage_pct",
                "GPRINT:pool_pct:LAST: last\\:%6.1lf%%",
                "GPRINT:pool_pct:MAX: max\\:%6.1lf%%\\l",
            ],
        },
        {
            "suffix": "bucket",
            "title": "Leaky bucket",
            "vertical_label": "tokens",
            "extra": ["--units-exponent", "0"],
            "items": [
                f"DEF:bucket={{rrd}}:bucket_tokens:AVERAGE",
                f"DEF:bucket_cap={{rrd}}:bucket_capacity:AVERAGE",
                "LINE1:bucket_cap#7F7F7F:bucket_capacity",
                "GPRINT:bucket_cap:LAST: last\\:%6.0lf\\l",
                "LINE2:bucket#9467BD:bucket_tokens",
                "GPRINT:bucket:LAST: last\\:%6.0lf",
                "GPRINT:bucket:MIN: min\\:%6.0lf\\l",
            ],
        },
        {
            "suffix": "pool",
            "title": "DHCP pool leases",
            "vertical_label": "leases",
            "extra": ["--units-exponent", "0"],
            "items": [
                f"DEF:pool_used={{rrd}}:pool_used:MAX",
                f"DEF:pool_total={{rrd}}:pool_total:AVERAGE",
                "GPRINT:pool_total:LAST:pool_total last\\:%6.0lf\\l",
                "LINE2:pool_used#111111:pool_used",
                "GPRINT:pool_used:LAST: last\\:%6.0lf",
                "GPRINT:pool_used:MAX: max\\:%6.0lf\\l",
            ],
        },
        {
            "suffix": "pool-growth",
            "title": "DHCP pool lease growth",
            "vertical_label": "leases",
            "extra": ["--units-exponent", "0"],
            "items": [
                f"DEF:pool_growth={{rrd}}:pool_growth:MAX",
                "LINE2:pool_growth#BCBD22:pool_growth",
                "GPRINT:pool_growth:LAST: last\\:%6.0lf",
                "GPRINT:pool_growth:MAX: max\\:%6.0lf\\l",
            ],
        },
        {
            "suffix": "tte",
            "title": "Pool time-to-exhaustion projection",
            "vertical_label": "minutes",
            "extra": ["--units-exponent", "0"],
            "items": [
                f"DEF:tte={{rrd}}:pool_tte_secs:AVERAGE",
                "CDEF:tte_min=tte,60,/",
                "LINE2:tte_min#FFD700:pool_tte_min",
                "GPRINT:tte_min:LAST: last\\:%6.1lf",
                "GPRINT:tte_min:MAX: max\\:%6.1lf\\l",
                "COMMENT:pool_tte_min=0 means no current exhaustion projection\\l",
            ],
        },
    ]

def remote_rrd_graph_path(name: str, suffix: str) -> str:

    return remote_tmp(f"ct.{RUN_ID}.{name}.rrd-{suffix}.png")

def remote_rrd_graph_paths(name: str) -> list[str]:

    return [
        remote_rrd_graph_path(name, str(spec["suffix"]))
        for spec in rrd_graph_specs()
    ]

def rrd_graph_command(name: str, spec: dict[str, object], rrd_path: str,
                      graph_path: str, start_ts: int, end_ts: int) -> str:

    title = f"{name} - {spec['title']}"
    watermark = f"{RUN_ID} / {RUNTIME['test_type']}"
    args = [
        "rrdtool", "graph", graph_path,
        "--start", str(start_ts),
        "--end", str(end_ts),
        "--width", "1200",
        "--height", "420",
        "--title", title,
        "--vertical-label", str(spec["vertical_label"]),
        "--lower-limit", "0",
        "--alt-autoscale-max",
        "--slope-mode",
        "--watermark", watermark,
    ]
    args.extend(str(item) for item in spec.get("extra", []))
    args.extend(str(item).format(rrd=rrd_path) for item in spec["items"])
    return " ".join(shlex.quote(arg) for arg in args)

def fetch_remote_binary(vm: str, rpath: str, lpath: Path) -> None:

    lpath.parent.mkdir(parents=True, exist_ok=True)
    if RUNTIME['test_type'] == "docker":
        container = DOCKER_BY_ROLE.get(vm)
        if not container:
            raise RuntimeError(f"unknown Docker role: {vm}")
        proc = subprocess.run(
            ["docker", "cp", f"{container}:{rpath}", str(lpath)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise RuntimeError(detail or f"docker cp exit {proc.returncode}")
        return

    if vm not in ("ubuntu", "detector"):
        raise RuntimeError(f"binary fetch supports detector/ubuntu, got {vm}")
    _pool.get(LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'], rpath, lpath)

def collect_rrd_graph(name: str) -> None:

    if name in RUNTIME['rrd_graph_collected']:
        return
    out_dir = result_group_dir(name)
    note_path = out_dir / f"{name}.rrd-graph.txt"
    RUNTIME['rrd_graph_collected'].add(name)

    rrd_path = remote_rrd_path()
    step = rrd_step_secs()
    start_ts = RUNTIME['rrd_start_times'].get(name)
    if not start_ts:
        note_path.write_text("RRD graph not generated: detector was not started for this scenario.\n")
        return

    end_ts = detector_epoch_secs() + step
    start_ts = max(0, int(start_ts) - step)
    if end_ts <= start_ts + step:
        end_ts = start_ts + (step * 2)

    saved: list[str] = []
    failures: list[str] = []
    try:
        for spec in rrd_graph_specs():
            suffix = str(spec["suffix"])
            graph_path = remote_rrd_graph_path(name, suffix)
            local_graph = out_dir / f"{name}.rrd-{suffix}.png"
            try:
                rc, out, err = detector_privileged_run(
                    f"test -f {shlex.quote(rrd_path)} && "
                    f"{rrd_graph_command(name, spec, rrd_path, graph_path, start_ts, end_ts)} && "
                    f"chmod 0644 {shlex.quote(graph_path)}",
                    timeout=60,
                    retries=1,
                )
                if rc != 0:
                    detail = (err or out).strip()
                    raise RuntimeError(detail or f"rrdtool graph exit {rc}")
                fetch_remote_binary("detector", graph_path, local_graph)
                saved.append(local_graph.name)
            except Exception as exc:
                failures.append(f"{suffix}: {exc}")
        if saved:
            log(f"  [OK] RRD graphs saved: {', '.join(saved)}")
        if failures:
            note_path.write_text(
                "RRD graph generation had failures:\n" +
                "\n".join(f"- {failure}" for failure in failures) +
                "\n"
            )
            log(f"  [WARN] RRD graph generation incomplete: {len(failures)} failed")
        elif note_path.exists():
            try:
                note_path.unlink()
            except OSError:
                pass
    except Exception as exc:
        note_path.write_text(f"RRD graphs not generated: {exc}\n")
        log(f"  [WARN] RRD graphs not generated: {exc}")
    finally:
        try:
            graph_paths = " ".join(shlex.quote(path) for path in remote_rrd_graph_paths(name))
            detector_privileged_run(
                f"rm -f {graph_paths} "
                f"{shlex.quote(rrd_path)} {shlex.quote(rrd_path + '.old')}",
                timeout=20,
                retries=1,
            )
        except Exception:
            pass

# Update the whitelist for a specific test.
def push_whitelist(
    *,
    include_vm_legit_client: bool = True,
    exclude_macs: list[str] | tuple[str, ...] | set[str] = (),
) -> bool:

    remote_wl = runtime_whitelist_path()
    remote_dir = posixpath.dirname(remote_wl)
    tmp_wl = remote_tmp(f"ct.{RUN_ID}.whitelist_ct.txt")
    try:
        content = PATHS['local_whitelist_file'].read_text()
    except OSError as exc:
        log(f"  [FAIL] whitelist source read failed: {PATHS['local_whitelist_file']}: {exc}")
        return False

    if include_vm_legit_client:
        content = ensure_vm_legit_client_whitelisted(content)
    content = whitelist_content_without_macs(content, exclude_macs)

    if RUNTIME['test_type'] == "docker":
        try:
            docker_write(DOCKER['detector_container'], remote_wl, content)
            rc, out, err = detector_run(
                f"test -f {shlex.quote(remote_wl)} && wc -l < {shlex.quote(remote_wl)}",
                timeout=20,
            )
            if rc == 0:
                return True
            detail = (err or out).strip()
            log(f"  [FAIL] whitelist verify failed: {detail or f'exit {rc}'}")
            return False
        except Exception as exc:
            log(f"  [FAIL] whitelist push error: {exc}")
            return False

    try:
        _pool.write_remote(LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'], tmp_wl, content)
        install_cmd = (
            f"mkdir -p {shlex.quote(remote_dir)} && "
            f"cat {shlex.quote(tmp_wl)} > {shlex.quote(remote_wl)} && "
            f"chmod 0644 {shlex.quote(remote_wl)} && "
            f"rm -f {shlex.quote(tmp_wl)}"
        )
        rc, out, err = detector_run(
            f"printf '%s\\n' {shlex.quote(LAB['ubuntu_pass'])} | "
            f"sudo -S -p '' sh -c {shlex.quote(install_cmd)}",
            timeout=20,
        )
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] whitelist install failed: {detail or f'exit {rc}'}")
            return False
        verify_cmd = f"test -f {shlex.quote(remote_wl)} && wc -l < {shlex.quote(remote_wl)}"
        rc, out, err = detector_run(verify_cmd, timeout=20)
        if rc == 0:
            return True
        detail = (err or out).strip()
        log(f"  [FAIL] whitelist verify failed: {detail or f'exit {rc}'}")
        return False
    except Exception as exc:
        log(f"  [FAIL] whitelist push error: {exc}")
        return False

# Start the detector/defense process.
def start_defense(
    name: str,
    *,
    include_vm_legit_client: bool = True,
    exclude_whitelist_macs: list[str] | tuple[str, ...] | set[str] = (),
) -> bool:

    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    prepare_rrd_for_test(name)
    if not push_whitelist(
        include_vm_legit_client=include_vm_legit_client,
        exclude_macs=exclude_whitelist_macs,
    ):
        log("  [FAIL] whitelist push failed")
        return False
    config_arg = PATHS['remote_config_path']
    if RUNTIME['test_type'] == "docker":
        try:
            env_args = detector_env_args(detector_start_env())
            cmd = (
                "pkill -x dhcp_starvation_detector >/dev/null 2>&1 || true; "
                f"cd {shlex.quote(LAB['ubuntu_def_dir'])} && "
                f"nohup env {env_args} "
                f"{shlex.quote(posixpath.join(LAB['ubuntu_bin_dir'], 'dhcp_starvation_detector'))} "
                f"{shlex.quote(config_arg)} "
                f"> {shlex.quote(def_log)} 2>&1 & echo $!"
            )
            rc, out, _ = detector_run(cmd, timeout=30)
            if rc != 0:
                log(f"  [FAIL] defense start command failed: exit {rc}")
                return False
            last_line = (out.strip().splitlines() or [""])[-1].strip()
            if not re.fullmatch(r"[0-9]+", last_line):
                log("  [FAIL] defense PID not obtained")
                return False
            RUNTIME['current_defense_pid'] = last_line
            time.sleep(3)
            return True
        except Exception as exc:
            log(f"  [FAIL] defense start error: {exc}")
            return False

    # Map the active lab role settings to Docker containers and paths.
    try:
        env_args = detector_env_args(detector_start_env())
        start_cmd = (
            f"cd {shlex.quote(LAB['ubuntu_def_dir'])} && "
            f"nohup env {env_args} "
            f"{shlex.quote(posixpath.join(LAB['ubuntu_bin_dir'], 'dhcp_starvation_detector'))} "
            f"{shlex.quote(config_arg)} "
            f"> {shlex.quote(def_log)} 2>&1 & echo $!"
        )
        rc, out, _ = detector_run(
            f"printf '%s\\n' {shlex.quote(LAB['ubuntu_pass'])} | "
            "sudo -S -p '' pkill -x dhcp_starvation_detector >/dev/null 2>&1 || true; "
            f"printf '%s\\n' {shlex.quote(LAB['ubuntu_pass'])} | "
            f"sudo -S -p '' sh -c {shlex.quote(start_cmd)}",
            timeout=30,
        )
        if rc != 0:
            log(f"  [FAIL] defense start command failed: exit {rc}")
            return False
        last_line = (out.strip().splitlines() or [""])[-1].strip()
        if not re.fullmatch(r"[0-9]+", last_line):
            log("  [FAIL] defense PID not obtained")
            return False
        RUNTIME['current_defense_pid'] = last_line
        time.sleep(3)
        return True
    except Exception as exc:
        log(f"  [FAIL] defense start error: {exc}")
        return False

def result_group(name: str) -> str:
    if len(name) >= 2 and name[0] == "S" and name[1] in "ABCDEFGHIJK":
        return name[1]
    if name and name[0] in "ABCDEFGHIJK":
        return name[0]
    return "misc"

def result_group_dir(name: str) -> Path:
    group_dir = RESULT_DIR / result_group(name)
    group_dir.mkdir(parents=True, exist_ok=True)
    return group_dir

# Reproduce the fixed MAC used by the attacker in the repeated-request phase. Mirrors the attack script random_mac() logic.
def mac_from_seed(seed: int, la: str) -> str:

    rng = random.Random(seed)
    r = rng.randint(0, 255)
    if la == "on":
        first = (r & 0xFE) | 0x02
    elif la == "off":
        first = r & 0xFC
    else:
        first = (r & 0xFE) | 0x02 if rng.randint(0, 1) else (r & 0xFC)
    rest = [rng.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first] + rest)

def defense_log_has_attack_feature(name: str, feature: str) -> bool:

    feature = feature.lower()
    if feature not in {"f4", "f5", "f6"}:
        raise ValueError(f"unknown attack feature: {feature}")
    try:
        content = (result_group_dir(name) / f"{name}.defense.log").read_text(errors="replace")
    except OSError:
        return False
    return re.search(rf"\b{feature}=1\b.*\*\*\* ATTACK \*\*\*", content) is not None

def stop_defense(name: str = "") -> None:

    if RUNTIME['test_type'] == "docker":
        if RUNTIME['current_defense_pid']:
            try:
                detector_run(f"kill '{RUNTIME['current_defense_pid']}' >/dev/null 2>&1 || true")
            except Exception:
                pass
            time.sleep(2)
        kill_remote_defense()
        RUNTIME['current_defense_pid'] = ""
        return

    # VM section.
    if RUNTIME['current_defense_pid']:
        try:
            detector_run(
                f"printf '%s\\n' '{LAB['ubuntu_pass']}' | sudo -S -p '' "
                f"kill '{RUNTIME['current_defense_pid']}' >/dev/null 2>&1 || true"
            )
        except Exception:
            pass
        time.sleep(2)
    kill_remote_defense()
    RUNTIME['current_defense_pid'] = ""

def legit_client_current_ip() -> str:
    
    lease = legit_client_lease_on_router()
    if lease:
        parts = lease.split()
        if len(parts) >= 3:
            return parts[2]
    try:
        iface = shlex.quote(LAB['debian_iface'])
        _, out, _ = client_run(
            f"ip -4 addr show dev {iface} scope global 2>/dev/null"
            r" | awk '/inet /{split($2,a,\"/\"); print a[1]}' | head -1"
        )
        return out.strip()
    except Exception:
        return ""

def wait_for_legit_client(name: str, timeout: int) -> bool:
    
    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    elapsed = 0
    while elapsed < timeout:
        lease = legit_client_lease_on_router()
        if lease:
            parts = lease.split()
            if len(parts) >= 3 and parts[2].startswith(DHCP_LAB['ipv4_prefix']):
                RUNTIME['debian_lease_ip'] = parts[2]
                return True
        if RUNTIME['debian_mac']:
            reputation_msg = shlex.quote(f"reputation: confirmed {RUNTIME['debian_mac']}")
            if detector_ok(
                f"grep -qi {reputation_msg} "
                f"{shlex.quote(def_log)} 2>/dev/null"
            ):
                return True
        time.sleep(4)
        elapsed += 4
    return False

def wait_for_whitelist_applied(name: str, timeout: int = 30) -> bool:
    
    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    elapsed = 0
    while elapsed < timeout:
        if detector_ok(
            f"grep -q 'netconf_action: edit-config OK' "
            f"{shlex.quote(def_log)} 2>/dev/null"
        ):
            return True
        time.sleep(1)
        elapsed += 1
    return False

def wait_for_attack_detected(name: str, timeout: int, attack_name: str | None = None) -> bool:
    
    def_log = remote_tmp(f"ct.{RUN_ID}.{name}.defense.log")
    status_name = attack_name or name
    elapsed = 0
    while elapsed < timeout:
        if attack_status_failed(status_name):
            return False
        if detector_ok(
            f"grep -qE '\\*\\*\\* ATTACK \\*\\*\\*|ATTACK detected' "
            f"{shlex.quote(def_log)} 2>/dev/null"
        ):
            return True
        time.sleep(3)
        elapsed += 3
    return False

# Get router state to be saved in logs files.
def collect_router_state(name: str) -> None:
    out_dir = result_group_dir(name)
    lease_path = out_dir / f"{name}.router.leases"
    fetch_remote("router", DHCP_LAB['router_lease_file'], lease_path)
    try:
        if RUNTIME['test_type'] == "docker":
            if DOCKER['dhcp_type'] == "isc":
                _, out, _ = router_run(
                    "grep -q '^deny unknown-clients;$' "
                    "/etc/dhcp/dhcpd.whitelist-policy.conf 2>/dev/null"
                    " && echo whitelist-on || echo whitelist-off"
                )
            else:
                _, out, _ = router_run(
                    "grep -q '^dhcp-ignore=tag:!known$' /etc/dnsmasq.d/whitelist.conf 2>/dev/null"
                    " && echo whitelist-on || echo whitelist-off"
                )
        else:
            _, out, _ = router_run(
                "grep -q '^dhcp-ignore=tag:!known$' /etc/dnsmasq.conf 2>/dev/null"
                " && echo whitelist-on || echo whitelist-off"
            )
        (out_dir / f"{name}.whitelist-state.txt").write_text(out)
    except Exception:
        pass
    lease = legit_client_lease_on_router()
    if lease:
        (out_dir / f"{name}.client.lease.txt").write_text(lease + "\n")

# Get a remote file in VM o Docker, used for collecting leases and defense logs.
def fetch_remote(vm: str, rpath: str, lpath: Path) -> None:
    try:
        lpath.parent.mkdir(parents=True, exist_ok=True)
        cmd = f"cat {shlex.quote(rpath)} 2>/dev/null || true"
        if vm == "ubuntu":
            _, out, _ = detector_run(cmd)
        elif vm == "kali":
            _, out, _ = attacker_run(cmd)
        elif vm in ("client", "debian"):
            _, out, _ = client_run(cmd)
        elif vm == "router":
            _, out, _ = router_run(cmd)
        else:
            return
        lpath.write_text(out, errors="replace")
    except Exception:
        try:
            lpath.parent.mkdir(parents=True, exist_ok=True)
            lpath.write_text(f"[fetch error] could not fetch {vm}:{rpath}\n")
        except Exception:
            pass

# Get remote logs files.
def collect_logs(name: str) -> None:
    
    out_dir = result_group_dir(name)
    collect_rrd_graph(name)
    fetch_remote("ubuntu", remote_tmp(f"ct.{RUN_ID}.{name}.defense.log"),
                 out_dir / f"{name}.defense.log")
    fetch_remote("kali",   remote_tmp(f"ct.{RUN_ID}.{name}.attack.log"),
                 out_dir / f"{name}.attack.log")
    if not (out_dir / f"{name}.router.leases").exists():
        collect_router_state(name)
    fetch_remote("client",
                 f"{LAB['debian_log_dir']}/{RUN_ID}.{name}.client.log",
                 out_dir / f"{name}.client.log")

def ip_in_dhcp_pool(ip: str) -> bool:

    if not ip.startswith(DHCP_LAB['ipv4_prefix']):
        return False
    try:
        host = int(ip.rsplit(".", 1)[1])
    except (IndexError, ValueError):
        return False
    return DHCP_LAB['pool_start_host'] <= host < DHCP_LAB['pool_start_host'] + RUNTIME['pool_total']

# Has the legit client obtained a lease on the router? Check on client.
def legit_client_pool_ip() -> str:
    
    try:
        iface = shlex.quote(LAB['debian_iface'])
        _, out, _ = client_run(
            f"ip -4 -o addr show dev {iface} scope global 2>/dev/null "
            "| awk '{split($4,a,\"/\"); print a[1]}'"
        )
        for ip in out.strip().splitlines():
            ip = ip.strip()
            if ip_in_dhcp_pool(ip):
                return ip
    except Exception:
        pass
    return ""

def router_active_leases_cmd() -> str:

    lease_file = shlex.quote(DHCP_LAB['router_lease_file'])
    if RUNTIME['test_type'] == "docker" and DOCKER['dhcp_type'] == "isc":
        return (
            "awk '"
            "/^lease[[:space:]]+[0-9.]+[[:space:]]*[{]/ "
            "{inlease=1; ip=$2; mac=\"\"; state=\"\"; next} "
            "inlease && $1==\"hardware\" && $2==\"ethernet\" "
            "{mac=tolower($3); sub(/;$/, \"\", mac); next} "
            "inlease && $1==\"binding\" && $2==\"state\" "
            "{state=$3; sub(/;$/, \"\", state); next} "
            "inlease && /^}/ "
            "{if (state==\"active\" && mac!=\"\") active[ip]=mac; "
            "else delete active[ip]; inlease=0; ip=\"\"; mac=\"\"; state=\"\"; next} "
            "END {for (ip in active) print \"0 \" active[ip] \" \" ip \" * *\"}' "
            f"{lease_file} 2>/dev/null | sort -k3"
        )
    return f"cat {lease_file} 2>/dev/null"

# Has the legit client obtained a lease on the router? Check on router.
def legit_client_lease_on_router() -> str:

    if not RUNTIME['debian_mac']:
        return ""
    try:
        _, out, _ = router_run(
            f"{router_active_leases_cmd()} | "
            f"awk -v mac={shlex.quote(RUNTIME['debian_mac'])} "
            "'tolower($2)==tolower(mac){print; exit}'"
        )
        return out.strip()
    except Exception:
        return ""

# Count tests results.
def mark(name: str, ok: bool, details: str) -> None:
    RUNTIME['total_count'] += 1
    if ok:
        RUNTIME['pass_count'] += 1
        log(f"  [PASS] {name}: {details}")
    else:
        RUNTIME['fail_count'] += 1
        log(f"  [FAIL] {details}")

# Core function for each test.
# A general implementation for all tests, “reset env → defense → attack → wait detection → legit client check → pool check → verdict”.
def _run_case_impl(
    name: str, scenario: str, la: str,
    count: int, delay: float, seed: int,
    detect_timeout: int = None,
    legit_timeout: int = None,
    expect_detect: bool = True,
    check_attacker_rep: bool = False,
    require_f6: bool = False,
    require_f4: bool = False,
    require_f5: bool = False,
    require_whitelist: bool = False,
    expect_silent: bool = False,
) -> None:
    

    if detect_timeout is None:
        detect_timeout = SUITE['detect_timeout_burst']
    if legit_timeout is None:
        legit_timeout = SUITE['legit_timeout']

    RUNTIME['current_test'] = name
    RUNTIME['current_defense_pid'] = ""
    RUNTIME['current_attack_pid'] = ""
    RUNTIME['debian_lease_ip'] = ""
    detected = pool_ok = legit_ok = False
    f6_ok = True
    f4_ok = True
    f5_ok = True
    whitelist_ok = True
    used = 0

    log()
    log(f"── {ts()}  {name} ──────────────────────────────────────────")
    log(f"  scenario={scenario}  la-bit={la}  count={count}  delay (between each count request)={delay}s  seed={seed}")
    if not expect_detect:
        log("  (control case: detection not required)")
    if expect_silent:
        log("  (silent control: detection must stay silent)")

    log()

    cleanup_all()
    reset_router()
    time.sleep(1)

    if not resolve_client_ip():
        log("  [WARN] legit client unreachable before test — legit check will likely fail")

    # Check that the legit client doesn't already have a lease before starting the attack, which could interfere with the test logic. 
    if expect_detect:
        pre_attack_lease = legit_client_lease_on_router()
        pre_attack_ip = legit_client_pool_ip()
        if pre_attack_lease or pre_attack_ip:
            detail = pre_attack_lease or f"client still has pool IP {pre_attack_ip}"
            log(f"  [FAIL] legit client lease exists before attack: {detail}")
            kill_remote_attack(); kill_client_loop(); stop_defense(name)
            collect_logs(name)
            reset_router()
            mark(name, False, "legit_client_pre_attack_lease_present")
            return
        else:
            log(f"  [{ts()}] [OK] legit client has no router lease before attack")

    if not start_defense(name):
        kill_remote_attack(); kill_client_loop(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "defense_start_failed")
        return

    record_pre_attack_rrd_baseline()

    if not start_attack(name, scenario, la, count, delay, seed):
        kill_remote_attack(); kill_client_loop(); stop_defense(name)
        collect_logs(name)
        reset_router()
        mark(name, False, "attack_start_failed")
        return

    log("  attack running…")

    if wait_for_attack_detected(name, detect_timeout):
        detected = True
        if expect_detect:
            log(f"  [{ts()}] [OK] ATTACK DETECTED")
        elif expect_silent:
            log(f"  [{ts()}] [FAIL] unexpected attack detection in silent control")
        else:
            log(f"  [{ts()}] [WARN] attack detected in control case; detection is informational")
    else:
        if expect_detect:
            log(f"  [{ts()}] [FAIL] attack NOT detected within {detect_timeout}s")
        else:
            log(f"  [{ts()}] [OK] attack NOT detected within {detect_timeout}s")

    if expect_detect:
        if detected:
            whitelist_ok = wait_for_whitelist_applied(name)
            if whitelist_ok:
                log(f"  [{ts()}] [OK] whitelist-only mode applied")
            elif require_whitelist:
                log("  [FAIL] whitelist-only apply confirmation not seen before legit client start")
            else:
                log("  [WARN] whitelist-only apply confirmation not seen before legit client start")
            if require_whitelist and not whitelist_ok:
                kill_remote_attack()
            else:
                if not start_client_loop(name):
                    log("  [FAIL] legit client loop start failed")
                else:
                    log("  checking legitimate client access…")
                    if wait_for_legit_client(name, legit_timeout):
                        legit_ok = True
                        log(f"  [{ts()}] [OK] legit client access verified ({RUNTIME['debian_lease_ip'] or LAB['debian_ip']})")
                    else:
                        log(f"  [{ts()}] [FAIL] legit client lease/reputation confirmation NOT found within {legit_timeout}s")
        else:
            ip = legit_client_current_ip()
            if ip.startswith(DHCP_LAB['ipv4_prefix']):
                legit_ok = True
                log(f"  [{ts()}] [OK] legit client has IP {ip} (no whitelist enforced)")

    time.sleep(SUITE['post_detect_secs'])
    attack_status_failed(name)
    kill_remote_attack()
    kill_client_loop()

    used = pool_used()
    pool_ok = used < RUNTIME['pool_limit']
    if pool_ok:
        log(f"  [{ts()}] [OK] DHCP router pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")
    else:
        log(f"  [{ts()}] [FAIL] DHCP router pool used = {used} / {RUNTIME['pool_total']} (limit={RUNTIME['pool_limit']})")

    wait_for_post_pool_rrd_sample()
    collect_router_state(name)
    stop_defense(name)
    collect_logs(name)
    reset_router()

    # Some attacks requires specifc features to be triggered.
    if require_f6:
        f6_ok = defense_log_has_attack_feature(name, "f6")
        if f6_ok:
            log(f"  [{ts()}] [OK] detection feature verified: F6 pool pressure")
        else:
            log("  [FAIL] detection feature did not show f6=1 during attack")

    if require_f4:
        f4_ok = defense_log_has_attack_feature(name, "f4")
        if f4_ok:
            log(f"  [{ts()}] [OK] detection feature verified: F4 adaptive baseline")
        else:
            log("  [FAIL] detection feature did not show f4=1 during attack")

    if require_f5:
        f5_ok = defense_log_has_attack_feature(name, "f5")
        if f5_ok:
            log(f"  [{ts()}] [OK] detection feature verified: F5 LA-bit ratio")
        else:
            log("  [FAIL] detection feature did not show f5=1 during attack")

    # Scenario-specific check: verify attacker MAC was NOT promoted to whitelist/ready state.
    # Enabled by burst_then_same_flat tests: after the trigger burst, one fixed seed MAC
    # sends slow DHCP attempts hoping to appear legitimate; reputation must reject it.
    attacker_rep_ok = True
    if check_attacker_rep:
        atk_mac = mac_from_seed(seed, la)
        def_log_local = result_group_dir(name) / f"{name}.defense.log"
        try:
            content = def_log_local.read_text(errors="replace").lower()
            promoted = re.search(
                rf"{re.escape(atk_mac)}\s+(ready|temp-whitelist)|"
                rf"temporary whitelist entry {re.escape(atk_mac)}",
                content,
            )
            if promoted:
                attacker_rep_ok = False
                log(f"  [FAIL] attacker MAC {atk_mac} was incorrectly promoted by reputation")
            else:
                log(f"  [{ts()}] [OK] attacker MAC {atk_mac} not promoted by reputation system")
        except Exception:
            log(f"  [WARN] could not read defense log to check attacker reputation ({atk_mac})")

    attack_ok = not RUNTIME['attack_failed']

    if expect_detect:
        if detected and pool_ok and legit_ok and attacker_rep_ok and f6_ok and f4_ok and f5_ok and whitelist_ok and attack_ok:
            extras = []
            if check_attacker_rep:
                extras.append("attacker_rep=ok")
            if require_whitelist:
                extras.append("whitelist=ok")
            if require_f6:
                extras.append("f6=ok")
            if require_f4:
                extras.append("f4=ok")
            if require_f5:
                extras.append("f5=ok")
            extra = f"  {'  '.join(extras)}" if extras else ""
            mark(name, True,  f"detected=yes  pool={used}/{RUNTIME['pool_total']}  legit=yes{extra}")
        else:
            extras = []
            if not attack_ok:
                extras.append("attack_failed=1")
            if check_attacker_rep:
                extras.append(f"attacker_rep={int(attacker_rep_ok)}")
            if require_whitelist:
                extras.append(f"whitelist={int(whitelist_ok)}")
            if require_f6:
                extras.append(f"f6={int(f6_ok)}")
            if require_f4:
                extras.append(f"f4={int(f4_ok)}")
            if require_f5:
                extras.append(f"f5={int(f5_ok)}")
            extra = f"  {'  '.join(extras)}" if extras else ""
            mark(name, False,
                 f"detected={int(detected)}  pool_ok={int(pool_ok)}({used}/{RUNTIME['pool_total']})"
                 f"  legit={int(legit_ok)}{extra}")
    else:
        if pool_ok and attack_ok and (not expect_silent or not detected):
            if expect_silent:
                mark(name, True,  f"silent control: pool={used}/{RUNTIME['pool_total']}  detected=no")
            else:
                mark(name, True,  f"control: pool={used}/{RUNTIME['pool_total']}  detected(informational)={int(detected)}")
        else:
            if not attack_ok:
                mark(name, False, f"control: attack_failed=1  pool={used}/{RUNTIME['pool_total']}")
            elif not pool_ok:
                mark(name, False, f"control: pool EXHAUSTED {used}/{RUNTIME['pool_total']}")
            else:
                mark(name, False, f"silent control: unexpected detection  pool={used}/{RUNTIME['pool_total']}")

def run_case(
    name: str, scenario: str, la: str,
    count: int, delay: float, seed: int,
    detect_timeout: int = None,
    legit_timeout: int = None,
    expect_detect: bool = True,
    check_attacker_rep: bool = False,
    require_f6: bool = False,
    require_f4: bool = False,
    require_f5: bool = False,
    require_whitelist: bool = False,
    expect_silent: bool = False,
) -> None:
    
    try:
        _run_case_impl(
            name, scenario, la, count, delay, seed,
            detect_timeout, legit_timeout, expect_detect,
            check_attacker_rep, require_f6, require_f4, require_f5,
            require_whitelist, expect_silent,
        )
    except Exception as exc:
        log(f"  [FAIL] unexpected test error: {exc}")
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            collect_logs(name)
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass
        mark(name, False, f"unexpected_error={type(exc).__name__}")

def run_group_a() -> None:

    log()
    log("════════ GROUP A: Unique-MAC bursts ════════════════════════════════")
    log("  A1-A4 send no-wait unique-MAC DISCOVER bursts: 90, 90, 90, then 160.")
    log("  Expected path: F2 unique-MAC window + F3 leaky bucket; LA=on cases must show F5.")
    log("  A5 sends 30 no-wait DISCOVERs as a sub-threshold control: pool must stay healthy; detection is informational.")

    run_case("A1_burst_unique_la_on",    "burst_unique", "on",    90,  0.0, 1001, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True, require_f5=True)
    run_case("A2_burst_unique_la_off",   "burst_unique", "off",   90,  0.0, 1101, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True)
    run_case("A3_burst_unique_la_mixed", "burst_unique", "mixed", 90,  0.0, 1201, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True)
    run_case("A4_large_burst_la_on",     "burst_unique", "on",    160, 0.0, 1301, SUITE['detect_timeout_burst'], SUITE['legit_timeout'], True, require_f5=True)
    run_case("A5_small_burst_la_on",     "burst_unique", "on",    30,  0.0, 1401, 45, 0, False)

def check_vm_deps() -> None:

    log("Checking VM dependencies…")

    if paramiko is None:
        log("  [FAIL] Host Python package 'paramiko' not installed (required for --env-type vms)")
        sys.exit(1)
    host_sync = subprocess.run(
        ["sh", "-c", "command -v find >/dev/null 2>&1 && command -v tar >/dev/null 2>&1"],
        capture_output=True,
        text=True,
    )
    if host_sync.returncode != 0:
        log("  [FAIL] Host sync tools missing: find or tar")
        sys.exit(1)
    log("  [OK] Host VM control deps: paramiko + find + tar")

    if not detector_ok("command -v gcc >/dev/null 2>&1"):
        log("  [FAIL] Ubuntu: gcc not found"); sys.exit(1)
    if not detector_ok("command -v make >/dev/null 2>&1"):
        log("  [FAIL] Ubuntu: make not found"); sys.exit(1)
    ubuntu_dep_groups = [
        ("libpcap-dev", ["libpcap-dev"]),
        ("rrdtool", ["rrdtool"]),
        ("libnetconf2-dev", ["libnetconf2-dev"]),
        ("libyang-dev/libyang2-dev", ["libyang-dev", "libyang2-dev"]),
        ("libssh-dev", ["libssh-dev"]),
    ]
    for label, packages in ubuntu_dep_groups:
        checks = " || ".join(
            f"dpkg -l '{package}' 2>/dev/null | grep -q '^ii'"
            for package in packages
        )
        if not detector_ok(f"{{ {checks}; }}"):
            log(f"  [FAIL] Ubuntu: package '{label}' not installed"); sys.exit(1)
    yang_dir = (
        os.environ.get("NETCONF_YANG_DIR") or
        yaml_get(CONFIG_FILE, "netconf", "yang_dir") or
        "/usr/share/yang/modules/libnetconf2"
    )
    if not detector_ok(
        f"test -d {shlex.quote(yang_dir)} && "
        f"find {shlex.quote(yang_dir)} -name 'ietf-netconf@*.yang' -print -quit 2>/dev/null | "
        "grep -q ."
    ):
        log(f"  [FAIL] Ubuntu: ietf-netconf YANG module not found under {yang_dir}"); sys.exit(1)
    log("  [OK] Ubuntu build/runtime deps: gcc + make + libpcap-dev + rrdtool + libnetconf2-dev + libyang-dev/libyang2-dev + libssh-dev + ietf-netconf YANG modules")
    if not detector_ok(
        "command -v sudo >/dev/null 2>&1 && "
        "command -v pkill >/dev/null 2>&1 && "
        "command -v tar >/dev/null 2>&1 && "
        "command -v find >/dev/null 2>&1 && "
        "command -v touch >/dev/null 2>&1"
    ):
        log("  [FAIL] Ubuntu: sudo, pkill, tar, find or touch not found"); sys.exit(1)
    log("  [OK] Ubuntu detector control/sync tools: sudo + pkill + tar + find + touch")

    if not attacker_ok("command -v python3 >/dev/null 2>&1"):
        log("  [FAIL] Kali: python3 not found"); sys.exit(1)
    if not attacker_ok("python3 -c 'import scapy.all' 2>/dev/null"):
        log("  [FAIL] Kali: scapy not available (pip install scapy)"); sys.exit(1)
    if not attacker_ok("python3 -c 'import ctypes.util, sys; sys.exit(0 if ctypes.util.find_library(\"pcap\") else 1)' 2>/dev/null"):
        log("  [FAIL] Kali: libpcap runtime not found"); sys.exit(1)
    if not attacker_ok("command -v ip >/dev/null 2>&1"):
        log("  [FAIL] Kali: ip command not found (install iproute2)"); sys.exit(1)
    if not attacker_ok("command -v sudo >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1"):
        log("  [FAIL] Kali: sudo or pkill not found"); sys.exit(1)
    if not attacker_ok("command -v yersinia >/dev/null 2>&1"):
        log("  [FAIL] Kali: yersinia not found"); sys.exit(1)
    log("  [OK] Kali: python3 + scapy + libpcap runtime + ip + sudo + pkill + yersinia")

    if not client_ok(
        "{ [ -x /sbin/dhcpcd ] || [ -x /usr/sbin/dhcpcd ]; } && "
        "command -v ip >/dev/null 2>&1 && "
        "command -v awk >/dev/null 2>&1 && "
        "command -v pkill >/dev/null 2>&1 && "
        "command -v su >/dev/null 2>&1 && "
        "command -v tar >/dev/null 2>&1"
    ):
        log("  [FAIL] Debian: dhcpcd, ip, awk, pkill, su or tar not found"); sys.exit(1)
    log("  [OK] Debian: dhcpcd + ip + awk + pkill + su + tar")

    if not router_ok(
        "command -v dnsmasq >/dev/null 2>&1 && "
        "test -x /etc/init.d/dnsmasq && "
        "command -v uci >/dev/null 2>&1 && "
        "command -v sed >/dev/null 2>&1 && "
        "command -v awk >/dev/null 2>&1 && "
        "command -v grep >/dev/null 2>&1 && "
        "command -v wc >/dev/null 2>&1 && "
        "command -v tr >/dev/null 2>&1 && "
        "command -v head >/dev/null 2>&1 && "
        "command -v sort >/dev/null 2>&1 && "
        "{ command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; } && "
        "grep -q '^Port 830$' /etc/ssh/sshd_config && "
        "grep -q '^Subsystem netconf ' /etc/ssh/sshd_config"
    ):
        log("  [FAIL] OpenWrt: dnsmasq, dnsmasq init, uci, sed, awk, grep, wc, tr, head, sort or NETCONF-over-SSH subsystem missing"); sys.exit(1)
    log("  [OK] OpenWrt: dnsmasq + dnsmasq init + uci + sed + awk + grep + wc + tr + head + sort + NETCONF-over-SSH subsystem")

# Get total pool size by asking the detector to query the router via NETCONF.
def router_pool_total(default: int) -> int:

    try:
        rc, out, err = run_detector_router_message("pool", timeout=30)
        if rc != 0:
            raise RuntimeError((err or out).strip() or f"dhcp_starvation_detector pool exit {rc}")
        match = re.search(r"\btotal=([0-9]+)\b", out)
        if not match:
            raise RuntimeError("pool total not found in detector output")
        total = clean_num(match.group(1))
        return total or default
    except Exception as exc:
        log(f"  [WARN] pool size via dhcp_starvation_detector failed: {exc}")
        return default

# Build a remote path inside the remote tmp directory.
def remote_tmp(name: str) -> str:
    return posixpath.join(PATHS['remote_tmp_dir'], name)

def docker_put(container: str, local: Path, remote: str) -> None:

    data = local.read_bytes()
    rc, out, err = docker_exec(
        container,
        f"mkdir -p {shlex.quote(posixpath.dirname(remote) or '/')} && "
        f"cat > {shlex.quote(remote)}",
        stdin_data=data,
        timeout=30,
        retries=1,
    )
    if rc != 0:
        detail = (err or out).strip()
        raise RuntimeError(f"docker copy into {container}:{remote} failed: {detail or f'exit {rc}'}")

def docker_copy_dir_contents(container: str, local_dir: Path, remote_dir: str,
                             timeout: int = 120) -> None:
    
    if not local_dir.is_dir():
        raise RuntimeError(f"local directory not found: {local_dir}")

    rc, out, err = docker_exec(
        container,
        f"mkdir -p {shlex.quote(remote_dir)}",
        timeout=30,
        retries=1,
    )
    if rc != 0:
        detail = (err or out).strip()
        raise RuntimeError(f"mkdir failed for {container}:{remote_dir}: {detail or f'exit {rc}'}")

    proc = subprocess.run(
        ["docker", "cp", f"{local_dir}/.", f"{container}:{remote_dir}"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(f"docker copy into {container}:{remote_dir} failed: {detail or f'exit {proc.returncode}'}")

# Sync code from the current workspace to the VMs or Docker lab, so the latest code is used.
def sync_code() -> None:

    if RUNTIME['test_type'] == "docker":

        log("Syncing code to Docker lab…")

        docker_dnsmasq_handler = PATHS['local_defense_dir'] / "netconf_action/netconf-handler-dnsmasq.sh"
        docker_isc_handler = PATHS['local_defense_dir'] / "netconf_action/netconf-handler-isc.sh"
        required_files = [
            ("selected config", CONFIG_FILE),
            ("db/whitelist.txt", PATHS['local_whitelist_file']),
            ("attack script", PATHS['local_attack_script']),
            ("legit DHCP client script", PATHS['local_legit_dhcp_client_script']),
            ("dnsmasq netconf handler", docker_dnsmasq_handler),
            ("ISC netconf handler", docker_isc_handler),
        ]
        if not PATHS['local_defense_dir'].is_dir():
            log(f"  [FAIL] detector source directory not found: {PATHS['local_defense_dir']}")
            sys.exit(1)
        for label, path in required_files:
            if not path.is_file():
                log(f"  [FAIL] {label} not found: {path}")
                sys.exit(1)

        try:
            detector_root_q = shlex.quote(DOCKER['detector_dir'])
            rc, out, err = detector_run(
                f"mkdir -p {detector_root_q} && "
                f"find {detector_root_q} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +",
                timeout=30,
            )
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] prepare Docker detector source dir: {detail or f'exit {rc}'}")
                sys.exit(1)
            docker_copy_dir_contents(
                DOCKER['detector_container'],
                PATHS['local_defense_dir'],
                DOCKER['detector_dir'],
            )
            log(f"  [OK] detector source → Docker detector:{DOCKER['detector_dir']}")

            rc, out, err = detector_run(
                f"cd {detector_root_q} && "
                f"rm -rf {shlex.quote(DOCKER['detector_bin_dir'])} && "
                f"mkdir -p {shlex.quote(DOCKER['detector_bin_dir'])} && "
                f"make all BINDIR={shlex.quote(DOCKER['detector_bin_dir'])} && "
                f"test -x {shlex.quote(posixpath.join(DOCKER['detector_bin_dir'], 'dhcp_starvation_detector'))}",
                timeout=180,
            )
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] detector build → Docker detector: {detail or f'exit {rc}'}")
                sys.exit(1)
            log(f"  [OK] detector built inside Docker detector:{DOCKER['detector_bin_dir']}")

            docker_put(
                DOCKER['detector_container'],
                CONFIG_FILE,
                posixpath.join(DOCKER['detector_dir'], PATHS['remote_config_path']),
            )
            log(f"  [OK] config {CONFIG_FILE} → Docker detector:{DOCKER['detector_dir']}/{PATHS['remote_config_path']}")

            docker_put(
                DOCKER['detector_container'],
                PATHS['local_whitelist_file'],
                posixpath.join(DOCKER['detector_dir'], "db/whitelist.txt"),
            )
            log(f"  [OK] whitelist.txt → Docker detector:{DOCKER['detector_dir']}/db/whitelist.txt")

            docker_put(DOCKER['attacker_container'], PATHS['local_attack_script'], DOCKER['attack_script'])
            rc, out, err = attacker_run(f"chmod +x {shlex.quote(DOCKER['attack_script'])}", timeout=10)
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] attack script chmod → Docker attacker: {detail or f'exit {rc}'}")
                sys.exit(1)
            log(f"  [OK] attack script → Docker attacker:{DOCKER['attack_script']}")

            docker_put(DOCKER['client_container'], PATHS['local_legit_dhcp_client_script'], DOCKER['legit_dhcp_client_path'])
            rc, out, err = client_run(f"chmod +x {shlex.quote(DOCKER['legit_dhcp_client_path'])}", timeout=10)
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] legit DHCP client script chmod → Docker client: {detail or f'exit {rc}'}")
                sys.exit(1)
            log(f"  [OK] legit DHCP client script → Docker client:{DOCKER['legit_dhcp_client_path']}")

            docker_put(DOCKER['router_container'], docker_dnsmasq_handler,
                       "/usr/local/bin/netconf-handler-dnsmasq")
            docker_put(DOCKER['router_container'], docker_isc_handler,
                       "/usr/local/bin/netconf-handler-isc")
            active_handler = (
                "/usr/local/bin/netconf-handler-isc"
                if DOCKER['dhcp_type'] == "isc"
                else "/usr/local/bin/netconf-handler-dnsmasq"
            )
            rc, out, err = router_run(
                "chmod +x /usr/local/bin/netconf-handler-dnsmasq "
                "/usr/local/bin/netconf-handler-isc && "
                f"ln -sf {shlex.quote(active_handler)} /usr/local/bin/netconf-handler && "
                "test -x /usr/local/bin/netconf-handler",
                timeout=10,
            )
            if rc != 0:
                detail = (err or out).strip()
                log(f"  [FAIL] netconf handlers → Docker router: {detail or f'exit {rc}'}")
                sys.exit(1)
            log("  [OK] netconf handlers → Docker router:/usr/local/bin")
            log(f"  [OK] active netconf handler → {active_handler}")
        except Exception as exc:
            log(f"  [FAIL] Docker sync: {exc}")
            sys.exit(1)
        return

    # VM section.
    log("Syncing code to VMs…")

    openwrt_handler = PATHS['local_defense_dir'] / "netconf_action/netconf-handler-dnsmasq.sh"
    required_files = [
        ("selected config", CONFIG_FILE),
        ("db/whitelist.txt", PATHS['local_whitelist_file']),
        ("attack script", PATHS['local_attack_script']),
        ("legit DHCP client script", PATHS['local_legit_dhcp_client_script']),
        ("OpenWrt netconf handler", openwrt_handler),
    ]
    if not PATHS['local_defense_dir'].is_dir():
        log(f"  [FAIL] Local defense source not found: {PATHS['local_defense_dir']}"); sys.exit(1)
    if not PATHS['local_debian_scripts'].is_dir():
        log(f"  [FAIL] Debian scripts directory not found: {PATHS['local_debian_scripts']}"); sys.exit(1)
    for label, path in required_files:
        if not path.is_file():
            log(f"  [FAIL] {label} not found: {path}"); sys.exit(1)

    kali_attack_script = remote_attack_script_path()
    try:
        attacker_run(f"mkdir -p {shlex.quote(LAB['kali_attack_dir'])}")
        _pool.put(LAB['kali_ip'], LAB['kali_user'], LAB['kali_pass'],
                  PATHS['local_attack_script'],
                  kali_attack_script)
        rc, out, err = attacker_run(f"chmod +x {shlex.quote(kali_attack_script)}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] attack script chmod → Kali: {detail or f'exit {rc}'}"); sys.exit(1)
        log(f"  [OK] attack script → Kali:{kali_attack_script}")
    except Exception as exc:
        log(f"  [FAIL] attack script → Kali: {exc}"); sys.exit(1)

    ubuntu_project_dir = posixpath.dirname(LAB['ubuntu_bin_dir'].rstrip("/"))
    try:
        rc, out, err = detector_run(
            "mkdir -p "
            f"{shlex.quote(ubuntu_project_dir)} "
            f"{shlex.quote(posixpath.dirname(LAB['ubuntu_def_dir'].rstrip('/')))} "
            f"{shlex.quote(LAB['ubuntu_bin_dir'])}"
        )
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] prepare Ubuntu project dirs: {detail or f'exit {rc}'}"); sys.exit(1)
        rc, out, err = detector_run(
            "rm -rf "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'src'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'lab'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'docs'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'tests'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'config'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'db'))} "
            f"{shlex.quote(posixpath.join(ubuntu_project_dir, 'netconf_action'))}"
        )
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] clean Ubuntu project root: {detail or f'exit {rc}'}"); sys.exit(1)
    except Exception as exc:
        log(f"  [FAIL] prepare Ubuntu project root: {exc}"); sys.exit(1)

    ok = _pool.put_tar(
        LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'],
        [
            "sh", "-c",
            "cd \"$1\" && "
            "find . -mindepth 1 "
            "\\( -path './bin' -o "
            "-path './tests/results' -o "
            "-name '__pycache__' -o "
            "-name '.*' \\) "
            "-prune -o -print0 | "
            "env COPYFILE_DISABLE=1 tar --null --no-recursion -T - -czf -",
            "workspace-tar",
            str(PATHS["project_root"]),
        ],
        f"tar -C {shlex.quote(ubuntu_project_dir)} -xzf - 2>/dev/null",
    )
    if not ok:
        log("  [FAIL] workspace layout → Ubuntu"); sys.exit(1)
    detector_run(
        f"find {shlex.quote(ubuntu_project_dir)} -name .DS_Store -delete; "
        f"find {shlex.quote(ubuntu_project_dir)} -name '._*' -delete; "
        f"find {shlex.quote(ubuntu_project_dir)} -exec touch {{}} +"
    )
    log(f"  [OK] workspace layout → Ubuntu:{ubuntu_project_dir}")
    log(f"  [OK] detector source → Ubuntu:{LAB['ubuntu_def_dir']}")

    try:
        rc, out, err = detector_run(f"mkdir -p {shlex.quote(posixpath.join(LAB['ubuntu_def_dir'], 'config'))}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] prepare Ubuntu config dir: {detail or f'exit {rc}'}"); sys.exit(1)
        _pool.put(LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'],
                  CONFIG_FILE, f"{LAB['ubuntu_def_dir']}/{PATHS['remote_config_path']}")
        log(f"  [OK] config {CONFIG_FILE} → Ubuntu:{LAB['ubuntu_def_dir']}/{PATHS['remote_config_path']}")
    except Exception as exc:
        log(f"  [FAIL] config {CONFIG_FILE} → Ubuntu: {exc}"); sys.exit(1)

    log("  Building defense on Ubuntu…")
    # Makefile compile log.
    make_log = remote_tmp("ct_make.log")
    if not detector_ok(
        f"cd '{LAB['ubuntu_def_dir']}' && "
        f"make all BINDIR='{LAB['ubuntu_bin_dir']}' >{shlex.quote(make_log)} 2>&1 && "
        f"test -x {shlex.quote(posixpath.join(LAB['ubuntu_bin_dir'], 'dhcp_starvation_detector'))}",
        timeout=180,
    ):
        log(f"  [FAIL] Ubuntu build — see {make_log}"); sys.exit(1)
    log(f"  [OK] detector build → Ubuntu:{LAB['ubuntu_bin_dir']}")

    try:
        rc, out, err = detector_run(f"mkdir -p {shlex.quote(posixpath.join(LAB['ubuntu_def_dir'], 'db'))}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] prepare Ubuntu whitelist dir: {detail or f'exit {rc}'}"); sys.exit(1)
        _pool.put(LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'],
                  PATHS['local_whitelist_file'], f"{LAB['ubuntu_def_dir']}/db/whitelist.txt")
        log(f"  [OK] whitelist.txt → Ubuntu:{LAB['ubuntu_def_dir']}/db/whitelist.txt")
    except Exception as exc:
        log(f"  [FAIL] whitelist.txt → Ubuntu: {exc}"); sys.exit(1)

    remote_debian_scripts_path = posixpath.dirname(LAB['debian_dhcpget'].rstrip("/")) or "."
    remote_debian_scripts_dir = shlex.quote(remote_debian_scripts_path)
    remote_dhcpget = shlex.quote(LAB['debian_dhcpget'])
    try:
        rc, out, err = client_run(f"mkdir -p {remote_debian_scripts_dir}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] prepare Debian scripts dir: {detail or f'exit {rc}'}"); sys.exit(1)
    except Exception as exc:
        log(f"  [FAIL] prepare Debian scripts dir: {exc}"); sys.exit(1)
    ok = _pool.put_tar(
        LAB['debian_ip'], LAB['debian_user'], LAB['debian_pass'],
        ["tar", "-C", str(PATHS['local_debian_scripts']), "-czf", "-", "."],
        f"tar -C {remote_debian_scripts_dir} -xzf - 2>/dev/null"
        f" && chmod +x {remote_dhcpget}",
    )
    if not ok:
        log("  [FAIL] debian-scripts → Debian"); sys.exit(1)
    log(f"  [OK] debian-scripts → Debian:{remote_debian_scripts_path}")

    try:
        remote_client_script_dir = posixpath.dirname(DHCP_LAB['legit_client_path'].rstrip("/")) or "/"
        rc, out, err = client_run(f"mkdir -p {shlex.quote(remote_client_script_dir)}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] prepare Debian legit DHCP client script dir: {detail or f'exit {rc}'}"); sys.exit(1)
        _pool.put(LAB['debian_ip'], LAB['debian_user'], LAB['debian_pass'],
                  PATHS['local_legit_dhcp_client_script'], DHCP_LAB['legit_client_path'])
        rc, out, err = client_run(f"chmod +x {shlex.quote(DHCP_LAB['legit_client_path'])}")
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] legit DHCP client script chmod → Debian: {detail or f'exit {rc}'}"); sys.exit(1)
        log(f"  [OK] legit DHCP client script → Debian:{DHCP_LAB['legit_client_path']}")
    except Exception as exc:
        log(f"  [FAIL] legit DHCP client script → Debian: {exc}"); sys.exit(1)

    try:
        _pool.put(LAB['openwrt_ip'], LAB['openwrt_user'], LAB['openwrt_pass'],
                  openwrt_handler, LAB['openwrt_netconf_handler'])
        rc, out, err = router_run(
            f"chmod +x {shlex.quote(LAB['openwrt_netconf_handler'])} && "
            f"test -x {shlex.quote(LAB['openwrt_netconf_handler'])}"
        )
        if rc != 0:
            detail = (err or out).strip()
            log(f"  [FAIL] netconf handler chmod → OpenWrt: {detail or f'exit {rc}'}"); sys.exit(1)
        log(f"  [OK] netconf handler → OpenWrt:{LAB['openwrt_netconf_handler']}")
    except Exception as exc:
        log(f"  [FAIL] netconf handler → OpenWrt: {exc}"); sys.exit(1)

def check_docker_deps() -> None:

    log("Checking Docker lab dependencies…")

    router_backend_cmd = "command -v dnsmasq >/dev/null 2>&1"
    router_backend_name = "dnsmasq"
    if DOCKER['dhcp_type'] == "isc":
        router_backend_cmd = "command -v dhcpd >/dev/null 2>&1"
        router_backend_name = "ISC DHCP"

    if not router_ok(
        f"{router_backend_cmd} && "
        "test -x /bin/bash && "
        "command -v sshd >/dev/null 2>&1 && "
        "command -v ssh-keygen >/dev/null 2>&1 && "
        "command -v ip >/dev/null 2>&1 && "
        "command -v sed >/dev/null 2>&1 && "
        "command -v awk >/dev/null 2>&1 && "
        "command -v grep >/dev/null 2>&1 && "
        "command -v wc >/dev/null 2>&1 && "
        "command -v tr >/dev/null 2>&1 && "
        "command -v head >/dev/null 2>&1 && "
        "command -v mktemp >/dev/null 2>&1 && "
        "command -v pidof >/dev/null 2>&1"
    ):
        log(f"  [FAIL] Docker router: {router_backend_name}, bash, sshd, ssh-keygen, ip, sed, awk, grep, wc, tr, head, mktemp or pidof missing"); sys.exit(1)
    log(f"  [OK] Docker router: {router_backend_name} + bash + sshd + ssh-keygen + ip + sed + awk + grep + wc + tr + head + mktemp + pidof")

    if not detector_ok(
        "command -v gcc >/dev/null 2>&1 && "
        "command -v make >/dev/null 2>&1 && "
        "command -v rrdtool >/dev/null 2>&1 && "
        "command -v pkill >/dev/null 2>&1 && "
        "command -v find >/dev/null 2>&1 && "
        "command -v nc >/dev/null 2>&1 && "
        "dpkg -l libpcap-dev 2>/dev/null | grep -q '^ii' && "
        "dpkg -l libnetconf2-dev 2>/dev/null | grep -q '^ii' && "
        "{ dpkg -l libyang2-dev 2>/dev/null | grep -q '^ii' || "
        "dpkg -l libyang-dev 2>/dev/null | grep -q '^ii'; } && "
        "dpkg -l libssh-dev 2>/dev/null | grep -q '^ii' && "
        f"test -d {shlex.quote(DOCKER['netconf_yang_dir'])} && "
        f"find {shlex.quote(DOCKER['netconf_yang_dir'])} -name 'ietf-netconf@*.yang' -print -quit 2>/dev/null | "
        "grep -q ."
    ):
        log("  [FAIL] Docker detector: gcc, make, rrdtool, pkill, find, nc, libpcap-dev, libnetconf2-dev, libyang-dev/libyang2-dev, libssh-dev or ietf-netconf YANG modules missing"); sys.exit(1)
    log("  [OK] Docker detector: gcc + make + rrdtool + pkill + find + nc + libpcap-dev + libnetconf2-dev + libyang-dev/libyang2-dev + libssh-dev + ietf-netconf YANG modules")

    if not attacker_ok(
        "command -v python3 >/dev/null 2>&1 && "
        "python3 -c 'import scapy.all' 2>/dev/null && "
        "python3 -c 'import ctypes.util, sys; sys.exit(0 if ctypes.util.find_library(\"pcap\") else 1)' 2>/dev/null && "
        "command -v ip >/dev/null 2>&1 && "
        "command -v pkill >/dev/null 2>&1 && "
        "command -v yersinia >/dev/null 2>&1"
    ):
        log("  [FAIL] Docker attacker: python3, scapy, libpcap runtime, ip, pkill or yersinia missing"); sys.exit(1)
    log("  [OK] Docker attacker: python3 + scapy + libpcap runtime + ip + pkill + yersinia")

    if not client_ok(
        "{ [ -x /sbin/dhcpcd ] || [ -x /usr/sbin/dhcpcd ]; } && "
        "command -v ip >/dev/null 2>&1 && "
        "command -v awk >/dev/null 2>&1 && "
        "command -v pkill >/dev/null 2>&1"
    ):
        log("  [FAIL] Docker client: dhcpcd, ip, awk or pkill missing"); sys.exit(1)
    log("  [OK] Docker client: dhcpcd + ip + awk + pkill")

def check_docker_host_deps() -> None:

    log("Checking Docker host dependencies…")

    checks = [
        (
            ["docker", "--version"],
            "Host Docker CLI not found (required for --env-type docker)",
            "Host Docker CLI failed",
        ),
        (
            ["docker", "compose", "version"],
            "Host Docker Compose plugin not found (required for --env-type docker)",
            "Host Docker Compose plugin failed",
        ),
        (
            ["docker", "info"],
            "Host Docker daemon not reachable (start Docker Desktop)",
            "Host Docker daemon check failed",
        ),
    ]
    for cmd, missing_msg, failed_msg in checks:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except FileNotFoundError:
            log(f"  [FAIL] {missing_msg}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            log(f"  [FAIL] {failed_msg}: timed out")
            sys.exit(1)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            log(f"  [FAIL] {failed_msg}: {detail or f'exit {proc.returncode}'}")
            sys.exit(1)

    log("  [OK] Host Docker control deps: docker CLI + compose plugin + daemon")

def preflight_docker() -> None:
    
    check_docker_host_deps()

    log()
    log("Checking Docker compose lab…")
    if not DOCKER['compose_file'].is_file():
        log(f"  [FAIL] Docker compose file not found: {DOCKER['compose_file']}"); sys.exit(1)
    try:
        rc, out, err = docker_compose("config", timeout=60)
    except RuntimeError as exc:
        log(f"  [FAIL] Docker compose config failed: {exc}")
        sys.exit(1)
    if rc != 0:
        log(f"  [FAIL] Docker compose config failed: {(err or out).strip()}"); sys.exit(1)
    log(f"  [OK] Docker compose file {DOCKER['compose_file']}")

    log("  Building and starting Docker lab from current workspace…")
    try:
        rc, out, err = docker_compose("up", "-d", "--build", "--force-recreate", timeout=900)
    except RuntimeError as exc:
        log(f"  [FAIL] Docker compose up failed: {exc}")
        sys.exit(1)
    if rc != 0:
        log(f"  [FAIL] Docker compose up failed: {(err or out).strip()}"); sys.exit(1)
    log("  [OK] Docker lab running")

    # Monotonic is not changed by system clock updates.
    log("  Connecting to Docker containers…")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if router_ok("echo ok", timeout=5) and detector_ok("echo ok", timeout=5) \
           and attacker_ok("echo ok", timeout=5) and client_ok("echo ok", timeout=5):
            break
        time.sleep(2)
    else:
        log("  [FAIL] one or more Docker containers are not reachable via docker exec"); sys.exit(1)

    log(f"  [OK] Router   {DOCKER['router_container']} ({DOCKER['router_ip']})")
    log(f"  [OK] Detector {DOCKER['detector_container']}")
    log(f"  [OK] Attacker {DOCKER['attacker_container']}")
    if resolve_client_ip():
        log(f"  [OK] Client   {DOCKER['client_container']}  MAC={RUNTIME['debian_mac']}")
    else:
        log("  [FAIL] Docker client MAC could not be read"); sys.exit(1)

    # Search for a yang directory to use for netconf tests. 
    rc, out, _ = detector_run(
        "find /usr/share/yuma/modules/ietf /usr/share/yang/modules /usr "
        "-name 'ietf-netconf@*.yang' -exec dirname {} \\; 2>/dev/null | head -1",
        timeout=10,
    )
    found_yang_dir = (out.strip().splitlines() or [""])[0].strip() if rc == 0 else ""
    if found_yang_dir:
        DOCKER['netconf_yang_dir'] = found_yang_dir

    log()
    check_docker_deps()

    log()
    sync_code()

    log()
    log("Resetting DHCP pool…")
    cleanup_all()
    reset_router()
    log("  [OK] pool cleared, whitelist disabled, DHCP backend reloaded")

    RUNTIME['pool_total'] = router_pool_total(DOCKER['dhcp_pool_total_default'])
    RUNTIME['pool_limit'] = RUNTIME['pool_total']
    pool_end = DHCP_LAB['pool_start_host'] + RUNTIME['pool_limit'] - 1
    log(f"  Pool     : limit={RUNTIME['pool_limit']} ({DHCP_LAB['ipv4_prefix']}{DHCP_LAB['pool_start_host']} – {DHCP_LAB['ipv4_prefix']}{pool_end})")
    log()

def preflight() -> None:

    log("DHCP Starvation Detector — Test Suite")
    log(f"Env Type    : {RUNTIME['test_type']}")
    if RUNTIME['test_type'] == "docker":
        log(f"DHCP        : {DOCKER['dhcp_type']}")
    log(f"Run ID      : {RUN_ID}")
    log(f"Results     : {RESULT_DIR}")
    log()

    # Docker section.
    if RUNTIME['test_type'] == "docker":
        preflight_docker()
        return

    # VM Section.
    log("Checking VM connectivity…")
    if not router_ok("echo ok"):
        log("  [FAIL] OpenWrt unreachable"); sys.exit(1)
    log(f"  [OK] OpenWrt {LAB['openwrt_ip']}")

    if not detector_ok("echo ok"):
        log("  [FAIL] Ubuntu unreachable"); sys.exit(1)
    log(f"  [OK] Ubuntu  {LAB['ubuntu_ip']}")

    if not attacker_ok("echo ok"):
        log("  [FAIL] Kali unreachable"); sys.exit(1)
    log(f"  [OK] Kali    {LAB['kali_ip']}")

    if resolve_client_ip():
        log(f"  [OK] Debian  {LAB['debian_ip']}  MAC={RUNTIME['debian_mac']}")
    else:
        log("  [WARN] Debian not reachable — legit client checks will fail...")
        RUNTIME['debian_mac'] = LAB['debian_mac_hint']

    log()
    check_vm_deps()

    log()
    sync_code()

    log()
    log("Resetting DHCP pool…")
    reset_router()
    log("  [OK] pool cleared, whitelist disabled, dnsmasq restarted")

    RUNTIME['pool_total'] = router_pool_total(DHCP_LAB['pool_total_default'])
    RUNTIME['pool_limit'] = RUNTIME['pool_total']
    pool_end = DHCP_LAB['pool_start_host'] + RUNTIME['pool_limit'] - 1
    log(f"  Pool    : limit={RUNTIME['pool_limit']} ({DHCP_LAB['ipv4_prefix']}{DHCP_LAB['pool_start_host']} – {DHCP_LAB['ipv4_prefix']}{pool_end})")
    log()

# Test a legitimate client vm IP. This is needed since the VM client can change
# its reachable address during DHCP tests.
def _try_client_ip(ip: str) -> bool:

    if not ip:
        return False
    
    LAB['debian_ip'] = ip
    try:
        rc, out, _ = _pool.run(LAB['debian_ip'], LAB['debian_user'], LAB['debian_pass'],
                               f"cat /sys/class/net/{LAB['debian_iface']}/address",
                               retries=1, timeout=10)
        if rc == 0 and out.strip():
            RUNTIME['debian_mac'] = out.strip().lower()
            return True
    except Exception:
        pass
    return False

# Resolve the legitimate client address/MAC for the selected environment.
def resolve_client_ip() -> bool:

    if RUNTIME['test_type'] == "docker":
        try:
            rc, out, _ = client_run(f"cat /sys/class/net/{shlex.quote(LAB['debian_iface'])}/address",
                                    retries=1, timeout=10)
            if rc == 0 and out.strip():
                RUNTIME['debian_mac'] = out.strip().lower()
                return True
        except Exception:
            pass
        if not RUNTIME['debian_mac']:
            RUNTIME['debian_mac'] = LAB['debian_mac_hint']
        return False

    # VM section.
    if _try_client_ip(LAB['debian_ip']):
        return True
    if _try_client_ip(LAB['debian_static_ip']):
        return True
    
    mac = RUNTIME['debian_mac'] or LAB['debian_mac_hint']
    prefix = DHCP_LAB['ipv4_prefix'].replace("\\", "\\\\").replace('"', '\\"')
    try:
        _, out, _ = router_run(
            f"ip neigh show 2>/dev/null | awk 'BEGIN{{m=tolower(\"{mac}\"); p=\"{prefix}\"}} "
            f"tolower($0)~m && index($1,p)==1 && $0!~/FAILED/{{print $1}}' | sort -u"
        )
        for ip in out.strip().splitlines():
            if _try_client_ip(ip.strip()):
                return True
    except Exception:
        pass
    try:
        lease_file = shlex.quote(DHCP_LAB['router_lease_file'])
        _, out, _ = router_run(
            f"awk 'BEGIN{{m=tolower(\"{mac}\")}} tolower($2)==m{{print $3}}'"
            f" {lease_file} 2>/dev/null | sort -u"
        )
        for ip in out.strip().splitlines():
            if _try_client_ip(ip.strip()):
                return True
    except Exception:
        pass
    if not RUNTIME['debian_mac']:
        RUNTIME['debian_mac'] = LAB['debian_mac_hint']
    return False

# Leave the legitimate client reachable by using a static IP, without any DHCP-pool lease.
def reset_client_state() -> None:

    RUNTIME['debian_lease_ip'] = ""
    client_script_pattern = shlex.quote(pkill_pattern_for_path(DHCP_LAB['legit_client_path']))
    if RUNTIME['test_type'] == "docker":
        try:
            iface = shlex.quote(LAB['debian_iface'])
            pool_end = DHCP_LAB['pool_start_host'] + RUNTIME['pool_total'] - 1
            client_run(
                f"pkill -f {client_script_pattern} >/dev/null 2>&1 || true; "
                f"ip -4 -o addr show dev {iface} scope global 2>/dev/null | awk '{{print $4}}' | "
                "while read -r cidr; do "
                "ipaddr=${cidr%%/*}; host=${ipaddr##*.}; "
                f"case \"$ipaddr\" in {DHCP_LAB['ipv4_prefix']}*) "
                f"if [ \"$host\" -ge {DHCP_LAB['pool_start_host']} ] 2>/dev/null && "
                f"[ \"$host\" -le {pool_end} ] 2>/dev/null; then "
                f"ip addr del \"$cidr\" dev {iface} 2>/dev/null || true; "
                "fi ;; "
                "esac; "
                "done; "
                "rm -f /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/*/*.lease 2>/dev/null || true; "
                "pkill -x dhcpcd >/dev/null 2>&1 || true",
                timeout=20,
            )
        except Exception:
            pass
        return

    # VM section.
    if not resolve_client_ip():
        return

    iface = shlex.quote(LAB['debian_iface'])
    static_ip = shlex.quote(LAB['debian_static_ip'])
    pool_end = DHCP_LAB['pool_start_host'] + RUNTIME['pool_total'] - 1
    reset_script = (
        f"pkill -f {client_script_pattern} >/dev/null 2>&1 || true; "
        f"ip addr add {static_ip}/24 dev {iface} 2>/dev/null || true; "
        f"ip link set {iface} up 2>/dev/null || true; "
        f"ip -4 -o addr show dev {iface} scope global 2>/dev/null | awk '{{print $4}}' | "
        "while read -r cidr; do "
        "ipaddr=${cidr%%/*}; host=${ipaddr##*.}; "
        f"case \"$ipaddr\" in {DHCP_LAB['ipv4_prefix']}*) "
        f"if [ \"$host\" -ge {DHCP_LAB['pool_start_host']} ] 2>/dev/null && "
        f"[ \"$host\" -le {pool_end} ] 2>/dev/null; then "
        f"ip addr del \"$cidr\" dev {iface} 2>/dev/null || true; "
        "fi ;; "
        "esac; "
        "done; "
        "rm -f /var/lib/dhcpcd/*.lease /var/lib/dhcpcd/*/*.lease 2>/dev/null || true; "
        "pkill -x dhcpcd >/dev/null 2>&1 || true; "
        f"ip addr add {static_ip}/24 dev {iface} 2>/dev/null || true; "
        f"ip -4 -o addr show dev {iface} scope global 2>/dev/null | awk '{{print $4}}' | "
        "while read -r cidr; do "
        "ipaddr=${cidr%%/*}; host=${ipaddr##*.}; "
        f"case \"$ipaddr\" in {DHCP_LAB['ipv4_prefix']}*) "
        f"if [ \"$host\" -ge {DHCP_LAB['pool_start_host']} ] 2>/dev/null && "
        f"[ \"$host\" -le {pool_end} ] 2>/dev/null; then "
        f"ip addr del \"$cidr\" dev {iface} 2>/dev/null || true; "
        "fi ;; "
        "esac; "
        "done"
    )
    try:
        client_run(
            f"printf '%s\\n' {shlex.quote(LAB['debian_pass'])} | "
            f"su -c {shlex.quote(reset_script)}",
            timeout=20,
        )
    except Exception:
        pass
    time.sleep(2)
    LAB['debian_ip'] = LAB['debian_static_ip']

# Executes a docker compose command. Returns (rc, stdout, stderr). Raises RuntimeError on failure.
def docker_compose(*args: str, timeout: int = 300) -> tuple[int, str, str]:

    cmd = ["docker", "compose", "-f", str(DOCKER['compose_file']), *args]
    env = os.environ.copy()
    env["DHCP_TYPE"] = DOCKER['dhcp_type']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except FileNotFoundError:
        raise RuntimeError("'docker' command not found")
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"docker compose {' '.join(args)} timed out after {timeout}s") from exc
    
    if RUNTIME['verbose']:
        if proc.stdout:
            sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
            
    return proc.returncode, proc.stdout, proc.stderr

def strip_yaml_comment(line: str) -> str:
    
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line

# Return flattened YAML leaf keys for the project's simple YAML subset.
def yaml_leaf_keys(filepath: Path, skip_sections: set[str] | None = None) -> list[str]:

    skip_sections = skip_sections or set()
    if not filepath.is_file():
        return []

    keys: list[str] = []
    stack: list[tuple[int, list[str]]] = []
    try:
        fh = open(filepath)
    except OSError as exc:
        fail_and_exit(f"cannot read config file {filepath}: {exc}")

    with fh:
        for raw in fh:
            line = strip_yaml_comment(raw.rstrip("\n")).rstrip()
            if not line.strip() or ":" not in line:
                continue

            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            key, _, value = stripped.partition(":")
            key = key.strip().strip('"').strip("'")
            if not key:
                continue

            while stack and stack[-1][0] >= indent:
                stack.pop()

            parent_parts: list[str] = []
            for _, parts in stack:
                parent_parts.extend(parts)
            full_parts = parent_parts + key.split(".")

            if value.strip() == "":
                stack.append((indent, key.split(".")))
                continue

            if full_parts and full_parts[0] not in skip_sections:
                keys.append(".".join(full_parts))

    return sorted(dict.fromkeys(keys))

def detector_env_name(config_key: str) -> str:
    return config_key.replace(".", "_").upper()

def detector_source_config_keys() -> list[str]:
    
    if not PATHS['local_defense_dir'].is_dir():
        return []

    keys: set[str] = set()
    for path in PATHS['local_defense_dir'].rglob("*.[ch]"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        keys.update(CFG_GETTER_RE.findall(text))
    return sorted(keys)

def detector_config_env_names() -> list[str]:
    keys = set(yaml_leaf_keys(CONFIG_FILE, skip_sections={"test_suite"}))
    keys.update(detector_source_config_keys())
    return sorted(detector_env_name(key) for key in keys)

def detector_forwarded_env() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in detector_config_env_names()
        if name in os.environ
    }

def detector_router_message_env() -> dict[str, str]:
    
    env = detector_forwarded_env()
    env.update({
        "DHCP_BACKEND": DOCKER['dhcp_type'],
        "NETCONF_HOST": LAB['openwrt_ip'],
        "NETCONF_USERNAME": "root",
        "NETCONF_PASSWORD": "root" if RUNTIME['test_type'] == "docker" else "",
    })
    if RUNTIME['test_type'] == "docker":
        env["NETCONF_YANG_DIR"] = DOCKER['netconf_yang_dir']
    return env

# Build the env vars to be used when dhcp_starvation_detector --router-message is called.
def detector_router_env_parts() -> list[str]:

    return [
        f"{key}={shlex.quote(value)}"
        for key, value in sorted(detector_router_message_env().items())
    ]

# Send a message to the router using the NETCONF module incorporated in the dhcp_starvation_detector.
def run_detector_router_message(message: str, timeout: int = 30) -> tuple[int, str, str]:
    
    return detector_run(
        f"cd {shlex.quote(LAB['ubuntu_def_dir'])} && "
        f"{' '.join(detector_router_env_parts())} "
        f"{shlex.quote(posixpath.join(LAB['ubuntu_bin_dir'], 'dhcp_starvation_detector'))} "
        f"--router-message {shlex.quote(message)} {shlex.quote(PATHS['remote_config_path'])}",
        timeout=timeout,
    )

# Reset router state to clear DHCP leases, disable whitelist-only mode, and reload the DHCP backend by sending a router message.
def reset_router() -> None:

    try:
        rc, out, err = run_detector_router_message("reset-pool", timeout=30)
        if rc != 0:
            detail = (err or out).strip()
            raise RuntimeError(detail or f"dhcp_starvation_detector reset exit {rc}")
    except Exception as exc:
        log(f"  [WARN] reset-pool via dhcp_starvation_detector failed: {exc}")

    if RUNTIME['test_type'] == "docker":
        try:
            docker_compose("restart", "client", timeout=60)
        except Exception:
            pass
        reset_client_state()
        time.sleep(2)
        return

    reset_client_state()
    time.sleep(2)

def kill_client_loop() -> None:

    client_script_pattern = shlex.quote(pkill_pattern_for_path(DHCP_LAB['legit_client_path']))

    if RUNTIME['test_type'] == "docker":
        try:
            client_run(
                f"pkill -f {client_script_pattern} >/dev/null 2>&1 || true; "
                "pkill -f '[d]hcpcd -4 -1' >/dev/null 2>&1 || true"
            )
        except Exception:
            pass
        return
    
    # VM section.
    try:
        kill_cmd = f"pkill -f {client_script_pattern} >/dev/null 2>&1 || true"
        client_run(
            f"printf '%s\\n' {shlex.quote(LAB['debian_pass'])} | su -c "
            f"{shlex.quote(kill_cmd)}"
        )
    except Exception:
        pass

def kill_remote_defense() -> None:

    if RUNTIME['test_type'] == "docker":
        try:
            detector_run("pkill -x dhcp_starvation_detector >/dev/null 2>&1 || true")
        except Exception:
            pass
        return
    
    # VM section.
    try:
        detector_run(
            f"printf '%s\\n' {shlex.quote(LAB['ubuntu_pass'])} | "
            "sudo -S -p '' pkill -x dhcp_starvation_detector >/dev/null 2>&1 || true"
        )
    except Exception:
        pass

# Class to manage SSH connections to the VMs and command execution. Uses paramiko.
class SSHPool:
    """One persistent paramiko connection per host; auto-reconnects on drop."""

    def __init__(self):
        self._clients: dict[str, paramiko.SSHClient] = {}

    # Connect to an host via SSH.
    def _connect(self, host: str, user: str, password: str) -> paramiko.SSHClient:

        if paramiko is None:
            raise RuntimeError("paramiko not installed. Install it for --env-type vms using: pip install paramiko")
        
        key = f"{user}@{host}"
        # Already have a connection.
        client = self._clients.get(key)
        if client:
            t = client.get_transport()
            if t and t.is_active():
                return client
            try:
                client.close()
            except Exception:
                pass
            del self._clients[key]

        import socket as _socket
        sock = _socket.create_connection((host, 22), timeout=10)
        t = paramiko.Transport(sock)
        t.set_keepalive(30)
        t.start_client(timeout=15)

        # Try auth_none first (e.g. OpenWrt with no password configured),
        # fall back to password auth for other hosts.
        try:
            t.auth_none(user)
        except paramiko.BadAuthenticationType:
            if password:
                t.auth_password(user, password)
            else:
                agent = paramiko.agent.Agent()
                for akey in agent.get_keys():
                    try:
                        t.auth_publickey(user, akey)
                        break
                    except paramiko.AuthenticationException:
                        continue

        if not t.is_authenticated():
            t.close()
            raise paramiko.AuthenticationException(
                f"SSH VM authentication failed for {user}@{host}"
            )

        client = paramiko.SSHClient()
        client._transport = t
        self._clients[key] = client
        return client

    # Run a remote command. Returns (rc, stdout, stderr).
    def run(self, host: str, user: str, password: str, cmd: str,
            stdin_data: bytes = b"", timeout: int = 60,
            retries: int = SUITE['remote_retries']) -> tuple[int, str, str]:

        last_exc: Exception = RuntimeError("no attempts")
        for attempt in range(retries):
            try:
                client = self._connect(host, user, password)
                transport = client.get_transport()
                ch = transport.open_session()
                ch.settimeout(timeout)
                ch.exec_command(cmd)
                if stdin_data:
                    ch.sendall(stdin_data)
                    ch.shutdown_write()
                out = b""
                err = b""
                deadline = time.monotonic() + timeout
                while True:
                    if ch.recv_ready():
                        out += ch.recv(65536)
                    if ch.recv_stderr_ready():
                        err += ch.recv_stderr(65536)
                    if ch.exit_status_ready():
                        while ch.recv_ready():
                            out += ch.recv(65536)
                        while ch.recv_stderr_ready():
                            err += ch.recv_stderr(65536)
                        break
                    if time.monotonic() > deadline:
                        ch.close()
                        raise TimeoutError(f"command timed out after {timeout}s")
                    time.sleep(0.05)
                rc = ch.recv_exit_status()
                ch.close()
                if RUNTIME['verbose']:
                    if out:
                        sys.stdout.write(out.decode(errors="replace"))
                    if err:
                        sys.stderr.write(err.decode(errors="replace"))
                return rc, out.decode(errors="replace"), err.decode(errors="replace")
            except Exception as exc:
                last_exc = exc
                key = f"{user}@{host}"
                if key in self._clients:
                    try:
                        self._clients[key].close()
                    except Exception:
                        pass
                    del self._clients[key]
                if attempt < retries - 1:
                    log(
                        f"  [WARN] SSH {user}@{host} attempt {attempt + 1}/{retries} "
                        f"failed ({type(exc).__name__}: {exc}); retrying..."
                    )
                    time.sleep(2)

        raise RuntimeError(f"SSH {user}@{host} failed after {retries} attempts: {last_exc}")

    # Like run but for multi line commands, basically a wrapper.
    # Equivalent to: ssh host bash -s -- arg1 arg2 < script.
    def bash(self, host: str, user: str, password: str,
             script: str, *args: str, timeout: int = 120) -> tuple[int, str, str]:

        quoted = " ".join(shlex.quote(str(a)) for a in args)
        cmd = f"bash -s -- {quoted}"
        return self.run(host, user, password, cmd, stdin_data=script.encode(), timeout=timeout)

    # Upload a single file via SFTP, falling back to stdin pipe (e.g. Dropbear).
    def put(self, host: str, user: str, password: str,
            local: Path, remote: str) -> None:

        try:
            client = self._connect(host, user, password)
            sftp = client.open_sftp()
            try:
                sftp.put(str(local), remote)
                return
            finally:
                sftp.close()
        except Exception:
            pass

        # Fallback for hosts without SFTP (e.g. OpenWrt/Dropbear): pipe via stdin.
        data = local.read_bytes()
        self.run(host, user, password,
                 f"cat > {shlex.quote(remote)}",
                 stdin_data=data, timeout=30, retries=1)

    def get(self, host: str, user: str, password: str,
            remote: str, local: Path) -> None:

        try:
            client = self._connect(host, user, password)
            sftp = client.open_sftp()
            try:
                sftp.get(remote, str(local))
                return
            finally:
                sftp.close()
        except Exception:
            pass

        client = self._connect(host, user, password)
        transport = client.get_transport()
        ch = transport.open_session()
        ch.settimeout(30)
        ch.exec_command(f"cat {shlex.quote(remote)}")
        out = b""
        err = b""
        deadline = time.monotonic() + 30
        while True:
            if ch.recv_ready():
                out += ch.recv(65536)
            if ch.recv_stderr_ready():
                err += ch.recv_stderr(65536)
            if ch.exit_status_ready():
                while ch.recv_ready():
                    out += ch.recv(65536)
                while ch.recv_stderr_ready():
                    err += ch.recv_stderr(65536)
                break
            if time.monotonic() > deadline:
                ch.close()
                raise TimeoutError(f"download timed out after 30s: {remote}")
            time.sleep(0.05)
        rc = ch.recv_exit_status()
        ch.close()
        if rc != 0:
            detail = err.decode(errors="replace").strip()
            raise RuntimeError(detail or f"remote cat exit {rc}: {remote}")
        local.write_bytes(out)

    # Pipe local `tar` files into a remote command (e.g. remote tar -x). 
    # It doesn't create a new temporary tar file, so for that we don't use the put() method.
    def put_tar(self, host: str, user: str, password: str,
                tar_args: list[str], remote_cmd: str) -> bool:

        try:
            client = self._connect(host, user, password)
            transport = client.get_transport()
            ch = transport.open_session()
            ch.exec_command(remote_cmd)
            proc = subprocess.Popen(tar_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            while True:
                data = proc.stdout.read(65536)
                if not data:
                    break
                ch.sendall(data)
            proc.wait()
            ch.shutdown_write()
            rc = ch.recv_exit_status()
            ch.close()
            return rc == 0
        except Exception as exc:
            if RUNTIME['verbose']:
                log(f"  [FAIL] put_tar error: {exc}")
            return False

    # Write a memory content to a remote, whithout passing through a local file. 
    def write_remote(self, host: str, user: str, password: str,
                     remote_path: str, content: str) -> None:
        
        data = content.encode()
        try:
            client = self._connect(host, user, password)
            sftp = client.open_sftp()
            try:
                with sftp.open(remote_path, 'w') as f:
                    f.write(content)
                return
            finally:
                sftp.close()
        except Exception as sftp_exc:
            rc, out, err = self.run(
                host, user, password,
                f"cat > {shlex.quote(remote_path)}",
                stdin_data=data, timeout=30, retries=1,
            )
            if rc != 0:
                detail = (err or out or str(sftp_exc)).strip()
                raise RuntimeError(f"remote write failed for {remote_path}: {detail}")

    def close_all(self) -> None:
        for c in self._clients.values():
            try:
                c.close()
            except Exception:
                pass
        self._clients.clear()

_pool = SSHPool()

# Executes a command inside a docker container. Returns (rc, stdout, stderr). Raises RuntimeError on failure.
def docker_exec(container: str, cmd: str, stdin_data: bytes = b"",
                timeout: int = 60, retries: int = SUITE['remote_retries']) -> tuple[int, str, str]:
    
    args = ["docker", "exec", "-i", container, "sh", "-lc", cmd]
    last_exc: Exception = RuntimeError("no attempts")
    for attempt in range(retries):
        try:
            proc = subprocess.run(
                args,
                input=stdin_data if stdin_data else None,
                capture_output=True,
                timeout=timeout,
            )
            out = proc.stdout.decode(errors="replace")
            err = proc.stderr.decode(errors="replace")
            if RUNTIME['verbose']:
                if out:
                    sys.stdout.write(out)
                if err:
                    sys.stderr.write(err)
            return proc.returncode, out, err
        except FileNotFoundError as exc:
            raise RuntimeError("'docker' command not found") from exc
        except subprocess.TimeoutExpired as exc:
            last_exc = TimeoutError(f"docker exec {container} command timed out after {timeout}s")
        if attempt < retries - 1:
            time.sleep(2)

    raise RuntimeError(f"docker exec {container} failed after {retries} attempts: {last_exc}")

# Execute a command on a lab role (router, detector, attacker, client), or forward to docker.
def _run_role(role: str, cmd: str, **kw) -> tuple[int, str, str]:

    if RUNTIME['test_type'] == "docker":
        return docker_exec(DOCKER_BY_ROLE[role], cmd, **kw)
    
    # VM section.
    if role == "router":
        return _pool.run(LAB['openwrt_ip'], LAB['openwrt_user'], LAB['openwrt_pass'], cmd, **kw)
    if role == "detector":
        return _pool.run(LAB['ubuntu_ip'], LAB['ubuntu_user'], LAB['ubuntu_pass'], cmd, **kw)
    if role == "attacker":
        return _pool.run(LAB['kali_ip'], LAB['kali_user'], LAB['kali_pass'], cmd, **kw)
    if role == "client":
        return _pool.run(LAB['debian_ip'], LAB['debian_user'], LAB['debian_pass'], cmd, **kw)
    
    raise ValueError(f"unknown role: {role}")

# Shortcuts for running commands on specific roles.
# Instead of _run_role("router", cmd, **kw).
# Returns (rc, stdout, stderr) or raises RuntimeError on failure.
def router_run(cmd, **kw):    return _run_role("router", cmd, **kw)
def detector_run(cmd, **kw):  return _run_role("detector", cmd, **kw)
def attacker_run(cmd, **kw):  return _run_role("attacker", cmd, **kw)
def client_run(cmd, **kw):    return _run_role("client", cmd, **kw)

# Wrapper, command execution to boolean.
def _ok_role(role: str, cmd: str, **kw) -> bool:
    
    try:
        rc, _, _ = _run_role(role, cmd, retries=1, **kw)
        return rc == 0
    except Exception:
        return False

# Returns True if command succeeded (exit code 0), False on failure or exception.
def router_ok(cmd, **kw):    return _ok_role("router", cmd, **kw)
def detector_ok(cmd, **kw):  return _ok_role("detector", cmd, **kw)
def attacker_ok(cmd, **kw):  return _ok_role("attacker", cmd, **kw)
def client_ok(cmd, **kw):    return _ok_role("client", cmd, **kw)

# Find remote attack script path.
def remote_attack_script_path() -> str:

    if RUNTIME['test_type'] == "docker":
        return DOCKER['attack_script']
    
    return posixpath.join(LAB['kali_attack_dir'], "dhcp_starvation_attack.py")

# Safe pattern costruction for pkill.
def pkill_pattern_for_path(path: str) -> str:

    name = posixpath.basename(path.rstrip("/")) or path
    if not name:
        return ""
    
    return f"[{re.escape(name[0])}]{re.escape(name[1:])}"

def kill_remote_attack() -> None:
    attack_pattern = shlex.quote(pkill_pattern_for_path(remote_attack_script_path()))

    if RUNTIME['test_type'] == "docker":
        # [] trick to avoid pkill killing itself.
        try:
            attacker_run(
                # Kill temporary sh attack scripts.
                "pkill -f '[s]h /tmp/ct\\.' >/dev/null 2>&1 || true; "
                # Kill main python attack script.
                f"pkill -f {attack_pattern} >/dev/null 2>&1 || true; "
                "pkill -f '[y]ersinia' >/dev/null 2>&1 || true"
            )
        except Exception:
            pass

        if RUNTIME['current_attack_pid']:
            try:
                attacker_run(f"kill '{RUNTIME['current_attack_pid']}' >/dev/null 2>&1 || true")
            except Exception:
                pass
            RUNTIME['current_attack_pid'] = ""
        return
    
    # VM section.
    try:
        attacker_run(
            f"printf '%s\\n' {shlex.quote(LAB['kali_pass'])} | sudo -S -p '' "
            "sh -c \""
            "pkill -f '[s]h /tmp/ct\\.' >/dev/null 2>&1 || true; "
            f"pkill -f {attack_pattern} >/dev/null 2>&1 || true; "
            "pkill -f '[y]ersinia' >/dev/null 2>&1 || true"
            "\""
        )
    except Exception:
        pass
    if RUNTIME['current_attack_pid']:
        try:
            attacker_run(f"kill '{RUNTIME['current_attack_pid']}' >/dev/null 2>&1 || true")
        except Exception:
            pass
        RUNTIME['current_attack_pid'] = ""

# Stop all remote processes.
def cleanup_all() -> None:
    kill_remote_attack()
    kill_remote_defense()
    kill_client_loop()

# Exit handler.
def _on_exit() -> None:

    if RUNTIME['exit_called']:
        return
    RUNTIME['exit_called'] = True

    if RUNTIME['interrupted']:
        print()
        log("Interrupted (Ctrl+C) — stopping attack, defense, legit client, resetting router…")

    if RUNTIME['current_test']:
        try:
            cleanup_all()
        except Exception:
            pass
        try:
            reset_router()
        except Exception:
            pass

    _pool.close_all()

    log()
    log("═══════════════════════════════════════════════════════")
    log(f"  Results: passed={RUNTIME['pass_count']}  failed={RUNTIME['fail_count']}  total={RUNTIME['total_count']}")
    log(f"  Dir    : {RESULT_DIR}")
    log("═══════════════════════════════════════════════════════")

    if RUNTIME['summary_fh']:
        try:
            RUNTIME['summary_fh'].close()
        except Exception:
            pass

def log(msg: str = "") -> None:

    _emit_log(msg)

# Set interrupted after Ctrl+C.
def _signal_handler(sig, frame) -> None:
    RUNTIME['interrupted'] = True
    sys.exit(130)

# Adjust global variables based on the selected backend (Docker or VMs).
def configure_backend(test_type: str) -> None:

    RUNTIME['test_type'] = test_type
    if RUNTIME['test_type'] != "docker":
        return

    # VM section.
    LAB['openwrt_ip'] = DOCKER['router_ip']
    LAB['ubuntu_iface'] = DOCKER['detector_iface']
    LAB['ubuntu_def_dir'] = DOCKER['detector_dir']
    LAB['ubuntu_bin_dir'] = DOCKER['detector_bin_dir']
    LAB['kali_iface'] = DOCKER['attacker_iface']
    LAB['kali_attack_dir'] = posixpath.dirname(DOCKER['attack_script'])
    LAB['debian_ip'] = DOCKER['client_container']
    LAB['debian_static_ip'] = DOCKER['client_container']
    LAB['debian_iface'] = DOCKER['client_iface']
    LAB['debian_log_dir'] = DOCKER['client_log_dir']
    DHCP_LAB['legit_client_path'] = DOCKER['legit_dhcp_client_path']
    DHCP_LAB['router_lease_file'] = (
        DOCKER['isc_router_lease_file']
        if DOCKER['dhcp_type'] == "isc"
        else DOCKER['router_lease_file']
    )
    DHCP_LAB['ipv4_prefix'] = DOCKER['dhcp_ipv4_prefix']
    DHCP_LAB['pool_start_host'] = DOCKER['dhcp_pool_start_host']
    DHCP_LAB['pool_total_default'] = DOCKER['dhcp_pool_total_default']

# Decide whether to emit ANSI colors in --help output.
def _help_color_enabled() -> bool:

    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty() or bool(os.environ.get("COLORTERM"))

class LoggingArgumentParser(argparse.ArgumentParser):

    def error(self, message: str) -> None:
        fail_and_exit(f"argument error: {message}. Run with --help for usage.", 2)

# Used for coloring help text.
class ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):

    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _DIM = "\033[2m"
    _CYAN = "\033[36m"
    _BLUE = "\033[94m"
    _YELLOW = "\033[33m"
    _MAGENTA = "\033[35m"

    def _c(self, text: str, color: str) -> str:
        if not _help_color_enabled():
            return text
        return f"{color}{text}{self._RESET}"

    def start_section(self, heading: str) -> None:
        super().start_section(self._c(heading, self._BOLD + self._CYAN))

    def _color_cli_syntax(self, text: str) -> str:
        if not _help_color_enabled():
            return text

        text = re.sub(
            r"(?<![\w-])(--?[A-Za-z0-9][A-Za-z0-9_-]*)",
            lambda m: self._c(m.group(1), self._BLUE),
            text,
        )
        return re.sub(
            r"(\{[^}]+\}|\b[A-Z][A-Z0-9_]*\b)",
            lambda m: self._c(m.group(1), self._YELLOW),
            text,
        )

    def _color_option_line(self, line: str) -> str:
        match = re.match(r"^(\s+.*?)(\s{2,}\S.*)$", line)
        if not match:
            return self._color_cli_syntax(line)
        return self._color_cli_syntax(match.group(1)) + match.group(2)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        return super()._format_action_invocation(action)

    def format_help(self) -> str:
        text = super().format_help()
        if not _help_color_enabled():
            return text

        lines = []
        in_groups = False
        in_usage = False
        for line in text.splitlines():
            if line.startswith("usage:"):
                in_usage = True
                line = (self._c("usage:", self._BOLD + self._CYAN) +
                        self._color_cli_syntax(line[len("usage:"):]))
            elif in_usage and line.strip():
                line = self._color_cli_syntax(line)
            elif in_usage:
                in_usage = False
            elif re.match(r"^\s+--?[A-Za-z0-9]", line):
                line = self._color_option_line(line)
            elif line == "Groups:":
                in_groups = True
                line = self._c(line, self._BOLD + self._CYAN)
            elif line.startswith("Test-suite parameters"):
                in_groups = False
            elif line == "Example:":
                line = self._c(line, self._BOLD + self._CYAN)
            elif in_groups and re.match(r"^  [A-K]  ", line):
                line = re.sub(
                    r"^(  [A-K]  .+?)(\s+—\s+)(.*)$",
                    lambda m: self._c(m.group(1), self._MAGENTA) +
                              self._c(m.group(2), self._DIM) +
                              m.group(3),
                    line,
                )
            lines.append(line)
        return "\n".join(lines) + "\n"

def main() -> None:

    # Help page and argument parsing.
    parser_kwargs = {
        "description": "DHCP starvation detector test suite",
        "formatter_class": ColorHelpFormatter,
        "epilog": (
            "Groups:\n"
            "  A  Unique-MAC bursts          — unique MAC DISCOVER bursts; A1-A4 verify legit access, A5 is sub-threshold and starts no legit client loop\n"
            "  B  Same-MAC then unique burst — about 1/3 repeated same MAC DISCOVERs every 0.2s, then unique-MAC no-wait burst; legit access verified\n"
            "  C  Slow-to-low pool pressure  — full DHCP attempts every 3-4s, every 10th MAC repeats, must use F6, legit access verified\n"
            "  D  Same-MAC control           — repeated full DHCP attempts from one fixed MAC, pool intact and detector silent, no legit client loop\n"
            "  E  IDLE check                 — no attack launched, legitimate client DHCP loop only, detector silent and pool intact\n"
            "  F  Whitelist evasion          — whitelist-only, then 6 slow full DHCP attempts from one fixed MAC 4s apart, attacker not promoted, legit access verified\n"
            "  G  Adaptive baseline          — same MAC warmup builds EMA baseline, then unique-MAC spike must trigger f4=1, legit access verified\n"
            "  H  ARP-failed lease removal   — detection enables whitelist-only, legit access works, fake attacker lease removed after ARP failure\n"
            "  I  Yersinia tool DHCP DoS     — external yersinia DHCP DISCOVER DoS detected, whitelist-only enabled, legit access verified\n"
            "  J  Eth/DHCP-src mismatch      — legit access verified, then 12 DISCOVERs with Ethernet source different from DHCP chaddr/client-id are discarded\n"
            "  K  Reputation confirmation    — legit client is removed from runtime whitelist, then must pass DHCP backoff, ARP OK, and final whitelist entry\n"
            "\n"
            "Test-suite parameters live under test_suite in config.yaml and can be\n"
            "overridden with uppercase environment variables. The DHCP backend used is\n"
            "the global dhcp.backend value in config.yaml; For VMs environment can be used only dnsmasq.\n"
            "Use --config, env CONFIG_FILE, or env DHCP_DEFENSE_CONFIG to select a different YAML file.\n"
            "Example:\n"
            "  DETECT_TIMEOUT_SLOW=500 KALI_IP=10.0.0.5 python3 run_tests.py --env-type vms --group C\n"
            "  python3 run_tests.py --env-type docker --groups K\n"
            "  python3 run_tests.py --env-type docker --smoke"
        ),
        "add_help": False,
    }
    # Compatibility with older Python versions that don't support the "color" argument in ArgumentParser.
    if "color" in inspect.signature(argparse.ArgumentParser).parameters:
        parser_kwargs["color"] = False
    parser = LoggingArgumentParser(**parser_kwargs)
    parser.add_argument("--help", action="help",
                        help="show this help message and exit")
    parser.add_argument("--env-type", choices=("docker", "vms"), required=True,
                        help="test environment type: docker or vms")
    parser.add_argument("--config", metavar="PATH",
                        help=(
                            f"YAML config path (default: {PATHS['default_config_display']}; "
                            "env: CONFIG_FILE or DHCP_DEFENSE_CONFIG)"
                        ))
    parser.add_argument("--output", metavar="PATH",
                        help=f"results output directory (default: {PATHS['default_output_display']})")
    parser.add_argument("--verbose", action="store_true",
                        help="print remote command output in real time")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--smoke", action="store_true",
                            help="run one short test per group instead of the full test suite (SA, SB, SC, SD, SE, SF, SG, SH, SI, SJ, SK)")
    mode_group.add_argument("--group", "--groups", choices=list("ABCDEFGHIJK"),
                            metavar="{A,B,C,D,E,F,G,H,I,J,K}", dest="group",
                            help="run only the named group of tests")
    args = parser.parse_args()
    if DOCKER['dhcp_type'] not in ("dnsmasq", "isc"):
        parser.error("dhcp.backend must be one of: dnsmasq, isc")
    if args.env_type == "vms" and DOCKER['dhcp_type'] != "dnsmasq":
        parser.error("dhcp.backend=isc is supported only with --env-type docker; VMs must use dnsmasq")

    # Adjust vars for docker type.
    configure_backend(args.env_type)

    RUNTIME['verbose'] = args.verbose

    # Create output.
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    for group in "ABCDEFGHIJK":
        (RESULT_DIR / group).mkdir(exist_ok=True)
    RUNTIME['summary_fh'] = open(SUMMARY, "w")

    # Signals and exit handler.
    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    atexit.register(_on_exit)

    preflight()

    groups = {"A": run_group_a, "B": run_group_b, "C": run_group_c,
              "D": run_group_d, "E": run_group_e, "F": run_group_f,
              "G": run_group_g, "H": run_group_h, "I": run_group_i,
              "J": run_group_j, "K": run_group_k}
    order  = list("ABCDEFGHIJK")

    # Execution order.
    if args.smoke:
        run_smoke()
    elif args.group:
        groups[args.group]()
    else:
        for g in order:
            groups[g]()

    sys.exit(1 if RUNTIME['fail_count'] > 0 else 0)

if __name__ == "__main__":
    main()
