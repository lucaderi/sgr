import argparse
from pathlib import Path

from scapy.error import Scapy_Exception

from firewall.engine.policy_engine import PolicyContractError
from firewall.engine.policy_profile import *
from firewall.orchestrator import run_capture

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="analyze an offline PCAP with Hybrid Multilayer Firewall")

    parser.add_argument("pcap", type=Path, help="input PCAP or PCAPNG file")

    parser.add_argument("--json", type=Path, dest="output_path", help="insert path for JSON report")

    parser.add_argument("--profile", choices=("demo", "custom", "test"), default="demo", help="policy profile to apply")

    args = parser.parse_args(argv)

    profiles = {
        "demo": demo_profile,
        "custom": example_profile,
        "test": test_profile,
    }

    # configured networks and services determine which traffic can be allowed (default: academic profile)

    try:
        profile = profiles[args.profile]()

        print(f"Policy profile: {profiles[args.profile].__name__}")

        run_capture(args.pcap, profile, args.output_path)
    except (OSError, ValueError, PolicyContractError, Scapy_Exception) as exc:
        parser.exit(1, f"Error: {exc}\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
