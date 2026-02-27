#!/usr/bin/env python3
"""Minimal ASN lookup for an IP list using Team Cymru WHOIS."""

# NOTE:
# This tool reports authoritative routing ownership via ASN (BGP).
# It does NOT infer application ownership or testing authorization.

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import socket
import re
from collections import defaultdict
from datetime import datetime, timezone

VERSION = "1.1.0"
CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
DEFAULT_TIMEOUT = 20
FIELDNAMES = [
    "IP",
    "ASN",
    "ASN_Org",
    "Authority_Source",
    "BGP_Prefix",
    "CC",
    "RIR",
    "Allocated",
    "Lookup_Status",
    "Error",
    "Timestamp",
    "Tool_Version",
]
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
AUTHORITY_SOURCE = "BGP / ASN (Team Cymru)"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lookup ASN data for a list of IP addresses (Team Cymru)."
    )
    parser.add_argument("--input", required=True, help="Input file with one IP per line")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout (seconds) for Team Cymru lookup",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print summary only; do not write output file",
    )
    parser.add_argument(
        "--prefix-summary",
        action="store_true",
        help="Print BGP prefix aggregation summary from OK rows",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def print_start_banner() -> None:
    print("[INFO] Performing ASN-based routing authority discovery (no scanning).", flush=True)


def load_ips(path: str) -> list[str]:
    ips: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for idx, raw in enumerate(f, start=1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            try:
                ip_obj = ipaddress.ip_address(value)
                if ip_obj.is_private or ip_obj.is_reserved:
                    logging.warning("Non-public IP will be marked as skipped: %s", value)
                ips.append(value)
            except ValueError:
                logging.warning("Skipping invalid IP on line %d: %s", idx, value)
    return ips


def is_non_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return bool(addr.is_private or addr.is_reserved)


def build_cymru_query(ips: list[str]) -> str:
    return "begin\nverbose\n" + "\n".join(ips) + "\nend\n"


def parse_cymru_response(response: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for line in response.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("as |"):
            continue
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, cc, registry, allocated, as_name = parts[:7]
        rows[ip] = {
            "ASN": asn,
            "ASN_Org": normalize_asn_org(as_name),
            "BGP_Prefix": prefix,
            "CC": cc,
            "RIR": registry,
            "Allocated": allocated,
        }
    return rows


def normalize_asn_org(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value


def batch_cymru_lookup(ips: list[str], timeout: int) -> dict[str, dict[str, str]]:
    if not ips:
        return {}

    query = build_cymru_query(ips)
    with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=timeout) as sock:
        sock.sendall(query.encode("ascii", errors="ignore"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)

    response = b"".join(chunks).decode("utf-8", errors="replace")
    return parse_cymru_response(response)


def write_csv(path: str, rows: list[dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: str, rows: list[dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)


def build_output_rows(ips: list[str], lookup: dict[str, dict[str, str]], fatal_error: str) -> list[dict[str, str]]:
    now = datetime.now(timezone.utc).isoformat()
    output_rows: list[dict[str, str]] = []
    for ip in ips:
        if is_non_public(ip):
            output_rows.append(
                {
                    "IP": ip,
                    "ASN": "",
                    "ASN_Org": "",
                    "Authority_Source": AUTHORITY_SOURCE,
                    "BGP_Prefix": "",
                    "CC": "",
                    "RIR": "",
                    "Allocated": "",
                    "Lookup_Status": "SKIPPED_PRIVATE",
                    "Error": "Non-public IP skipped (private or reserved)",
                    "Timestamp": now,
                    "Tool_Version": VERSION,
                }
            )
            continue

        item = lookup.get(ip)
        if item:
            asn = item["ASN"]
            output_rows.append(
                {
                    "IP": ip,
                    "ASN": asn,
                    "ASN_Org": item["ASN_Org"],
                    "Authority_Source": AUTHORITY_SOURCE,
                    "BGP_Prefix": item["BGP_Prefix"],
                    "CC": item["CC"],
                    "RIR": item["RIR"],
                    "Allocated": item["Allocated"],
                    "Lookup_Status": "OK",
                    "Error": "",
                    "Timestamp": now,
                    "Tool_Version": VERSION,
                }
            )
            continue

        status = "ERROR" if fatal_error else "NOT_FOUND"
        error = fatal_error if fatal_error else "No Team Cymru result for IP"
        output_rows.append(
            {
                "IP": ip,
                "ASN": "",
                "ASN_Org": "",
                "Authority_Source": AUTHORITY_SOURCE,
                "BGP_Prefix": "",
                "CC": "",
                "RIR": "",
                "Allocated": "",
                "Lookup_Status": status,
                "Error": error,
                "Timestamp": now,
                "Tool_Version": VERSION,
            }
        )
    return sort_output_rows(output_rows)


def sort_output_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    def asn_num(asn: str) -> int:
        return int(asn) if asn.isdigit() else 10**9

    return sorted(
        rows,
        key=lambda r: (
            asn_num(r.get("ASN", "")),
            r.get("ASN_Org", ""),
            r.get("IP", ""),
        ),
    )


def print_asn_summary(rows: list[dict[str, str]]) -> None:
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for row in rows:
        asn = (row.get("ASN", "") or "").strip().upper()
        if row.get("Lookup_Status") == "OK" and asn not in {"", "NA"}:
            key = (row.get("ASN", "") or "UNKNOWN", row.get("ASN_Org", "") or "Unknown")
        else:
            key = ("UNKNOWN", "Unattributed / Not Found")
        counts[key] += 1

    summary_rows = sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0][0], item[0][1]),
    )

    print("")
    print("ASN Summary (by routing authority):")
    print("")
    org_width = max(30, min(50, max(len(org) for (_, org), _ in summary_rows)))
    print(f"{'ASN':<8} {'ASN Org':<{org_width}} {'IPs':>3}")
    print(f"{'-'*8} {'-'*org_width} {'-'*3}")
    for (asn, org), count in summary_rows:
        print(f"{asn:<8} {org[:org_width]:<{org_width}} {count:>3}")
    print("-" * (8 + 1 + org_width + 1 + 3))
    print(f"Total IPs processed: {len(rows)}")

    status_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        status_counts[row.get("Lookup_Status", "UNKNOWN")] += 1

    print("")
    print("Lookup Outcome:")
    for status in ("OK", "NOT_FOUND", "SKIPPED_PRIVATE", "ERROR"):
        print(f"  {status:<17}: {status_counts.get(status, 0)}")
    for status in sorted(k for k in status_counts.keys() if k not in {"OK", "NOT_FOUND", "SKIPPED_PRIVATE", "ERROR"}):
        print(f"  {status:<17}: {status_counts[status]}")


def print_prefix_summary(rows: list[dict[str, str]]) -> None:
    groups: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        if row.get("Lookup_Status") != "OK":
            continue
        prefix = row.get("BGP_Prefix", "") or ""
        asn = row.get("ASN", "") or ""
        asn_org = row.get("ASN_Org", "") or ""
        groups[(prefix, asn, asn_org)] += 1

    def asn_num(asn: str) -> int:
        return int(asn) if asn.isdigit() else 10**9

    def prefix_len(prefix: str) -> int:
        if "/" not in prefix:
            return 999
        try:
            return int(prefix.split("/", 1)[1])
        except ValueError:
            return 999

    items = sorted(
        groups.items(),
        key=lambda item: (
            asn_num(item[0][1]),
            prefix_len(item[0][0]),
            -item[1],
            item[0][0],
            item[0][2],
        ),
    )

    print("")
    print("BGP Prefix Summary:")
    if not items:
        print("No OK rows available for prefix summary.")
        return

    prefix_width = max(6, min(25, max(len(k[0]) for k, _ in items)))
    asn_width = max(3, min(10, max(len(k[1]) for k, _ in items)))
    org_width = max(7, min(50, max(len(k[2]) for k, _ in items)))
    print(f"{'Prefix':<{prefix_width}} {'ASN':<{asn_width}} {'ASN Org':<{org_width}} {'IPs':>3}")
    print(f"{'-'*prefix_width} {'-'*asn_width} {'-'*org_width} {'-'*3}")
    for (prefix, asn, asn_org), count in items:
        print(f"{prefix:<{prefix_width}} {asn:<{asn_width}} {asn_org[:org_width]:<{org_width}} {count:>3}")


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    print_start_banner()

    if args.timeout <= 0:
        logging.error("--timeout must be a positive integer")
        return 2
    if not args.summary_only and not args.output:
        logging.error("--output is required unless --summary-only is used")
        return 2

    ips = load_ips(args.input)
    if not ips:
        logging.error("No valid IPs found in %s", args.input)
        return 1

    routable_ips = [ip for ip in ips if not is_non_public(ip)]
    logging.info("Looking up ASN data for %d IPs (%d non-public skipped)", len(ips), len(ips) - len(routable_ips))

    lookup: dict[str, dict[str, str]] = {}
    fatal_error = ""
    try:
        lookup = batch_cymru_lookup(routable_ips, args.timeout)
    except OSError as exc:
        fatal_error = f"Team Cymru query failed: {exc}"
        logging.error("%s", fatal_error)

    output_rows = build_output_rows(ips, lookup, fatal_error)

    if not args.summary_only:
        if args.format == "csv":
            write_csv(args.output, output_rows)
        else:
            write_json(args.output, output_rows)
        logging.info("Wrote %s: %s (%d rows)", args.format.upper(), args.output, len(output_rows))
    print_asn_summary(output_rows)
    if args.prefix_summary:
        print_prefix_summary(output_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
