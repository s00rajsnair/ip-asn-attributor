# ASN Lookup (IP List)

## Overview

This tool maps IP addresses to their Autonomous System Number (ASN) and related BGP attribution data using Team Cymru.

It is intended for asset attribution and scope validation workflows where routing authority needs to be established before any active security activity.

## What This Tool Does

- Performs ASN lookup for input IP addresses using Team Cymru IP-to-ASN data.
- Operates passively and non-intrusively.
- Produces deterministic, repeatable output for the same input and data source state.

## What This Tool Does NOT Do

- No scanning.
- No probing of target IPs.
- No ownership inference.
- No scope decisions.
- No use of Shodan, Censys, WHOIS heuristics, or DNS.

## Why ASN-Based Attribution

ASN data reflects routing control on the public internet.

Routing control is a stronger authority signal for infrastructure attribution than application-layer artifacts such as domains, TLS banners, or host fingerprints. Using ASN-based attribution reduces ambiguity and provides a safer, more defensible basis for pre-engagement validation.

## Installation

- Python 3.9+
- No external dependencies

Run directly with Python:

```bash
python3 asn_lookup.py --help
```

## Usage

Input format: text file with one IP address per line.

Example (`ips.txt`):

```txt
13.235.169.43
23.52.42.188
8.8.8.8
```

CSV output:

```bash
python3 asn_lookup.py --input ips.txt --output report.csv --format csv
```

JSON output:

```bash
python3 asn_lookup.py --input ips.txt --output report.json --format json
```

Summary only (no file output):

```bash
python3 asn_lookup.py --input ips.txt --summary-only
```

Prefix aggregation summary:

```bash
python3 asn_lookup.py --input ips.txt --output report.csv --format csv --prefix-summary
```

Common options:

- `--timeout`: socket timeout in seconds (default: `20`)
- `--summary-only`: print console summary without writing output file
- `--prefix-summary`: print grouped BGP prefix summary from `Lookup_Status=OK` rows
- `--verbose`: verbose logging
- `--version`: print tool version

## Output

Key output fields:

- `ASN`: Autonomous System Number from Team Cymru.
- `ASN_Org`: ASN organization string from Team Cymru.
- `BGP_Prefix`: Prefix associated with the IP in routing data.
- `Authority_Source`: Attribution source (`BGP / ASN (Team Cymru)`).
- `Lookup_Status`: Outcome per IP (`OK`, `NOT_FOUND`, `SKIPPED_PRIVATE`, `ERROR`).
- `Timestamp`: UTC timestamp for the run record.

At the end of execution, the CLI prints an ASN summary table, total IP count, and lookup outcome counts.
When `--prefix-summary` is enabled, it also prints a grouped table with `Prefix`, `ASN`, `ASN Org`, and `IPs` using only `OK` rows.

## Intended Use

- External pentest scoping preparation
- Asset ownership validation workflows
- Compliance and audit preparation

## Legal / Compliance Note

This tool uses public routing attribution data and performs no active interaction with target systems. Any active testing, probing, or scanning requires separate and explicit authorization.

## Design Philosophy

- Separation of facts from policy: the tool reports routing facts and does not make scope or ownership decisions.
- Authority over inference: ASN/BGP attribution is prioritized over heuristic signals.
- Fail-closed behavior: lookup failures are explicit in output and summaries.
