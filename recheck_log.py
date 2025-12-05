#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import json
from dataclasses import dataclass, asdict
from typing import List, Optional

from web3 import Web3


DEFAULT_LOG_PATH = "verification_log.txt"
DEFAULT_INFURA_MAINNET = "https://mainnet.infura.io/v3/{key}"


@dataclass
class LogEntry:
    index: int
    raw_line: str
    timestamp: str
    address: str
    logged_hash: str


@dataclass
class CheckResult:
    index: int
    timestamp: str
    address: str
    logged_hash: str
    current_hash: Optional[str]
    status: str  # "match", "mismatch", "no_code", "error"
    error: Optional[str]


def resolve_rpc_url() -> str:
    """
    Resolve RPC URL from environment:

    - RPC_URL
    - INFURA_API_KEY -> mainnet Infura URL
    """
    env_rpc = os.getenv("RPC_URL")
    if env_rpc:
        return env_rpc

    infura_key = os.getenv("INFURA_API_KEY")
    if infura_key:
        return DEFAULT_INFURA_MAINNET.format(key=infura_key)

    # Fallback placeholder (user should override)
    return "https://mainnet.infura.io/v3/YOUR_INFURA_KEY"


def connect(rpc_url: str, timeout: int = 30) -> Web3:
    """Connect to RPC and print a short banner."""
    start = time.time()
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))

    if not w3.is_connected():
        print(f"❌ Failed to connect to RPC endpoint: {rpc_url}", file=sys.stderr)
        sys.exit(1)

    try:
        chain_id = w3.eth.chain_id
    except Exception:
        chain_id = "unknown"

    latest = w3.eth.block_number
    elapsed = time.time() - start
    print(f"🌐 Connected. chainId={chain_id} tip={latest}", file=sys.stderr)
    print(f"⚡ RPC connected in {elapsed:.2f}s", file=sys.stderr)
    return w3


def parse_log_line(line: str, idx: int) -> Optional[LogEntry]:
    """
    Parse a single log line of the form:

        ts | address | sha256

    Returns None if the line is blank or a comment.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        return None

    parts = [p.strip() for p in stripped.split("|")]
    if len(parts) != 3:
        # Malformed line; treat as error entry.
        return LogEntry(
            index=idx,
            raw_line=line.rstrip("\n"),
            timestamp="?",
            address="?",
            logged_hash="?",
        )

    ts, addr, h = parts
    return LogEntry(
        index=idx,
        raw_line=line.rstrip("\n"),
        timestamp=ts,
        address=addr,
        logged_hash=h,
    )


def load_log(path: str) -> List[LogEntry]:
    entries: List[LogEntry] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                entry = parse_log_line(line, idx)
                if entry is None:
                    continue
                entries.append(entry)
    except FileNotFoundError:
        print(f"❌ Log file not found: {path}", file=sys.stderr)
        sys.exit(2)
    return entries


def checksum_address(w3: Web3, addr: str) -> str:
    """Normalize/validate an Ethereum address."""
    if not isinstance(addr, str) or not w3.is_address(addr):
        raise ValueError(f"invalid Ethereum address: {addr!r}")
    return w3.to_checksum_address(addr)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_entry(w3: Web3, entry: LogEntry) -> CheckResult:
    try:
        if entry.address in ("?", ""):
            raise ValueError("malformed log line (cannot parse address)")

        addr = checksum_address(w3, entry.address)
        code = w3.eth.get_code(addr)

        if not code:
            return CheckResult(
                index=entry.index,
                timestamp=entry.timestamp,
                address=addr,
                logged_hash=entry.logged_hash,
                current_hash=None,
                status="no_code",
                error=None,
            )

        current_hash = sha256_hex(bytes(code))

        if entry.logged_hash.lower().strip() == current_hash.lower():
            status = "match"
        else:
            status = "mismatch"

        return CheckResult(
            index=entry.index,
            timestamp=entry.timestamp,
            address=addr,
            logged_hash=entry.logged_hash,
            current_hash=current_hash,
            status=status,
            error=None,
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            index=entry.index,
            timestamp=entry.timestamp,
            address=entry.address,
            logged_hash=entry.logged_hash,
            current_hash=None,
            status="error",
            error=str(exc) or type(exc).__name__,
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Re-check verification_log.txt entries against current on-chain bytecode.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--log",
        default=DEFAULT_LOG_PATH,
        help=f"Path to verification log (default: {DEFAULT_LOG_PATH})",
    )
    p.add_argument(
        "--rpc",
        help="RPC URL override (otherwise from RPC_URL/INFURA_API_KEY env).",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP RPC timeout in seconds.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of a human-readable table.",
    )
    p.add_argument(
        "--limit",
        type=int,
        help="Optionally limit the number of log entries to re-check (from the top).",
    )
    return p.parse_args()


def format_human(results: List[CheckResult], log_path: str, rpc_url: str) -> str:
    headers = ["#", "Timestamp", "Address", "Status", "Logged SHA-256", "Current SHA-256 / Error"]
    rows = []

    for r in results:
        if r.status == "match":
            status = "✅ match"
        elif r.status == "mismatch":
            status = "❌ mismatch"
        elif r.status == "no_code":
            status = "⚠️ no_code"
        else:
            status = "⚠️ error"

        current = r.current_hash or (r.error or "")
        rows.append(
            [
                str(r.index),
                r.timestamp,
                r.address,
                status,
                r.logged_hash,
                current,
            ]
        )

    all_rows = [headers] + rows
    col_widths = [
        max(len(str(row[i])) for row in all_rows) for i in range(len(headers))
    ]

    def fmt_row(cols: List[str]) -> str:
        return "  ".join(
            str(col).ljust(col_widths[idx]) for idx, col in enumerate(cols)
        )

    lines = [
        f"zk-soundness-lite :: log re-check",
        f"Log file : {log_path}",
        f"RPC URL  : {rpc_url}",
        "",
        fmt_row(headers),
        fmt_row(["-" * w for w in col_widths]),
    ]
    lines.extend(fmt_row(r) for r in rows)
    return "\n".join(lines)


def main() -> None:
    args = parse_args()

    rpc_url = args.rpc or resolve_rpc_url()
    print(
        f"📅 Re-check run at UTC: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}",
        file=sys.stderr,
    )
    print(f"⚙️ Using RPC: {rpc_url}", file=sys.stderr)
    print(f"📄 Using log: {args.log}", file=sys.stderr)

    entries = load_log(args.log)
    if not entries:
        print("⚠️ Log file has no entries to check.", file=sys.stderr)
        sys.exit(0)

    if args.limit is not None and args.limit > 0:
        entries = entries[: args.limit]

    w3 = connect(rpc_url, timeout=args.timeout)

     results: List[CheckResult] = []
    for entry in entries:
        res = check_entry(w3, entry)
        results.append(res)

    # Basic stats
    total = len(results)
    matches = sum(1 for r in results if r.status == "match")
    mismatches = sum(1 for r in results if r.status == "mismatch")
    no_code = sum(1 for r in results if r.status == "no_code")
    errors = sum(1 for r in results if r.status == "error")

    if args.json:
        payload = {
            "logPath": args.log,
            "rpc": rpc_url,
            "generatedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": [asdict(r) for r in results],
            "summary": {
                "total": total,
                "matches": matches,
                "mismatches": mismatches,
                "noCode": no_code,
                "errors": errors,
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    print(format_human(results, args.log, rpc_url))
    print()
    print(
        f"Summary: total={total}  "
        f"matches={matches}  mismatches={mismatches}  "
        f"no_code={no_code}  errors={errors}"
    )


    print(format_human(results, args.log, rpc_url))


if __name__ == "__main__":
    main()
