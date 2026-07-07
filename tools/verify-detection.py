#!/usr/bin/env python3
"""Verify anti-detection signatures in frida-server binary (static + optional runtime)."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

HARD_FAIL_PATTERNS = [
    (b"frida-helper", "frida-helper"),
    (b"re.frida.", "re.frida."),
    (b"frida:rpc", "frida:rpc"),
    (b"/re/frida/HostSession", "/re/frida/HostSession"),
    (b"frida-server", "frida-server"),
]

REQUIRED_PATTERNS = [
    (b"re.nginx.", "re.nginx."),
]

FRIDA_SUBSTRING_LIMIT = 15


def count_frida_substrings(data: bytes) -> int:
    return len(re.findall(rb"(?i)frida", data))


def static_check(path: Path) -> tuple[list[str], list[str]]:
    data = path.read_bytes()
    fails: list[str] = []
    warns: list[str] = []

    for pattern, label in HARD_FAIL_PATTERNS:
        count = data.count(pattern)
        if count:
            fails.append(f"FAIL: {label} found {count} time(s)")

    for pattern, label in REQUIRED_PATTERNS:
        if data.count(pattern) == 0:
            fails.append(f"FAIL: required pattern missing: {label}")

    total_frida = count_frida_substrings(data)
    if total_frida > FRIDA_SUBSTRING_LIMIT:
        warns.append(
            f"WARN: frida substring count {total_frida} exceeds limit {FRIDA_SUBSTRING_LIMIT}"
        )

    if data.count(b"gmain") or data.count(b"gdbus"):
        warns.append("WARN: gmain/gdbus present in binary strings")

    if not fails:
        fails.append("PASS: static checks OK")

    return fails, warns


def _adb_base(adb_serial: str | None) -> list[str]:
    adb = ["adb"]
    if adb_serial:
        adb += ["-s", adb_serial]
    return adb


def _adb_shell(adb: list[str], command: str) -> str:
    result = subprocess.run(
        adb + ["shell", "su", "-c", command],
        capture_output=True,
        text=True,
    )
    return result.stdout


def runtime_check(pid: int, port: int | None, adb_serial: str | None) -> tuple[list[str], list[str]]:
    fails: list[str] = []
    warns: list[str] = []
    adb = _adb_base(adb_serial)

    ps = subprocess.run(adb + ["shell", "ps -A"], capture_output=True, text=True)
    if "frida" in ps.stdout.lower():
        fails.append("FAIL: frida visible in ps output")

    if port is not None:
        net = subprocess.run(
            adb + ["shell", f"netstat -tln 2>/dev/null | grep ':{port}' || true"],
            capture_output=True,
            text=True,
        )
        if "27042" in net.stdout:
            fails.append("FAIL: default port 27042 listening")

    cmdline_raw = subprocess.run(
        adb + ["shell", f"cat /proc/{pid}/cmdline"],
        capture_output=True,
    ).stdout
    cmdline = cmdline_raw.replace(b"\x00", b" ").decode("ascii", errors="replace").strip()
    if b"-l" in cmdline_raw or b"unix:" in cmdline_raw:
        fails.append(f"FAIL: listen args visible in cmdline: {cmdline!r}")
    elif not cmdline.startswith("kworker/"):
        warns.append(f"WARN: cmdline argv[0] is not kworker/*: {cmdline!r}")

    exe = subprocess.run(
        adb + ["shell", "su", "-c", f"readlink /proc/{pid}/exe"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    if "(deleted)" not in exe:
        warns.append(f"WARN: /proc/{pid}/exe is not deleted staging copy: {exe!r}")

    maps = _adb_shell(adb, f"grep -i frida-helper /proc/{pid}/maps 2>/dev/null || true")
    if maps.strip():
        fails.append(f"FAIL: frida-helper in /proc/{pid}/maps")

    threads = _adb_shell(
        adb,
        f"for t in /proc/{pid}/task/*/comm; do cat $t 2>/dev/null; done",
    )
    bad_threads = [
        ln.strip()
        for ln in threads.splitlines()
        if ln.strip() in ("gmain", "gdbus", "GDBus", "GMain")
    ]
    if bad_threads:
        fails.append(
            f"FAIL: {len(bad_threads)} sensitive thread name(s) on PID {pid}: "
            + ", ".join(sorted(set(bad_threads)))
        )

    if not fails:
        fails.append("PASS: runtime checks OK")

    return fails, warns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", help="post-processed ELF to scan")
    parser.add_argument("--device-pid", type=int, help="server PID for runtime checks")
    parser.add_argument("--port", type=int, help="listening port")
    parser.add_argument("--adb-serial", help="adb device serial")
    args = parser.parse_args()

    exit_code = 0

    if args.binary:
        path = Path(args.binary)
        if not path.is_file():
            print(f"binary not found: {path}", file=sys.stderr)
            return 1
        fails, warns = static_check(path)
        for line in fails:
            print(line)
            if line.startswith("FAIL"):
                exit_code = 1
        for line in warns:
            print(line)

    if args.device_pid is not None:
        fails, warns = runtime_check(args.device_pid, args.port, args.adb_serial)
        for line in fails:
            print(line)
            if line.startswith("FAIL"):
                exit_code = 1
        for line in warns:
            print(line)

    if not args.binary and args.device_pid is None:
        parser.error("provide binary path and/or --device-pid")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
