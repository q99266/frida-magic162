#!/usr/bin/env python3
"""Verify embedded agent blobs in a post-processed frida-server binary."""
from __future__ import annotations

import argparse
import struct
import sys
import tempfile
from pathlib import Path

try:
    import lief
except ImportError:
    print("Error: lief is required. Install with: pip install lief", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from post_process import (  # noqa: E402
    ELFCLASS32,
    ELFCLASS64,
    find_agent_elf_spans,
)

AGENT_ENTRYPOINT = "main"


def _elf_class_name(blob: bytes) -> str:
    if len(blob) < 5:
        return "unknown"
    if blob[4] == ELFCLASS64:
        return "64"
    if blob[4] == ELFCLASS32:
        return "32"
    return "unknown"


def _agent_entrypoint_symbols(binary: lief.ELF.Binary) -> list[str]:
    names: list[str] = []
    for symbol in binary.dynamic_symbols:
        if symbol.name in ("main", "frida_agent_main", "app_agent_main"):
            names.append(symbol.name)
    for symbol in binary.exported_symbols:
        if symbol.name in ("main", "frida_agent_main", "app_agent_main"):
            if symbol.name not in names:
                names.append(symbol.name)
    return names


def verify_server(path: Path) -> int:
    binary = lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        print(f"FAIL: not a valid ELF server binary: {path}")
        return 1

    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None:
        print("FAIL: .text section missing")
        return 1

    content = bytes(text.content)
    agents = find_agent_elf_spans(content)
    if not agents:
        print("FAIL: no embedded agent ELF blobs found")
        return 1

    errors = 0
    has_native_64 = False
    has_native_32 = False

    for start, end in agents:
        blob = content[start:end]
        bitness = _elf_class_name(blob)
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tmp:
            tmp.write(blob)
            tmp_path = tmp.name

        agent = lief.parse(tmp_path)
        Path(tmp_path).unlink(missing_ok=True)
        if agent is None or not isinstance(agent, lief.ELF.Binary):
            print(f"FAIL: agent at .text+0x{start:x} ({bitness}-bit) is not parseable")
            errors += 1
            continue

        syms = _agent_entrypoint_symbols(agent)
        label = f".text+0x{start:x} ({bitness}-bit, {len(blob) // 1024}KB)"
        if AGENT_ENTRYPOINT not in syms:
            print(
                f"FAIL: {label} missing export '{AGENT_ENTRYPOINT}' "
                f"(found: {syms or 'none'})"
            )
            errors += 1
        elif "frida_agent_main" in syms:
            print(f"FAIL: {label} still exports frida_agent_main")
            errors += 1
        else:
            print(f"OK: {label} entrypoint={AGENT_ENTRYPOINT}")

        if bitness == "64":
            has_native_64 = True
        elif bitness == "32":
            has_native_32 = True

    if not has_native_64:
        print("FAIL: missing native 64-bit embedded agent (frida-agent-64.so)")
        errors += 1
    if not has_native_32:
        print("FAIL: missing native 32-bit embedded agent (frida-agent-32.so)")
        errors += 1

    if errors:
        print(f"\n{errors} verification error(s)")
        return 1

    print("\nAll embedded agents verified.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=Path, help="Path to frida-server-processed")
    args = parser.parse_args()
    if not args.server.is_file():
        print(f"FAIL: file not found: {args.server}", file=sys.stderr)
        sys.exit(1)
    sys.exit(verify_server(args.server))


if __name__ == "__main__":
    main()
