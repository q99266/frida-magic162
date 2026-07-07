#!/usr/bin/env python3
"""Apply anti-detection source patches to Frida 16.2.1 frida-core submodule."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "frida-core"

FILES_RE_FRIDA = [
    CORE / "lib/base/session.vala",
    CORE / "src/linux/frida-helper-types.vala",
    CORE / "src/darwin/frida-helper-types.vala",
    CORE / "src/windows/frida-helper-types.vala",
]

APP_LISTEN_BLOCK = """
\t\tif (listen_address == null) {
\t\t\tlisten_address = GLib.Environment.get_variable ("APP_LISTEN");
\t\t}

"""

ENTRYPOINT_FILES = [
    CORE / "src/linux/linux-host-session.vala",
    CORE / "src/darwin/darwin-host-session.vala",
    CORE / "src/windows/windows-host-session.vala",
    CORE / "src/qnx/qnx-host-session.vala",
    CORE / "src/freebsd/freebsd-host-session.vala",
    CORE / "src/agent-container.vala",
]


def patch_re_frida(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    updated = text.replace("re.frida.", "re.nginx.").replace("/re/frida/", "/re/nginx/")
    if updated == text:
        print(f"skip (already patched): {path}")
        return
    path.write_text(updated, encoding="utf-8")
    print(f"patched: {path}")


def patch_agent_sources() -> None:
    """Patch agent/payload sources so embedded agents match re.nginx at build time."""
    agent_globs = [
        CORE / "lib/base/session.vala",
        CORE / "lib/agent/agent.vala",
        CORE / "lib/payload/portal-client.vala",
        CORE / "lib/payload/fork-monitor.vala",
    ]
    for path in agent_globs:
        if path.is_file():
            patch_re_frida(path)


def patch_server() -> None:
    path = CORE / "server/server.vala"
    if not path.is_file():
        print(f"skip missing: {path}")
        return
    text = path.read_text(encoding="utf-8")
    text = text.replace("re.frida.server", "re.nginx.server")
    if "APP_LISTEN" not in text:
        needle = "\t\tEnvironment.set_verbose_logging_enabled (verbose);"
        if needle not in text:
            sys.exit(f"APP_LISTEN anchor not found in {path}")
        text = text.replace(needle, APP_LISTEN_BLOCK + needle, 1)
    path.write_text(text, encoding="utf-8")
    print(f"patched: {path}")


def patch_agent_entrypoint(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if '"main"' in text and '"frida_agent_main"' not in text:
        print(f"skip (entrypoint already patched): {path}")
        return
    if '"frida_agent_main"' not in text:
        print(f"skip (no frida_agent_main): {path}")
        return
    path.write_text(text.replace('"frida_agent_main"', '"main"'), encoding="utf-8")
    print(f"patched entrypoint: {path}")


def main() -> None:
    if not (CORE / "lib/base").is_dir():
        sys.exit("frida-core submodule missing — run git submodule update --init --recursive")
    for f in FILES_RE_FRIDA:
        if f.is_file():
            patch_re_frida(f)
    patch_agent_sources()
    for f in ENTRYPOINT_FILES:
        if f.is_file():
            patch_agent_entrypoint(f)
    patch_server()
    print("Magic patches applied.")


if __name__ == "__main__":
    main()
