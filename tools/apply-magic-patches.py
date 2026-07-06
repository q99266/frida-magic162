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


def patch_re_frida(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "re.nginx." in text and "re.frida." not in text:
        print(f"skip (already patched): {path}")
        return
    path.write_text(text.replace("re.frida.", "re.nginx."), encoding="utf-8")
    print(f"patched: {path}")


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


def main() -> None:
    if not (CORE / "lib/base").is_dir():
        sys.exit("frida-core submodule missing — run git submodule update --init --recursive")
    for f in FILES_RE_FRIDA:
        if f.is_file():
            patch_re_frida(f)
    patch_server()
    print("Magic patches applied.")


if __name__ == "__main__":
    main()
