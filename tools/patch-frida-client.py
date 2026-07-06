#!/usr/bin/env python3
"""
Patch stock frida-python 16.2.1 to talk to anti-detection server (re.nginx / nginx:rpc).

Patches:
  1. _frida.pyd  — equal-length D-Bus namespace (re.frida -> re.nginx)
  2. core.py     — script RPC token (frida:rpc -> nginx:rpc)

Usage:
  python tools/patch-frida-client.py          # patch active frida install
  python tools/patch-frida-client.py --restore
  python tools/patch-frida-client.py --dry-run
"""
from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys
from pathlib import Path

PYD_REPLACEMENTS = [
    (b"re.frida.", b"re.nginx."),
    (b"re/frida/", b"re/nginx/"),
    (b"/re/frida/", b"/re/nginx/"),
]

CORE_REPLACEMENTS = [
    ('"frida:rpc"', '"nginx:rpc"'),
    ("'frida:rpc'", "'nginx:rpc'"),
]


def find_frida_package() -> Path:
    spec = importlib.util.find_spec("frida")
    if spec is None or not spec.origin:
        raise SystemExit("frida is not installed in this Python environment")
    return Path(spec.origin).resolve().parent


def find_frida_extension(frida_dir: Path) -> Path:
    """Frida 16.x: site-packages/_frida.pyd; Frida 17.x: site-packages/frida/_frida.pyd."""
    names = ("_frida.pyd", "_frida.so", "_frida.dylib")
    for base in (frida_dir.parent, frida_dir):
        for name in names:
            path = base / name
            if path.is_file():
                return path
    raise SystemExit(
        f"missing native extension under {frida_dir.parent} or {frida_dir} "
        f"(tried {', '.join(names)})"
    )


def count_pyd_markers(data: bytes) -> dict[str, int]:
    return {
        "re.frida.": data.count(b"re.frida."),
        "re/frida/": data.count(b"re/frida/"),
        "/re/frida/": data.count(b"/re/frida/"),
        "re.nginx.": data.count(b"re.nginx."),
        "re/nginx/": data.count(b"re/nginx/"),
        "/re/nginx/": data.count(b"/re/nginx/"),
    }


def patch_pyd(path: Path, dry_run: bool, output: Path | None = None) -> Path:
    data = bytearray(path.read_bytes())
    before = count_pyd_markers(data)
    print(f"  _frida.pyd before: {before}")

    if before["re.frida."] == 0 and before["re/frida/"] == 0 and before["/re/frida/"] == 0:
        if before["re.nginx."] > 0:
            print("  _frida.pyd already patched (re.nginx present)")
            if not dry_run and output and output != path:
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, output)
            return output or path
        raise SystemExit("  no re.frida markers found — unexpected frida build")

    for old, new in PYD_REPLACEMENTS:
        if len(old) != len(new):
            raise SystemExit(f"length mismatch: {old!r} vs {new!r}")
        data = data.replace(old, new)

    after = count_pyd_markers(data)
    print(f"  _frida.pyd after:  {after}")

    dest = output or path
    if not dry_run:
        if dest != path:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            print(f"  wrote patched extension: {dest}")
        else:
            dest.write_bytes(data)
    return dest


def patch_core(path: Path, dry_run: bool, output: Path | None = None) -> Path:
    text = path.read_text(encoding="utf-8")
    before = text.count("frida:rpc")
    nginx_before = text.count("nginx:rpc")
    print(f"  core.py before: frida:rpc={before}, nginx:rpc={nginx_before}")

    if before == 0 and nginx_before >= 2:
        print("  core.py already patched")
        if not dry_run and output and output != path:
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)
        return output or path
    if before < 2:
        raise SystemExit(f"  expected 2 frida:rpc occurrences, found {before}")

    for old, new in CORE_REPLACEMENTS:
        text = text.replace(old, new)

    nginx_after = text.count("nginx:rpc")
    print(f"  core.py after:  nginx:rpc={nginx_after}")

    dest = output or path
    if not dry_run:
        if dest != path:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", newline="\n")
            print(f"  wrote patched core.py: {dest}")
        else:
            dest.write_text(text, encoding="utf-8", newline="\n")
    return dest


def backup_file(path: Path, backup_dir: Path) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    dest = backup_dir / path.name
    if not dest.exists():
        shutil.copy2(path, dest)
        print(f"  backup: {dest}")


def restore_file(path: Path, backup_dir: Path) -> None:
    src = backup_dir / path.name
    if not src.exists():
        raise SystemExit(f"  missing backup: {src}")
    shutil.copy2(src, path)
    print(f"  restored: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Patch frida-python for re.nginx server")
    parser.add_argument("--dry-run", action="store_true", help="report only, do not write")
    parser.add_argument("--restore", action="store_true", help="restore from backup")
    parser.add_argument(
        "--frida-dir",
        type=Path,
        help="frida package directory (default: auto-detect via import)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="write patched artifacts here instead of overwriting site-packages",
    )
    args = parser.parse_args()

    frida_dir = args.frida_dir or find_frida_package()
    pyd_path = find_frida_extension(frida_dir)
    core_path = frida_dir / "core.py"
    backup_dir = frida_dir / ".frida-magic162-backup"
    out_dir = args.output_dir

    print(f"frida package: {frida_dir}")
    print(f"native extension: {pyd_path}")
    if not core_path.is_file():
        raise SystemExit(f"missing core.py: {core_path}")

    if args.restore:
        if out_dir:
            raise SystemExit("--restore cannot be used with --output-dir")
        print("Restoring stock client...")
        restore_file(pyd_path, backup_dir)
        restore_file(core_path, backup_dir)
        print("Done. Re-open your shell if frida was already imported.")
        return

    pyd_out = (out_dir / "_frida.pyd") if out_dir else None
    core_out = (out_dir / "core.py") if out_dir else None

    if not args.dry_run and not out_dir:
        backup_file(pyd_path, backup_dir)
        backup_file(core_path, backup_dir)

    print("Patching _frida.pyd...")
    patched_pyd = patch_pyd(pyd_path, args.dry_run, pyd_out)
    print("Patching core.py...")
    patched_core = patch_core(core_path, args.dry_run, core_out)

    if args.dry_run:
        print("Dry run complete — no files modified.")
    elif out_dir:
        shadow_pkg = out_dir / "frida"
        if shadow_pkg.exists():
            shutil.rmtree(shadow_pkg)
        shutil.copytree(frida_dir, shadow_pkg, ignore=shutil.ignore_patterns(
            ".frida-magic162-backup", "__pycache__", "*.pyc"
        ))
        shutil.copy2(patched_core, shadow_pkg / "core.py")
        shutil.copy2(patched_pyd, out_dir / pyd_path.name)
        typings = pyd_path.parent / "_frida"
        if typings.is_dir():
            shutil.copytree(typings, out_dir / "_frida", dirs_exist_ok=True)
        pkg_parent = out_dir.resolve()
        print()
        print("Patched shadow package written to:", pkg_parent)
        print("Layout: frida/ + _frida.pyd (sibling, required for Frida 16.x)")
        print("Use without touching site-packages:")
        print(f'  set PYTHONPATH={pkg_parent}')
        print("  frida-ps -H <host>:<port>")
        print("Or: .\\tools\\run-frida-patched.ps1 frida-ps -H <host>:<port>")
    else:
        print("Done. Test with: frida-ps -H <host>:<port>")
        print("Restore with: python tools/patch-frida-client.py --restore")


if __name__ == "__main__":
    main()
