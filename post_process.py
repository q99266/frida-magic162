#!/usr/bin/env python3
"""
Post-process frida-server ELF binary to remove detection signatures.

Modifications performed:
  1. Rename exported symbol 'frida_agent_main' to a random name
  2. Scan and replace static strings containing 'frida', 'gumjs', 'gum'
     (case-insensitive) with random strings of the same length
  3. Remove .comment section if present
  4. Remove debug info sections (.debug_*)

Requires: lief (pip install lief)
"""

import argparse
import logging
import random
import string
import struct
import sys
import tempfile
from pathlib import Path

try:
    import lief
except ImportError:
    print("Error: lief is required. Install with: pip install lief", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("post_process")

# Strings to scrub from the binary (case-insensitive)
# NOTE: Only scrub in .rodata section to avoid breaking GType internal lookups
FRIDA_PATTERNS = ["frida", "gumjs"]

# Targeted replacement rules for runtime-detectable strings
# Each rule: (pattern_bytes, replacement_bytes)
# Applied only to .rodata section, case-sensitive
# IMPORTANT: Longer patterns MUST come before shorter patterns to avoid partial matches
# Repair zymbiote socket_path placeholders split by shortening /frida-zymbiote- -> /app-zymbiote-.
# Must stay equal-length so embedded ELF layout is unchanged.
PLACEHOLDER_ZEROS = b"0" * 32
ZYMBIOTE_PLACEHOLDER_REPAIRS = [
    (
        b"/app-zymbiote-\x00\x00" + PLACEHOLDER_ZEROS,
        b"/app-zymbiote-" + PLACEHOLDER_ZEROS + b"\x00\x00",
    ),
    (
        b"/app-zymbiote-\x00" + PLACEHOLDER_ZEROS + b"\x00",
        b"/app-zymbiote-" + PLACEHOLDER_ZEROS + b"\x00\x00",
    ),
    (
        b"/app-zymbiote-\x00" + PLACEHOLDER_ZEROS,
        b"/app-zymbiote-" + PLACEHOLDER_ZEROS + b"\x00",
    ),
]

# find_class() uses re/frida/HelperBackend; /frida/ -> /app/ breaks it to re/app/\0\0HelperBackend.
JNI_HELPER_REPAIRS = [
    (b"re/app/\x00\x00HelperBackend", b"re/frida/HelperBackend"),
]

# Equal-length scrub for embedded dex blobs and debug assert paths (.text + .rodata).
EMBEDDED_STRING_REPLACEMENTS = [
    (b"/data/local/tmp/frida-helper-", b"/data/local/tmp/app-helper-\x00\x00"),
    (b"/frida-helper-", b"/app-helper-\x00\x00"),
    (b"Usage: frida-helper", b"Usage: app-helper  "),
    (b"-frida", b"-build"),
]

DEBUG_PATH_REPLACEMENTS = [
    (b"frida-core", b"app-core\x00\x00"),
    (b"frida-gum", b"app-gum\x00\x00"),
    (b"/__w/frida/frida/", b"/__w/app/magic/\x00\x00"),
]

DEX_MAGIC = b"dex\n035"
ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
PT_LOAD = 1
MIN_AGENT_BLOB_SIZE = 1_000_000
AGENT_MAIN_NAMES = (b"app_agent_main", b"frida_agent_main")
DEFAULT_HELPER_DEX = (
    Path(__file__).resolve().parent
    / "frida-core/src/droidy/helper/build/helper.dex"
)

TARGETED_REPLACEMENTS = [
    # Long patterns first (sorted by length, longest first)
    (b"frida-selinux-error-quark", b"app-selinux-error-quark"),
    (b"frida-error-quark",         b"app-error-quark"),
    (b"frida-json-root",           b"app-json-root"),
    (b"frida-context",             b"app-context"),
    (b"frida-server",              b"app-server"),
    (b"frida-helper",              b"app-helper"),
    (b"frida-agent",               b"app-agent"),
    (b"frida-gadget",              b"app-gadget"),
    (b"frida-inject",              b"app-inject"),
    (b"frida-portal",              b"app-portal"),
    (b"frida-selinux",             b"app-selinux"),
    (b"frida-ctrl",                b"app-ctrl"),
    (b"/re/frida/",                b"/re/nginx/"),
    (b"re.frida.",                 b"re.nginx."),
    # Do NOT replace bare re/frida/ — JNI still loads re.frida.HelperBackend from dex.
    (b"frida:rpc",                 b"nginx:rpc"),
    (b"frida:stdout",              b"app:stdout"),
    (b"frida:stderr",              b"app:stderr"),
    # Do NOT replace /frida/ -> /app/ — it corrupts JNI path re/frida/HelperBackend.
]


def random_name(length: int) -> str:
    """Generate a random alphanumeric string of the given length."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def matches_frida_pattern(data: bytes) -> bool:
    """Return True if the byte string contains any frida-related pattern (case-insensitive)."""
    try:
        text = data.decode("ascii", errors="ignore").lower()
    except Exception:
        return False
    return any(pat in text for pat in FRIDA_PATTERNS)


def rename_agent_main(binary, dry_run: bool) -> int:
    """
    Rename the exported symbol 'frida_agent_main' to a random 16-char name.
    Returns the number of symbols renamed.
    """
    renamed = 0
    new_name = None

    for sym in binary.exported_symbols:
        if sym.name == "frida_agent_main":
            if dry_run:
                if new_name is None:
                    new_name = random_name(16)
                log.info("[dry-run] Would rename exported symbol 'frida_agent_main' -> '%s'", new_name)
            else:
                if new_name is None:
                    new_name = random_name(16)
                log.info("Renaming exported symbol 'frida_agent_main' -> '%s'", new_name)
                sym.name = new_name
            renamed += 1

    # Also check dynamic_symbols as a fallback
    for sym in binary.dynamic_symbols:
        if sym.name == "frida_agent_main":
            if dry_run:
                if new_name is None:
                    new_name = random_name(16)
                log.info("[dry-run] Would rename dynamic symbol 'frida_agent_main' -> '%s'", new_name)
            else:
                if new_name is None:
                    new_name = random_name(16)
                log.info("Renaming dynamic symbol 'frida_agent_main' -> '%s'", new_name)
                sym.name = new_name
            renamed += 1

    if renamed == 0:
        log.warning("Symbol 'frida_agent_main' not found in exported/dynamic symbols")

    return renamed


def scrub_strings(binary, dry_run: bool) -> int:
    """
    Scan .rodata section for static strings matching frida-related patterns.
    Replace matching substrings with random characters of the same length.

    Only targets .rodata to avoid breaking GType internal class name lookups.

    Returns the number of replacements made.
    """
    replacements = 0

    # Only scrub .rodata section - safe for external strings
    # Skip .text/.data/etc to preserve GType internal type names
    target_sections = [".rodata"]

    for section in binary.sections:
        name = section.name
        if name not in target_sections:
            continue

        content = bytes(section.content)

        # Quick check before expensive scan
        try:
            text_lower = content.decode("ascii", errors="ignore").lower()
        except Exception:
            continue

        if not any(pat in text_lower for pat in FRIDA_PATTERNS):
            continue

        # Work on a mutable copy
        mutable = bytearray(content)

        for pat in FRIDA_PATTERNS:
            pat_bytes = pat.encode("ascii")
            pat_lower = pat.lower().encode("ascii")
            pat_len = len(pat_bytes)

            # Scan for case-insensitive matches
            i = 0
            while i <= len(mutable) - pat_len:
                chunk = bytes(mutable[i : i + pat_len]).lower()
                if chunk == pat_lower:
                    replacement = random_name(pat_len).encode("ascii")
                    if dry_run:
                        original = bytes(mutable[i : i + pat_len])
                        log.info(
                            "[dry-run] Section '%s' offset 0x%x: '%s' -> '%s'",
                            name, i, original.decode("ascii", errors="replace"),
                            replacement.decode("ascii"),
                        )
                    else:
                        mutable[i : i + pat_len] = replacement
                        log.debug(
                            "Section '%s' offset 0x%x: replaced %d bytes",
                            name, i, pat_len,
                        )
                    replacements += 1
                    i += pat_len  # skip past the replacement
                else:
                    i += 1

        # Write back the modified content
        if not dry_run and mutable != bytearray(content):
            # lief requires setting content as a list of ints
            section.content = list(mutable)

    return replacements


def remove_section(binary, section_name: str, dry_run: bool) -> bool:
    """Remove a section by name if it exists. Returns True if removed."""
    for section in binary.sections:
        if section.name == section_name:
            if dry_run:
                log.info("[dry-run] Would remove section '%s' (size=%d)", section_name, section.size)
            else:
                log.info("Removing section '%s' (size=%d)", section_name, section.size)
                binary.remove_section(section_name)
            return True
    return False


def remove_debug_sections(binary, dry_run: bool) -> int:
    """Remove all .debug_* sections. Returns count of removed sections."""
    debug_sections = [s.name for s in binary.sections if s.name.startswith(".debug_")]

    if not debug_sections:
        log.info("No .debug_* sections found")
        return 0

    removed = 0
    # Remove in reverse order to avoid index shifting issues
    for sec_name in reversed(debug_sections):
        if dry_run:
            log.info("[dry-run] Would remove debug section '%s'", sec_name)
        else:
            log.info("Removing debug section '%s'", sec_name)
            binary.remove_section(sec_name)
        removed += 1

    return removed


def repair_zymbiote_placeholders(binary, dry_run: bool) -> int:
    """
    Fix split zymbiote socket_path strings in embedded helper ELF blobs.

    The blobs live in .text; targeted .rodata rules do not reach them.
    """
    repairs = 0

    for section_name in (".text", ".rodata"):
        for section in binary.sections:
            if section.name != section_name:
                continue

            content = bytes(section.content)
            mutable = bytearray(content)
            section_repairs = 0

            for pattern, replacement in ZYMBIOTE_PLACEHOLDER_REPAIRS:
                if len(pattern) != len(replacement):
                    log.warning(
                        "Skipping zymbiote repair: pattern/replacement length mismatch (%d vs %d)",
                        len(pattern),
                        len(replacement),
                    )
                    continue

                i = 0
                while i <= len(mutable) - len(pattern):
                    if mutable[i : i + len(pattern)] == pattern:
                        if dry_run:
                            log.info(
                                "[dry-run] %s offset 0x%x: repair zymbiote placeholder",
                                section_name,
                                i,
                            )
                        else:
                            mutable[i : i + len(replacement)] = replacement
                        section_repairs += 1
                        i += len(pattern)
                    else:
                        i += 1

            if not dry_run and mutable != bytearray(content):
                section.content = list(mutable)
            repairs += section_repairs

    return repairs


def repair_jni_helper_strings(binary, dry_run: bool) -> int:
    """Restore JNI find_class path corrupted by legacy /frida/ -> /app/ scrub."""
    repairs = 0

    for section in binary.sections:
        if section.name != ".rodata":
            continue

        content = bytes(section.content)
        mutable = bytearray(content)
        section_repairs = 0

        for pattern, replacement in JNI_HELPER_REPAIRS:
            if len(pattern) != len(replacement):
                log.warning(
                    "Skipping JNI repair: pattern/replacement length mismatch (%d vs %d)",
                    len(pattern),
                    len(replacement),
                )
                continue

            i = 0
            while i <= len(mutable) - len(pattern):
                if mutable[i : i + len(pattern)] == pattern:
                    if dry_run:
                        log.info("[dry-run] .rodata offset 0x%x: repair JNI helper path", i)
                    else:
                        mutable[i : i + len(replacement)] = replacement
                    section_repairs += 1
                    i += len(pattern)
                else:
                    i += 1

        if not dry_run and mutable != bytearray(content):
            section.content = list(mutable)
        repairs += section_repairs

    return repairs


def _apply_equal_length_replacements(
    mutable: bytearray,
    replacements: list[tuple[bytes, bytes]],
    dry_run: bool,
    section_name: str,
    label: str,
) -> int:
    count = 0
    for pattern, replacement in replacements:
        if len(pattern) != len(replacement):
            log.warning(
                "Skipping %s rule: length mismatch (%d vs %d)",
                label,
                len(pattern),
                len(replacement),
            )
            continue

        i = 0
        while i <= len(mutable) - len(pattern):
            if mutable[i : i + len(pattern)] == pattern:
                if dry_run:
                    log.info(
                        "[dry-run] %s %s offset 0x%x: %s",
                        label,
                        section_name,
                        i,
                        pattern.decode("ascii", errors="replace"),
                    )
                else:
                    mutable[i : i + len(replacement)] = replacement
                count += 1
                i += len(pattern)
            else:
                i += 1
    return count


def scrub_embedded_strings(binary, dry_run: bool) -> int:
    """Patch version strings in .text and .rodata, skipping the embedded dex blob."""
    repairs = 0

    for section_name in (".text", ".rodata"):
        for section in binary.sections:
            if section.name != section_name:
                continue

            content = bytes(section.content)
            mutable = bytearray(content)
            skip_ranges = collect_text_skip_ranges(content) if section_name == ".text" else []
            section_repairs = _apply_equal_length_replacements_skip_ranges(
                mutable,
                EMBEDDED_STRING_REPLACEMENTS,
                dry_run,
                section_name,
                "embedded",
                skip_ranges,
            )

            if not dry_run and mutable != bytearray(content):
                section.content = list(mutable)
            repairs += section_repairs

    return repairs


def find_helper_dex_span(content: bytes) -> tuple[int, int] | None:
    """Return (start, end) slice bounds for an embedded dex blob inside a section."""
    idx = content.find(DEX_MAGIC)
    if idx < 0 or idx + 36 > len(content):
        return None

    file_size = int.from_bytes(content[idx + 32 : idx + 36], "little")
    if file_size <= 0 or idx + file_size > len(content):
        return None

    return idx, idx + file_size


def _elf64_span(content: bytes, start: int) -> tuple[int, int] | None:
    if start + 64 > len(content) or content[start : start + 4] != ELF_MAGIC:
        return None
    if content[start + 4] != ELFCLASS64:
        return None

    e_phoff = struct.unpack("<Q", content[start + 32 : start + 40])[0]
    e_phnum = struct.unpack("<H", content[start + 56 : start + 58])[0]
    e_phentsize = struct.unpack("<H", content[start + 54 : start + 56])[0]
    if e_phoff == 0 or e_phnum == 0:
        return None

    max_off = 0
    for p in range(min(e_phnum, 64)):
        ph = start + e_phoff + p * e_phentsize
        if ph + 56 > len(content):
            break
        p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack(
            "<IIQQQQQQ", content[ph : ph + 56]
        )
        if p_type == PT_LOAD:
            max_off = max(max_off, p_offset + p_filesz)

    if max_off < 4096:
        return None

    end = start + max_off
    if end > len(content):
        return None

    return start, end


def _elf32_span(content: bytes, start: int) -> tuple[int, int] | None:
    if start + 52 > len(content) or content[start : start + 4] != ELF_MAGIC:
        return None
    if content[start + 4] != ELFCLASS32:
        return None

    e_phoff = struct.unpack("<I", content[start + 28 : start + 32])[0]
    e_phnum = struct.unpack("<H", content[start + 44 : start + 46])[0]
    e_phentsize = struct.unpack("<H", content[start + 42 : start + 44])[0]
    if e_phoff == 0 or e_phnum == 0:
        return None

    max_off = 0
    for p in range(min(e_phnum, 64)):
        ph = start + e_phoff + p * e_phentsize
        if ph + 32 > len(content):
            break
        p_type = struct.unpack("<I", content[ph : ph + 4])[0]
        p_offset = struct.unpack("<I", content[ph + 4 : ph + 8])[0]
        p_filesz = struct.unpack("<I", content[ph + 16 : ph + 20])[0]
        if p_type == PT_LOAD:
            max_off = max(max_off, p_offset + p_filesz)

    if max_off < 4096:
        return None

    end = start + max_off
    if end > len(content):
        return None

    return start, end


def find_embedded_elf_spans(content: bytes) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    idx = 0
    while True:
        i = content.find(ELF_MAGIC, idx)
        if i < 0:
            break
        for span_fn in (_elf64_span, _elf32_span):
            span = span_fn(content, i)
            if span is not None:
                spans.append(span)
                break
        idx = i + 4
    return merge_skip_ranges(spans)


def _looks_like_agent_blob(blob: bytes) -> bool:
    if len(blob) < MIN_AGENT_BLOB_SIZE:
        return False
    if any(name in blob for name in AGENT_MAIN_NAMES):
        return True
    if b"JNI_OnLoad" not in blob:
        return False
    return b"gum" in blob or b"GumJS" in blob or b"frida-" in blob or b"app-" in blob


def find_agent_elf_spans(content: bytes) -> list[tuple[int, int]]:
    agent_spans: list[tuple[int, int]] = []
    for start, end in find_embedded_elf_spans(content):
        blob = content[start:end]
        if _looks_like_agent_blob(blob):
            agent_spans.append((start, end))
    return agent_spans


def merge_skip_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r[0])
    merged = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def collect_text_skip_ranges(content: bytes) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    dex_span = find_helper_dex_span(content)
    if dex_span:
        ranges.append(dex_span)
    ranges.extend(find_embedded_elf_spans(content))
    return merge_skip_ranges(ranges)


def _position_in_skip_range(
    pos: int, length: int, skip_ranges: list[tuple[int, int]]
) -> tuple[int, int] | None:
    for start, end in skip_ranges:
        if pos + length > start and pos < end:
            return start, end
    return None


def _apply_equal_length_replacements_skip_range(
    mutable: bytearray,
    replacements: list[tuple[bytes, bytes]],
    dry_run: bool,
    section_name: str,
    label: str,
    skip_start: int | None,
    skip_end: int | None,
) -> int:
    count = 0
    for pattern, replacement in replacements:
        if len(pattern) != len(replacement):
            log.warning(
                "Skipping %s rule: length mismatch (%d vs %d)",
                label,
                len(pattern),
                len(replacement),
            )
            continue

        i = 0
        while i <= len(mutable) - len(pattern):
            if (
                skip_start is not None
                and skip_end is not None
                and i + len(pattern) > skip_start
                and i < skip_end
            ):
                i = skip_end
                continue

            if mutable[i : i + len(pattern)] == pattern:
                if dry_run:
                    log.info(
                        "[dry-run] %s %s offset 0x%x: %s",
                        label,
                        section_name,
                        i,
                        pattern.decode("ascii", errors="replace"),
                    )
                else:
                    mutable[i : i + len(replacement)] = replacement
                count += 1
                i += len(pattern)
            else:
                i += 1
    return count


def _apply_equal_length_replacements_skip_ranges(
    mutable: bytearray,
    replacements: list[tuple[bytes, bytes]],
    dry_run: bool,
    section_name: str,
    label: str,
    skip_ranges: list[tuple[int, int]],
) -> int:
    count = 0
    for pattern, replacement in replacements:
        if len(pattern) != len(replacement):
            log.warning(
                "Skipping %s rule: length mismatch (%d vs %d)",
                label,
                len(pattern),
                len(replacement),
            )
            continue

        i = 0
        while i <= len(mutable) - len(pattern):
            overlap = _position_in_skip_range(i, len(pattern), skip_ranges)
            if overlap is not None:
                i = overlap[1]
                continue

            if mutable[i : i + len(pattern)] == pattern:
                if dry_run:
                    log.info(
                        "[dry-run] %s %s offset 0x%x: %s",
                        label,
                        section_name,
                        i,
                        pattern.decode("ascii", errors="replace"),
                    )
                else:
                    mutable[i : i + len(replacement)] = replacement
                count += 1
                i += len(pattern)
            else:
                i += 1
    return count


def _read_pt_dynamic_filesz(blob: bytes) -> int | None:
    if len(blob) < 64 or blob[:4] != ELF_MAGIC:
        return None
    e_phoff = struct.unpack("<Q", blob[32:40])[0]
    e_phnum = struct.unpack("<H", blob[56:58])[0]
    e_phentsize = struct.unpack("<H", blob[54:56])[0]
    for p in range(e_phnum):
        ph = e_phoff + p * e_phentsize
        if ph + 56 > len(blob):
            break
        if struct.unpack("<I", blob[ph : ph + 4])[0] == 2:
            return struct.unpack("<Q", blob[ph + 32 : ph + 40])[0]
    return None


def _fix_elf_dynamic_consistency(blob: bytearray, target_filesz: int | None = None) -> None:
    """Restore PT_DYNAMIC filesz after lief rewrites (embedded agents may truncate SHDR)."""
    if len(blob) < 64 or blob[:4] != ELF_MAGIC:
        return

    e_phoff = struct.unpack("<Q", blob[32:40])[0]
    e_phnum = struct.unpack("<H", blob[56:58])[0]
    e_phentsize = struct.unpack("<H", blob[54:56])[0]
    e_shoff = struct.unpack("<Q", blob[40:48])[0]
    e_shentsize = struct.unpack("<H", blob[58:60])[0]
    e_shnum = struct.unpack("<H", blob[60:62])[0]

    sh_dynamic_size = None
    for n in range(e_shnum):
        sh = e_shoff + n * e_shentsize
        if sh + 40 > len(blob):
            break
        if struct.unpack("<I", blob[sh + 4 : sh + 8])[0] == 6:
            sh_dynamic_size = struct.unpack("<Q", blob[sh + 32 : sh + 40])[0]
            break

    filesz = target_filesz or sh_dynamic_size
    if filesz is None:
        return

    for p in range(e_phnum):
        ph = e_phoff + p * e_phentsize
        if ph + 56 > len(blob):
            break
        if struct.unpack("<I", blob[ph : ph + 4])[0] == 2:
            blob[ph + 32 : ph + 40] = struct.pack("<Q", filesz)
            log.debug("Synced PT_DYNAMIC filesz to 0x%x", filesz)
            break


def _revert_scrubs_in_agent_blob(blob: bytearray) -> int:
    revert_rules = [
        (b"app-core\x00\x00", b"frida-core"),
        (b"app-gum\x00\x00", b"frida-gum"),
        (b"/__w/app/magic/\x00\x00", b"/__w/frida/frida/"),
        (b"/data/local/tmp/app-helper-\x00\x00", b"/data/local/tmp/frida-helper-"),
        (b"/app-helper-\x00\x00", b"/frida-helper-"),
        (b"Usage: app-helper  ", b"Usage: frida-helper"),
        (b"-build", b"-frida"),
    ]
    reverted = 0
    for corrupted, original in revert_rules:
        if len(corrupted) != len(original):
            continue
        idx = 0
        while idx <= len(blob) - len(corrupted):
            if blob[idx : idx + len(corrupted)] == corrupted:
                blob[idx : idx + len(corrupted)] = original
                reverted += 1
                idx += len(corrupted)
            else:
                idx += 1
    return reverted


def _rename_agent_entrypoint_with_lief(blob: bytearray) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(blob)

    orig_pt_dynamic = _read_pt_dynamic_filesz(bytes(blob))

    try:
        agent_binary = lief.parse(tmp_path)
        if agent_binary is None:
            return False

        renamed = False
        for symbol in list(agent_binary.dynamic_symbols) + list(
            agent_binary.exported_symbols
        ):
            if symbol.name == "main":
                return True

        for old_name in AGENT_MAIN_NAMES:
            old_str = old_name.decode("ascii")
            for symbol in agent_binary.dynamic_symbols:
                if symbol.name == old_str:
                    log.info("Renaming dynamic symbol '%s' -> 'main'", old_str)
                    symbol.name = "main"
                    renamed = True
                    break
            if renamed:
                break
            for symbol in agent_binary.exported_symbols:
                if symbol.name == old_str:
                    log.info("Renaming exported symbol '%s' -> 'main'", old_str)
                    symbol.name = "main"
                    renamed = True
                    break
            if renamed:
                break

        if not renamed:
            return False

        agent_binary.write(tmp_path)
        patched = bytearray(Path(tmp_path).read_bytes())
        if len(patched) != len(blob):
            log.error(
                "Embedded agent size changed after lief rename (%d -> %d)",
                len(blob),
                len(patched),
            )
            sys.exit(1)

        _fix_elf_dynamic_consistency(patched, orig_pt_dynamic)
        blob[:] = patched
        return True
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def repair_embedded_agent_main(binary, dry_run: bool) -> int:
    """
    Rename app_agent_main/frida_agent_main -> main inside embedded agent ELF blobs.

  Both 32-bit and 64-bit embedded agents are repaired. The patched server
  injects with entrypoint "main" (see tools/apply-magic-patches.py). Uses lief
  so .gnu.hash stays consistent with dlsym('main'). Scrubs in steps 2d/2e skip
  embedded ELF spans; legacy blobs get scrub reverts here.
    """
    repairs = 0

    for section in binary.sections:
        if section.name != ".text":
            continue

        content = bytearray(section.content)
        modified = False
        for start, end in find_agent_elf_spans(bytes(content)):
            blob_size = end - start

            if dry_run:
                log.info(
                    "[dry-run] Would repair agent entrypoint in .text offset 0x%x (%d bytes)",
                    start,
                    blob_size,
                )
                repairs += 1
                continue

            agent_blob = bytearray(content[start:end])
            reverted = _revert_scrubs_in_agent_blob(agent_blob)
            if reverted:
                log.info(
                    "Reverted %d embedded scrub hits inside agent at .text offset 0x%x",
                    reverted,
                    start,
                )

            if not _rename_agent_entrypoint_with_lief(agent_blob):
                log.warning(
                    "No agent entrypoint symbol in embedded ELF at .text offset 0x%x",
                    start,
                )
                continue

            content[start:end] = agent_blob
            repairs += 1
            modified = True
            log.info(
                "Repaired agent entrypoint in .text offset 0x%x (%d bytes)",
                start,
                blob_size,
            )

        if modified and not dry_run:
            section.content = list(content)

    if repairs == 0:
        log.warning("No embedded agent ELF blobs found for entrypoint repair")

    return repairs


def repair_gum_tcc_prefix_offset(binary, dry_run: bool) -> int:
    """
    Fix gum_tcc_cmodule_load_header in embedded agent after /frida/ -> /app/ rename.

    Two sites in the load_header epilogue (agent .text ~+0xa0c270):
      1) ADRP+ADD x1 prefix pointer still aimed at base64, (was /frida/) not /app/
      2) ADD x0,x0,#7 should be #5 for the 5-char /app/ prefix
    """
    import struct

    text_sec = None
    for section in binary.sections:
        if section.name == ".text":
            text_sec = section
            break
    if text_sec is None:
        return 0

    content = bytearray(text_sec.content)
    agent_start, agent_end = 0, 0
    for start, end in find_embedded_elf_spans(bytes(content)):
        if end - start > agent_end - agent_start:
            agent_start, agent_end = start, end
    if agent_end <= agent_start:
        log.warning("No embedded agent ELF for gum tcc prefix repair")
        return 0

    agent = bytes(content[agent_start:agent_end])
    app_off = agent.find(b"/app/\x00")
    if app_off < 0:
        log.warning("'/app/' prefix string not found in embedded agent")
        return 0

    repairs = 0

    # Site 2: mov x0,x19; bl; cbz x0; add x0,x0,#7  (strip /app/ length)
    strip_rel = None
    for off in range(0, len(agent) - 16, 4):
        w_mov = struct.unpack_from("<I", agent, off)[0]
        w_bl = struct.unpack_from("<I", agent, off + 4)[0]
        w_cbz = struct.unpack_from("<I", agent, off + 8)[0]
        w_add = struct.unpack_from("<I", agent, off + 12)[0]
        if (w_mov & 0xFFE0FFE0) != (0xAA1303E0 & 0xFFE0FFE0):  # mov x0, x19
            continue
        if (w_bl & 0xFC000000) != 0x94000000:
            continue
        if (w_cbz & 0xFF000000) not in (0xB4000000, 0x34000000):
            continue
        if (w_add & 0xFF800000) != 0x91000000:
            continue
        if ((w_add >> 10) & 0xFFF) != 7:
            continue
        rd = w_add & 0x1F
        rn = (w_add >> 5) & 0x1F
        if rd != rn or rd != 0:
            continue
        strip_rel = agent_start + off + 12
        break

    if strip_rel is None:
        log.warning("gum tcc load_header ADD #7 site not found in embedded agent")
    else:
        old = struct.unpack_from("<I", content, strip_rel)[0]
        new = old - (7 << 10) + (5 << 10)
        # Compiler emits ADD x0,x0,#7 after prefix helper; must strip x19 (path).
        new = 0x91001673  # add x19, x19, #5
        if dry_run:
            log.info(
                "[dry-run] gum tcc strip: .text+0x%x ADD x0,#7 -> ADD x19,#5 (%#x -> %#x)",
                strip_rel,
                old,
                new,
            )
        else:
            struct.pack_into("<I", content, strip_rel, new)
            log.info(
                "gum tcc strip: .text+0x%x ADD x0,#7 -> ADD x19,#5 (%#x -> %#x)",
                strip_rel,
                old,
                new,
            )
        repairs += 1

        nop_rel = strip_rel + 12  # mov x19, x0 after bl using stripped path
        if strip_rel + 12 < agent_start + len(agent):
            nop_old = struct.unpack_from("<I", content, nop_rel)[0]
            if (nop_old & 0xFFE0FFE0) == (0xAA1303E0 & 0xFFE0FFE0):  # mov x19, x0
                if dry_run:
                    log.info("[dry-run] gum tcc strip: .text+0x%x NOP mov x19,x0", nop_rel)
                else:
                    struct.pack_into("<I", content, nop_rel, 0xD503201F)
                    log.info("gum tcc strip: .text+0x%x NOP mov x19,x0", nop_rel)
                repairs += 1

    # Site 1: ADRP x1; ADD x1,#imm; mov x0,x19 — repoint imm to /app/ string
    def adrp_page(pc: int, word: int) -> int:
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        return (pc & ~0xFFF) + (imm << 12)

    prefix_rel = None
    target_lo = None
    for off in range(0, len(agent) - 12, 4):
        w_adrp = struct.unpack_from("<I", agent, off)[0]
        w_add = struct.unpack_from("<I", agent, off + 4)[0]
        w_mov = struct.unpack_from("<I", agent, off + 8)[0]
        if (w_adrp & 0x9F000000) != 0x90000000:
            continue
        if (w_add & 0xFF800000) != 0x91000000:
            continue
        if (w_mov & 0xFFE0FFE0) != (0xAA1303E0 & 0xFFE0FFE0):  # mov x0, x19
            continue
        rd = w_add & 0x1F
        rn = (w_add >> 5) & 0x1F
        if rd != 1 or rn != 1:
            continue
        lo = (w_add >> 10) & 0xFFF
        page = adrp_page(off, w_adrp)
        if page + lo == app_off:
            continue  # already correct
        if lo != 0x5CC:
            continue  # load_header site uses #0x5cc (was base64, not /frida/)
        if (page + lo) & ~0xFFF != app_off & ~0xFFF:
            continue
        prefix_rel = agent_start + off + 4
        target_lo = app_off - page
        break

    if prefix_rel is None:
        log.warning(
            "gum tcc prefix pointer site not found (app string at agent+0x%x)",
            app_off,
        )
    else:
        old = struct.unpack_from("<I", content, prefix_rel)[0]
        new = (old & ~((0xFFF) << 10)) | (target_lo << 10)
        if dry_run:
            log.info(
                "[dry-run] gum tcc prefix ptr: .text+0x%x ADD imm %#x -> %#x",
                prefix_rel,
                (old >> 10) & 0xFFF,
                target_lo,
            )
        else:
            struct.pack_into("<I", content, prefix_rel, new)
            log.info(
                "gum tcc prefix ptr: .text+0x%x ADD imm %#x -> %#x",
                prefix_rel,
                (old >> 10) & 0xFFF,
                target_lo,
            )
        repairs += 1

    if repairs and not dry_run:
        text_sec.content = list(content)

    return repairs


def repair_devkit_runtime_strings(binary, dry_run: bool) -> int:
    """
    Revert DEBUG_PATH scrubs in .text (outside agent/dex blobs) so gum/js
    runtime resolves gum/guminterceptor.h for the Java bridge.
    .rodata scrubs are kept for static anti-detection.
    """
    revert_rules = [(new, old) for old, new in DEBUG_PATH_REPLACEMENTS]
    repairs = 0

    for section in binary.sections:
        if section.name != ".text":
            continue

        content = bytearray(section.content)
        skip_ranges = collect_text_skip_ranges(bytes(content))
        modified = False

        for corrupted, original in revert_rules:
            if len(corrupted) != len(original):
                continue
            i = 0
            while i <= len(content) - len(corrupted):
                overlap = _position_in_skip_range(i, len(corrupted), skip_ranges)
                if overlap:
                    i = overlap[1]
                    continue
                if content[i : i + len(corrupted)] == corrupted:
                    if dry_run:
                        log.info(
                            "[dry-run] devkit revert %r at .text+0x%x",
                            original.decode("ascii", errors="replace"),
                            i,
                        )
                    else:
                        content[i : i + len(corrupted)] = original
                    repairs += 1
                    modified = True
                    i += len(corrupted)
                else:
                    i += 1

        if not dry_run and modified:
            section.content = list(content)

    return repairs


def replace_embedded_helper_dex(binary, helper_dex_path: Path, dry_run: bool) -> bool:
    """
    Swap the embedded helper.dex blob with the patched file from disk.

    Runs after string scrubs so incidental replacements inside the dex cannot
    corrupt the JNI classpath the Android helper loads at runtime.
    """
    if not helper_dex_path.is_file():
        log.error("Helper dex not found: %s", helper_dex_path)
        return False

    helper = helper_dex_path.read_bytes()
    if not helper.startswith(DEX_MAGIC):
        log.error("Helper dex has invalid magic: %s", helper_dex_path)
        return False

    for section in binary.sections:
        if section.name != ".text":
            continue

        content = bytes(section.content)
        span = find_helper_dex_span(content)
        if span is None:
            continue

        start, end = span
        embedded_size = end - start
        if embedded_size != len(helper):
            log.warning(
                "Embedded dex size mismatch: blob=%d helper.dex=%d — "
                "rebuild frida-server after updating helper.dex",
                embedded_size,
                len(helper),
            )
            return False

        if dry_run:
            log.info(
                "[dry-run] Would replace embedded helper dex in .text at offset 0x%x (%d bytes)",
                start,
                len(helper),
            )
            return True

        new_content = content[:start] + helper + content[end:]
        section.content = list(new_content)
        log.info(
            "Replaced embedded helper dex in .text at offset 0x%x (%d bytes)",
            start,
            len(helper),
        )
        return True

    log.warning("No embedded helper dex found in .text")
    return False


def scrub_debug_paths(binary, dry_run: bool) -> int:
    """Replace Vala assert / CI path substrings that leak frida in binaries."""
    repairs = 0

    for section_name in (".text", ".rodata"):
        for section in binary.sections:
            if section.name != section_name:
                continue

            content = bytes(section.content)
            mutable = bytearray(content)
            skip_ranges = collect_text_skip_ranges(content) if section_name == ".text" else []
            section_repairs = _apply_equal_length_replacements_skip_ranges(
                mutable,
                DEBUG_PATH_REPLACEMENTS,
                dry_run,
                section_name,
                "debug-path",
                skip_ranges,
            )

            if not dry_run and mutable != bytearray(content):
                section.content = list(mutable)
            repairs += section_repairs

    return repairs


def targeted_scrub(binary, dry_run: bool) -> int:
    """
    Apply targeted string replacements in .rodata section.
    Replaces specific frida-related strings while preserving GType class names.

    For null-terminated strings, shorter replacements are safe (padded with null).
    Longer replacements are skipped to avoid corrupting the binary.

    Returns the number of replacements made.
    """
    replacements = 0

    for section in binary.sections:
        if section.name != ".rodata":
            continue

        content = bytes(section.content)
        mutable = bytearray(content)

        for pattern, replacement in TARGETED_REPLACEMENTS:
            if len(replacement) > len(pattern):
                log.warning("Skipping rule '%s' -> '%s': replacement longer than pattern",
                           pattern.decode(), replacement.decode())
                continue

            i = 0
            while i <= len(mutable) - len(pattern):
                if mutable[i:i+len(pattern)] == pattern:
                    if dry_run:
                        log.info("[dry-run] .rodata offset 0x%x: '%s' -> '%s'",
                                i, pattern.decode(), replacement.decode())
                    else:
                        # Write replacement, pad rest with nulls (for null-terminated strings)
                        mutable[i:i+len(replacement)] = replacement
                        if len(pattern) > len(replacement):
                            for j in range(i+len(replacement), i+len(pattern)):
                                mutable[j] = 0
                        log.debug(".rodata offset 0x%x: replaced %d bytes", i, len(pattern))
                    replacements += 1
                    i += len(pattern)
                else:
                    i += 1

        if not dry_run and mutable != bytearray(content):
            section.content = list(mutable)

    return replacements


def validate_elf(binary) -> bool:
    """Basic validation that the binary is still a valid ELF."""
    if binary is None:
        return False
    if not binary.segments and not binary.sections:
        log.error("Validation failed: no segments or sections remain")
        return False
    return True


def process_binary(
    input_path: str,
    output_path: str,
    dry_run: bool = False,
    helper_dex_path: Path | None = None,
):
    """Main entry point: load, transform, and save the binary."""

    log.info("Loading binary: %s", input_path)
    binary = lief.parse(input_path)

    if binary is None:
        log.error("Failed to parse ELF binary: %s", input_path)
        sys.exit(1)

    if not isinstance(binary, lief.ELF.Binary):
        log.error("Input is not an ELF binary: %s", input_path)
        sys.exit(1)

    log.info("Binary: %d sections, %d segments",
             len(list(binary.sections)), len(list(binary.segments)))

    # --- Step 1: Rename exported symbol ---
    log.info("--- Step 1: Rename frida_agent_main ---")
    renamed = rename_agent_main(binary, dry_run)
    log.info("Symbols processed: %d", renamed)

    # --- Step 2: Targeted string replacement ---
    # Replaces specific frida strings in .rodata while preserving GType class names
    log.info("--- Step 2: Targeted string replacement ---")
    scrubbed = targeted_scrub(binary, dry_run)
    log.info("Targeted replacements: %d", scrubbed)

    # --- Step 2b: Repair zymbiote placeholders in embedded helper blobs ---
    log.info("--- Step 2b: Repair zymbiote placeholders ---")
    zymbiote_repairs = repair_zymbiote_placeholders(binary, dry_run)
    log.info("Zymbiote placeholder repairs: %d", zymbiote_repairs)

    # --- Step 2c: Repair JNI helper class path ---
    log.info("--- Step 2c: Repair JNI helper class path ---")
    jni_repairs = repair_jni_helper_strings(binary, dry_run)
    log.info("JNI helper repairs: %d", jni_repairs)

    # --- Step 2d: Embedded dex / version string scrub ---
    log.info("--- Step 2d: Embedded string scrub ---")
    embedded_repairs = scrub_embedded_strings(binary, dry_run)
    log.info("Embedded string repairs: %d", embedded_repairs)

    # --- Step 2e: Debug path scrub ---
    log.info("--- Step 2e: Debug path scrub ---")
    debug_repairs = scrub_debug_paths(binary, dry_run)
    log.info("Debug path repairs: %d", debug_repairs)

    # --- Step 2g: Repair embedded agent entrypoint (app_agent_main -> main) ---
    log.info("--- Step 2g: Repair embedded agent entrypoint ---")
    agent_repairs = repair_embedded_agent_main(binary, dry_run)
    log.info("Embedded agent entrypoint repairs: %d", agent_repairs)

    # --- Step 2h: Fix gum tcc /app/ prefix offset (5 chars, not 7) ---
    log.info("--- Step 2h: Repair gum tcc /app/ prefix offset ---")
    gum_prefix_repairs = repair_gum_tcc_prefix_offset(binary, dry_run)
    log.info("Gum tcc prefix offset repairs: %d", gum_prefix_repairs)

    # --- Step 2i: Restore gum devkit paths in .text (legacy scrub revert) ---
    log.info("--- Step 2i: Repair gum devkit runtime strings ---")
    devkit_repairs = repair_devkit_runtime_strings(binary, dry_run)
    log.info("Devkit runtime string repairs: %d", devkit_repairs)

    # --- Step 2f: Replace embedded helper.dex with patched file ---
    log.info("--- Step 2f: Replace embedded helper.dex ---")
    dex_path = helper_dex_path or DEFAULT_HELPER_DEX
    if not replace_embedded_helper_dex(binary, dex_path, dry_run):
        log.warning(
            "Skipped embedded helper dex replacement (see warnings above)"
        )
    else:
        log.info("Embedded helper dex: OK (%s)", dex_path)

    # --- Step 3: Remove .comment section ---
    log.info("--- Step 3: Remove .comment section ---")
    removed_comment = remove_section(binary, ".comment", dry_run)
    if not removed_comment:
        log.info(".comment section not found (nothing to do)")

    # --- Step 4: Remove debug sections ---
    log.info("--- Step 4: Remove .debug_* sections ---")
    removed_debug = remove_debug_sections(binary, dry_run)
    log.info("Debug sections removed: %d", removed_debug)

    # --- Write output ---
    if dry_run:
        log.info("[dry-run] No changes written. Would write to: %s", output_path)
        return

    log.info("Validating modified binary...")
    if not validate_elf(binary):
        log.error("Modified binary failed validation -- aborting write")
        sys.exit(1)

    log.info("Writing modified binary: %s", output_path)
    binary.write(output_path)

    # Re-parse to double-check integrity
    log.info("Re-validating output binary...")
    check = lief.parse(output_path)
    if check is None or not isinstance(check, lief.ELF.Binary):
        log.error("Output binary failed re-validation!")
        sys.exit(1)

    log.info("Post-processing complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Post-process frida-server binary to remove detection signatures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="Path to the input ELF binary")
    parser.add_argument("output", help="Path to write the processed binary")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying the binary",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )
    parser.add_argument(
        "--helper-dex",
        type=Path,
        default=DEFAULT_HELPER_DEX,
        help="Patched helper.dex to embed (default: subprojects/.../helper.dex)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.input == args.output:
        log.error("Input and output paths must be different")
        sys.exit(1)

    process_binary(
        args.input,
        args.output,
        dry_run=args.dry_run,
        helper_dex_path=args.helper_dex,
    )


if __name__ == "__main__":
    main()
