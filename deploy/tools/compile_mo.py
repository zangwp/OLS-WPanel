#!/usr/bin/env python3
"""Compile the project's simple gettext PO catalog using the Python stdlib."""

from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path


def read_catalog(path: Path) -> dict[str, str]:
    catalog: dict[str, str] = {}
    current: str | None = None
    msgid = ""
    msgstr = ""
    fuzzy = False
    entry_seen = False

    def finish() -> None:
        nonlocal msgid, msgstr, fuzzy, entry_seen
        if entry_seen and msgstr and not fuzzy:
            if msgid in catalog:
                raise ValueError(f"duplicate msgid: {msgid!r}")
            catalog[msgid] = msgstr
        msgid = ""
        msgstr = ""
        fuzzy = False
        entry_seen = False

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines() + [""]:
        line = raw_line.strip()
        if not line:
            finish()
            current = None
            continue
        if line.startswith("#," ) and "fuzzy" in line:
            fuzzy = True
            continue
        if line.startswith("#"):
            continue
        if line.startswith("msgid "):
            current = "msgid"
            entry_seen = True
            msgid = ast.literal_eval(line[6:])
            continue
        if line.startswith("msgstr "):
            current = "msgstr"
            msgstr = ast.literal_eval(line[7:])
            continue
        if line.startswith('"'):
            value = ast.literal_eval(line)
            if current == "msgid":
                msgid += value
            elif current == "msgstr":
                msgstr += value
            continue
        raise ValueError(f"unsupported PO line: {raw_line}")
    return catalog


def compile_catalog(catalog: dict[str, str]) -> bytes:
    keys = sorted(catalog)
    ids = [key.encode("utf-8") for key in keys]
    translations = [catalog[key].encode("utf-8") for key in keys]
    count = len(keys)
    header_size = 7 * 4
    originals_table = header_size
    translations_table = originals_table + count * 8
    ids_offset = translations_table + count * 8

    ids_blob = b"\0".join(ids) + (b"\0" if ids else b"")
    translations_offset = ids_offset + len(ids_blob)
    translations_blob = b"\0".join(translations) + (b"\0" if translations else b"")

    original_entries = []
    cursor = ids_offset
    for value in ids:
        original_entries.append((len(value), cursor))
        cursor += len(value) + 1
    translation_entries = []
    cursor = translations_offset
    for value in translations:
        translation_entries.append((len(value), cursor))
        cursor += len(value) + 1

    output = bytearray(
        struct.pack(
            "<7I",
            0x950412DE,
            0,
            count,
            originals_table,
            translations_table,
            0,
            0,
        )
    )
    for entry in original_entries:
        output.extend(struct.pack("<2I", *entry))
    for entry in translation_entries:
        output.extend(struct.pack("<2I", *entry))
    output.extend(ids_blob)
    output.extend(translations_blob)
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} input.po output.mo", file=sys.stderr)
        return 2
    source = Path(sys.argv[1])
    target = Path(sys.argv[2])
    target.write_bytes(compile_catalog(read_catalog(source)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
