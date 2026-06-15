#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_patterns.py -- Build cross-version AOB patterns from context JSON dumps

Iterates all version_files/*_context.json files.  For each address name that
appears in 2+ version files, combines context_before + context_after (256 bytes
total) byte-by-byte: bytes that agree across every version are kept as-is;
bytes that differ become ??.

Output JSON:
  {
    "animSpeed": { "pattern": "XX XX ?? ...", "offset": N },
    ...
  }

The offset equals the context size N (default 128).  With --context 512 the
offset will be 512.  Mixed-size context JSONs are trimmed to the smallest N.

Usage:
  python build_patterns.py
  python build_patterns.py --output my_patterns.json
  python build_patterns.py --min-versions 1
"""

import argparse
import json
from pathlib import Path


def parse_hex_bytes(hex_str: str) -> list[int]:
    return [int(b, 16) for b in hex_str.split()]


def build_pattern(all_byte_rows: list[list[int]]) -> str:
    """Return a space-separated pattern string; '??' where rows disagree."""
    length = len(all_byte_rows[0])
    parts: list[str] = []
    for i in range(length):
        vals = {row[i] for row in all_byte_rows}
        parts.append(f"{next(iter(vals)):02X}" if len(vals) == 1 else "??")
    return " ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build cross-version AOB patterns")
    parser.add_argument("--output", type=Path, default=Path("patterns.json"),
                        help="Output JSON file (default: patterns.json)")
    parser.add_argument("--min-versions", type=int, default=2,
                        help="Minimum number of versions an address must appear in (default: 2)")
    parser.add_argument("--filter", metavar="NAME", nargs="+",
                        help="Only rebuild patterns for these named addresses; "
                             "all other existing entries are left unchanged")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    context_files = sorted((script_dir / "version_files").glob("*_context.json"))

    if not context_files:
        raise SystemExit("No *_context.json files found in version_files/")

    # Load all version dumps
    version_data: dict[str, dict] = {}
    for path in context_files:
        version_name = path.stem.replace("_context", "")
        with path.open() as fh:
            version_data[version_name] = json.load(fh)
    print(f"Loaded {len(version_data)} version files: {', '.join(sorted(version_data))}")

    # Load existing output to preserve manually set fields (e.g. match_index)
    existing: dict = {}
    if args.output.exists():
        try:
            with args.output.open() as fh:
                existing = json.load(fh)
        except Exception:
            pass

    # Find all address names and group by name
    all_names: set[str] = set()
    for data in version_data.values():
        all_names.update(data)

    filter_names: set[str] | None = set(args.filter) if args.filter else None

    output: dict = {}
    skipped = 0

    for name in sorted(all_names):
        if filter_names is not None and name not in filter_names:
            continue
        rows: list[list[int]] = []
        for data in version_data.values():
            entry = data.get(name)
            if not entry:
                continue
            before_str = entry.get("context_before") or ""
            after_str = entry.get("context_after") or ""
            if not before_str or not after_str:
                continue
            before = parse_hex_bytes(before_str)
            after = parse_hex_bytes(after_str)
            if not before or not after or len(before) != len(after):
                continue
            rows.append((before, after))

        if len(rows) < args.min_versions:
            skipped += 1
            continue

        # Use the smallest context size across all versions so mixed-size
        # JSONs (captured with different --context values) still work.
        ctx_size = min(len(b) for b, _ in rows)
        combined = [b[:ctx_size] + a[:ctx_size] for b, a in rows]
        entry: dict = {
            "pattern": build_pattern(combined),
            "offset": ctx_size,
            "versions": len(rows),
        }
        # Preserve manually-set fields from the existing patterns.json
        if name in existing:
            ex = existing[name]
            for field in ("match_index", "skip", "pointer_scan", "data_pattern",
                          "pointer_index", "relative_to", "constant"):
                if field in ex:
                    entry[field] = ex[field]
            # If the existing entry has no AOB pattern (it's relative_to or
            # constant), keep the existing entry entirely and just update versions.
            if "pattern" not in ex:
                entry = {**ex, "versions": len(rows)}
        output[name] = entry

    # Preserve any existing entries that had no context data (constants,
    # pointer_scan entries without a matching context, skip entries, etc.)
    for name, ex in existing.items():
        if name not in output:
            output[name] = ex

    with args.output.open("w") as fh:
        json.dump(output, fh, indent=2)

    aob_entries = [p for p in output.values() if "pattern" in p]
    wildcard_counts = [p["pattern"].split().count("??") for p in aob_entries]
    avg_wc = sum(wildcard_counts) / len(wildcard_counts) if wildcard_counts else 0
    pat_len = len(aob_entries[0]["pattern"].split()) if aob_entries else 0
    print(f"Generated {len(output)} entries ({len(aob_entries)} AOB, skipped {skipped} with <{args.min_versions} versions)")
    print(f"Average wildcards per AOB pattern: {avg_wc:.1f} / {pat_len}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
