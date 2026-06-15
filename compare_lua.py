#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compare_lua.py -- Compare two KH1 Lua address files

Prints a single list of all entries that don't match between the two files.
Entries that match exactly are not shown.

Usage:
  python compare_lua.py version_files/EGSGlobal_1_0_0_10.lua scan_results.lua
  python compare_lua.py a.lua b.lua --patterns my_patterns.json
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Lua parser
# ---------------------------------------------------------------------------

def parse_lua(path: Path) -> dict[str, int | list[int] | None]:
    """
    Parse a KH1 Lua address file.
    Returns name -> value where value is:
      int        for scalar addresses / integers
      list[int]  for array entries
      None       for nil
    """
    result: dict = {}
    in_array = False
    array_name = ""
    array_values: list[int] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        # Strip inline comments before processing
        code = re.sub(r"\s*--.*$", "", raw).strip()
        if not code:
            continue

        if not in_array:
            # Array start
            m = re.match(r"(\w+)\s*=\s*\{(.*)", code)
            if m:
                array_name = m.group(1)
                in_array = True
                array_values = []
                rest = m.group(2)
                array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", rest))
                if "}" in rest:
                    result[array_name] = list(array_values)
                    in_array = False
                continue

            # Scalar: address, integer, or nil
            m = re.match(r"(\w+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+|nil)\s*$", code)
            if m:
                name, val_str = m.group(1), m.group(2)
                if val_str == "nil":
                    result[name] = None
                elif val_str.startswith("0x"):
                    result[name] = int(val_str, 16)
                else:
                    result[name] = int(val_str)

        else:  # inside array
            array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", code))
            if "}" in code:
                result[array_name] = list(array_values)
                in_array = False
                array_name = ""
                array_values = []

    return result


# ---------------------------------------------------------------------------
# Value formatting
# ---------------------------------------------------------------------------

def fmt(val: int | list[int] | None) -> str:
    if val is None:
        return "nil"
    if isinstance(val, list):
        inner = ", ".join(f"0x{v:X}" for v in val)
        return f"{{ {inner} }}"
    return f"0x{val:X}"


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def load_skip_set(patterns_path: Path) -> set[str]:
    """Return the set of names that have "skip": true in patterns.json."""
    if not patterns_path.exists():
        return set()
    try:
        data = json.loads(patterns_path.read_text(encoding="utf-8"))
        return {name for name, entry in data.items() if entry.get("skip")}
    except (json.JSONDecodeError, AttributeError):
        return set()


def compare(
    a: dict, b: dict, skip_set: set[str] = frozenset()
) -> tuple[list, list, list, list, list, list]:
    """
    Returns (matches, differs, one_nil, only_a, only_b, skipped).
    Each entry:
      matches / only_a / only_b -> name
      differs / one_nil / skipped -> (name, val_a, val_b)
    """
    all_keys = sorted(set(a) | set(b))
    matches, differs, one_nil, only_a, only_b, skipped = [], [], [], [], [], []

    for key in all_keys:
        in_a, in_b = key in a, key in b
        va = a.get(key)
        vb = b.get(key)

        if key in skip_set:
            skipped.append((key, va, vb))
            continue

        if not in_a:
            only_b.append(key)
        elif not in_b:
            only_a.append(key)
        else:
            if va == vb:
                matches.append(key)
            elif va is None or vb is None:
                one_nil.append((key, va, vb))
            else:
                differs.append((key, va, vb))

    return matches, differs, one_nil, only_a, only_b, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare two KH1 Lua address files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file_a", type=Path, help="First Lua file")
    parser.add_argument("file_b", type=Path, help="Second Lua file")
    parser.add_argument(
        "--patterns", type=Path, default=Path("patterns.json"),
        help="Path to patterns.json for skip detection (default: patterns.json)",
    )
    args = parser.parse_args()

    a = parse_lua(args.file_a)
    b = parse_lua(args.file_b)
    name_a = args.file_a.name
    name_b = args.file_b.name

    skip_set = load_skip_set(args.patterns)
    matches, differs, one_nil, only_a, only_b, skipped = compare(a, b, skip_set)

    col = max((len(k) for k in set(a) | set(b)), default=20) + 2
    _MISSING = object()

    def fmt_cell(val):
        return "(missing)" if val is _MISSING else fmt(val)

    mismatches = []
    for name, va, vb in differs:
        mismatches.append((name, va, vb))
    for name, va, vb in one_nil:
        mismatches.append((name, va, vb))
    for name in only_a:
        mismatches.append((name, a[name], _MISSING))
    for name in only_b:
        mismatches.append((name, _MISSING, b[name]))

    mismatches.sort(key=lambda x: x[0])

    total = len(matches) + len(mismatches)
    print(f"Match: {len(matches)}/{total}    Mismatch: {len(mismatches)}/{total}")

    if mismatches:
        print()
        print(f"  {'name':<{col}} {name_a:<24}  {name_b}")
        print(f"  {'-'*col} {'-'*24}  {'-'*24}")
        for name, va, vb in mismatches:
            print(f"  {name:<{col}} {fmt_cell(va):<24}  {fmt_cell(vb)}")


if __name__ == "__main__":
    main()
