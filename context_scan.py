#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
context_scan.py -- Memory context capture for every address in a KH1 version file

Reads CONTEXT bytes before and after each address listed in a Lua version file
while the game is running, and writes the results to a JSON file for inspection.

Output format:
  {
    "entry_name": {
      "rva": "0xXXXXXX",
      "abs": "0x14XXXXXXXX",
      "section": ".data",
      "context_before": "XX XX XX ...",   // CONTEXT bytes before the address
      "context_after":  "XX XX XX ..."    // CONTEXT bytes starting at the address
    }
  }

Array entries produce "entry_name[0]", "entry_name[1]", etc.

Examples:
  python context_scan.py --lua version_files/EGSGlobal_1_0_0_10.lua
  python context_scan.py --lua version_files/EGSGlobal_1_0_0_10.lua --context 64
  python context_scan.py --lua version_files/EGSGlobal_1_0_0_10.lua --output my_dump.json
"""

import argparse
import json
import re
import struct
import sys
from pathlib import Path
from typing import Optional

try:
    import pymem
    import pymem.process
    import pymem.exception
except ImportError:
    sys.exit("pymem not installed -- run:  pip install pymem")

PROCESS_NAME = "KINGDOM HEARTS FINAL MIX.exe"
ADDRESS_THRESHOLD = 0x10000
DEFAULT_CONTEXT = 128


# ---------------------------------------------------------------------------
# Lua file parsing (mirrors versionfinder.py)
# ---------------------------------------------------------------------------

def parse_lua_file(path: Path) -> list[dict]:
    entries: list[dict] = []
    current_section = ""
    in_array = False
    array_name = ""
    array_values: list[int] = []

    with open(path, "r") as fh:
        lines = fh.readlines()

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if not stripped:
            entries.append({"type": "blank"})
            continue

        if stripped.startswith("--") and not in_array:
            current_section = stripped[2:].strip()
            entries.append({"type": "comment", "text": current_section})
            continue

        if not in_array:
            m = re.match(r"(\w+)\s*=\s*\{(.*)", stripped)
            if m:
                array_name = m.group(1)
                in_array = True
                array_values = []
                array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", m.group(2)))
                if "}" in m.group(2):
                    entries.append({
                        "type": "array", "name": array_name,
                        "value": array_values, "is_address": True,
                        "section": current_section,
                    })
                    in_array = False
                continue

        if in_array:
            array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", line))
            if "}" in line:
                entries.append({
                    "type": "array", "name": array_name,
                    "value": list(array_values), "is_address": True,
                    "section": current_section,
                })
                in_array = False
                array_name = ""
                array_values = []
            continue

        code_part = stripped
        m_ic = re.match(r"(.*?)\s+--\s*(.*)", stripped)
        if m_ic:
            code_part = m_ic.group(1).strip()

        m = re.match(r"(\w+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)", code_part)
        if m:
            name = m.group(1)
            vs = m.group(2)
            val = int(vs, 16) if vs.startswith("0x") else int(vs)
            entries.append({
                "type": "scalar", "name": name, "value": val,
                "is_address": val >= ADDRESS_THRESHOLD,
                "section": current_section,
            })

    return entries


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def attach(name: str) -> pymem.Pymem:
    try:
        return pymem.Pymem(name)
    except pymem.exception.ProcessNotFound:
        sys.exit(f"Process '{name}' not found -- is the game running?")


def module_info(pm: pymem.Pymem, mod_name: str) -> tuple[int, int]:
    mod = pymem.process.module_from_name(pm.process_handle, mod_name)
    if not mod:
        raise RuntimeError(f"Module '{mod_name}' not found in process")
    return mod.lpBaseOfDll, mod.SizeOfImage


def read_pe_sections(pm: pymem.Pymem, base: int) -> list[dict]:
    dos = pm.read_bytes(base, 64)
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    nt_hdr = pm.read_bytes(base + e_lfanew, 24)
    num_sections = struct.unpack_from("<H", nt_hdr, 6)[0]
    opt_size = struct.unpack_from("<H", nt_hdr, 20)[0]
    sec_table_offset = e_lfanew + 4 + 20 + opt_size
    sec_data = pm.read_bytes(base + sec_table_offset, num_sections * 40)
    sections = []
    for i in range(num_sections):
        o = i * 40
        sec_name = sec_data[o:o + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", sec_data, o + 8)[0]
        vrva = struct.unpack_from("<I", sec_data, o + 12)[0]
        chars = struct.unpack_from("<I", sec_data, o + 36)[0]
        sections.append({
            "name": sec_name,
            "rva": vrva,
            "size": vsize,
            "read": bool(chars & 0x40000000),
            "exec": bool(chars & 0x20000000),
        })
    return sections


def section_for_rva(rva: int, pe_sections: list[dict]) -> str:
    for sec in pe_sections:
        if sec["rva"] <= rva < sec["rva"] + sec["size"]:
            return sec["name"]
    return "?"


def safe_read(pm: pymem.Pymem, addr: int, size: int) -> Optional[bytes]:
    try:
        return bytes(pm.read_bytes(addr, size))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core command
# ---------------------------------------------------------------------------

def cmd_scan(lua_path: Path, output_path: Path, context: int,
             filter_names: set[str] | None = None) -> None:
    print(f"Parsing {lua_path.name}...")
    entries = parse_lua_file(lua_path)

    # Flatten all address entries to (flat_key, rva) pairs
    addr_entries: list[tuple[str, int]] = []
    for e in entries:
        if e["type"] == "scalar" and e.get("is_address"):
            addr_entries.append((e["name"], e["value"]))
        elif e["type"] == "array" and e.get("is_address"):
            for i, rva in enumerate(e["value"]):
                addr_entries.append((f"{e['name']}[{i}]", rva))

    if filter_names is not None:
        addr_entries = [(n, r) for n, r in addr_entries if n in filter_names]
        print(f"  {len(addr_entries)} address entries selected by --filter")
    else:
        print(f"  {len(addr_entries)} address entries found")

    print(f"\nAttaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    base, img_size = module_info(pm, PROCESS_NAME)
    print(f"  Module base: 0x{base:X}  image size: {img_size // 1024}KB")

    pe_sections = read_pe_sections(pm, base)

    print(f"\nReading {context} bytes before and after each address...")
    results: dict = {}
    failed = 0

    for idx, (name, rva) in enumerate(addr_entries, 1):
        print(f"  [{idx:4d}/{len(addr_entries)}] {name}", end="\r", flush=True)

        abs_addr = base + rva
        sec_name = section_for_rva(rva, pe_sections)

        before_data = safe_read(pm, abs_addr - context, context)
        after_data = safe_read(pm, abs_addr, context)

        if before_data is None or after_data is None:
            failed += 1

        results[name] = {
            "rva":            f"0x{rva:X}",
            "abs":            f"0x{abs_addr:X}",
            "section":        sec_name,
            "context_before": " ".join(f"{b:02X}" for b in before_data) if before_data else None,
            "context_after":  " ".join(f"{b:02X}" for b in after_data) if after_data else None,
        }

    print()  # clear \r line
    print(f"  Read: {len(addr_entries) - failed}/{len(addr_entries)}")

    # Merge into existing JSON when filtering so unrelated entries are preserved.
    if filter_names is not None and output_path.exists():
        try:
            with output_path.open() as fh:
                existing = json.load(fh)
            existing.update(results)
            results = existing
        except Exception:
            pass

    with open(output_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nContext dump saved to {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture memory context around every address in a KH1 version file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--lua", required=True, type=Path,
                        help="Lua version file (e.g. version_files/EGSGlobal_1_0_0_10.lua)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output JSON file (default: <lua_stem>_context.json)")
    parser.add_argument("--context", type=int, default=DEFAULT_CONTEXT,
                        help=f"Bytes to read before and after each address (default: {DEFAULT_CONTEXT})")
    parser.add_argument("--filter", metavar="NAME", nargs="+",
                        help="Only capture context for these named addresses; "
                             "merges results into the existing output file")

    args = parser.parse_args()

    output = args.output
    if output is None:
        output = Path("version_files") / (args.lua.stem + "_context.json")

    filter_names = set(args.filter) if args.filter else None
    cmd_scan(args.lua, output, args.context, filter_names)


if __name__ == "__main__":
    main()
