#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_patterns.py -- Scan game memory for AOB patterns from patterns.json

Reads the module image from the live process once, then slides each pattern
over it.  Bytes marked '??' in the pattern are wildcards.  The 'offset' field
(128) is added to the pattern-start address to get the address of interest.

Output per entry:
  unique   -- one match: reports rva / abs of the target address
  multiple -- 2-50 matches: lists each rva / abs
  no_match -- pattern not found

Usage:
  python scan_patterns.py
  python scan_patterns.py --patterns my_patterns.json --max-matches 20
  python scan_patterns.py --filter animSpeed
  python scan_patterns.py --output results.json
"""

import argparse
import ctypes
import json
import re
import struct
import sys
import time
from pathlib import Path

try:
    import pymem
    import pymem.process
    import pymem.exception
except ImportError:
    sys.exit("pymem not installed -- run:  pip install pymem")

PROCESS_NAME = "KINGDOM HEARTS FINAL MIX.exe"
READ_CHUNK = 4 * 1024 * 1024  # 4 MB per read call

MEM_COMMIT    = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100

class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("_padding",          ctypes.c_ulong),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             ctypes.c_ulong),
        ("Protect",           ctypes.c_ulong),
        ("Type",              ctypes.c_ulong),
        ("_padding2",         ctypes.c_ulong),
    ]


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

def parse_pattern(s: str) -> list[int | None]:
    """'XX ?? YY ...' -> [0xXX, None, 0xYY, ...]"""
    return [None if tok == "??" else int(tok, 16) for tok in s.split()]


def byte_freq_table(image: bytes) -> list[int]:
    """Return a 256-element list: freq[b] = number of times byte b appears in image."""
    import array as _array
    freq = _array.array("Q", [0] * 256)
    for b in image:
        freq[b] += 1
    return freq


def make_anchor(pattern: list[int | None],
                freq: list[int] | None = None) -> tuple[int, int] | None:
    """
    Return (byte_value, offset_in_pattern) of the best anchor byte.
    With a freq table, picks the least-frequent non-wildcard byte so
    bytes.find() has the fewest candidates to verify.
    Without one, falls back to the first non-zero byte (avoids the
    pathological case of 0x00 anchors in zero-heavy .data regions).
    """
    candidates = [(b, i) for i, b in enumerate(pattern) if b is not None]
    if not candidates:
        return None
    if freq is not None:
        return min(candidates, key=lambda bi: freq[bi[0]])
    non_zero = [(b, i) for b, i in candidates if b != 0]
    return non_zero[0] if non_zero else candidates[0]


def scan_image(image: bytes, pattern: list[int | None], max_matches: int,
               freq: list[int] | None = None) -> list[int]:
    """
    Return up to max_matches offsets within `image` where `pattern` matches.
    Uses bytes.find() on the rarest anchor byte to minimise candidates checked.
    """
    pat_len = len(pattern)
    img_len = len(image)
    matches: list[int] = []

    anchor = make_anchor(pattern, freq)
    if anchor is None:
        return []  # all-wildcard pattern -- skip
    anchor_val, anchor_off = anchor
    anchor_byte = bytes([anchor_val])

    search = 0
    while search <= img_len - pat_len:
        hit = image.find(anchor_byte, search + anchor_off)
        if hit == -1:
            break
        candidate = hit - anchor_off
        if candidate < 0:
            search = hit + 1
            continue
        if candidate + pat_len > img_len:
            break

        # Full pattern check
        if all(b is None or image[candidate + i] == b for i, b in enumerate(pattern)):
            matches.append(candidate)
            if len(matches) >= max_matches:
                break

        search = hit + 1

    return matches


# ---------------------------------------------------------------------------
# Process / module helpers
# ---------------------------------------------------------------------------

def attach(name: str) -> pymem.Pymem:
    try:
        return pymem.Pymem(name)
    except pymem.exception.ProcessNotFound:
        sys.exit(f"Process '{name}' not found -- is the game running?")


def module_info(pm: pymem.Pymem, mod_name: str) -> tuple[int, int]:
    mod = pymem.process.module_from_name(pm.process_handle, mod_name)
    if not mod:
        sys.exit(f"Module '{mod_name}' not found in process")
    return mod.lpBaseOfDll, mod.SizeOfImage


def read_module_image(pm: pymem.Pymem, base: int, size: int) -> bytes:
    """
    Read the full module image using VirtualQueryEx to enumerate committed regions.
    Reading in one large chunk silently zeros out ~4 MB whenever a gap between PE
    sections causes an exception mid-chunk.  Enumerating regions first means only
    the uncommitted gaps (which contain no data anyway) stay zero.
    """
    buf = bytearray(size)
    kernel32 = ctypes.windll.kernel32
    mbi = _MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    limit = base + size
    addr = base

    while addr < limit:
        ret = kernel32.VirtualQueryEx(
            pm.process_handle,
            ctypes.c_ulonglong(addr),
            ctypes.byref(mbi),
            mbi_size,
        )
        if ret == 0:
            break

        region_end = mbi.BaseAddress + mbi.RegionSize

        if (mbi.State == MEM_COMMIT
                and mbi.Protect != PAGE_NOACCESS
                and (mbi.Protect & PAGE_GUARD) == 0):
            read_start = mbi.BaseAddress
            read_end   = min(region_end, limit)
            read_len   = read_end - read_start
            if read_len > 0:
                buf_off = read_start - base
                try:
                    chunk = pm.read_bytes(read_start, read_len)
                    buf[buf_off:buf_off + len(chunk)] = chunk
                except Exception:
                    pass  # leave zeros for any page that still can't be read

        if region_end <= addr:
            break
        addr = region_end

    return bytes(buf)


# ---------------------------------------------------------------------------
# Pointer scan (soraPointer and similar)
# ---------------------------------------------------------------------------

def scan_process_memory(pm: pymem.Pymem, pattern_bytes: bytes) -> list[int]:
    """Scan all readable committed memory regions of the process for pattern_bytes."""
    kernel32 = ctypes.windll.kernel32
    mbi = _MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    addr = 0
    matches: list[int] = []

    while True:
        ret = kernel32.VirtualQueryEx(
            pm.process_handle,
            ctypes.c_ulonglong(addr),
            ctypes.byref(mbi),
            mbi_size,
        )
        if ret == 0:
            break

        if (mbi.State == MEM_COMMIT
                and mbi.Protect != PAGE_NOACCESS
                and (mbi.Protect & PAGE_GUARD) == 0
                and mbi.RegionSize > 0):
            try:
                data = pm.read_bytes(mbi.BaseAddress, mbi.RegionSize)
                pos = 0
                while True:
                    pos = data.find(pattern_bytes, pos)
                    if pos == -1:
                        break
                    matches.append(mbi.BaseAddress + pos)
                    pos += 1
            except Exception:
                pass

        next_addr = mbi.BaseAddress + mbi.RegionSize
        if next_addr <= addr:
            break
        addr = next_addr
        if addr >= 0x7FFFFFFF0000:
            break

    return matches


def resolve_pointer_scan(
    pm: pymem.Pymem,
    base: int,
    image: bytes,
    data_pattern_str: str,
    pointer_index: int,
) -> int | None:
    """
    Two-pass pointer resolution:
    1. Scan all process memory for data_pattern_str to find where the target data lives.
    2. Scan the module image for an 8-byte LE value equal to that raw address.
    3. Return the RVA of the match at pointer_index, or None on failure.
    """
    pattern_bytes = bytes(int(b, 16) for b in data_pattern_str.split())

    print("  Scanning process memory for target data... ", end="", flush=True)
    data_matches = scan_process_memory(pm, pattern_bytes)
    print(f"{len(data_matches)} match(es)")

    if not data_matches:
        print("  Target data pattern not found")
        return None

    if len(data_matches) > 1:
        print(f"  WARNING: {len(data_matches)} data matches -- using first")

    target_addr = data_matches[0]
    print(f"  Target data at 0x{target_addr:X}")

    ptr_bytes = struct.pack("<Q", target_addr)
    ptr_matches: list[int] = []
    pos = 0
    while True:
        pos = image.find(ptr_bytes, pos)
        if pos == -1:
            break
        ptr_matches.append(pos)
        pos += 1

    if not ptr_matches:
        print(f"  No pointer to 0x{target_addr:X} found in module image")
        return None

    used = pointer_index if pointer_index < len(ptr_matches) else len(ptr_matches) - 1
    if used != pointer_index:
        print(f"  WARNING: index {pointer_index} out of range, using [{used}]")

    print(f"  Found {len(ptr_matches)} pointer(s) in module image, using [{used}]:")
    for i, p in enumerate(ptr_matches):
        marker = " <--" if i == used else ""
        print(f"    [{i}]  rva=0x{p:X}  abs=0x{base + p:X}{marker}")

    return ptr_matches[used]


# ---------------------------------------------------------------------------
# Lua output
# ---------------------------------------------------------------------------

def write_lua(results: dict, path: Path) -> None:
    arrays: dict[str, dict[int, dict]] = {}
    scalars: dict[str, dict] = {}

    for name, r in results.items():
        m = re.match(r'^(\w+)\[(\d+)\]$', name)
        if m:
            arrays.setdefault(m.group(1), {})[int(m.group(2))] = r
        else:
            scalars[name] = r

    lines: list[str] = ["-- Generated by scan_patterns.py", ""]

    for name, r in sorted(scalars.items()):
        if r["status"] != "unique":
            lines.append(f"{name} = nil  -- no match")
        elif r.get("constant"):
            lines.append(f"{name} = {r['value']}")
        else:
            rva = int(r["rva"], 16)
            if "relative_to" in r:
                extra = f"  -- {r['relative_offset']:+#x} from {r['relative_to']}"
            elif "match_count" in r:
                extra = f"  -- {r['match_count']} matches, used [{r['match_index_used']}]"
            else:
                extra = ""
            lines.append(f"{name} = 0x{rva:X}{extra}")

    for arr_name, entries in sorted(arrays.items()):
        if not all(r["status"] == "unique" for r in entries.values()):
            for idx, r in sorted(entries.items()):
                if r["status"] == "unique":
                    lines.append(f"{arr_name}[{idx}] = 0x{int(r['rva'], 16):X}")
                else:
                    lines.append(f"{arr_name}[{idx}] = nil  -- no match")
        else:
            max_idx = max(entries.keys())
            vals = [
                f"0x{int(entries[i]['rva'], 16):X}" if i in entries else "nil"
                for i in range(max_idx + 1)
            ]
            inner_lines = [
                "\t" + ", ".join(vals[i:i + 5])
                for i in range(0, len(vals), 5)
            ]
            lines.append(f"{arr_name} = {{\n" + ",\n".join(inner_lines) + "\n}")

    lines.append("")
    path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan game memory for AOB patterns from patterns.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--patterns", type=Path, default=Path("patterns.json"),
                        help="Input patterns JSON (default: patterns.json)")
    parser.add_argument("--max-matches", type=int, default=50,
                        help="Maximum matches to report per pattern (default: 50)")
    parser.add_argument("--filter", metavar="SUBSTR",
                        help="Only scan patterns whose name contains SUBSTR (case-insensitive)")
    parser.add_argument("--output", type=Path,
                        help="Write full results JSON to this file")
    parser.add_argument("--lua", type=Path, default=Path("scan_results.lua"),
                        help="Write Lua output to this file (default: scan_results.lua)")
    parser.add_argument("--address", metavar="NAME",
                        help="Scan a single named address, print all matches, write nothing")
    parser.add_argument("--dump", metavar="RVA",
                        help="Dump 80 bytes from the module image at hex RVA (e.g. 0x23404C0) for pattern debugging")
    args = parser.parse_args()

    # Load patterns
    with args.patterns.open() as fh:
        patterns_data: dict = json.load(fh)

    if args.dump:
        rva = int(args.dump, 16)
        pm = attach(PROCESS_NAME)
        base, img_size = module_info(pm, PROCESS_NAME)
        print(f"Base: 0x{base:X}   SizeOfImage: 0x{img_size:X} ({img_size / (1024*1024):.1f} MB)")
        if rva >= img_size:
            sys.exit(f"RVA 0x{rva:X} is outside SizeOfImage (0x{img_size:X})")
        print("Reading module image... ", end="", flush=True)
        image = read_module_image(pm, base, img_size)
        print("done")
        dump_len = 80
        chunk = image[rva:rva + dump_len]
        print(f"\nBytes at RVA 0x{rva:X}  (abs 0x{base + rva:X}):")
        for row_start in range(0, len(chunk), 16):
            row = chunk[row_start:row_start + 16]
            hex_part = " ".join(f"{b:02X}" for b in row)
            print(f"  +{row_start:04X}  {hex_part}")
        return

    if args.address:
        entry = patterns_data.get(args.address)
        if entry is None:
            sys.exit(f"'{args.address}' not found in {args.patterns}")
        if entry.get("skip"):
            print(f"Warning: '{args.address}' has skip=true in patterns.json")

        if entry.get("pointer_scan"):
            pm = attach(PROCESS_NAME)
            base, img_size = module_info(pm, PROCESS_NAME)
            print(f"Base: 0x{base:X}   Image size: {img_size / (1024*1024):.1f} MB")
            print("Reading module image... ", end="", flush=True)
            image = read_module_image(pm, base, img_size)
            print("done")
            data_pattern = entry.get("data_pattern", "")
            pointer_index = entry.get("pointer_index", 0)
            print(f"\n{args.address}  (pointer_scan, pointer_index={pointer_index})")
            rva = resolve_pointer_scan(pm, base, image, data_pattern, pointer_index)
            if rva is not None:
                print(f"\n-> {args.address}  rva=0x{rva:X}  abs=0x{base + rva:X}")
            return

        if "relative_to" in entry:
            base_name = entry["relative_to"]
            base_entry = patterns_data.get(base_name)
            if base_entry is None:
                sys.exit(f"'{args.address}' is relative_to '{base_name}', which is not in {args.patterns}")
            if "relative_to" in base_entry:
                sys.exit(f"Chained relative_to not supported ('{base_name}' is also a relative entry)")

            pm = attach(PROCESS_NAME)
            base, img_size = module_info(pm, PROCESS_NAME)
            print(f"Base: 0x{base:X}   Image size: {img_size / (1024*1024):.1f} MB")
            print("Reading module image... ", end="", flush=True)
            image = read_module_image(pm, base, img_size)
            print("done")
            freq = byte_freq_table(image)

            pattern = parse_pattern(base_entry["pattern"])
            base_scan_offset: int = base_entry["offset"]
            hits = scan_image(image, pattern, args.max_matches, freq)
            rel_offset: int = entry.get("offset", 0)
            base_index = base_entry.get("match_index", 0)

            print(f"\n{args.address}  (relative_to={base_name}, offset={rel_offset:+#x})")
            if not hits:
                print(f"  base '{base_name}': no matches -- cannot resolve")
            else:
                chosen = base_index if base_index < len(hits) else 0
                base_rva = hits[chosen] + base_scan_offset
                rva = base_rva + rel_offset
                print(f"  base '{base_name}'  rva=0x{base_rva:X}  ({len(hits)} match{'es' if len(hits) != 1 else ''})")
                print(f"  -> {args.address}  rva=0x{rva:X}  abs=0x{base + rva:X}")
            return

        pm = attach(PROCESS_NAME)
        base, img_size = module_info(pm, PROCESS_NAME)
        print(f"Base: 0x{base:X}   Image size: {img_size / (1024*1024):.1f} MB")
        print("Reading module image... ", end="", flush=True)
        image = read_module_image(pm, base, img_size)
        print(f"done")
        freq = byte_freq_table(image)

        pattern = parse_pattern(entry["pattern"])
        offset: int = entry["offset"]
        hits = scan_image(image, pattern, args.max_matches, freq)
        current_index = entry.get("match_index", 0)

        print(f"\n{args.address}  ({len(hits)} match{'es' if len(hits) != 1 else ''})")
        if not hits:
            print("  (no matches)")
        for i, h in enumerate(hits):
            rva = h + offset
            marker = " <-- current" if i == current_index else ""
            print(f"  [{i}]  rva=0x{rva:X}  abs=0x{base + rva:X}{marker}")
        return

    skipped_data  = {k: v for k, v in patterns_data.items() if v.get("skip")}
    active_data   = {k: v for k, v in patterns_data.items() if not v.get("skip")}

    const_data    = {k: v for k, v in active_data.items() if "constant" in v}
    ptr_scan_data = {k: v for k, v in active_data.items() if v.get("pointer_scan") and "constant" not in v}
    aob_data      = {k: v for k, v in active_data.items() if "pattern" in v and not v.get("pointer_scan") and "constant" not in v}
    relative_data = {k: v for k, v in active_data.items() if "relative_to" in v and "constant" not in v}

    if args.filter:
        f = args.filter.lower()
        aob_data      = {k: v for k, v in aob_data.items()      if f in k.lower()}
        ptr_scan_data = {k: v for k, v in ptr_scan_data.items() if f in k.lower()}
        const_data    = {k: v for k, v in const_data.items()    if f in k.lower()}
        if not aob_data and not ptr_scan_data and not const_data:
            sys.exit(f"No patterns match filter '{args.filter}'")
        relative_data = {k: v for k, v in relative_data.items()
                         if v["relative_to"] in aob_data}

    skip_note  = f"  ({len(skipped_data)} skipped)" if skipped_data else ""
    rel_note   = f", {len(relative_data)} relative" if relative_data else ""
    ptr_note   = f", {len(ptr_scan_data)} pointer-scan" if ptr_scan_data else ""
    const_note = f", {len(const_data)} constant" if const_data else ""
    print(f"Loaded {len(aob_data)} pattern(s){rel_note}{ptr_note}{const_note} from {args.patterns}{skip_note}")

    # Attach and read image
    print(f"Attaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    base, img_size = module_info(pm, PROCESS_NAME)
    print(f"  Base: 0x{base:X}   Image size: {img_size / (1024*1024):.1f} MB")

    print("Reading module image... ", end="", flush=True)
    t0 = time.perf_counter()
    image = read_module_image(pm, base, img_size)
    print(f"done ({time.perf_counter() - t0:.2f}s)")

    print("Building byte frequency table... ", end="", flush=True)
    freq = byte_freq_table(image)
    print(f"done  (rarest byte: 0x{freq.index(min(freq)):02X} appears {min(freq)}x)")

    # Scan AOB patterns
    print(f"Scanning {len(aob_data)} pattern(s)...")
    t0 = time.perf_counter()

    results: dict = {}
    unique_count = 0
    resolved_count = 0  # multiple hits, resolved via match_index or default [0]
    no_match_names: list[str] = []
    multi_names: list[str] = []  # still tracked for console review

    for name, entry in aob_data.items():
        pattern = parse_pattern(entry["pattern"])
        offset: int = entry["offset"]
        match_index: int = entry.get("match_index", 0)

        hits = scan_image(image, pattern, args.max_matches, freq)

        if not hits:
            no_match_names.append(name)
            results[name] = {"status": "no_match"}
            continue

        chosen = match_index if match_index < len(hits) else 0
        target_rva = hits[chosen] + offset

        if len(hits) == 1:
            unique_count += 1
            results[name] = {
                "status": "unique",
                "rva": f"0x{target_rva:X}",
                "abs": f"0x{base + target_rva:X}",
            }
        else:
            resolved_count += 1
            multi_names.append(name)
            results[name] = {
                "status": "unique",
                "rva": f"0x{target_rva:X}",
                "abs": f"0x{base + target_rva:X}",
                "match_count": len(hits),
                "match_index_used": chosen,
                "all_matches": [
                    {"rva": f"0x{h + offset:X}", "abs": f"0x{base + h + offset:X}"}
                    for h in hits
                ],
            }

    elapsed = time.perf_counter() - t0

    # Resolve pointer_scan entries first (relative entries may depend on them)
    if ptr_scan_data:
        print(f"\nResolving {len(ptr_scan_data)} pointer-scan entry(ies)...")
        for name, entry in ptr_scan_data.items():
            data_pattern = entry.get("data_pattern", "")
            pointer_index = entry.get("pointer_index", 0)
            print(f"\n{name}  (pointer_index={pointer_index})")
            rva = resolve_pointer_scan(pm, base, image, data_pattern, pointer_index)
            if rva is None:
                no_match_names.append(name)
                results[name] = {"status": "no_match"}
            else:
                unique_count += 1
                results[name] = {
                    "status": "unique",
                    "rva": f"0x{rva:X}",
                    "abs": f"0x{base + rva:X}",
                }

    # Resolve relative entries from AOB and pointer-scan results
    for name, entry in relative_data.items():
        base_name  = entry["relative_to"]
        rel_offset: int = entry.get("offset", 0)
        base_result = results.get(base_name)
        if base_result is None or base_result["status"] != "unique":
            no_match_names.append(name)
            results[name] = {"status": "no_match", "reason": f"base '{base_name}' not resolved"}
            continue
        base_rva = int(base_result["rva"], 16)
        rva = base_rva + rel_offset
        unique_count += 1
        results[name] = {
            "status": "unique",
            "rva": f"0x{rva:X}",
            "abs": f"0x{base + rva:X}",
            "relative_to": base_name,
            "relative_offset": rel_offset,
        }

    # Write constants directly (no scanning needed)
    for name, entry in const_data.items():
        val = entry["constant"]
        results[name] = {"status": "unique", "constant": True, "value": val, "rva": str(val)}
        unique_count += 1

    # Summary
    print(f"\nScan complete in {elapsed:.2f}s\n")
    rel_resolved = sum(1 for r in results.values() if r.get("relative_to"))
    ptr_resolved = sum(1 for k in ptr_scan_data if results.get(k, {}).get("status") == "unique")
    print(f"  Unique:          {unique_count - rel_resolved - ptr_resolved}  (+ {rel_resolved} relative, + {ptr_resolved} pointer-scan)")
    print(f"  Multi (used [{0}]): {resolved_count}  (override with match_index in patterns.json)")
    print(f"  No match:        {len(no_match_names)}")
    print(f"  Skipped:         {len(skipped_data)}")

    if multi_names:
        print("\nMultiple matches found (defaulted to [0] -- set match_index in patterns.json to override):")
        for name in multi_names:
            r = results[name]
            used = r["match_index_used"]
            print(f"  {name}  ({r['match_count']} matches, used [{used}])")
            for i, m in enumerate(r["all_matches"]):
                marker = " <--" if i == used else ""
                print(f"    [{i}]  rva={m['rva']}  abs={m['abs']}{marker}")

    if no_match_names:
        print("\nNo match:")
        for name in no_match_names:
            print(f"  {name}")

    write_lua(results, args.lua)
    print(f"\nLua output written to {args.lua}")

    if args.output:
        with args.output.open("w") as fh:
            json.dump(results, fh, indent=2)
        print(f"Full results written to {args.output}")


if __name__ == "__main__":
    main()
