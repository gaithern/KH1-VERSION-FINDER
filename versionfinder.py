#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VersionFinder for KINGDOM HEARTS FINAL MIX
Scans a running KH1 process using AOB (Array of Bytes) patterns to locate
memory addresses, then outputs a version-appropriate Lua address file.

Modes
-----
generate  Attach to a running known-version game, derive AOB patterns from the
          reference Lua file's addresses, save to patterns/<basename>.json.

find      Attach to any game version, scan with stored patterns, output a new
          Lua file with updated addresses.

Examples
--------
  # Generate patterns from the running EGS 1.0.0.10 game
  python versionfinder.py generate --lua version_files/EGSGlobal_1_0_0_10.lua

  # Find addresses for an unknown/new version
  python versionfinder.py find --patterns patterns/EGSGlobal_1_0_0_10.json \\
                                --output version_files/EGSGlobal_1_0_0_11.lua
"""

import argparse
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

try:
    import pymem
    import pymem.process
    import pymem.exception
except ImportError:
    sys.exit("pymem not installed -- run:  pip install pymem")

try:
    import numpy as np
    from numpy.lib.stride_tricks import as_strided
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

PROCESS_NAME = "KINGDOM HEARTS FINAL MIX.exe"
ROOT = Path(__file__).parent
VERSION_FILES_DIR = ROOT / "version_files"
PATTERNS_DIR = ROOT / "patterns"

# Values smaller than this are treated as literal constants, not addresses.
ADDRESS_THRESHOLD = 0x10000

# How many bytes of code context to capture around the 4-byte RIP offset.
CONTEXT_BEFORE = 12
CONTEXT_AFTER = 8
DIRECT_PATTERN_SIZE = 14   # bytes read at a code-section address for a direct pattern
DUMP_SIZE = 32             # bytes read at each address for the dump/compare workflow
MIN_LITERAL_BYTES = 6      # minimum non-wildcard bytes required to keep a cross-version pattern
MIN_ANCHOR_LEN = 12        # minimum consecutive literal bytes needed to attempt a direct scan
MAX_DIRECT_MATCHES = 5     # abort direct scan early if this many matches accumulate (pattern too broad)
CONSENSUS_TOLERANCE = 0x1000  # max difference between individual find and consensus before consensus wins


# -----------------------------------------------------------------------------
# Lua file parsing
# -----------------------------------------------------------------------------

def parse_lua_file(path: Path) -> list[dict]:
    """
    Parse a KH1 Lua address file into a list of entry dicts.

    Entry types
    -----------
    blank   : empty line
    comment : -- section header
    scalar  : name = 0xVALUE  (address or literal)
    array   : name = { 0xV, ... }
    raw     : anything else (preserved verbatim)

    Each scalar/array entry carries:
      name, value (int or list[int]), is_address (bool),
      section (str), inline_comment (str)
    Array entries also carry raw_lines (list[str]) for verbatim fallback.
    """
    entries: list[dict] = []
    current_section = ""
    in_array = False
    array_name = ""
    array_values: list[int] = []
    array_raw_lines: list[str] = []

    with open(path, "r") as fh:
        lines = fh.readlines()

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if not stripped:
            entries.append({"type": "blank"})
            continue

        if stripped.startswith("--") and not in_array:
            text = stripped[2:].strip()
            current_section = text
            entries.append({"type": "comment", "text": text})
            continue

        # -- array start --
        if not in_array:
            m = re.match(r"(\w+)\s*=\s*\{(.*)", stripped)
            if m:
                array_name = m.group(1)
                in_array = True
                array_values = []
                array_raw_lines = [line]
                array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", m.group(2)))
                if "}" in m.group(2):
                    entries.append({
                        "type": "array", "name": array_name,
                        "value": array_values, "is_address": True,
                        "section": current_section, "inline_comment": "",
                        "raw_lines": array_raw_lines,
                    })
                    in_array = False
                continue

        # -- inside array --
        if in_array:
            array_raw_lines.append(line)
            array_values.extend(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]+)", line))
            if "}" in line:
                entries.append({
                    "type": "array", "name": array_name,
                    "value": array_values, "is_address": True,
                    "section": current_section, "inline_comment": "",
                    "raw_lines": array_raw_lines,
                })
                in_array = False
                array_name = ""
                array_values = []
                array_raw_lines = []
            continue

        # -- scalar assignment --
        inline_comment = ""
        code_part = stripped
        m_ic = re.match(r"(.*?)\s+--\s*(.*)", stripped)
        if m_ic:
            code_part = m_ic.group(1).strip()
            inline_comment = m_ic.group(2).strip()

        m = re.match(r"(\w+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)", code_part)
        if m:
            name = m.group(1)
            vs = m.group(2)
            val = int(vs, 16) if vs.startswith("0x") else int(vs)
            entries.append({
                "type": "scalar", "name": name, "value": val,
                "is_address": val >= ADDRESS_THRESHOLD,
                "section": current_section, "inline_comment": inline_comment,
                "raw_line": line,
            })
            continue

        entries.append({"type": "raw", "raw_line": line})

    return entries


def entries_to_address_map(entries: list[dict]) -> dict[str, int | list[int]]:
    """Return {name: rva_or_list} for all address-type entries."""
    out: dict = {}
    for e in entries:
        if e["type"] in ("scalar", "array") and e.get("is_address"):
            out[e["name"]] = e["value"]
    return out


# -----------------------------------------------------------------------------
# Process / PE utilities
# -----------------------------------------------------------------------------

def attach(name: str) -> pymem.Pymem:
    try:
        return pymem.Pymem(name)
    except pymem.exception.ProcessNotFound:
        sys.exit(f"Process '{name}' not found -- is the game running?")


def module_info(pm: pymem.Pymem, mod_name: str) -> tuple[int, int]:
    """Return (base_address, image_size) for a loaded module."""
    mod = pymem.process.module_from_name(pm.process_handle, mod_name)
    if not mod:
        raise RuntimeError(f"Module '{mod_name}' not found in process")
    return mod.lpBaseOfDll, mod.SizeOfImage


def read_pe_sections(pm: pymem.Pymem, base: int) -> list[dict]:
    """Parse the PE section table of a module loaded at `base`."""
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
        name = sec_data[o:o + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", sec_data, o + 8)[0]
        vrva = struct.unpack_from("<I", sec_data, o + 12)[0]
        chars = struct.unpack_from("<I", sec_data, o + 36)[0]
        sections.append({
            "name": name,
            "rva": vrva,
            "size": vsize,
            "exec": bool(chars & 0x20000000),
            "read": bool(chars & 0x40000000),
            "write": bool(chars & 0x80000000),
        })
    return sections


def safe_read(pm: pymem.Pymem, addr: int, size: int) -> Optional[bytes]:
    """Read `size` bytes from `addr`, returning None on failure."""
    try:
        return bytes(pm.read_bytes(addr, size))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# RIP-relative reference index
# -----------------------------------------------------------------------------

def build_rip_index(code_bytes: bytes, code_base: int) -> dict[int, list[int]]:
    """
    Scan `code_bytes` (loaded at `code_base`) for all 4-byte little-endian
    signed integers that, when interpreted as a RIP-relative offset, resolve
    to a valid positive address.

    Returns:  target_abs_address  ->  [list of byte offsets within code_bytes
                                      where that offset field starts]

    This covers *all* byte-aligned positions, not just instruction boundaries,
    so a subsequent pattern-match step filters out spurious hits.
    """
    n = len(code_bytes) - 3
    if n <= 0:
        return {}

    index: dict[int, list[int]] = defaultdict(list)

    if _HAS_NUMPY:
        arr = np.frombuffer(code_bytes, dtype=np.uint8)
        # Overlapping 4-byte windows at every byte offset
        wins = as_strided(arr, shape=(n, 4), strides=(1, 1))
        u32 = (wins[:, 0].astype(np.uint32) |
               (wins[:, 1].astype(np.uint32) << 8) |
               (wins[:, 2].astype(np.uint32) << 16) |
               (wins[:, 3].astype(np.uint32) << 24))
        # Reinterpret as signed int32 without copying
        i32 = u32.view(np.int32).astype(np.int64)
        positions = np.arange(n, dtype=np.int64)
        # target = code_base + pos + 4 + rel32
        targets = code_base + positions + 4 + i32
        for pos, tgt in zip(positions.tolist(), targets.tolist()):
            if tgt > 0:
                index[int(tgt)].append(int(pos))
    else:
        # Pure-Python fallback (~5-30 s for large sections)
        print("  (numpy not found -- falling back to pure-Python scan, may be slow)")
        for i in range(n):
            rel = struct.unpack_from("<i", code_bytes, i)[0]
            tgt = code_base + i + 4 + rel
            if tgt > 0:
                index[tgt].append(i)

    return dict(index)


# -----------------------------------------------------------------------------
# Pattern representation
# -----------------------------------------------------------------------------

def make_pattern(code_bytes: bytes, ref_pos: int,
                 before: int = CONTEXT_BEFORE,
                 after: int = CONTEXT_AFTER) -> Optional[tuple[list, int]]:
    """
    Build an AOB pattern centred on the 4-byte RIP offset field at `ref_pos`.

    Returns (pattern, wildcard_start) where pattern is a list of int|None
    (None = wildcard byte) and wildcard_start is the index of the first
    wildcard within the pattern.  Returns None if out of bounds.
    """
    start = ref_pos - before
    end = ref_pos + 4 + after
    if start < 0 or end > len(code_bytes):
        return None
    pattern = [
        None if ref_pos <= i < ref_pos + 4 else code_bytes[i]
        for i in range(start, end)
    ]
    return pattern, before   # wildcard starts at index `before`


def pattern_to_str(pattern: list) -> str:
    return " ".join("??" if b is None else f"{b:02X}" for b in pattern)


def str_to_pattern(s: str) -> list:
    return [None if tok == "??" else int(tok, 16) for tok in s.split()]


# -----------------------------------------------------------------------------
# Pattern scanning
# -----------------------------------------------------------------------------

def scan_pattern(code_bytes: bytes, code_base: int,
                 pattern: list, wc_start: int) -> list[int]:
    """
    Search `code_bytes` for `pattern`.  For each match, extract the
    RIP-relative offset at `wc_start` and compute the target absolute address.

    Returns a list of target absolute addresses (one per match).
    """
    # Build a literal prefix for fast bytes.find() pre-filtering
    prefix = bytearray()
    for b in pattern[:wc_start]:
        if b is None:
            break
        prefix.append(b)

    pat_len = len(pattern)
    results: list[int] = []
    search_from = 0

    def check_and_extract(pos: int) -> None:
        for j, pb in enumerate(pattern):
            if pb is not None and code_bytes[pos + j] != pb:
                return
        rel = struct.unpack_from("<i", code_bytes, pos + wc_start)[0]
        target = code_base + pos + wc_start + 4 + rel
        results.append(target)

    if prefix:
        pfx = bytes(prefix)
        while True:
            pos = code_bytes.find(pfx, search_from)
            if pos == -1 or pos + pat_len > len(code_bytes):
                break
            check_and_extract(pos)
            search_from = pos + 1
    else:
        for i in range(len(code_bytes) - pat_len + 1):
            check_and_extract(i)

    return results


def scan_direct_pattern(code_bytes: bytes, code_base: int, pattern: list) -> list[int]:
    """
    Scan for a byte pattern where None = wildcard.  The match position itself
    is the target address (no embedded RIP offset to extract).
    Returns a list of absolute addresses where `pattern` was found.

    Uses the longest consecutive run of literal bytes as the search anchor so
    that common leading bytes (e.g. 00 00 00) don't cause thousands of false
    prefix hits.
    """
    # Find the longest consecutive run of literal (non-None) bytes
    best_start = best_len = cur_start = cur_len = 0
    for i, b in enumerate(pattern):
        if b is not None:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len = cur_len
                best_start = cur_start
        else:
            cur_len = 0

    if best_len < MIN_ANCHOR_LEN:
        return []   # anchor too short -- would produce too many false hits

    anchor = bytes(pattern[best_start:best_start + best_len])
    if len(set(anchor)) <= 1:
        return []   # trivial anchor (e.g. all 0x00) -- would flood with false hits
    pat_len = len(pattern)
    results: list[int] = []
    search_from = best_start

    while True:
        found = code_bytes.find(anchor, search_from)
        if found == -1:
            break
        pat_start = found - best_start
        if pat_start < 0 or pat_start + pat_len > len(code_bytes):
            search_from = found + 1
            continue
        if all(pb is None or code_bytes[pat_start + j] == pb for j, pb in enumerate(pattern)):
            results.append(code_base + pat_start)
            if len(results) > MAX_DIRECT_MATCHES:
                break   # pattern too broad, stop early to avoid hanging
        search_from = found + 1

    return results


def best_pattern_for(target_abs: int, rva: int,
                     sections: dict[str, tuple[int, bytes]],
                     rip_indexes: dict[str, dict],
                     data_sections: Optional[dict] = None) -> Optional[dict]:
    """
    Find the best AOB pattern for `target_abs` using two strategies:

    1. RIP-relative reference -- search code for an instruction whose embedded
       RIP+disp32 offset resolves to target_abs.  Pattern has 4 wildcard bytes
       where the offset lives.  Preferred because it handles ASLR automatically.

    2. Direct bytes -- if no RIP reference exists, read DIRECT_PATTERN_SIZE bytes
       at target_abs (from exec or data sections) and use those as the literal AOB.
       Used for code-patch addresses and data addresses with no RIP reference.

    Returns a JSON-serialisable dict or None if no usable pattern was found.
    """
    best: Optional[dict] = None

    # --- strategy 1: RIP-relative reference ---
    for sec_name, (sec_base, sec_data) in sections.items():
        refs = rip_indexes.get(sec_name, {}).get(target_abs, [])
        for ref_pos in refs:
            result = make_pattern(sec_data, ref_pos)
            if result is None:
                continue
            pattern, wc_start = result
            matches = scan_pattern(sec_data, sec_base, pattern, wc_start)
            if not matches:
                continue
            score = 1_000_000 // len(matches)
            if best is None or score > best["score"]:
                best = {
                    "kind": "rip",
                    "pattern": pattern_to_str(pattern),
                    "wc_start": wc_start,
                    "rva": rva,
                    "match_count": len(matches),
                    "score": score,
                    "section": sec_name,
                }

    if best is not None:
        return best

    # --- strategy 2: direct bytes at target address (exec or data section) ---
    all_for_direct = dict(sections)
    if data_sections:
        all_for_direct.update(data_sections)
    for sec_name, (sec_base, sec_data) in all_for_direct.items():
        offset = target_abs - sec_base
        if not (0 <= offset <= len(sec_data) - DIRECT_PATTERN_SIZE):
            continue
        pat_bytes = list(sec_data[offset:offset + DIRECT_PATTERN_SIZE])
        # Skip padding / zero-fill regions
        unique = set(pat_bytes)
        if unique <= {0xCC} or unique <= {0x00} or unique <= {0x90}:
            continue
        matches = scan_direct_pattern(sec_data, sec_base, pat_bytes)
        if not matches:
            continue
        score = 1_000_000 // len(matches)
        if best is None or score > best["score"]:
            best = {
                "kind": "direct",
                "pattern": " ".join(f"{b:02X}" for b in pat_bytes),
                "wc_start": None,
                "rva": rva,
                "match_count": len(matches),
                "score": score,
                "section": sec_name,
            }

    return best


# -----------------------------------------------------------------------------
# Generate mode
# -----------------------------------------------------------------------------

def cmd_generate(lua_path: Path, output_path: Optional[Path]) -> None:
    """Derive AOB patterns from a reference Lua file and a running game process."""
    print(f"Parsing {lua_path.name}...")
    entries = parse_lua_file(lua_path)
    addr_map = entries_to_address_map(entries)
    print(f"  {len(addr_map)} address entries found")

    print(f"\nAttaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    base, img_size = module_info(pm, PROCESS_NAME)
    print(f"  Module base: 0x{base:X}  image size: {img_size // 1024}KB")

    print("\nReading PE sections...")
    pe_sections = read_pe_sections(pm, base)
    exec_sections: dict[str, tuple[int, bytes]] = {}
    data_sections: dict[str, tuple[int, bytes]] = {}
    for sec in pe_sections:
        sec_base = base + sec["rva"]
        data = safe_read(pm, sec_base, sec["size"])
        if data is None:
            print(f"  WARNING: could not read section {sec['name']}")
            continue
        if sec["exec"]:
            exec_sections[sec["name"]] = (sec_base, data)
            print(f"  {sec['name']:10s}  RVA=0x{sec['rva']:08X}  size={sec['size'] // 1024}KB  <- code")
        elif sec["read"]:
            data_sections[sec["name"]] = (sec_base, data)

    print("\nBuilding RIP-relative reference index...")
    rip_indexes: dict[str, dict] = {}
    for sec_name, (sec_base, sec_data) in exec_sections.items():
        print(f"  Indexing {sec_name}...")
        rip_indexes[sec_name] = build_rip_index(sec_data, sec_base)

    print("\nExtracting patterns...")
    pattern_db: dict[str, dict] = {}
    missing: list[str] = []

    for name, value in addr_map.items():
        if isinstance(value, list):
            # Array: process each element
            entry_patterns = []
            for rva in value:
                tgt = base + rva
                p = best_pattern_for(tgt, rva, exec_sections, rip_indexes, data_sections)
                entry_patterns.append(p)
            found = sum(1 for p in entry_patterns if p)
            print(f"  {name:40s}  [{found}/{len(value)} patterns]")
            pattern_db[name] = {"type": "array", "entries": entry_patterns}
        else:
            rva = value
            tgt = base + rva
            p = best_pattern_for(tgt, rva, exec_sections, rip_indexes, data_sections)
            if p:
                status = f"RVA 0x{rva:X}  ->  {p['match_count']} match(es)"
            else:
                status = f"RVA 0x{rva:X}  ->  NO REFERENCE FOUND"
                missing.append(name)
            print(f"  {name:40s}  {status}")
            pattern_db[name] = {"type": "scalar", "entry": p}

    # Persist
    if output_path is None:
        PATTERNS_DIR.mkdir(exist_ok=True)
        output_path = PATTERNS_DIR / (lua_path.stem + ".json")

    with open(output_path, "w") as fh:
        json.dump(pattern_db, fh, indent=2)

    print(f"\nPatterns saved to {output_path}")
    if missing:
        print(f"  {len(missing)} addresses had no code reference (likely accessed via pointer):")
        for n in missing[:20]:
            print(f"    {n}")
        if len(missing) > 20:
            print(f"    ... and {len(missing) - 20} more")


# -----------------------------------------------------------------------------
# Find mode
# -----------------------------------------------------------------------------

def cmd_find(patterns_path: Path, template_lua: Optional[Path], output_path: Optional[Path]) -> None:
    """Use stored AOB patterns to find addresses in the currently running game."""
    print(f"Loading patterns from {patterns_path.name}...")
    with open(patterns_path) as fh:
        pattern_db: dict[str, dict] = json.load(fh)
    print(f"  {len(pattern_db)} entries")

    print(f"\nAttaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    base, img_size = module_info(pm, PROCESS_NAME)
    print(f"  Module base: 0x{base:X}")

    # Collect which non-exec section names are actually needed by direct patterns
    direct_sections: set[str] = set()
    for db_entry in pattern_db.values():
        flat = []
        if db_entry.get("type") == "scalar":
            flat = [e for e in db_entry.get("candidates") or ([db_entry["entry"]] if db_entry.get("entry") else []) if e]
        elif db_entry.get("type") == "array":
            flat = [e for e in db_entry.get("entries", []) if e]
        for e in flat:
            if e.get("kind") == "direct":
                for key in ("section_b", "section_a", "section"):
                    s = e.get(key)
                    if s and s != "?":
                        direct_sections.add(s)
                        break

    print("\nReading sections...")
    pe_sections = read_pe_sections(pm, base)
    exec_sections: dict[str, tuple[int, bytes]] = {}
    for sec in pe_sections:
        if not sec["read"]:
            continue
        if not sec["exec"] and sec["name"] not in direct_sections:
            continue   # skip non-exec sections not referenced by any direct pattern
        sec_base = base + sec["rva"]
        data = safe_read(pm, sec_base, sec["size"])
        if data:
            exec_sections[sec["name"]] = (sec_base, data)
            kind_tag = "exec" if sec["exec"] else "data"
            print(f"  {sec['name']:10s}  [{kind_tag}]  size={sec['size'] // 1024}KB")

    total_entries = len(pattern_db)
    print(f"\nScanning {total_entries} patterns...")
    found_rvas: dict[str, int | list[int]] = {}
    not_found: list[str] = []

    for idx, (name, db_entry) in enumerate(pattern_db.items(), 1):
        if db_entry["type"] == "scalar":
            # Determine a label for the progress line from the first available candidate
            candidates = db_entry.get("candidates") or ([db_entry["entry"]] if db_entry.get("entry") else [])
            if not candidates:
                not_found.append(name)
                continue
            first = next((e for e in candidates if e), None)
            kind = first.get("kind", "rip") if first else "?"
            sec  = (first.get("section_b") or first.get("section_a") or first.get("section", "?")) if first else "?"
            print(f"  [{idx:3d}/{total_entries}] {name:40s}  ({kind}, {sec})", end="\r", flush=True)
            rvas = _find_rva(db_entry, exec_sections, base)
            if rvas:
                found_rvas[name] = rvas[0]
                if len(rvas) > 1:
                    print(f"  WARNING: {name} matched {len(rvas)} locations; using first"
                          f"  ({kind}, {sec})")
            else:
                not_found.append(name)

        elif db_entry["type"] == "array":
            print(f"  [{idx:3d}/{total_entries}] {name:40s}  (array)", end="\r", flush=True)
            rva_list = []
            for i, sub_entry in enumerate(db_entry.get("entries", [])):
                if sub_entry is None:
                    rva_list.append(None)
                    continue
                kind = sub_entry.get("kind", "rip")
                sec  = sub_entry.get("section_b") or sub_entry.get("section_a") or sub_entry.get("section", "?")
                print(f"  [{idx:3d}/{total_entries}] {name}[{i}]  ({kind}, {sec})", end="\r", flush=True)
                # Array sub-entries are single entries, not candidate lists
                rvas = _find_rva_entry(sub_entry, exec_sections, base)
                rva_list.append(rvas[0] if rvas else None)
            found_rvas[name] = rva_list

    print()  # clear the \r line

    # Derive array entries from a consensus anchor using stored relative offsets.
    # For each found entry, compute what the "base" (entry[0]) address would need to be.
    # Take the majority vote — if >= 2 entries agree, use that anchor to derive ALL entries.
    # This corrects both null entries and pattern-matched entries that were false hits.
    from collections import Counter
    derived_count = corrected_count = 0
    for name, db_entry in pattern_db.items():
        if db_entry["type"] != "array":
            continue
        sub_entries = db_entry.get("entries", [])
        rva_list = found_rvas.get(name)
        if rva_list is None:
            continue

        # rva_b of entry[0] is the reference base; all others are offsets from it
        base_ref_b = next((e["rva_b"] for e in sub_entries if e and e.get("rva_b") is not None), None)
        if base_ref_b is None:
            continue

        # Each found entry implies a consensus base address
        votes: Counter = Counter()
        for found_rva, sub_e in zip(rva_list, sub_entries):
            if found_rva is not None and sub_e and sub_e.get("rva_b") is not None:
                votes[found_rva - (sub_e["rva_b"] - base_ref_b)] += 1

        if not votes:
            continue
        consensus_base, vote_count = votes.most_common(1)[0]
        if vote_count < 2:
            continue  # no consensus — skip derivation for this array

        # Recompute all entries from the consensus base.
        # - None entries: always fill (pattern found nothing, consensus is the best guess).
        # - Found entries: only override when the individual match is far from the
        #   consensus value (> CONSENSUS_TOLERANCE). A small difference means the entry
        #   is in a slightly different memory region that moves independently (e.g.
        #   bossAdjustAddresses[0-2] in .text vs [3-21] in .data) — keep the individual
        #   value. A large difference means a wrong pattern match elsewhere in the binary
        #   — trust the consensus instead.
        for i, sub_e in enumerate(sub_entries):
            if not sub_e or sub_e.get("rva_b") is None:
                continue
            derived = consensus_base + (sub_e["rva_b"] - base_ref_b)
            if derived <= 0:
                continue
            if rva_list[i] is None:
                rva_list[i] = derived
                derived_count += 1
            elif abs(rva_list[i] - derived) > CONSENSUS_TOLERANCE:
                rva_list[i] = derived
                corrected_count += 1

    if derived_count or corrected_count:
        print(f"  Derived from array consensus: {derived_count} filled, {corrected_count} corrected")

    # Second pass: resolve offset patterns from anchors found above.
    offset_resolved = 0
    for name, db_entry in pattern_db.items():
        if db_entry["type"] != "scalar":
            continue
        if found_rvas.get(name) is not None:
            continue
        for cand in (db_entry.get("candidates") or []):
            if not cand or cand.get("kind") != "offset":
                continue
            anchor_rva = found_rvas.get(cand["anchor"])
            if anchor_rva is not None:
                found_rvas[name] = anchor_rva + cand["delta"]
                if name in not_found:
                    not_found.remove(name)
                offset_resolved += 1
                break
    if offset_resolved:
        print(f"  Resolved via anchor offset : {offset_resolved}")

    print(f"\n  Found: {sum(1 for v in found_rvas.values() if v is not None)}")
    print(f"  Not found: {len(not_found)}")
    if not_found:
        for n in not_found[:15]:
            print(f"    {n}")
        if len(not_found) > 15:
            print(f"    ... and {len(not_found) - 15} more")

    # Determine output path
    if output_path is None:
        stem = patterns_path.stem
        output_path = VERSION_FILES_DIR / (stem + "_found.lua")

    # Build Lua output
    if template_lua and template_lua.exists():
        entries = parse_lua_file(template_lua)
        lua_text = render_lua(entries, found_rvas)
    else:
        lua_text = render_lua_simple(found_rvas)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        fh.write(lua_text)
    print(f"\nLua file written to {output_path}")


def _find_rva_entry(entry: dict, exec_sections: dict, module_base: int) -> list[int]:
    """Scan code sections for a single pattern entry; return list of RVAs."""
    kind = entry.get("kind", "rip")   # older JSON files won't have "kind"
    sec_name = entry.get("section")
    results: list[int] = []

    search_order = ([sec_name] if sec_name in exec_sections else []) + \
                   [s for s in exec_sections if s != sec_name]

    if kind == "offset":
        return []  # resolved in a post-scan pass in cmd_find, not by memory scanning

    if kind == "direct":
        pattern = str_to_pattern(entry["pattern"])   # handles ?? as None
        for sn in search_order:
            sec_base, sec_data = exec_sections[sn]
            for match_abs in scan_direct_pattern(sec_data, sec_base, pattern):
                rva = match_abs - module_base
                if 0 < rva < 0x80000000:
                    results.append(rva)
            if results:
                break
    else:  # "rip"
        pattern = str_to_pattern(entry["pattern"])
        wc_start = entry["wc_start"]
        for sn in search_order:
            sec_base, sec_data = exec_sections[sn]
            for tgt in scan_pattern(sec_data, sec_base, pattern, wc_start):
                rva = tgt - module_base
                if 0 < rva < 0x80000000:
                    results.append(rva)
            if results:
                break

    return results


def _find_rva(db_entry: dict, exec_sections: dict, module_base: int) -> list[int]:
    """
    Try each candidate pattern in db_entry in order; return the first result found.

    Supports both the legacy single-entry format {"entry": ...} and the multi-candidate
    format {"candidates": [e1, e2, ...]}.  The multi-candidate format lets merge store
    patterns from multiple source versions so find works regardless of which version
    the binary happens to match.
    """
    candidates = db_entry.get("candidates")
    if candidates is None:
        # Legacy format — single "entry" key
        single = db_entry.get("entry")
        candidates = [single] if single is not None else []

    for entry in candidates:
        if entry is None:
            continue
        results = _find_rva_entry(entry, exec_sections, module_base)
        if results:
            return results
    return []


# -----------------------------------------------------------------------------
# Lua output rendering
# -----------------------------------------------------------------------------

def render_lua(entries: list[dict], found_rvas: dict) -> str:
    """
    Render a Lua file by substituting found RVAs into the template structure
    of `entries`.  Preserves comments, section headers, and array formatting.
    Unfound addresses are written as `nil` rather than inheriting the template's
    old value, so the output never silently contains stale addresses.
    """
    lines: list[str] = []

    for e in entries:
        t = e["type"]
        if t == "blank":
            lines.append("")
        elif t == "comment":
            lines.append(f"-- {e['text']}")
        elif t == "raw":
            lines.append(e["raw_line"])
        elif t == "scalar":
            name = e["name"]
            if name in found_rvas and e["is_address"]:
                val = found_rvas[name]
                if isinstance(val, int):
                    ic = f"  -- {e['inline_comment']}" if e.get("inline_comment") else ""
                    lines.append(f"{name} = 0x{val:X}{ic}")
                else:
                    lines.append(f"{name} = nil")
            elif e["is_address"]:
                lines.append(f"{name} = nil")
            else:
                lines.append(e["raw_line"])
        elif t == "array":
            name = e["name"]
            if name in found_rvas:
                new_vals = found_rvas[name]
                filled = [v if v is not None else 0 for v in new_vals]
                lines.extend(_format_array(name, filled))
            else:
                lines.append(f"{name} = nil")

    return "\n".join(lines) + "\n"


def _format_array(name: str, values: list[int], per_row: int = 5) -> list[str]:
    """Format a Lua array assignment matching the original file style."""
    out = [f"{name} = {{"]
    for i in range(0, len(values), per_row):
        row = values[i:i + per_row]
        row_str = ", ".join(f"0x{v:X}" for v in row)
        trailing = "," if i + per_row < len(values) else ""
        out.append(f"\t{row_str}{trailing}")
    out.append("}")
    return out


def render_lua_simple(found_rvas: dict) -> str:
    """Minimal Lua output when no template is available."""
    lines = ["-- Generated by VersionFinder"]
    for name, val in sorted(found_rvas.items()):
        if isinstance(val, list):
            lines.extend(_format_array(name, [v for v in val if v is not None]))
        elif val is not None:
            lines.append(f"{name} = 0x{val:X}")
    return "\n".join(lines) + "\n"


# -----------------------------------------------------------------------------
# Dump mode  (step 1 of cross-version workflow)
# -----------------------------------------------------------------------------

def cmd_dump(lua_path: Path, output_path: Optional[Path], size: int = DUMP_SIZE) -> None:
    """
    Read `size` bytes at every known address while the game is running and
    the target save file is loaded.  Produces a JSON file used by 'compare'.

    Run this once for Steam and once for EGS (same save each time).
    Larger --size means more unique patterns but slightly more brittle across
    versions; 64-128 bytes is a good balance for data-section addresses.
    """
    print(f"Parsing {lua_path.name}...")
    entries = parse_lua_file(lua_path)
    addr_map = entries_to_address_map(entries)
    print(f"  {len(addr_map)} address entries")

    print(f"\nAttaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    base, _ = module_info(pm, PROCESS_NAME)
    print(f"  Module base: 0x{base:X}")

    # Read PE sections so we can tag which section each address lives in
    pe_sections = read_pe_sections(pm, base)

    def section_for_rva(rva: int) -> str:
        for sec in pe_sections:
            if sec["rva"] <= rva < sec["rva"] + sec["size"]:
                return sec["name"]
        return "?"

    print(f"\nReading {size} bytes at each address...")
    dump: dict = {}
    failed = 0

    for name, value in addr_map.items():
        if isinstance(value, list):
            sub_entries = []
            for rva in value:
                data = safe_read(pm, base + rva, size)
                sub_entries.append({
                    "rva": rva,
                    "section": section_for_rva(rva),
                    "bytes": " ".join(f"{b:02X}" for b in data) if data else None,
                })
                if data is None:
                    failed += 1
            dump[name] = {"type": "array", "entries": sub_entries}
        else:
            rva = value
            data = safe_read(pm, base + rva, size)
            dump[name] = {
                "type": "scalar",
                "rva": rva,
                "section": section_for_rva(rva),
                "bytes": " ".join(f"{b:02X}" for b in data) if data else None,
            }
            if data is None:
                failed += 1

    if output_path is None:
        PATTERNS_DIR.mkdir(exist_ok=True)
        output_path = PATTERNS_DIR / (lua_path.stem + "_dump.json")

    with open(output_path, "w") as fh:
        json.dump(dump, fh, indent=2)

    total = sum(
        len(v["entries"]) if v["type"] == "array" else 1
        for v in dump.values()
    )
    print(f"\n  {total - failed}/{total} addresses read successfully")
    print(f"Dump saved to {output_path}")


# -----------------------------------------------------------------------------
# Compare mode  (step 2 of cross-version workflow)
# -----------------------------------------------------------------------------

def _cross_pattern(entry_a: dict, entry_b: dict) -> Optional[dict]:
    """
    Align two dump entries byte-by-byte.
    Same byte  -> literal in pattern
    Diff byte  -> ?? wildcard
    Returns None if either entry is missing or the result has too few literals.
    """
    if entry_a is None or entry_b is None:
        return None
    bs_a = entry_a.get("bytes")
    bs_b = entry_b.get("bytes")
    if bs_a is None or bs_b is None:
        return None

    arr_a = [int(x, 16) for x in bs_a.split()]
    arr_b = [int(x, 16) for x in bs_b.split()]
    n = min(len(arr_a), len(arr_b))

    pattern = [a if a == b else None for a, b in zip(arr_a[:n], arr_b[:n])]

    literals = sum(1 for b in pattern if b is not None)
    if literals < MIN_LITERAL_BYTES:
        return None   # too volatile to be useful

    # Trim trailing wildcards -- they add nothing
    while pattern and pattern[-1] is None:
        pattern.pop()
    if not pattern:
        return None

    return {
        "kind": "direct",
        "pattern": pattern_to_str(pattern),
        "wc_start": None,
        "rva_a": entry_a.get("rva"),
        "rva_b": entry_b.get("rva"),
        "section_a": entry_a.get("section"),
        "section_b": entry_b.get("section"),
        "literals": literals,
        "total": n,
    }


def cmd_compare(dump_a: Path, dump_b: Path, output_path: Path,
                label_a: str = "A", label_b: str = "B") -> None:
    """
    Compare two memory dumps (produced by 'dump') to create cross-version
    AOB patterns.  Bytes that are the same in both versions stay literal;
    differing bytes become ?? wildcards.

    The resulting pattern file can be used directly with 'find'.
    """
    print(f"Loading {dump_a.name}  ({label_a})...")
    with open(dump_a) as fh:
        da: dict = json.load(fh)
    print(f"Loading {dump_b.name}  ({label_b})...")
    with open(dump_b) as fh:
        db: dict = json.load(fh)

    all_names = sorted(set(da) | set(db))
    print(f"\nComparing {len(all_names)} entries...")

    pattern_db: dict = {}
    stats = {"good": 0, "weak": 0, "missing": 0}

    for name in all_names:
        ea = da.get(name)
        eb = db.get(name)

        if ea is None or eb is None:
            pattern_db[name] = {"type": "scalar", "entry": None}
            stats["missing"] += 1
            continue

        if ea.get("type") == "array":
            entries_a = ea.get("entries", [])
            entries_b = eb.get("entries", []) if eb else []
            result_entries = []
            for suba, subb in zip(entries_a, entries_b):
                p = _cross_pattern(suba, subb)
                result_entries.append(p)
                if p:
                    stats["good"] += 1
                else:
                    stats["weak"] += 1
            pattern_db[name] = {"type": "array", "entries": result_entries}
        else:
            p = _cross_pattern(ea, eb)
            pattern_db[name] = {"type": "scalar", "entry": p}
            if p:
                stats["good"] += 1
            else:
                stats["weak"] += 1

    with open(output_path, "w") as fh:
        json.dump(pattern_db, fh, indent=2)

    print(f"\n  Strong patterns : {stats['good']}")
    print(f"  Weak/null       : {stats['weak']}")
    print(f"  Only in one ver : {stats['missing']}")
    print(f"\nCross-version patterns saved to {output_path}")

    # Print weak/null list so the user knows what needs manual attention
    weak = [
        name for name, v in pattern_db.items()
        if v.get("type") == "scalar" and v.get("entry") is None
    ]
    if weak:
        print(f"\nThe following {len(weak)} scalars have no usable pattern "
              f"(bytes differ too much between versions):")
        for n in weak:
            print(f"  {n}")


# -----------------------------------------------------------------------------
# Merge mode
# -----------------------------------------------------------------------------

def cmd_merge(primaries: list[Path], fallback: Path, output: Path,
              offsets: Optional[Path] = None) -> None:
    """
    Combine multiple pattern files into one ordered candidate list per entry.

    For each address the candidates list is built as:
      [primary[0] entry, primary[1] entry, ..., fallback entry, offset entry]
    with None slots removed.  During find, candidates are tried in order and
    the first that finds a result is used.

    Typical use: pass both EGS and Steam 'generate' outputs as primaries and
    the 'compare' cross-version output as fallback, so each binary gets its own
    RIP pattern tried first and the direct pattern is a last resort.
    """
    dbs_primary = []
    for p in primaries:
        print(f"Loading primary  : {p.name}")
        with open(p) as fh:
            dbs_primary.append(json.load(fh))
    print(f"Loading fallback : {fallback.name}")
    with open(fallback) as fh:
        db_f: dict = json.load(fh)

    offsets_db: dict = {}
    if offsets is not None:
        print(f"Loading offsets  : {offsets.name}")
        with open(offsets) as fh:
            offsets_db = json.load(fh)

    all_names = sorted(set().union(*[set(db) for db in dbs_primary], set(db_f)))
    merged: dict = {}
    stats = {"with_candidates": 0, "null": 0}

    for name in all_names:
        # Collect entries from each primary, then fallback
        candidate_entries = []
        for db_p in dbs_primary:
            ep = db_p.get(name, {})
            e = ep.get("entry")
            if e is not None:
                candidate_entries.append(e)

        ef = db_f.get(name, {})
        f_entry = ef.get("entry")
        if f_entry is not None:
            candidate_entries.append(f_entry)

        # Determine type from first source that has it
        typ = next((db.get(name, {}).get("type") for db in dbs_primary + [db_f]
                    if db.get(name, {}).get("type")), "scalar")

        if typ == "array":
            # For arrays, keep using per-element single entries (arrays don't need candidates)
            # Use first primary that has entries, fall back to db_f
            ep_entries = next((db.get(name, {}).get("entries", []) for db in dbs_primary
                               if db.get(name, {}).get("entries")), [])
            ef_entries = ef.get("entries", [])
            length = max(len(ep_entries), len(ef_entries))
            out_entries = []
            for i in range(length):
                a = ep_entries[i] if i < len(ep_entries) else None
                b = ef_entries[i] if i < len(ef_entries) else None
                out_entries.append(a if a is not None else b)
            merged[name] = {"type": "array", "entries": out_entries}
            if any(e is not None for e in out_entries):
                stats["with_candidates"] += 1
            else:
                stats["null"] += 1
        else:
            if name in offsets_db:
                spec = offsets_db[name]
                candidate_entries.append({
                    "kind": "offset",
                    "anchor": spec["anchor"],
                    "delta": spec["delta"],
                })
            merged[name] = {"type": "scalar", "candidates": candidate_entries}
            if candidate_entries:
                stats["with_candidates"] += 1
            else:
                stats["null"] += 1

    with open(output, "w") as fh:
        json.dump(merged, fh, indent=2)

    print(f"\n  Entries with candidates : {stats['with_candidates']}")
    print(f"  Still null              : {stats['null']}")
    print(f"\nMerged patterns saved to {output}")


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
# Verify mode
# -----------------------------------------------------------------------------

def cmd_verify(patterns_path: Path, ref_lua_path: Path, output_path: Optional[Path]) -> None:
    """
    Scan every pattern in patterns_path against the currently running game.
    Keep only patterns that match EXACTLY once at the address given in ref_lua_path.
    Write the filtered result to output_path (default: <stem>_verified.json).
    """
    print(f"Loading patterns from {patterns_path.name}...")
    with open(patterns_path) as fh:
        pattern_db: dict[str, dict] = json.load(fh)
    print(f"  {len(pattern_db)} entries")

    print(f"Loading reference addresses from {ref_lua_path.name}...")
    ref_entries = parse_lua_file(ref_lua_path)
    ref_rvas: dict[str, int] = {}
    for e in ref_entries:
        if e.get("type") == "scalar" and e.get("value") is not None:
            ref_rvas[e["name"]] = e["value"]
        elif e.get("type") == "array":
            for i, v in enumerate(e.get("values", [])):
                if v is not None:
                    ref_rvas[f"{e['name']}[{i}]"] = v
    print(f"  {len(ref_rvas)} known addresses")

    print(f"\nAttaching to '{PROCESS_NAME}'...")
    pm = attach(PROCESS_NAME)
    module_base, img_size = module_info(pm, PROCESS_NAME)
    print(f"  Module base: 0x{module_base:X}")

    # Collect which non-exec sections are referenced by direct patterns
    direct_sections: set[str] = set()
    for db_entry in pattern_db.values():
        flat = []
        if db_entry.get("type") == "scalar":
            flat = [e for e in db_entry.get("candidates") or ([db_entry["entry"]] if db_entry.get("entry") else []) if e]
        elif db_entry.get("type") == "array":
            flat = [e for e in db_entry.get("entries", []) if e]
        for e in flat:
            if e.get("kind") == "direct":
                for key in ("section_b", "section_a", "section"):
                    s = e.get(key)
                    if s and s != "?":
                        direct_sections.add(s)
                        break

    print("\nReading sections...")
    pe_secs = read_pe_sections(pm, module_base)
    exec_sections: dict[str, tuple[int, bytes]] = {}
    for sec in pe_secs:
        if not sec["read"]:
            continue
        if not sec["exec"] and sec["name"] not in direct_sections:
            continue
        sec_base = module_base + sec["rva"]
        data = safe_read(pm, sec_base, sec["size"])
        if data:
            exec_sections[sec["name"]] = (sec_base, data)
            kind_tag = "exec" if sec["exec"] else "data"
            print(f"  {sec['name']:10s}  [{kind_tag}]  size={sec['size'] // 1024}KB")

    total = len(pattern_db)
    kept = null_out = no_ref = wrong = 0
    verified_db: dict[str, dict] = {}

    print(f"\nVerifying {total} patterns...")
    for idx, (name, db_entry) in enumerate(pattern_db.items(), 1):
        print(f"  [{idx:3d}/{total}] {name:40s}", end="\r", flush=True)

        if db_entry["type"] == "scalar":
            has_candidates = bool(db_entry.get("candidates") or db_entry.get("entry"))
            if not has_candidates:
                verified_db[name] = db_entry
                null_out += 1
                continue

            expected_rva = ref_rvas.get(name)
            if expected_rva is None:
                verified_db[name] = db_entry
                no_ref += 1
                continue

            # Test each candidate independently; keep the entry if any candidate
            # correctly finds the expected address as its first match.
            raw_candidates = db_entry.get("candidates")
            is_legacy = raw_candidates is None
            if is_legacy:
                raw_candidates = [db_entry.get("entry")]

            new_candidates = []
            first_bad_rvas = None
            for cand in raw_candidates:
                if cand is None:
                    new_candidates.append(None)
                    continue
                if cand.get("kind") == "offset":
                    anchor_ref = ref_rvas.get(cand["anchor"])
                    if anchor_ref is not None and anchor_ref + cand["delta"] == expected_rva:
                        new_candidates.append(cand)
                    else:
                        new_candidates.append(None)
                else:
                    rvas = _find_rva_entry(cand, exec_sections, module_base)
                    if rvas and rvas[0] == expected_rva:
                        new_candidates.append(cand)
                    else:
                        new_candidates.append(None)
                        if rvas and first_bad_rvas is None:
                            first_bad_rvas = rvas

            if any(c is not None for c in new_candidates):
                good_entry = dict(db_entry)
                if is_legacy:
                    good_entry["entry"] = new_candidates[0]
                else:
                    good_entry["candidates"] = new_candidates
                verified_db[name] = good_entry
                kept += 1
            else:
                bad_entry = dict(db_entry)
                bad_entry["entry"] = None
                bad_entry["candidates"] = []
                verified_db[name] = bad_entry
                if first_bad_rvas is not None:
                    wrong += 1
                    print(f"  WRONG:  {name:38s}  {len(first_bad_rvas)} matches, first 0x{first_bad_rvas[0]:X}, expected 0x{expected_rva:X}")
                else:
                    null_out += 1

        elif db_entry["type"] == "array":
            expected_list = []
            for i, sub_entry in enumerate(db_entry.get("entries", [])):
                key = f"{name}[{i}]"
                expected_list.append(ref_rvas.get(key))

            new_entries = []
            for i, sub_entry in enumerate(db_entry.get("entries", [])):
                if sub_entry is None:
                    new_entries.append(None)
                    null_out += 1
                    continue
                expected_rva = expected_list[i] if i < len(expected_list) else None
                if expected_rva is None:
                    new_entries.append(sub_entry)
                    no_ref += 1
                    continue
                rvas = _find_rva_entry(sub_entry, exec_sections, module_base)
                if rvas and rvas[0] == expected_rva:
                    new_entries.append(sub_entry)
                    kept += 1
                else:
                    new_entries.append(None)
                    if rvas:
                        wrong += 1
                    else:
                        null_out += 1

            bad_entry = dict(db_entry)
            bad_entry["entries"] = new_entries
            verified_db[name] = bad_entry

    print()
    print(f"\n  Kept (first match correct) : {kept}")
    print(f"  Nulled - wrong first match : {wrong}")
    print(f"  Already null / no ref      : {null_out + no_ref}")

    if output_path is None:
        stem = patterns_path.stem
        output_path = patterns_path.parent / (stem + "_verified.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(verified_db, fh, indent=2)
    print(f"\nVerified patterns written to {output_path}")


# -----------------------------------------------------------------------------
# Combine mode
# -----------------------------------------------------------------------------

def cmd_combine(inputs: list[Path], output: Path) -> None:
    """
    Merge two or more verified pattern files into one.

    For each candidate slot, keep the candidate from any input where it was
    non-null (i.e. passed that platform's verify).  This lets you run verify
    separately against EGS and Steam and then union the results so that patterns
    valid on either platform are all preserved.
    """
    dbs: list[dict] = []
    for p in inputs:
        print(f"Loading: {p.name}")
        with open(p) as fh:
            dbs.append(json.load(fh))

    all_names: set[str] = set()
    for db in dbs:
        all_names.update(db.keys())

    combined: dict = {}
    for name in all_names:
        entries = [db[name] for db in dbs if name in db]
        base = entries[0]
        entry_type = base.get("type")

        if entry_type == "scalar":
            all_cand_lists = []
            for e in entries:
                cands = e.get("candidates")
                if cands is None:
                    cands = [e.get("entry")]
                all_cand_lists.append(cands)

            max_len = max(len(c) for c in all_cand_lists)
            merged_cands: list = []
            for i in range(max_len):
                slot = None
                for cands in all_cand_lists:
                    if i < len(cands) and cands[i] is not None:
                        slot = cands[i]
                        break
                merged_cands.append(slot)

            out = dict(base)
            out["candidates"] = merged_cands
            out.pop("entry", None)
            combined[name] = out

        elif entry_type == "array":
            best = max(entries,
                       key=lambda e: sum(1 for x in e.get("entries", []) if x is not None))
            combined[name] = best
        else:
            combined[name] = base

    non_null_scalars = sum(
        1 for e in combined.values()
        if e.get("type") == "scalar"
        and any(c is not None for c in e.get("candidates", [e.get("entry")]))
    )
    print(f"\n  Combined entries          : {len(combined)}")
    print(f"  Scalars with ≥1 candidate : {non_null_scalars}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as fh:
        json.dump(combined, fh, indent=2)
    print(f"\nCombined patterns saved to {output}")


# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AOB-based address finder for KINGDOM HEARTS FINAL MIX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # generate
    gen = sub.add_parser("generate",
                         help="Derive AOB patterns from a reference Lua file")
    gen.add_argument("--lua", required=True, type=Path,
                     help="Reference Lua address file (e.g. version_files/EGSGlobal_1_0_0_10.lua)")
    gen.add_argument("--output", type=Path, default=None,
                     help="Output JSON pattern file (default: patterns/<lua_name>.json)")

    # dump
    dmp = sub.add_parser("dump",
                         help="Read raw bytes at each known address (step 1 of cross-version workflow)")
    dmp.add_argument("--lua", required=True, type=Path,
                     help="Lua address file for the currently running version")
    dmp.add_argument("--output", type=Path, default=None,
                     help="Output JSON dump file (default: patterns/<lua_name>_dump.json)")
    dmp.add_argument("--size", type=int, default=DUMP_SIZE,
                     help=f"Bytes to read at each address (default: {DUMP_SIZE}; "
                          "use 64-128 for more unique data-section patterns)")

    # compare
    cmp = sub.add_parser("compare",
                         help="Compare two dumps to create cross-version patterns (step 2)")
    cmp.add_argument("--dump-a", required=True, type=Path,
                     help="Dump JSON from first version (e.g. Steam)")
    cmp.add_argument("--dump-b", required=True, type=Path,
                     help="Dump JSON from second version (e.g. EGS)")
    cmp.add_argument("--label-a", default="A",
                     help="Label for dump-a in output (e.g. Steam)")
    cmp.add_argument("--label-b", default="B",
                     help="Label for dump-b in output (e.g. EGS)")
    cmp.add_argument("--output", required=True, type=Path,
                     help="Output cross-version pattern JSON file")

    # merge
    mrg = sub.add_parser("merge",
                         help="Combine generate (RIP) patterns with compare (direct) patterns")
    mrg.add_argument("--primary", required=True, type=Path, nargs='+',
                     help="One or more 'generate' JSON files (tried in order before fallback)")
    mrg.add_argument("--fallback", required=True, type=Path,
                     help="Pattern JSON from 'compare' (direct bytes -- used when all primaries are null)")
    mrg.add_argument("--offsets", type=Path, default=None,
                     help="Optional offset pattern JSON (anchor+delta pairs, appended as last-resort candidates)")
    mrg.add_argument("--output", required=True, type=Path,
                     help="Output merged pattern JSON file")

    # find
    find = sub.add_parser("find",
                          help="Scan the running game with stored patterns")
    find.add_argument("--patterns", required=True, type=Path,
                      help="Pattern JSON file (from 'generate' or 'compare')")
    find.add_argument("--template", type=Path, default=None,
                      help="Reference Lua file to use as output template (preserves structure)")
    find.add_argument("--output", type=Path, default=None,
                      help="Output Lua file path")

    # verify
    ver = sub.add_parser("verify",
                         help="Filter a pattern file to only patterns that uniquely match the expected address")
    ver.add_argument("--patterns", required=True, type=Path,
                     help="Pattern JSON file to verify (e.g. merged.json)")
    ver.add_argument("--lua", required=True, type=Path,
                     help="Reference Lua file with known correct addresses for the running version")
    ver.add_argument("--output", type=Path, default=None,
                     help="Output verified JSON file (default: <stem>_verified.json)")

    # combine
    cmb = sub.add_parser("combine",
                         help="Union two or more verified pattern files so candidates valid on any platform are kept")
    cmb.add_argument("--inputs", required=True, type=Path, nargs='+',
                     help="Two or more verified pattern JSON files to merge")
    cmb.add_argument("--output", required=True, type=Path,
                     help="Output combined pattern JSON file")

    args = parser.parse_args()

    if args.mode == "generate":
        cmd_generate(args.lua, args.output)
    elif args.mode == "dump":
        cmd_dump(args.lua, args.output, args.size)
    elif args.mode == "merge":
        cmd_merge(args.primary, args.fallback, args.output, args.offsets)
    elif args.mode == "compare":
        cmd_compare(args.dump_a, args.dump_b, args.output, args.label_a, args.label_b)
    elif args.mode == "find":
        cmd_find(args.patterns, args.template, args.output)
    elif args.mode == "verify":
        cmd_verify(args.patterns, args.lua, args.output)
    elif args.mode == "combine":
        cmd_combine(args.inputs, args.output)


if __name__ == "__main__":
    main()
