# VersionFinder — KH1 Final Mix Memory Address Scanner

Scans a running **Kingdom Hearts Final Mix (PC)** process using AOB (Array of Bytes) patterns to locate memory addresses, then outputs a Lua address file compatible with the game's modding tools. Useful when a new game version releases and all addresses shift.

## Requirements

- Windows (pymem is Windows-only)
- Python 3.10+
- The game running before you execute any command that reads memory

```
pip install -r requirements.txt
```

## Quick Start — New Version Released

**Step 1 — Run `find` with the game open on the new version.**

Use the template file that matches your platform:

```
:: Steam
python versionfinder.py find --patterns patterns\merged_verified_v2.json --lua version_files\SteamGlobal_1_0_0_2.lua --output version_files\SteamGlobal_new.lua

:: EGS
python versionfinder.py find --patterns patterns\merged_verified_v2.json --lua version_files\EGSGlobal_1_0_0_10.lua --output version_files\EGSGlobal_new.lua
```

The tool attaches to the running process, scans with the stored patterns, and writes a new Lua file with updated addresses.

**Step 2 — Check the console output.**

The summary line shows how many addresses were found vs. total. Any address that couldn't be located is written as `nil` in the output file and printed to the console. A small number of `nil` results is normal — `slideActive` and `textMemory` are always manual. Any address showing `WRONG` found the pattern but the result looked implausible; treat these the same as `nil`.

**Step 3 — Fill in any `nil` addresses manually.**

Open the output Lua file and find the `nil` entries. Locate the correct address using Cheat Engine or another memory scanner, then replace each `nil` with the new value. Compare against the previous version's Lua file to know what you're looking for.

**Step 4 — Update the pattern database (optional but recommended).**

Once you have a complete, verified Lua file for the new version, add it to the pattern database so future version updates have better coverage:

```
:: Generate patterns from the new version (game must be running on new version)
python versionfinder.py generate --lua version_files\SteamGlobal_new.lua

:: Verify the new patterns against the new version
python versionfinder.py verify --patterns patterns\SteamGlobal_new.json --lua version_files\SteamGlobal_new.lua --output patterns\steam_new_verified.json

:: Re-verify the existing merged file against each known version, then combine all
python versionfinder.py verify --patterns patterns\merged_verified_v2.json --lua version_files\EGSGlobal_1_0_0_10.lua --output patterns\egs_verified.json
python versionfinder.py combine --inputs patterns\egs_verified.json patterns\steam_new_verified.json --output patterns\merged_verified_v2.json
```

---

## How It Works

The tool maintains a pattern database (`patterns/merged_verified_v2.json`) built from two known versions (Steam 1.0.0.2 and EGS 1.0.0.10). Each address entry stores one or more **candidates** tried in order until one succeeds:

| Kind | How it finds the address |
|------|--------------------------|
| `rip` | Searches `.text` for an instruction whose RIP-relative operand points to the target address. Most reliable — the surrounding code context is highly unique. |
| `direct` | Searches all sections for the raw bytes stored at the target address. Used when no code reference exists (e.g. pure data addresses). |
| `offset` | Computes `anchor_address + delta`, where the anchor is found by another pattern. Used when the relative distance to a nearby address is stable across versions. |

When `find` runs, each candidate is tried in order. The first one that produces a unique, plausible match wins. If the pattern file contains candidates from both EGS and Steam, the tool works regardless of which version is running.

---

## Commands

### `find` — Locate addresses in a running game version

```
python versionfinder.py find
    --patterns  patterns\merged_verified_v2.json
    --lua       version_files\SteamGlobal_1_0_0_2.lua   (template for output structure)
    --output    version_files\SteamGlobal_new.lua        (optional, defaults to stdout)
```

Attach to the running game, run all patterns, and write a Lua file. Uses the `--lua` file as a structural template (preserves section comments and order).

---

### `generate` — Build patterns from a known version

With the game running at a known version:

```
python versionfinder.py generate --lua version_files\EGSGlobal_1_0_0_10.lua
```

Reads the live process, derives RIP and direct-byte patterns for every address in the Lua file, and saves them to `patterns\EGSGlobal_1_0_0_10.json`. Run this once per known version/platform.

---

### `verify` — Filter patterns to only those that pass on the running version

```
python versionfinder.py verify
    --patterns  patterns\merged_v2.json
    --lua       version_files\EGSGlobal_1_0_0_10.lua
    --output    patterns\egs_verified.json
```

Runs every candidate against the live process and nulls any that find the wrong address. Prevents a pattern that works on Steam from silently returning a wrong address on EGS (and vice versa).

---

### `combine` — Merge verified files from multiple platforms

```
python versionfinder.py combine
    --inputs  patterns\egs_verified.json  patterns\steam_verified.json
    --output  patterns\merged_verified_v2.json
```

For each address, takes the first non-null candidate from each input file, filling candidate slots in order. This produces a single pattern file that can find addresses on either platform.

---

### `dump` / `compare` / `merge` — Cross-version direct patterns

An alternative pattern-generation workflow for addresses that have no RIP reference in the binary. Run `dump` against two different known versions to capture raw bytes at each address, then `compare` to build patterns from bytes that are stable across both versions, then `merge` to combine them with `generate` output.

**Step 1** — Dump bytes from each known version (run with each version running):
```
python versionfinder.py dump --lua version_files\SteamGlobal_1_0_0_2.lua
python versionfinder.py dump --lua version_files\EGSGlobal_1_0_0_10.lua
```

**Step 2** — Compare the two dumps to find stable byte patterns:
```
python versionfinder.py compare
    --dump-a  patterns\SteamGlobal_1_0_0_2_dump.json
    --dump-b  patterns\EGSGlobal_1_0_0_10_dump.json
    --output  patterns\cross_version.json
```

**Step 3** — Merge primary (RIP) patterns with cross-version fallback:
```
python versionfinder.py merge
    --primary   patterns\EGSGlobal_1_0_0_10.json  patterns\SteamGlobal_1_0_0_2.json
    --fallback  patterns\cross_version.json
    --offsets   patterns\offsets.json
    --output    patterns\merged_v2.json
```

---

## Full Workflow — Adding Support for a New Platform or Version

1. Run `generate` with the new version running to produce a per-version pattern file.
2. Run `verify` against the new version to null any candidates that return wrong results.
3. Run `verify` against each existing known version to produce verified files for those too.
4. Run `combine` with all verified files to produce a new `merged_verified_v2.json`.

---

## Offset Patterns (`patterns/offsets.json`)

Some addresses sit at a fixed byte offset from a reliably-found anchor address and have no unique AOB pattern. These are stored separately:

```json
{
  "skipFlag2": { "anchor": "title", "delta": -24 },
  "textBox":   { "anchor": "fireState1", "delta": 996 }
}
```

The `merge` command appends these as last-resort candidates. The offset is only applied if the anchor was successfully found.

---

## File Reference

| Path | Purpose |
|------|---------|
| `versionfinder.py` | Main CLI tool |
| `requirements.txt` | Python dependencies |
| `version_files/` | Lua address files for each known game version |
| `version_files/EGSGlobal_1_0_0_10.lua` | EGS 1.0.0.10 — reference addresses |
| `version_files/SteamGlobal_1_0_0_2.lua` | Steam 1.0.0.2 — reference addresses |
| `patterns/merged_verified_v2.json` | **Authoritative pattern file** — use this for `find` |
| `patterns/merged_v2.json` | Unverified merge (input to `verify`) |
| `patterns/egs_verified.json` | EGS-only verified patterns (input to `combine`) |
| `patterns/steam_verified.json` | Steam-only verified patterns (input to `combine`) |
| `patterns/EGSGlobal_1_0_0_10_v2.json` | Raw generated patterns from EGS version |
| `patterns/SteamGlobal_1_0_0_2_v2.json` | Raw generated patterns from Steam version |
| `patterns/cross_version.json` | Direct-byte patterns stable across both versions |
| `patterns/offsets.json` | Anchor + delta patterns for addresses with no unique AOB |

---

## Notes

- Addresses below `0x10000` (e.g. `musicBaseSpeed = 0`) are treated as literal constants and skipped by the pattern engine.
- `slideActive` and `textMemory` are not in the pattern database and must be found manually after a version update.
- The `--lua` template passed to `find` only affects output structure (comments, ordering, section headers). The addresses in it are irrelevant to the scan.
