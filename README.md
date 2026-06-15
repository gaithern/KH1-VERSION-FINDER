# KH1 Version Finder

Scans a running **Kingdom Hearts Final Mix (PC)** process using AOB (Array of Bytes) patterns to locate memory addresses across game versions, then outputs a Lua address file.

## Requirements

- Windows (pymem is Windows-only)
- Python 3.10+

```
pip install -r requirements.txt
```

---

## When a New Game Version Drops

**1. Downpatch to a known version** on your platform of choice (e.g. Steam 1.0.0.2 or EGS 1.0.0.10).

This can be done by restoring a backed-up EXE of that version, or by applying a community xdelta patch.

**2. Load the included autosave** using [1fmSaveAnywhere.lua](https://github.com/Denhonator/KHPCSpeedrunTools/blob/main/1FMMods/scripts/1fmSaveAnywhere.lua).

The autosave is located in the `/save/` folder of this repository. Load it with the SaveAnywhere script.

**3. Make a save file in that room** using SaveAnywhere.

**4. Restore the new EXE.**

**5. Load the save file.**

**6. Open and close your menu.**

This populates the memory region related to the menu, which several patterns depend on.

**7. Run the scanner:**

```
python scan_patterns.py
```

**8. Check `scan_results.lua`.**

This file contains the updated memory addresses for the new version. Expect around 10% of addresses to be `nil` or missing — these will need to be found manually using Cheat Engine or another memory scanner and filled in.

---

## Files

| Path | Purpose |
|------|---------|
| `patterns.json` | AOB pattern database used by `scan_patterns.py` |
| `scan_results.lua` | Output — updated addresses for the new version |
| `version_files/` | Known-good Lua address files for reference |
| `save/` | Autosave to load before scanning |
| `scan_patterns.py` | Main scanner — reads `patterns.json`, writes `scan_results.lua` |
| `context_scan.py` | Captures memory context around addresses (used to build new patterns) |
| `build_patterns.py` | Builds cross-version AOB patterns from context dumps |
| `compare_lua.py` | Compares two Lua address files to check accuracy |
