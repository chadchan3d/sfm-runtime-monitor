# Provenance

## Origin

SFM Runtime Monitor 0.1.0 is a standalone edition of **S4 Live Monitor V2**, a tool written for the private *Model Browser for SFM* project by ChadChan3D, with AI coding assistance.

| Identity | SHA-256 |
| --- | --- |
| Frozen S4 Live Monitor V2 (the validated source) | `dc151e695d1891aa2a3d7b4307761bcdedfd8c4a5b3bddc0dadc3ee04a1d4614` |
| Earlier project observer it adapts (memory, commit and address-space logic) | `ff5e75f07e767ed33fcc2184be4e83e932c522404a147177c97ef7e09274c4b7` |
| Earlier project observer whose GPU counter rule it reuses | `14b5604359ed234a62ce40d2bf38b8bdde1c12e7be6d6db449254675dab258e5` |

**V2 is not reproduced in this repository.** It contains installation-specific values, such as a private report path. It is retained, unchanged, as **private, hash-identified source evidence** in durable private storage. It was **never committed to Model Browser's Git history**, or to any other. This repository has its own clean, independent history and imports nothing from Model Browser's history.

## Changes from V2 in this edition

- **Configuration:** the report directory, executable identity pin, thresholds, session and gap limits, and marker labels moved from constants into a required, strictly validated JSON config. Entry limits must be stricter than abort limits.
- **Identifiers:** project-specific wording and identifiers became generic (error codes `SRM_*`, outputs `SRM_<label>_*`, generic marker deltas).
- **Exit status:** a normal end now exits `0` (`CLEAN`) only if entry passed and no abort condition was ever seen. Otherwise it exits `4` (`LIMIT_VIOLATIONS_RECORDED`). V2 returned success for any normal end.
- **Unchanged:** measurement code, structures, identity checks, address-space bounds, the PDH allocation bound, gap fail-closed behavior and read-only operation.

## Validation record (of V2, not yet of this edition)

One idle validation was run on 2026-10-16, with SFM at its **no-session** screen. The designer's disposition was **PASS WITH NOTES, for idle monitor functionality only**:
- identity verified and `ENTRY_OK`;
- 89 valid samples over 178.9 s, at intervals of 1.969–2.032 s;
- all six readings valid; no gaps over 3 s; no abort conditions; normal operator stop.

**Not validated:**
- resource behavior inside an active SFM session;
- the live gap and abort warning paths;
- this standalone edition itself.

The validated SFM build's `sfm.exe` SHA-256 was `8c719e1b1c913695545eddbcd5ebd80f2737702ae1e68e614b0a38472354671c`. Use your own build's hash.

## License

- **License:** released under **CC0 1.0 Universal** (`LICENSE`; SPDX `CC0-1.0`) by owner decision, consistent with other ChadChan3D software projects.
- **Authorship:** all code is original project work. It uses only the Python standard library and documented Windows APIs (kernel32, psapi, pdh) through `ctypes`. No third-party source code was copied.
- **Scope:** CC0 covers this repository's own content only. It grants nothing for Source Filmmaker, Valve software, or any other third-party product the tool observes.
