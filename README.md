# SFM Runtime Monitor

A live, **read-only** resource monitor for a running Source Filmmaker (SFM) process on Windows. Every couple of seconds it shows how close SFM is to running out of memory, address space or GPU memory. It flags configured entry and abort thresholds, and it stops itself rather than guessing when it can't measure something.

Developed by **ChadChan3D** (ChadChanSFM).

> **Status: 0.1.0, pre-release.** It is derived from a monitor that passed one idle validation against SFM with no session open (see [PROVENANCE.md](PROVENANCE.md)). Its live warning paths have not been exercised, and this standalone edition has not itself been run.

**License:** [CC0 1.0 Universal](LICENSE), a public-domain dedication. Attribution is appreciated but not required.

## What it measures

For one SFM process, pinned by its executable's SHA-256 and process creation time:

| Reading | Source |
| --- | --- |
| SFM private memory | `GetProcessMemoryInfo` |
| Available physical RAM | `GlobalMemoryStatusEx` |
| System commit headroom | `GetPerformanceInfo` |
| Total free user-mode address space | `VirtualQueryEx` walk, up to the target's own 32-bit limit |
| Largest free address-space region | the same walk |
| SFM dedicated GPU memory | PDH counter `\GPU Process Memory(pid_N_…)\Dedicated Usage` |

SFM is a 32-bit (WOW64) program, so address-space exhaustion is usually its real limit, not system RAM.

## Safety behavior

- **Read-only.** It never sends input to SFM, injects code, terminates SFM, or writes SFM files or the registry. Flags are signals for **you** to act on.
- **Fail-closed identity.**
  - It refuses to attach unless the process image matches your configured SHA-256, is a 32-bit i386 image, runs under WOW64, and is alive.
  - Identity is reported verified only after all of those checks pass.
- **Fail-closed measurement.**
  - If any reading becomes unavailable, it stops and says the limits are no longer enforced. It never estimates.
  - The address-space walk never goes past the target's own user-mode limit, and any failed query below it stops the monitor.
- **Gaps.**
  - A gap longer than `gap_warning_seconds` is shown immediately.
  - A gap longer than `gap_fail_seconds` records the sample, then stops the monitor.
- **Strict config.** Unknown or missing keys, out-of-range values, or entry limits that aren't stricter than the abort limits all refuse to start. So does the placeholder example config.

## Requirements

- Windows 10 or 11, **64-bit Python 3.8+** (standard library only).
- A running 32-bit SFM.
- Your own SHA-256 of `sfm.exe`, for example from `Get-FileHash sfm.exe` in PowerShell.

## Usage

1. Copy `config/example.config.json` to a private config, for example `config/my-sfm.json`. Everything under `config/` except the example is ignored by `.gitignore`. Then:
   - set `expected_image_sha256` to your `sfm.exe` hash;
   - set `report_dir` to an **existing** folder that is outside any Git work tree and isn't a link;
   - review every threshold. The example values come from one project's bounded session and are **not** universal safe limits.
2. Start SFM normally and note its PID (Task Manager, Details tab).
3. In a console window, run:
   ```
   python -I -B sfm_runtime_monitor.py --pid <PID> --config <path-to-your-config> --label <unique-run-label>
   ```
4. After the attachment message, the **first sample line** should show `ENTRY_OK`. If it shows `ENTRY CONDITIONS NOT MET`, don't add load.
5. Press the configured marker keys (`1`–`9`) at notable moments, such as before and after loading a model. Press `q` to stop. The monitor also ends by itself if SFM exits.
6. **On `!!! ABORT CONDITION` or `!!! MONITOR STOPPED`:** stop what you're doing and close SFM normally if it's responsive.

## Outputs

These go into `report_dir`. They are never overwritten, and an existing label is refused.

- `SRM_<label>_SAMPLES.jsonl`: one JSON line per sample, written as it's taken.
- `SRM_<label>_REPORT.json`: result and stop code, identity status, entry result, abort flags seen, sampled peaks, gaps, markers with deltas between consecutive markers, the limits used, and the config's SHA-256.

The outputs contain no PID, paths or usernames. Treat them as private evidence anyway.

## Exit status

The same value is recorded as `outcome` in the report.

| Code | Outcome | Meaning |
| --- | --- | --- |
| 0 | `CLEAN` | Ended normally (`q` or SFM exit), entry passed, and no abort condition was ever seen |
| 4 | `LIMIT_VIOLATIONS_RECORDED` | Ended normally, but entry conditions were not met or abort conditions were seen. A later normal `q` does not make it a success. |
| 1 | `MONITORING_STOPPED` | Monitoring ended abnormally (missing measurement, sampling gap, identity change or hard cap), or no sample was taken |
| 2 | — | Refused before monitoring (config, output folder, or attach and identity checks) |
| 3 | — | Unexpected failure |

## Limitations

- **Sampling:** spikes between samples aren't seen.
- **Address space:** the readings are region metadata, not guaranteed allocatable memory.
- **Address-space limit:** the 32-bit end (`0xFFFF0000` with LargeAddressAware, `0x7FFF0000` without) is documented Windows behavior, not measured.
- **GPU attribution:** relies on Windows GPU counter instance names (`pid_N_…`). It is not independently checked, and instances that appear after attach are assumed to be picked up.
- **UI hangs** aren't measured. Watch SFM yourself.
- **Overhead:** the observer's own overhead isn't qualified.
