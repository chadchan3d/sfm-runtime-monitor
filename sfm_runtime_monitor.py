#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""SFM Runtime Monitor: live, read-only resource monitor for a running Source Filmmaker process.

Standalone edition derived from the validated "S4 Live Monitor V2" (see PROVENANCE.md). Measurement
logic and fail-closed behavior are unchanged; installation-specific values (report directory, image
identity pin, thresholds, marker labels) come from a required, strictly validated JSON config.

Every ~interval seconds it reports, for one pinned 32-bit (WOW64) SFM process:
  private memory, available physical RAM, commit headroom, total free user-mode virtual address
  space, largest free address-space region, and SFM-attributed dedicated GPU memory.

Fail-closed rules:
  * The process image must match the configured SHA-256 pin; identity is reported verified only after
    every attach check succeeds (image hash, i386 image, WOW64 target, creation time, liveness).
  * VA traversal ends at the target's own user-mode limit (from WOW64 status and the image's
    LargeAddressAware flag); any failed query below it stops the monitor.
  * Any unavailable required measurement stops the monitor; nothing is estimated or substituted.
  * A sampling gap over gap_warning_seconds is shown immediately; over gap_fail_seconds the monitor
    records the sample and stops.
  * The PDH counter array is bounded before allocation.

Read-only: no input to SFM, no injection, no termination, no writes to SFM files or the registry.
Entry/abort flags are signals for the operator; the monitor never acts on SFM.

Keys in this console: configured marker keys (e.g. 1-9), q to stop.

Exit status (also recorded as "outcome" in the report):
  0  CLEAN                      normal end (operator q or target exit), entry PASS, no abort condition seen
  4  LIMIT_VIOLATIONS_RECORDED  normal end, but entry conditions were not met and/or abort conditions were seen
  1  MONITORING_STOPPED         monitoring ended abnormally (missing measurement, gap, identity change, cap)
                               or no sample was taken
  2  REFUSED                    config, output or attach/identity checks refused before monitoring
  3  UNEXPECTED_FAILURE
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
import time
from datetime import datetime, timezone
from ctypes import wintypes

VERSION = "SFM_RUNTIME_MONITOR_0.1.0"
DERIVED_FROM = "S4_LIVE_MONITOR_V2 sha256 dc151e695d1891aa2a3d7b4307761bcdedfd8c4a5b3bddc0dadc3ee04a1d4614"
MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
# 32-bit (WOW64) user-mode limits, exclusive: highest application address 0xFFFEFFFF with
# LargeAddressAware, 0x7FFEFFFF without. The top 64 KiB is never queried.
VA_END_LAA = 0xFFFF0000
VA_END_NO_LAA = 0x7FFF0000
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
MAX_VA_QUERIES = 131072
MEM_FREE = 0x10000
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
MiB = 1024 * 1024
GiB = 1024 * MiB

GPU_COUNTER = "\\GPU Process Memory(*)\\Dedicated Usage"
PDH_FMT_LARGE = 0x00000400
PDH_MORE_DATA = 0x800007D2
MAX_PDH_ITEMS = 4096
MAX_PDH_BUFFER_BYTES = 4 * 1024 * 1024  # checked before allocation
_PID_RE = re.compile(r"(?i)^pid_([0-9]+)(?:_|$)")
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
_MARKER_LABEL_RE = re.compile(r"[A-Z0-9][A-Z0-9_]{0,31}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IMAGE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}\.exe")

# Config schema: section -> {key: (unit_bytes, lower_bound, upper_bound)}
ENTRY_KEYS = {"private_max_mib": (MiB, 1, 4096), "ram_min_gib": (GiB, 0.25, 4096),
              "commit_min_gib": (GiB, 0.25, 4096), "va_free_min_mib": (MiB, 1, 4096),
              "va_largest_min_mib": (MiB, 1, 4096), "gpu_max_mib": (MiB, 1, 1048576)}
ABORT_KEYS = {"private_above_mib": (MiB, 1, 4096), "ram_below_gib": (GiB, 0.25, 4096),
              "commit_below_gib": (GiB, 0.25, 4096), "va_free_below_mib": (MiB, 1, 4096),
              "va_largest_below_mib": (MiB, 1, 4096), "gpu_at_or_above_mib": (MiB, 1, 1048576)}
TOP_KEYS = {"project_label", "expected_image_name", "expected_image_sha256", "report_dir",
            "interval_seconds", "gap_warning_seconds", "gap_fail_seconds",
            "session_limit_seconds", "hard_cap_seconds", "entry", "abort", "markers"}


class ProbeError(Exception):
    """Contains only a fixed privacy-safe code."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _num(v, lo, hi, code):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not lo <= v <= hi:
        raise ProbeError(code)
    return v


def load_config(path: str) -> dict:
    """Strict config validation. Missing, unknown or inconsistent values refuse to start."""
    try:
        raw = pathlib.Path(path).read_bytes()
    except OSError:
        raise ProbeError("SRM_CONFIG_UNREADABLE") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ProbeError("SRM_CONFIG_TOO_LARGE")
    try:
        c = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProbeError("SRM_CONFIG_NOT_JSON") from None
    if not isinstance(c, dict) or set(c) != TOP_KEYS:
        raise ProbeError("SRM_CONFIG_KEYS")
    if not isinstance(c["project_label"], str) or not _LABEL_RE.fullmatch(c["project_label"]):
        raise ProbeError("SRM_CONFIG_PROJECT_LABEL")
    if not isinstance(c["expected_image_name"], str) or not _IMAGE_NAME_RE.fullmatch(c["expected_image_name"]):
        raise ProbeError("SRM_CONFIG_IMAGE_NAME")
    if not isinstance(c["expected_image_sha256"], str) or not _SHA256_RE.fullmatch(c["expected_image_sha256"]):
        raise ProbeError("SRM_CONFIG_IMAGE_SHA256")
    if not isinstance(c["report_dir"], str) or not os.path.isabs(c["report_dir"]):
        raise ProbeError("SRM_CONFIG_REPORT_DIR")
    interval = _num(c["interval_seconds"], 1, 10, "SRM_CONFIG_INTERVAL")
    warn = _num(c["gap_warning_seconds"], 1, 60, "SRM_CONFIG_GAP_WARNING")
    fail = _num(c["gap_fail_seconds"], 1, 60, "SRM_CONFIG_GAP_FAIL")
    if not interval < warn < fail:
        raise ProbeError("SRM_CONFIG_GAP_ORDER")
    session = _num(c["session_limit_seconds"], 10, 4 * 3600, "SRM_CONFIG_SESSION_LIMIT")
    hard = _num(c["hard_cap_seconds"], 10, 4 * 3600, "SRM_CONFIG_HARD_CAP")
    if not session <= hard:
        raise ProbeError("SRM_CONFIG_LIMIT_ORDER")
    entry, abort = {}, {}
    for sec, keys, out in (("entry", ENTRY_KEYS, entry), ("abort", ABORT_KEYS, abort)):
        if not isinstance(c[sec], dict) or set(c[sec]) != set(keys):
            raise ProbeError("SRM_CONFIG_%s_KEYS" % sec.upper())
        for k, (unit, lo, hi) in keys.items():
            out[k.rsplit("_", 1)[0]] = int(_num(c[sec][k], lo, hi, "SRM_CONFIG_%s_VALUE" % sec.upper()) * unit)
    # Entry conditions must be stricter than abort conditions.
    if not (entry["private_max"] < abort["private_above"]
            and entry["ram_min"] > abort["ram_below"]
            and entry["commit_min"] > abort["commit_below"]
            and entry["va_free_min"] > abort["va_free_below"]
            and entry["va_largest_min"] > abort["va_largest_below"]
            and entry["gpu_max"] < abort["gpu_at_or_above"]):
        raise ProbeError("SRM_CONFIG_ENTRY_NOT_STRICTER_THAN_ABORT")
    markers = c["markers"]
    if not isinstance(markers, dict) or len(markers) > 9:
        raise ProbeError("SRM_CONFIG_MARKERS")
    for k, v in markers.items():
        if k not in "123456789" or len(k) != 1 or not isinstance(v, str) or not _MARKER_LABEL_RE.fullmatch(v):
            raise ProbeError("SRM_CONFIG_MARKERS")
    return {"project_label": c["project_label"], "image_name": c["expected_image_name"],
            "image_sha256": c["expected_image_sha256"], "report_dir": c["report_dir"],
            "interval": float(interval), "gap_warn": float(warn), "gap_fail": float(fail),
            "session_limit": float(session), "hard_cap": float(hard),
            "entry": entry, "abort": abort, "markers": dict(markers),
            "config_sha256": hashlib.sha256(raw).hexdigest()}


def reject_git_ancestors(folder: pathlib.Path) -> None:
    for ancestor in (folder, *folder.parents):
        if (ancestor / ".git").exists():
            raise ProbeError("SRM_REPORT_DIRECTORY_IN_GIT")
        if ancestor.lstat().st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ProbeError("SRM_REPORT_DIRECTORY_REPARSE_POINT")


def validate_output(folder_str: str, label: str):
    if not _LABEL_RE.fullmatch(label):
        raise ProbeError("SRM_LABEL_INVALID")
    folder = pathlib.Path(folder_str)
    if not folder.is_absolute() or not folder.is_dir():
        raise ProbeError("SRM_REPORT_DIRECTORY_MUST_EXIST")
    reject_git_ancestors(folder)
    folder = folder.resolve(strict=True)
    report = folder / ("SRM_%s_REPORT.json" % label)
    samples = folder / ("SRM_%s_SAMPLES.jsonl" % label)
    for p in (report, samples):
        if p.exists() or p.is_symlink():
            raise ProbeError("SRM_REPORT_ALREADY_EXISTS")
    return report, samples


def digest_image(image_path: str, expected_name: str, expected_sha256: str) -> bool:
    """Verify the process image against the pin; return its LargeAddressAware flag from the verified bytes."""
    source = pathlib.Path(image_path)
    if source.name.casefold() != expected_name.casefold() or source.is_symlink():
        raise ProbeError("SRM_PROCESS_NOT_EXPECTED_IMAGE")
    try:
        if not 0 < source.stat().st_size <= MAX_BINARY_BYTES:
            raise ProbeError("SRM_IMAGE_SIZE_INVALID")
        with source.open("rb") as f:
            data = f.read(MAX_BINARY_BYTES + 1)
    except OSError:
        raise ProbeError("SRM_IMAGE_READ_FAILED") from None
    if len(data) > MAX_BINARY_BYTES or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ProbeError("SRM_IMAGE_IDENTITY_MISMATCH")
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ProbeError("SRM_IMAGE_HEADER_INVALID")
    pe = int.from_bytes(data[0x3C:0x40], "little")
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ProbeError("SRM_IMAGE_HEADER_INVALID")
    if int.from_bytes(data[pe + 4:pe + 6], "little") != IMAGE_FILE_MACHINE_I386:
        raise ProbeError("SRM_IMAGE_NOT_32BIT")
    return bool(int.from_bytes(data[pe + 22:pe + 24], "little") & IMAGE_FILE_LARGE_ADDRESS_AWARE)


def filetime_num(ft) -> int:
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


# ---- Windows structures ----
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
    ]

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]

class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]

class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    _fields_ = [("CStatus", wintypes.DWORD), ("largeValue", ctypes.c_longlong)]  # union read as LONGLONG

class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", ctypes.c_wchar_p), ("FmtValue", PDH_FMT_COUNTERVALUE)]


class WinApi:
    def __init__(self, cfg):
        if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ProbeError("SRM_REQUIRES_WINDOWS_64BIT_PYTHON")
        self.cfg = cfg
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ps = ctypes.WinDLL("psapi", use_last_error=True)
        self.pdh = ctypes.WinDLL("pdh")
        k, ps, pdh = self.k, self.ps, self.pdh
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(FILETIME)] * 4
        k.GetProcessTimes.restype = wintypes.BOOL
        k.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k.GetProcessHandleCount.restype = wintypes.BOOL
        k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
        k.GlobalMemoryStatusEx.restype = wintypes.BOOL
        k.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        k.IsWow64Process.restype = wintypes.BOOL
        ps.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
        ps.GetProcessMemoryInfo.restype = wintypes.BOOL
        ps.GetPerformanceInfo.argtypes = [ctypes.POINTER(PERFORMANCE_INFORMATION), wintypes.DWORD]
        ps.GetPerformanceInfo.restype = wintypes.BOOL
        pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wintypes.HANDLE)]
        pdh.PdhOpenQueryW.restype = wintypes.LONG
        pdh.PdhAddEnglishCounterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wintypes.HANDLE)]
        pdh.PdhAddEnglishCounterW.restype = wintypes.LONG
        pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
        pdh.PdhCollectQueryData.restype = wintypes.LONG
        pdh.PdhGetFormattedCounterArrayW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                     ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        pdh.PdhGetFormattedCounterArrayW.restype = wintypes.LONG
        pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
        pdh.PdhCloseQuery.restype = wintypes.LONG
        self.handle = None
        self.pid = None
        self.creation = None
        self.query = None
        self.counter = None
        self.va_end = None
        self.identity_verified = False  # set only after every attach/identity check below succeeds

    def open(self, pid):
        # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE. Handle retained all session.
        h = self.k.OpenProcess(0x0400 | 0x0010 | 0x00100000, False, pid)
        if not h:
            raise ProbeError("SRM_PROCESS_OPEN_FAILED")
        self.handle, self.pid = h, pid
        chars = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(chars))
        if not self.k.QueryFullProcessImageNameW(h, 0, chars, ctypes.byref(n)):
            raise ProbeError("SRM_IMAGE_QUERY_FAILED")
        laa = digest_image(chars.value[:n.value], self.cfg["image_name"], self.cfg["image_sha256"])
        wow64 = wintypes.BOOL()
        if not self.k.IsWow64Process(h, ctypes.byref(wow64)) or not wow64.value:
            raise ProbeError("SRM_TARGET_NOT_WOW64_32BIT")
        self.va_end = VA_END_LAA if laa else VA_END_NO_LAA
        self.creation = filetime_num(self.times()[0])
        if not self.is_alive():
            raise ProbeError("SRM_TARGET_EXITED")
        self.identity_verified = True
        q, c = wintypes.HANDLE(), wintypes.HANDLE()
        if self.pdh.PdhOpenQueryW(None, 0, ctypes.byref(q)) != 0:
            raise ProbeError("SRM_GPU_QUERY_OPEN_FAILED")
        self.query = q
        if self.pdh.PdhAddEnglishCounterW(q, GPU_COUNTER, 0, ctypes.byref(c)) != 0:
            raise ProbeError("SRM_GPU_COUNTER_ADD_FAILED")
        self.counter = c

    def close(self):
        if self.query:
            self.pdh.PdhCloseQuery(self.query)
            self.query = None
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def times(self):
        ft = [FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(self.handle, *[ctypes.byref(x) for x in ft]):
            raise ProbeError("SRM_PROCESS_TIMES_FAILED")
        return ft

    def is_alive(self):
        res = self.k.WaitForSingleObject(self.handle, 0)
        if res == WAIT_OBJECT_0:
            return False
        if res != WAIT_TIMEOUT:
            raise ProbeError("SRM_PROCESS_WAIT_FAILED")
        return True

    def va_map(self, deadline):
        """Bounded by the target's own user-mode limit (self.va_end). No address at or above va_end is
        ever queried; a failed query below it means incomplete coverage and stops the monitor."""
        if self.va_end not in (VA_END_LAA, VA_END_NO_LAA):
            raise ProbeError("SRM_VA_LIMIT_UNKNOWN")
        total_free = largest = committed = reserved = 0
        addr, q = 0x10000, 0
        while addr < self.va_end:
            if q >= MAX_VA_QUERIES or time.monotonic() > deadline:
                raise ProbeError("SRM_VA_MAP_LIMIT_EXCEEDED")
            info = MEMORY_BASIC_INFORMATION()
            result = self.k.VirtualQueryEx(self.handle, ctypes.c_void_p(addr), ctypes.byref(info), ctypes.sizeof(info))
            if not result:
                raise ProbeError("SRM_VA_MAP_INCOMPLETE")
            if result != ctypes.sizeof(info):
                raise ProbeError("SRM_VA_MAP_PARTIAL_STRUCTURE")
            base, size = int(info.BaseAddress or 0), int(info.RegionSize)
            end = base + size
            if size <= 0 or base > addr or end <= addr:
                raise ProbeError("SRM_VA_MAP_INVALID_REGION")
            clipped = min(end, self.va_end) - max(base, addr)
            if info.State == MEM_FREE:
                total_free += clipped
                largest = max(largest, clipped)
            elif info.State == MEM_COMMIT:
                committed += clipped
            elif info.State == MEM_RESERVE:
                reserved += clipped
            addr = end
            q += 1
        return {"free_bytes": total_free, "largest_free_bytes": largest,
                "committed_bytes": committed, "reserved_bytes": reserved, "query_count": q}

    def gpu_dedicated(self):
        """\\GPU Process Memory(pid_N_...)\\Dedicated Usage rows whose leading decimal pid equals the target's."""
        if self.pdh.PdhCollectQueryData(self.query) != 0:
            raise ProbeError("SRM_GPU_COLLECT_FAILED")
        size, count = wintypes.DWORD(0), wintypes.DWORD(0)
        st = self.pdh.PdhGetFormattedCounterArrayW(self.counter, PDH_FMT_LARGE, ctypes.byref(size), ctypes.byref(count), None)
        if (st & 0xFFFFFFFF) != PDH_MORE_DATA or size.value == 0:
            raise ProbeError("SRM_GPU_COUNTER_UNAVAILABLE")
        # Bound the requested allocation before allocating anything.
        if size.value > MAX_PDH_BUFFER_BYTES or count.value > MAX_PDH_ITEMS:
            raise ProbeError("SRM_GPU_COUNTER_ARRAY_TOO_LARGE")
        allocated = size.value
        buf = (ctypes.c_byte * allocated)()
        st = self.pdh.PdhGetFormattedCounterArrayW(self.counter, PDH_FMT_LARGE, ctypes.byref(size), ctypes.byref(count), buf)
        if (st != 0 or size.value > allocated or count.value > MAX_PDH_ITEMS
                or count.value * ctypes.sizeof(PDH_FMT_COUNTERVALUE_ITEM_W) > allocated):
            raise ProbeError("SRM_GPU_COUNTER_READ_FAILED")
        items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W * count.value)).contents
        total, matched = 0, 0
        for it in items:
            m = _PID_RE.match(it.szName or "")
            if not m or int(m.group(1)) != self.pid:
                continue
            v = it.FmtValue
            if v.CStatus not in (0, 1) or not 0 <= v.largeValue <= 1 << 40:
                raise ProbeError("SRM_GPU_VALUE_INVALID")
            total += int(v.largeValue)
            matched += 1
        if matched == 0:
            raise ProbeError("SRM_GPU_TARGET_INSTANCE_MISSING")
        return total, matched

    def sample(self, deadline):
        if not self.is_alive():
            raise ProbeError("SRM_TARGET_EXITED")
        if filetime_num(self.times()[0]) != self.creation:
            raise ProbeError("SRM_PROCESS_ASSOCIATION_CHANGED")
        mm = PROCESS_MEMORY_COUNTERS_EX()
        mm.cb = ctypes.sizeof(mm)
        if not self.ps.GetProcessMemoryInfo(self.handle, ctypes.byref(mm), mm.cb):
            raise ProbeError("SRM_MEMORY_COUNTERS_FAILED")
        handles = wintypes.DWORD()
        if not self.k.GetProcessHandleCount(self.handle, ctypes.byref(handles)):
            raise ProbeError("SRM_HANDLE_COUNTERS_FAILED")
        ms = MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(ms)
        if not self.k.GlobalMemoryStatusEx(ctypes.byref(ms)):
            raise ProbeError("SRM_SYSTEM_MEMORY_FAILED")
        pi = PERFORMANCE_INFORMATION()
        pi.cb = ctypes.sizeof(pi)
        if not self.ps.GetPerformanceInfo(ctypes.byref(pi), pi.cb) or pi.CommitTotal > pi.CommitLimit:
            raise ProbeError("SRM_COMMIT_HEADROOM_UNAVAILABLE")
        va = self.va_map(deadline)
        gpu, gpu_instances = self.gpu_dedicated()
        return {"private_bytes": int(mm.PrivateUsage), "working_set_bytes": int(mm.WorkingSetSize),
                "handle_count": int(handles.value),
                "system_available_physical_bytes": int(ms.ullAvailPhys),
                "system_commit_headroom_bytes": (int(pi.CommitLimit) - int(pi.CommitTotal)) * int(pi.PageSize),
                "va_free_bytes": va["free_bytes"], "va_largest_free_bytes": va["largest_free_bytes"],
                "va_query_count": va["query_count"],
                "gpu_dedicated_bytes": gpu, "gpu_memory_instances": gpu_instances}


def entry_flags(s, e):
    f = []
    if s["private_bytes"] > e["private_max"]: f.append("ENTRY_PRIVATE_ABOVE_LIMIT")
    if s["system_available_physical_bytes"] < e["ram_min"]: f.append("ENTRY_RAM_BELOW_LIMIT")
    if s["system_commit_headroom_bytes"] < e["commit_min"]: f.append("ENTRY_COMMIT_BELOW_LIMIT")
    if s["va_free_bytes"] < e["va_free_min"]: f.append("ENTRY_VA_FREE_BELOW_LIMIT")
    if s["va_largest_free_bytes"] < e["va_largest_min"]: f.append("ENTRY_VA_LARGEST_BELOW_LIMIT")
    if s["gpu_dedicated_bytes"] > e["gpu_max"]: f.append("ENTRY_GPU_ABOVE_LIMIT")
    return f


def abort_flags(s, a, elapsed, session_limit):
    f = []
    if s["private_bytes"] > a["private_above"]: f.append("ABORT_PRIVATE_ABOVE_LIMIT")
    if s["system_available_physical_bytes"] < a["ram_below"]: f.append("ABORT_RAM_BELOW_LIMIT")
    if s["system_commit_headroom_bytes"] < a["commit_below"]: f.append("ABORT_COMMIT_BELOW_LIMIT")
    if s["va_free_bytes"] < a["va_free_below"]: f.append("ABORT_VA_FREE_BELOW_LIMIT")
    if s["va_largest_free_bytes"] < a["va_largest_below"]: f.append("ABORT_VA_LARGEST_BELOW_LIMIT")
    if s["gpu_dedicated_bytes"] >= a["gpu_at_or_above"]: f.append("ABORT_GPU_AT_OR_ABOVE_LIMIT")
    if elapsed >= session_limit: f.append("ABORT_SESSION_LIMIT_REACHED")
    return f


def read_marker(markers):
    import msvcrt
    while msvcrt.kbhit():
        ch = msvcrt.getwch().lower()
        if ch == "q":
            return "QUIT"
        if ch in markers:
            return markers[ch]
    return None


def line(t, s, flags):
    return ("t=%6.1fs  priv=%7.1f MiB  RAM=%5.2f GiB  commit=%5.2f GiB  VAfree=%7.1f MiB  VAmax=%7.1f MiB  GPU=%6.1f MiB  %s" % (
        t, s["private_bytes"] / MiB, s["system_available_physical_bytes"] / GiB,
        s["system_commit_headroom_bytes"] / GiB, s["va_free_bytes"] / MiB, s["va_largest_free_bytes"] / MiB,
        s["gpu_dedicated_bytes"] / MiB, " ".join(flags) or "ok"))


def run(args):
    cfg = load_config(args.config)
    report_path, samples_path = validate_output(cfg["report_dir"], args.label)
    api = WinApi(cfg)
    start = time.monotonic()
    started_utc = utc_now()
    status, stop_code = "MONITORING", None
    entry_result, aborts_seen, markers, gaps = None, [], [], []
    peaks = {}
    count, last_t = 0, None
    samples_file = open(samples_path, "x", encoding="utf-8", newline="\n")
    try:
        api.open(args.pid)
        keys = ", ".join("%s=%s" % kv for kv in sorted(cfg["markers"].items())) or "none"
        print("Monitor attached (process identity verified). Marker keys: %s; q stops." % keys)
        while True:
            before = time.monotonic()
            elapsed = before - start
            if elapsed >= cfg["hard_cap"]:
                status, stop_code = "STOPPED", "SRM_HARD_CAP_REACHED"
                break
            mk = read_marker(cfg["markers"])
            if mk == "QUIT":
                status, stop_code = "STOPPED", "SRM_OPERATOR_STOP"
                break
            try:
                s = api.sample(deadline=before + 5)
            except ProbeError as exc:
                status, stop_code = "STOPPED", str(exc)
                if stop_code == "SRM_TARGET_EXITED":
                    print("Target process exited. Monitoring ended.")
                else:
                    print("!!! MONITOR STOPPED: %s - required measurement unavailable; LIMITS ARE NO LONGER ENFORCED. "
                          "Stop the session and close SFM normally if it is responsive." % stop_code)
                break
            t = round(time.monotonic() - start, 3)
            flags = []
            delayed = False
            if last_t is not None and t - last_t > cfg["gap_warn"]:
                gap = round(t - last_t, 3)
                delayed = gap > cfg["gap_fail"]
                gaps.append({"from_t": last_t, "to_t": t, "seconds": gap, "fail_closed": delayed})
                flags.append("MONITOR_GAP_%.1fS" % gap)
                print("!!! MONITORING GAP: %.1f s without a sample (t=%.1f to %.1f)." % (gap, last_t, t))
            last_t = t
            if entry_result is None:
                entry_result = entry_flags(s, cfg["entry"])
                flags += entry_result or ["ENTRY_OK"]
                if entry_result:
                    print("!!! ENTRY CONDITIONS NOT MET - DO NOT ADD LOAD: " + ", ".join(entry_result))
            ab = abort_flags(s, cfg["abort"], t, cfg["session_limit"])
            for a in ab:
                if a not in aborts_seen:
                    aborts_seen.append(a)
                    print("!!! ABORT CONDITION: %s at t=%.1fs - stop now; do not load or change anything further; "
                          "close SFM normally if responsive." % (a, t))
            flags += ab
            if mk:
                markers.append({"marker": mk, "t": t, "private_bytes": s["private_bytes"],
                                "gpu_dedicated_bytes": s["gpu_dedicated_bytes"]})
                flags.append("MARK_" + mk)
            row = dict(s, t_seconds=t, utc=utc_now(), flags=flags)
            samples_file.write(json.dumps(row, ensure_ascii=True) + "\n")
            samples_file.flush()
            count += 1
            for k, fn in (("private_bytes", max), ("gpu_dedicated_bytes", max),
                          ("system_available_physical_bytes", min), ("system_commit_headroom_bytes", min),
                          ("va_free_bytes", min), ("va_largest_free_bytes", min)):
                peaks[k] = s[k] if k not in peaks else fn(peaks[k], s[k])
            print(line(t, s, flags))
            if delayed:  # evidence row already written above; now fail closed
                status, stop_code = "STOPPED", "SRM_MONITOR_DELAYED"
                print("!!! MONITOR STOPPED: sampling gap over %.0f s - LIMITS ARE NO LONGER ENFORCED. "
                      "Stop the session and close SFM normally if it is responsive." % cfg["gap_fail"])
                break
            delay = cfg["interval"] - (time.monotonic() - before)
            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        status, stop_code = "STOPPED", "SRM_OPERATOR_INTERRUPT"
    except ProbeError as exc:
        status, stop_code = "STOPPED", str(exc)
        print("!!! MONITOR STOPPED: " + stop_code)
    finally:
        api.close()
        samples_file.close()

    marker_deltas = [{"from": a["marker"], "to": b["marker"],
                      "private_bytes": b["private_bytes"] - a["private_bytes"],
                      "gpu_dedicated_bytes": b["gpu_dedicated_bytes"] - a["gpu_dedicated_bytes"]}
                     for a, b in zip(markers, markers[1:])]
    report = {
        "tool": "SFM Runtime Monitor", "version": VERSION, "derived_from": DERIVED_FROM,
        "project_label": cfg["project_label"], "config_sha256": cfg["config_sha256"],
        "result": status, "stop_code": stop_code, "outcome": outcome(stop_code, entry_result, aborts_seen, count),
        "image_sha256_verified_against_pin": api.identity_verified,
        "process_identity": ("PINNED_IMAGE_SHA256_AND_PROCESS_CREATION_TIME_RETAINED_HANDLE"
                             if api.identity_verified else "NOT_VERIFIED"),
        "va_user_mode_end": ("0x%08X" % api.va_end) if api.identity_verified else None,
        "started_utc": started_utc, "elapsed_seconds": round(time.monotonic() - start, 3),
        "sample_count": count, "interval_requested_seconds": cfg["interval"],
        "entry_result": entry_result if entry_result else ("PASS" if entry_result is not None else "NOT_REACHED"),
        "abort_conditions_seen": aborts_seen, "sampled_peaks": peaks, "gaps": gaps,
        "operator_markers": markers, "marker_deltas": marker_deltas,
        "limits_bytes": {"entry": cfg["entry"], "abort": cfg["abort"]},
        "limits_seconds": {"session_limit": cfg["session_limit"], "hard_cap": cfg["hard_cap"],
                           "gap_warning": cfg["gap_warn"], "gap_fail_closed": cfg["gap_fail"]},
        "limitations": [
            "Sampled at the configured interval; peaks between samples are not observed.",
            "Entry/abort flags are signals for the operator; the monitor never acts on SFM.",
            "VA metadata is a proxy, not guaranteed allocatable headroom.",
            "VA coverage ends at the documented WOW64 user-mode limit derived from the image LAA flag; "
            "that limit is documented behavior, not independently measured.",
            "GPU attribution uses the anchored pid_N counter-instance rule; not independently ground-truthed.",
            "UI non-response is not measured; the operator observes it.",
            "Observer overhead not qualified.",
        ],
    }
    with open(report_path, "x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=True)
    return report


NORMAL_END_CODES = ("SRM_TARGET_EXITED", "SRM_OPERATOR_STOP")
OUTCOME_EXIT = {"CLEAN": 0, "LIMIT_VIOLATIONS_RECORDED": 4, "MONITORING_STOPPED": 1}


def outcome(stop_code, entry_result, aborts_seen, count):
    """A normal end is CLEAN only if entry passed and no abort condition was ever seen.
    Limit violations stay non-success even when the operator later quits normally."""
    if stop_code not in NORMAL_END_CODES or count == 0 or entry_result is None:
        return "MONITORING_STOPPED"
    if entry_result or aborts_seen:
        return "LIMIT_VIOLATIONS_RECORDED"
    return "CLEAN"


def main():
    parser = argparse.ArgumentParser(description="SFM Runtime Monitor: live read-only resource monitor. Never acts on SFM.")
    parser.add_argument("--pid", type=int, required=True, help="PID of the already running SFM process")
    parser.add_argument("--config", required=True, help="JSON config (see config/example.config.json)")
    parser.add_argument("--label", required=True, help="unique run label, e.g. idle-check-01")
    args = parser.parse_args()
    if not 0 < args.pid <= 0xFFFFFFFF:
        print("SRM_ARGUMENT_BOUNDS")
        return 2
    try:
        report = run(args)
    except ProbeError as exc:
        print(str(exc))
        return 2
    except Exception as exc:  # never print OS messages that may contain paths
        print("SRM_UNEXPECTED_FAILURE_" + type(exc).__name__.upper())
        return 3
    print("SRM_%s outcome=%s stop=%s samples=%d entry=%s aborts=%s" % (
        report["result"], report["outcome"], report["stop_code"], report["sample_count"],
        report["entry_result"] if isinstance(report["entry_result"], str) else ",".join(report["entry_result"]),
        ",".join(report["abort_conditions_seen"]) or "none"))
    return OUTCOME_EXIT[report["outcome"]]


if __name__ == "__main__":
    sys.exit(main())
