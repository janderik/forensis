"""Process enumeration from memory dumps.

This module provides process listing capabilities by scanning raw memory
dumps for EPROCESS-like structures using heuristic pattern matching.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class ProcessInfo:
    """Represents a discovered process from a memory dump."""

    pid: int = 0
    ppid: int = 0
    name: str = ""
    offset: int = 0
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    path: str = ""
    session_id: int = 0


class ProcessList:
    """Scans a memory dump buffer for process structures."""

    # Common Windows process names for validation
    KNOWN_PROCESSES = {
        "System",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "svchost.exe",
        "spoolsv.exe",
        "explorer.exe",
        "taskmgr.exe",
        "cmd.exe",
        "powershell.exe",
    }

    # EPROCESS.ImageFileName: fixed-size ASCII field (UCHAR[15]).
    IMAGE_NAME_OFFSET = 0x170
    IMAGE_NAME_LEN = 15

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        self._data = data
        self._size = len(data)

    def list_processes(self) -> List[Dict]:
        """Scan memory for process structures and return a list of process dicts."""
        processes: List[Dict] = []

        processes.extend(self._scan_peb_structures())
        processes.extend(self._scan_string_patterns())

        seen = set()
        unique: List[Dict] = []
        for p in processes:
            key = (p["pid"], p["name"])
            if key not in seen:
                seen.add(key)
                unique.append(p)

        return unique[:500]

    def _scan_peb_structures(self) -> List[Dict]:
        """Scan for PEB-like structures in the dump."""
        results: List[Dict] = []
        offset = 0
        # Scan for potential process structures using heuristics. The image
        # name sits at +0x170, so stop only when it no longer fits.
        while offset + self.IMAGE_NAME_OFFSET + 4 <= self._size:
            try:
                maybe_pid = struct.unpack_from("<I", self._data, offset)[0]
                maybe_ppid = struct.unpack_from("<I", self._data, offset + 8)[0]

                if (
                    4 <= maybe_pid <= 65535
                    and 0 <= maybe_ppid <= 65535
                    and maybe_ppid != maybe_pid
                ):
                    name = self._extract_image_name(offset + self.IMAGE_NAME_OFFSET)

                    if name and (
                        name.lower().endswith(".exe") or name in self.KNOWN_PROCESSES
                    ):
                        results.append(
                            {
                                "pid": maybe_pid,
                                "ppid": maybe_ppid,
                                "name": name,
                                "offset": hex(offset),
                                "create_time": self._parse_timestamp(offset + 0x68),
                                "exit_time": self._parse_timestamp(offset + 0x70),
                                "session_id": self._read_uint32(offset + 0x200),
                                "source": "peb_scan",
                            }
                        )
            except (struct.error, ValueError):
                pass
            offset += 4

        return results

    def _scan_string_patterns(self) -> List[Dict]:
        """Scan for process names as raw strings and infer structure."""
        results: List[Dict] = []

        for proc_name in self.KNOWN_PROCESSES:
            # Memory holds names both as ASCII (EPROCESS) and UTF-16LE (PEB);
            # search the name as written and in lower case, in both encodings.
            needles = {
                variant.encode(encoding)
                for variant in (proc_name, proc_name.lower())
                for encoding in ("ascii", "utf-16-le")
            }
            hits = sorted(
                (idx, len(needle))
                for needle in needles
                for idx in self._find_all(needle)
            )
            for idx, length in hits:
                name_bytes = self._data[idx : idx + length]
                context_start = max(0, idx - 64)
                context = self._data[context_start : idx + len(name_bytes) + 64]
                pid = self._heuristic_pid(context, idx - context_start)
                results.append(
                    {
                        "pid": pid if pid else 0,
                        "ppid": 0,
                        "name": proc_name,
                        "offset": hex(idx),
                        "create_time": None,
                        "exit_time": None,
                        "session_id": 0,
                        "source": "string_scan",
                    }
                )

        return results

    def _find_all(self, needle: bytes) -> List[int]:
        positions: List[int] = []
        pos = self._data.find(needle)
        while pos != -1:
            positions.append(pos)
            pos = self._data.find(needle, pos + len(needle))
        return positions

    def _extract_image_name(self, offset: int) -> str:
        """Read EPROCESS.ImageFileName (ASCII), falling back to UTF-16LE."""
        raw = self._data[offset : offset + self.IMAGE_NAME_LEN]
        ascii_name = raw.split(b"\x00", 1)[0]
        if len(ascii_name) >= 3 and all(0x20 <= b < 0x7F for b in ascii_name):
            return ascii_name.decode("ascii").strip()
        return self._extract_string(self._data[offset : offset + 0x80])

    def _extract_string(self, data: bytes) -> str:
        """Extract a null-terminated UTF-16LE string from binary data."""
        try:
            decoded = data.decode("utf-16-le", errors="ignore")
            null_idx = decoded.find("\x00")
            if null_idx != -1:
                decoded = decoded[:null_idx]
            decoded = decoded.strip()
            return decoded if len(decoded) >= 3 else ""
        except Exception:
            return ""

    def _parse_timestamp(self, offset: int) -> Optional[str]:
        """Try to parse a Windows FILETIME (64-bit) at the given offset."""
        try:
            filetime = struct.unpack_from("<Q", self._data, offset)[0]
            if filetime == 0 or filetime > 0x7FFFFFFFFFFFFFFF:
                return None
            # Windows FILETIME is 100-ns intervals since 1601-01-01
            unix_epoch = 11644473600  # seconds between 1601 and 1970
            try:
                ts = filetime / 10_000_000 - unix_epoch
                if ts < 0 or ts > 4102444800:  # year 2100
                    return None
                dt = datetime.utcfromtimestamp(ts)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (OSError, ValueError, OverflowError):
                return None
        except struct.error:
            return None

    def _read_uint32(self, offset: int) -> int:
        """Read a uint32 at offset, return 0 if out of bounds."""
        try:
            return struct.unpack_from("<I", self._data, offset)[0]
        except struct.error:
            return 0

    @staticmethod
    def _heuristic_pid(data: bytes, offset: int) -> Optional[int]:
        """Attempt to extract a PID value near the given offset."""
        for delta in range(0, 64, 4):
            try:
                val = struct.unpack_from("<I", data, delta)[0]
                if 4 <= val <= 65535:
                    return val
            except struct.error:
                continue
        return None
