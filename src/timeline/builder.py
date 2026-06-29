"""Timeline builder — constructs super-timelines from filesystem metadata
and event logs parsed from forensic images.
"""

from __future__ import annotations

import csv
import logging
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from dateutil import parser as dateparser

logger = logging.getLogger(__name__)


@dataclass
class TimelineEntry:
    """A single event in the timeline."""

    timestamp: str = ""
    timestamp_epoch: float = 0.0
    source: str = ""
    event_type: str = ""
    description: str = ""
    path: str = ""
    size: int = 0
    integrity: str = "unknown"


class TimelineBuilder:
    """Builds forensic timelines from disk images and metadata sources."""

    TIMESTAMP_PATTERNS = [
        # ISO 8601
        re.compile(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        ),
        # Windows event log style
        re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"),
        # US style
        re.compile(r"(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"),
        # Linux syslog
        re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
        # FILETIME hex
        re.compile(r"(0x[0-9a-fA-F]{16})"),
    ]

    # Common Windows event log sources to scan for
    EVENT_LOG_SOURCES = [
        b"Security",
        b"System",
        b"Application",
        b"PowerShell",
        b"Microsoft-Windows-Sysmon",
    ]

    def __init__(self, image_path: str) -> None:
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
        self.image_path = image_path
        self._data: Optional[bytes] = None

    def _load(self) -> None:
        if self._data is not None:
            return
        with open(self.image_path, "rb") as f:
            self._data = f.read()

    def build(self, source_types: Optional[List[str]] = None) -> List[TimelineEntry]:
        """Build a timeline from the image.

        Args:
            source_types: Types of sources to include (e.g. ['filesystem', 'events']).
                          If None, all available sources are scanned.

        Returns:
            Sorted list of TimelineEntry objects.
        """
        self._load()
        if self._data is None:
            return []

        entries: List[TimelineEntry] = []

        if source_types is None or "filesystem" in source_types:
            entries.extend(self._extract_filesystem_metadata())

        if source_types is None or "events" in source_types:
            entries.extend(self._extract_event_logs())

        if source_types is None or "strings" in source_types:
            entries.extend(self._extract_string_timestamps())

        # Deduplicate and sort chronologically
        entries = self._deduplicate(entries)
        entries.sort(key=lambda e: e.timestamp_epoch)
        return entries

    def _extract_filesystem_metadata(self) -> List[TimelineEntry]:
        """Extract file timestamps by scanning the image for filesystem structures."""
        entries: List[TimelineEntry] = []
        if self._data is None:
            return entries

        # Scan for NTFS file records
        offset = 0
        while offset < len(self._data) - 1024:
            try:
                if self._data[offset : offset + 4] == b"FILE":
                    name = self._extract_ntfs_name(offset)
                    if name and not name.startswith("$"):
                        # Parse standard info timestamps
                        stdinfo_offset = self._find_stdinfo(offset)
                        if stdinfo_offset:
                            for label, ts_offset in [
                                ("created", 0x18),
                                ("modified", 0x20),
                                ("mft_modified", 0x28),
                                ("accessed", 0x30),
                            ]:
                                epoch = self._parse_filetime(stdinfo_offset + ts_offset)
                                if epoch is not None:
                                    try:
                                        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                                        entries.append(TimelineEntry(
                                            timestamp=dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                            timestamp_epoch=epoch,
                                            source="NTFS",
                                            event_type=label,
                                            description=f"File {label}: {name}",
                                            path=name,
                                            size=self._read_mft_size(offset),
                                        ))
                                    except (OSError, ValueError, OverflowError):
                                        pass
            except (struct.error, ValueError, IndexError):
                pass
            offset += 2

        return entries

    def _extract_event_logs(self) -> List[TimelineEntry]:
        """Scan for Windows Event Log entries (ELF/EVT/EVTX)."""
        entries: List[TimelineEntry] = []
        if self._data is None:
            return entries

        for source in self.EVENT_LOG_SOURCES:
            pos = 0
            while pos < len(self._data):
                idx = self._data.find(source, pos)
                if idx == -1:
                    break
                context = self._data[max(0, idx - 64) : idx + 256]
                text = context.decode("utf-16-le", errors="replace")
                ts = self._find_date_in_text(text)
                if ts:
                    entries.append(TimelineEntry(
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        timestamp_epoch=ts.timestamp(),
                        source=source.decode("ascii", errors="replace"),
                        event_type="event_log",
                        description=f"Event log entry: {text[:80].strip()}",
                    ))
                pos = idx + 1

        return entries

    def _extract_string_timestamps(self) -> List[TimelineEntry]:
        """Extract timestamps from formatted date strings in the image."""
        entries: List[TimelineEntry] = []
        if self._data is None:
            return entries

        # Scan for ISO timestamps in readable strings
        for pattern in self.TIMESTAMP_PATTERNS:
            for match in pattern.finditer(self._data[:50_000_000]):  # First 50MB
                ts_str = match.group(1).decode("ascii", errors="ignore")

                # Skip hex patterns that are all zeros
                if ts_str.startswith("0x") and ts_str == "0x0000000000000000":
                    continue

                try:
                    if ts_str.startswith("0x"):
                        # Parse as Windows FILETIME hex
                        filetime = int(ts_str, 16)
                        if filetime == 0 or filetime > 0x7FFFFFFFFFFF:
                            continue
                        epoch = filetime / 10_000_000 - 11644473600
                        if epoch < 0 or epoch > 4102444800:
                            continue
                        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                    else:
                        dt = dateparser.parse(ts_str)
                        if dt is None:
                            continue
                        if dt.year < 1980 or dt.year > 2100:
                            continue
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)

                    epoch = dt.timestamp()
                    entries.append(TimelineEntry(
                        timestamp=dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        timestamp_epoch=epoch,
                        source="string",
                        event_type="timestamp",
                        description=f"Embedded timestamp: {ts_str}",
                    ))
                except (ValueError, OverflowError, OSError):
                    continue

        return entries

    def _find_stdinfo(self, mft_offset: int) -> Optional[int]:
        """Find the $STANDARD_INFORMATION attribute in an MFT record."""
        if self._data is None:
            return None
        try:
            attr_offset = struct.unpack_from("<H", self._data, mft_offset + 0x14)[0]
            pos = mft_offset + attr_offset
            while pos < mft_offset + 1024 - 24:
                attr_type = struct.unpack_from("<I", self._data, pos)[0]
                if attr_type == 0xFFFFFFFF:
                    break
                if attr_type == 0x10:  # $STANDARD_INFORMATION
                    return pos + 0x18  # Content offset
                attr_len = struct.unpack_from("<I", self._data, pos + 4)[0]
                if attr_len == 0:
                    break
                pos += attr_len
        except (struct.error, ValueError):
            pass
        return None

    def _parse_filetime(self, offset: int) -> Optional[float]:
        """Parse a 64-bit Windows FILETIME at offset, return Unix epoch."""
        if self._data is None or offset + 8 > len(self._data):
            return None
        try:
            filetime = struct.unpack_from("<Q", self._data, offset)[0]
            if filetime == 0 or filetime > 0x7FFFFFFFFFFF:
                return None
            epoch = filetime / 10_000_000 - 11644473600
            if epoch < 0 or epoch > 4102444800:
                return None
            return epoch
        except struct.error:
            return None

    def _read_mft_size(self, mft_offset: int) -> int:
        """Read file size from MFT record."""
        if self._data is None:
            return 0
        try:
            return struct.unpack_from("<Q", self._data, mft_offset + 0x30)[0]
        except struct.error:
            return 0

    def _extract_ntfs_name(self, mft_offset: int) -> Optional[str]:
        """Extract filename from NTFS FILE record."""
        if self._data is None:
            return None
        try:
            attr_offset = struct.unpack_from("<H", self._data, mft_offset + 0x14)[0]
            pos = mft_offset + attr_offset
            while pos < mft_offset + 1024 - 24:
                attr_type = struct.unpack_from("<I", self._data, pos)[0]
                if attr_type == 0xFFFFFFFF:
                    break
                if attr_type == 0x30:  # $FILE_NAME
                    name_len = self._data[pos + 0x58] if pos + 0x58 < len(self._data) else 0
                    name_offset = pos + 0x5A
                    if name_len > 0 and name_offset + name_len * 2 <= len(self._data):
                        raw = self._data[name_offset : name_offset + name_len * 2]
                        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                attr_len = struct.unpack_from("<I", self._data, pos + 4)[0]
                if attr_len == 0:
                    break
                pos += attr_len
        except (struct.error, ValueError, IndexError):
            pass
        return None

    @staticmethod
    def _find_date_in_text(text: str) -> Optional[datetime]:
        """Find and parse the first date string in a text fragment."""
        patterns = [
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
            r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    dt = dateparser.parse(match.group(1))
                    if dt and 1980 <= dt.year <= 2100:
                        return dt
                except (ValueError, OverflowError):
                    continue
        return None

    @staticmethod
    def _deduplicate(entries: List[TimelineEntry]) -> List[TimelineEntry]:
        """Remove duplicate entries based on timestamp+description."""
        seen: Set[Tuple[str, str]] = set()
        unique: List[TimelineEntry] = []
        for e in entries:
            key = (e.timestamp, e.description)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique

    def export_csv(self, entries: List[TimelineEntry], output_path: str) -> None:
        """Export timeline entries to CSV format."""
        if not entries:
            logger.warning("No timeline entries to export.")
            return
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Epoch", "Source", "Type", "Description", "Path", "Size", "Integrity"])
            for e in entries:
                writer.writerow([
                    e.timestamp, f"{e.timestamp_epoch:.6f}", e.source, e.event_type,
                    e.description, e.path, e.size, e.integrity,
                ])
        logger.info("Exported %d timeline entries to %s", len(entries), output_path)

    @staticmethod
    def load_csv(csv_path: str) -> List[TimelineEntry]:
        """Load timeline entries from a CSV file."""
        entries: List[TimelineEntry] = []
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = TimelineEntry(
                        timestamp=row.get("Timestamp", ""),
                        timestamp_epoch=float(row.get("Epoch", 0)),
                        source=row.get("Source", ""),
                        event_type=row.get("Type", ""),
                        description=row.get("Description", ""),
                        path=row.get("Path", ""),
                        size=int(row.get("Size", 0)),
                        integrity=row.get("Integrity", "unknown"),
                    )
                    entries.append(entry)
                except (ValueError, KeyError) as e:
                    logger.warning("Skipping invalid CSV row: %s", e)
        return entries
