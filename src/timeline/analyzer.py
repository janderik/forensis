"""Timeline analyzer — detects anomalies and patterns in forensic timelines."""

from __future__ import annotations

import logging
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from .builder import TimelineEntry

logger = logging.getLogger(__name__)


@dataclass
class Anomaly:
    """Represents a detected anomaly in the timeline."""

    type: str = ""
    severity: str = "medium"
    description: str = ""
    entries: List[TimelineEntry] = field(default_factory=list)
    details: Dict = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Contains full timeline analysis results."""

    total_events: int = 0
    time_span_hours: float = 0.0
    anomalies: List[Anomaly] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    source_breakdown: Dict[str, int] = field(default_factory=dict)
    event_type_breakdown: Dict[str, int] = field(default_factory=dict)


class TimelineAnalyzer:
    """Analyzes timeline entries for suspicious patterns and anomalies."""

    def __init__(self, entries: List[TimelineEntry]) -> None:
        self.entries = entries

    def analyze(self) -> AnalysisReport:
        """Run all analysis heuristics and return a report."""
        report = AnalysisReport(
            total_events=len(self.entries),
            source_breakdown=self._count_by_field("source"),
            event_type_breakdown=self._count_by_field("event_type"),
        )

        if not self.entries:
            return report

        epochs = [e.timestamp_epoch for e in self.entries]
        report.time_span_hours = (max(epochs) - min(epochs)) / 3600 if epochs else 0.0

        report.statistics = {
            "events_per_hour": round(len(self.entries) / max(report.time_span_hours, 0.01), 2),
            "unique_sources": len(report.source_breakdown),
            "unique_types": len(report.event_type_breakdown),
            "timespan_hours": round(report.time_span_hours, 2),
        }

        report.anomalies.extend(self._detect_time_gaps())
        report.anomalies.extend(self._detect_outlier_clusters())
        report.anomalies.extend(self._detect_high_frequency_events())
        report.anomalies.extend(self._detect_unusual_hours())
        report.anomalies.extend(self._detect_duplicate_timestamps())

        return report

    def _detect_time_gaps(self) -> List[Anomaly]:
        """Detect significant gaps in the timeline (potential data tampering)."""
        anomalies: List[Anomaly] = []
        if len(self.entries) < 2:
            return anomalies

        sorted_entries = sorted(self.entries, key=lambda e: e.timestamp_epoch)
        gaps: List[Tuple[float, TimelineEntry, TimelineEntry]] = []

        for i in range(1, len(sorted_entries)):
            gap = sorted_entries[i].timestamp_epoch - sorted_entries[i - 1].timestamp_epoch
            if gap > 3600:  # More than 1 hour
                gaps.append((gap, sorted_entries[i - 1], sorted_entries[i]))

        if gaps:
            # Report the largest gaps
            gaps.sort(key=lambda g: g[0], reverse=True)
            for gap, before, after in gaps[:5]:
                anomalies.append(Anomaly(
                    type="time_gap",
                    severity="high" if gap > 86400 else "medium",
                    description=(
                        f"Time gap of {gap / 3600:.1f} hours detected between "
                        f"[{before.timestamp}] ({before.description[:40]}) and "
                        f"[{after.timestamp}] ({after.description[:40]})"
                    ),
                    details={
                        "gap_seconds": gap,
                        "gap_hours": round(gap / 3600, 2),
                        "before": before.timestamp,
                        "after": after.timestamp,
                    },
                ))

        return anomalies

    def _detect_outlier_clusters(self) -> List[Anomaly]:
        """Detect clusters of events at unusual times or frequencies."""
        anomalies: List[Anomaly] = []
        if len(self.entries) < 10:
            return anomalies

        epochs = [e.timestamp_epoch for e in self.entries]
        try:
            mean = statistics.mean(epochs)
            stdev = statistics.stdev(epochs)
        except statistics.StatisticsError:
            return anomalies

        threshold = 2.5
        outliers: List[TimelineEntry] = [
            e for e in self.entries
            if abs(e.timestamp_epoch - mean) > threshold * stdev
        ]

        if outliers and len(outliers) >= 3:
            anomalies.append(Anomaly(
                type="outlier_cluster",
                severity="medium",
                description=f"Detected {len(outliers)} outlier events beyond {threshold} standard deviations from mean",
                entries=outliers[:20],
                details={
                    "outlier_count": len(outliers),
                    "mean_epoch": mean,
                    "stdev": stdev,
                    "threshold": threshold,
                },
            ))

        return anomalies

    def _detect_high_frequency_events(self) -> List[Anomaly]:
        """Detect bursts of events in short time windows."""
        anomalies: List[Anomaly] = []
        if len(self.entries) < 20:
            return anomalies

        sorted_entries = sorted(self.entries, key=lambda e: e.timestamp_epoch)
        window = 60  # 60-second window

        for i in range(len(sorted_entries)):
            window_end = sorted_entries[i].timestamp_epoch + window
            count = sum(
                1 for e in sorted_entries
                if sorted_entries[i].timestamp_epoch <= e.timestamp_epoch <= window_end
            )
            if count >= 10:
                anomalies.append(Anomaly(
                    type="high_frequency_burst",
                    severity="medium",
                    description=(
                        f"Burst of {count} events within {window}s window "
                        f"starting at {sorted_entries[i].timestamp}"
                    ),
                    entries=sorted_entries[i : i + count][:20],
                    details={
                        "burst_count": count,
                        "window_seconds": window,
                        "start_time": sorted_entries[i].timestamp,
                    },
                ))
                break  # Report the first burst found

        return anomalies

    def _detect_unusual_hours(self) -> List[Anomaly]:
        """Detect events occurring outside normal business hours (simplified)."""
        anomalies: List[Anomaly] = []
        unusual: List[TimelineEntry] = []

        for e in self.entries:
            try:
                dt = datetime.fromtimestamp(e.timestamp_epoch, tz=timezone.utc)
                hour = dt.hour
                if hour < 6 or hour > 22:
                    unusual.append(e)
            except (OSError, ValueError, OverflowError):
                continue

        if len(unusual) >= 5:
            anomalies.append(Anomaly(
                type="unusual_hours",
                severity="low",
                description=f"{len(unusual)} events occurred outside normal hours (06:00-22:00 UTC)",
                entries=unusual[:15],
                details={"event_count": len(unusual), "time_window": "00:00-06:00 & 22:00-24:00 UTC"},
            ))

        return anomalies

    def _detect_duplicate_timestamps(self) -> List[Anomaly]:
        """Detect events with identical timestamps (potential log injection)."""
        anomalies: List[Anomaly] = []
        ts_counts: Dict[str, List[TimelineEntry]] = defaultdict(list)

        for e in self.entries:
            ts_counts[e.timestamp].append(e)

        for ts, entries in ts_counts.items():
            if len(entries) >= 5:
                descriptions = [e.description[:50] for e in entries[:10]]
                anomalies.append(Anomaly(
                    type="duplicate_timestamp",
                    severity="low" if len(entries) < 20 else "medium",
                    description=f"{len(entries)} events share identical timestamp: {ts}",
                    entries=entries[:10],
                    details={
                        "timestamp": ts,
                        "count": len(entries),
                        "sample_descriptions": descriptions,
                    },
                ))

        return anomalies

    def _count_by_field(self, field_name: str) -> Dict[str, int]:
        """Count occurrences of a field across entries."""
        counter: Counter = Counter()
        for e in self.entries:
            val = getattr(e, field_name, "unknown")
            counter[val] += 1
        return dict(counter.most_common())
