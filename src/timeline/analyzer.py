"""Timeline analyzer — detects anomalies and patterns in forensic timelines."""

from __future__ import annotations

import logging
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple

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
            "events_per_hour": round(
                len(self.entries) / max(report.time_span_hours, 0.01), 2
            ),
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
            gap = (
                sorted_entries[i].timestamp_epoch
                - sorted_entries[i - 1].timestamp_epoch
            )
            if gap > 3600:  # More than 1 hour
                gaps.append((gap, sorted_entries[i - 1], sorted_entries[i]))

        if gaps:
            # Report the largest gaps
            gaps.sort(key=lambda g: g[0], reverse=True)
            for gap, before, after in gaps[:5]:
                anomalies.append(
                    Anomaly(
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
                    )
                )

        return anomalies

    # Modified z-score cut-off recommended by Iglewicz & Hoaglin.
    OUTLIER_THRESHOLD = 3.5
    BURST_WINDOW_SECONDS = 60
    BURST_MIN_EVENTS = 10

    def _detect_outlier_clusters(self) -> List[Anomaly]:
        """Detect events far away in time from the bulk of the timeline.

        Uses the modified z-score (median / MAD), which, unlike mean and
        standard deviation, is not dragged towards the outliers themselves.
        """
        anomalies: List[Anomaly] = []
        if len(self.entries) < 10:
            return anomalies

        epochs = [e.timestamp_epoch for e in self.entries]
        median = statistics.median(epochs)
        mad = statistics.median(abs(x - median) for x in epochs)
        if mad == 0:
            return anomalies

        threshold = self.OUTLIER_THRESHOLD
        outliers: List[TimelineEntry] = [
            e
            for e in self.entries
            if 0.6745 * abs(e.timestamp_epoch - median) / mad > threshold
        ]

        if outliers:
            anomalies.append(
                Anomaly(
                    type="outlier_cluster",
                    severity="medium",
                    description=(
                        f"Detected {len(outliers)} outlier event(s) with modified "
                        f"z-score above {threshold}"
                    ),
                    entries=outliers[:20],
                    details={
                        "outlier_count": len(outliers),
                        "median_epoch": median,
                        "mad": mad,
                        "threshold": threshold,
                    },
                )
            )

        return anomalies

    def _detect_high_frequency_events(self) -> List[Anomaly]:
        """Detect bursts of events in short time windows (sliding window)."""
        anomalies: List[Anomaly] = []
        min_events = self.BURST_MIN_EVENTS
        window = self.BURST_WINDOW_SECONDS
        if len(self.entries) < min_events:
            return anomalies

        sorted_entries = sorted(self.entries, key=lambda e: e.timestamp_epoch)
        end = 0
        for start, first in enumerate(sorted_entries):
            window_end = first.timestamp_epoch + window
            end = max(end, start)
            while (
                end < len(sorted_entries)
                and sorted_entries[end].timestamp_epoch <= window_end
            ):
                end += 1
            count = end - start
            if count >= min_events:
                anomalies.append(
                    Anomaly(
                        type="high_frequency_burst",
                        severity="medium",
                        description=(
                            f"Burst of {count} events within {window}s window "
                            f"starting at {first.timestamp}"
                        ),
                        entries=sorted_entries[start:end][:20],
                        details={
                            "burst_count": count,
                            "window_seconds": window,
                            "start_time": first.timestamp,
                        },
                    )
                )
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
            anomalies.append(
                Anomaly(
                    type="unusual_hours",
                    severity="low",
                    description=f"{len(unusual)} events occurred outside normal hours (06:00-22:00 UTC)",
                    entries=unusual[:15],
                    details={
                        "event_count": len(unusual),
                        "time_window": "00:00-06:00 & 22:00-24:00 UTC",
                    },
                )
            )

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
                anomalies.append(
                    Anomaly(
                        type="duplicate_timestamp",
                        severity="low" if len(entries) < 20 else "medium",
                        description=f"{len(entries)} events share identical timestamp: {ts}",
                        entries=entries[:10],
                        details={
                            "timestamp": ts,
                            "count": len(entries),
                            "sample_descriptions": descriptions,
                        },
                    )
                )

        return anomalies

    def _count_by_field(self, field_name: str) -> Dict[str, int]:
        """Count occurrences of a field across entries."""
        counter: Counter = Counter()
        for e in self.entries:
            val = getattr(e, field_name, "unknown")
            counter[val] += 1
        return dict(counter.most_common())
