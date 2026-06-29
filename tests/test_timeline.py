"""Tests for timeline analysis modules."""

import csv
import os
import struct
from datetime import datetime, timezone

import pytest

from src.timeline.analyzer import AnalysisReport, TimelineAnalyzer
from src.timeline.builder import TimelineBuilder, TimelineEntry


class TestTimelineBuilder:
    """Tests for TimelineBuilder."""

    def test_image_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            TimelineBuilder("/nonexistent/image.raw")

    def test_build_empty_image(self, tmp_path) -> None:
        image = tmp_path / "empty.img"
        image.write_bytes(b"")
        builder = TimelineBuilder(str(image))
        entries = builder.build()
        assert entries == []

    def test_build_iso_timestamps(self, tmp_path) -> None:
        image = tmp_path / "iso_test.img"
        ts = b"2024-03-15 14:30:00"
        image.write_bytes(ts * 10)
        builder = TimelineBuilder(str(image))
        entries = builder.build(source_types=["strings"])
        assert len(entries) >= 1
        assert any("2024-03-15" in e.timestamp for e in entries)

    def test_build_multiple_sources(self, tmp_path) -> None:
        image = tmp_path / "multi_src.img"
        data = (
            b"2024-01-01 00:00:00 " * 5 +
            b"2024-06-15 12:30:00 " * 3 +
            b"2025-12-31 23:59:59 " * 2
        )
        image.write_bytes(data)
        builder = TimelineBuilder(str(image))
        entries = builder.build()
        assert len(entries) >= 3

    def test_build_chronological_sort(self, tmp_path) -> None:
        image = tmp_path / "sort_test.img"
        data = b"2025-01-01 00:00:00 2024-01-01 00:00:00 2023-01-01 00:00:00"
        image.write_bytes(data)
        builder = TimelineBuilder(str(image))
        entries = builder.build(source_types=["strings"])
        epochs = [e.timestamp_epoch for e in entries]
        assert epochs == sorted(epochs)

    def test_export_csv(self, tmp_path) -> None:
        entries = [
            TimelineEntry(
                timestamp="2024-01-01 00:00:00 UTC",
                timestamp_epoch=1704067200.0,
                source="test",
                event_type="test_event",
                description="Test entry",
            ),
        ]
        csv_path = tmp_path / "test.csv"
        TimelineBuilder.export_csv(entries, str(csv_path))
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "Timestamp" in content
        assert "Test entry" in content

    def test_load_csv(self, tmp_path) -> None:
        csv_path = tmp_path / "load_test.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Epoch", "Source", "Type", "Description", "Path", "Size", "Integrity"])
            writer.writerow(["2024-01-01 UTC", "1704067200", "test", "event", "desc", "", "0", "ok"])

        entries = TimelineBuilder.load_csv(str(csv_path))
        assert len(entries) == 1
        assert entries[0].description == "desc"
        assert entries[0].source == "test"

    def test_deduplication(self, tmp_path) -> None:
        image = tmp_path / "dedup.img"
        data = b"identical timestamp entry " * 100
        image.write_bytes(data)
        builder = TimelineBuilder(str(image))
        entries = builder.build(source_types=["strings"])
        # Should be deduplicated
        timestamps = [(e.timestamp, e.description) for e in entries]
        assert len(timestamps) == len(set(timestamps))

    def test_hex_filetime_pattern(self, tmp_path) -> None:
        image = tmp_path / "filetime.img"
        # A valid FILETIME: Jan 1 2024 00:00:00 UTC
        filetime = 0x01D48B9F00000000
        # Write as hex string
        data = f"0x{filetime:016X}".encode("ascii")
        image.write_bytes(data)
        builder = TimelineBuilder(str(image))
        entries = builder.build(source_types=["strings"])
        assert len(entries) >= 1


class TestTimelineAnalyzer:
    """Tests for TimelineAnalyzer."""

    def test_empty_entries(self) -> None:
        analyzer = TimelineAnalyzer([])
        report = analyzer.analyze()
        assert report.total_events == 0
        assert report.anomalies == []

    def test_single_entry_no_anomalies(self) -> None:
        entries = [
            TimelineEntry(timestamp="2024-01-01", timestamp_epoch=1704067200.0, source="test", event_type="event", description=""),
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        assert report.total_events == 1
        assert len(report.anomalies) == 0

    def test_time_gap_detection(self) -> None:
        entries = [
            TimelineEntry(timestamp="2024-01-01 00:00:00", timestamp_epoch=1704067200.0, source="a", event_type="a", description="first"),
            TimelineEntry(timestamp="2024-01-03 00:00:00", timestamp_epoch=1704240000.0, source="b", event_type="b", description="second"),
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        gaps = [a for a in report.anomalies if a.type == "time_gap"]
        assert len(gaps) > 0
        assert "48.0 hours" in gaps[0].description or "48" in gaps[0].description

    def test_high_frequency_detection(self) -> None:
        base_epoch = 1704067200.0
        entries = [
            TimelineEntry(
                timestamp=f"2024-01-01 00:00:{i:02d}",
                timestamp_epoch=base_epoch + i,
                source="test",
                event_type="rapid",
                description=f"event_{i}",
            )
            for i in range(15)
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        bursts = [a for a in report.anomalies if a.type == "high_frequency_burst"]
        assert len(bursts) > 0

    def test_unusual_hours_detection(self) -> None:
        entries = [
            TimelineEntry(
                timestamp="2024-01-01 03:00:00",
                timestamp_epoch=1704078000.0,
                source="test",
                event_type="night",
                description=f"night_event_{i}",
            )
            for i in range(10)
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        unusual = [a for a in report.anomalies if a.type == "unusual_hours"]
        assert len(unusual) > 0

    def test_duplicate_timestamps(self) -> None:
        entries = [
            TimelineEntry(
                timestamp="2024-01-01 12:00:00 UTC",
                timestamp_epoch=1704120000.0,
                source="test",
                event_type="dup",
                description=f"dup_{i}",
            )
            for i in range(8)
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        dups = [a for a in report.anomalies if a.type == "duplicate_timestamp"]
        assert len(dups) > 0

    def test_statistics_in_report(self) -> None:
        entries = [
            TimelineEntry(timestamp=f"2024-01-0{d}", timestamp_epoch=1704067200.0 + d * 86400, source="src", event_type="evt", description="")
            for d in range(1, 6)
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        assert report.total_events == 5
        assert report.time_span_hours > 0
        assert "events_per_hour" in report.statistics
        assert "unique_sources" in report.statistics

    def test_outlier_detection(self) -> None:
        base = 1704067200.0
        entries = [
            TimelineEntry(timestamp="t", timestamp_epoch=base + i * 100, source="s", event_type="e", description=f"e{i}")
            for i in range(20)
        ]
        # Add an outlier
        entries.append(TimelineEntry(timestamp="outlier", timestamp_epoch=base + 86400 * 30, source="s", event_type="e", description="outlier"))
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        outliers = [a for a in report.anomalies if a.type == "outlier_cluster"]
        assert len(outliers) > 0

    def test_source_breakdown(self) -> None:
        entries = [
            TimelineEntry(timestamp="t", timestamp_epoch=100.0, source="syslog", event_type="log", description=""),
            TimelineEntry(timestamp="t", timestamp_epoch=200.0, source="syslog", event_type="log", description=""),
            TimelineEntry(timestamp="t", timestamp_epoch=300.0, source="security", event_type="log", description=""),
        ]
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        assert report.source_breakdown.get("syslog") == 2
        assert report.source_breakdown.get("security") == 1

    def test_timeline_analyzer_chaining(self, tmp_path) -> None:
        """Test that we can build a timeline from an image and analyze it."""
        image = tmp_path / "chain.img"
        image.write_bytes(b"2024-06-01 12:00:00 " * 20)
        builder = TimelineBuilder(str(image))
        entries = builder.build()
        assert len(entries) > 0
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        assert report.total_events > 0

    def test_analysis_report_dataclass(self) -> None:
        report = AnalysisReport(
            total_events=10,
            time_span_hours=24.0,
            anomalies=[],
            statistics={"mean": 0.5},
            source_breakdown={"test": 10},
            event_type_breakdown={"type": 10},
        )
        assert report.total_events == 10
        assert report.time_span_hours == 24.0
        assert report.statistics["mean"] == 0.5
