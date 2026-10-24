"""Forensis CLI — command-line interface for digital forensics operations.

Usage:
  forensis --help
  forensis memory processes <dump>
  forensis memory network <dump>
  forensis memory analyze <dump>
  forensis disk image <source> <destination> [--log LOG] [--no-verify]
  forensis disk carve <image> [--output DIR] [--types TYPES]
  forensis disk ls <image> [--path PATH]
  forensis timeline build <image> [--output CSV]
  forensis timeline analyze <csv> [--output JSON]
  forensis hash <file> [--sha256] [--sha1] [--md5] [--output FILE]
  forensis report generate --case CASE [--case-id ID] [--findings FILE] [--format FMT]
"""

from __future__ import annotations

import json
import logging
import sys
from typing import List, Optional

import click

from . import __version__
from .disk.carver import FileCarver
from .disk.filesystem import FilesystemNavigator
from .disk.imager import DiskImager
from .hashing.hasher import Hasher, HashResult
from .memory.analyzer import MemoryAnalyzer
from .reporting.report import ReportGenerator
from .timeline.analyzer import TimelineAnalyzer
from .timeline.builder import TimelineBuilder

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__, prog_name="forensis")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def cli(verbose: bool) -> None:
    """Forensis — Digital Forensics Toolkit.

    Memory analysis, disk imaging & carving, timeline reconstruction,
    hashing, and report generation for forensic investigations.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ── Memory subcommands ──────────────────────────────────────────────


@cli.group()
def memory() -> None:
    """Memory analysis commands."""
    pass


@memory.command()
@click.argument("dump", type=click.Path(exists=True, readable=True))
def processes(dump: str) -> None:
    """List processes found in a memory dump."""
    try:
        analyzer = MemoryAnalyzer(dump)
        procs = analyzer.analyze_processes()
        if not procs:
            click.echo("No processes found in dump.")
            return
        click.echo(f"{'PID':<8} {'PPID':<8} {'Name':<25} {'Offset':<20}")
        click.echo("-" * 65)
        for p in procs[:100]:
            click.echo(
                f"{p['pid']:<8} {p['ppid']:<8} {p['name']:<25} {p.get('offset', ''):<20}"
            )
        click.echo(f"\nTotal: {len(procs)} processes (showing up to 100)")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@memory.command()
@click.argument("dump", type=click.Path(exists=True, readable=True))
def network(dump: str) -> None:
    """List network connections found in a memory dump."""
    try:
        analyzer = MemoryAnalyzer(dump)
        conns = analyzer.analyze_network()
        if not conns:
            click.echo("No network connections found in dump.")
            return
        click.echo(
            f"{'Protocol':<10} {'Local IP':<18} {'Port':<8} {'Remote IP':<18} {'Port':<8} {'State':<15}"
        )
        click.echo("-" * 85)
        for c in conns[:50]:
            click.echo(
                f"{c['protocol']:<10} {c['local_ip']:<18} {c['local_port']:<8} {c['remote_ip']:<18} {c['remote_port']:<8} {c['state']:<15}"
            )
        click.echo(f"\nTotal: {len(conns)} connections (showing up to 50)")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@memory.command("analyze")
@click.argument("dump", type=click.Path(exists=True, readable=True))
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def memory_analyze(dump: str, json_output: bool) -> None:
    """Run full analysis on a memory dump (processes, network, modules)."""
    try:
        analyzer = MemoryAnalyzer(dump)
        result = analyzer.analyze_all()
        if json_output:
            click.echo(
                json.dumps(
                    {
                        "processes": result.processes[:100],
                        "connections": result.connections[:50],
                        "modules": result.modules[:50],
                        "errors": result.errors,
                    },
                    indent=2,
                    default=str,
                )
            )
        else:
            click.echo(f"\n=== Processes ({len(result.processes)}) ===")
            for p in result.processes[:30]:
                click.echo(f"  [{p['pid']}] {p['name']} (PPID: {p['ppid']})")
            click.echo(f"\n=== Network Connections ({len(result.connections)}) ===")
            for c in result.connections[:20]:
                click.echo(
                    f"  {c['protocol']} {c['local_ip']}:{c['local_port']} -> {c['remote_ip']}:{c['remote_port']} [{c['state']}]"
                )
            click.echo(f"\n=== Modules ({len(result.modules)}) ===")
            for m in result.modules[:20]:
                click.echo(f"  {m['description']} @ {m['offset']}")
            if result.errors:
                click.echo(f"\n=== Errors ({len(result.errors)}) ===")
                for err in result.errors:
                    click.echo(f"  ! {err}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ── Disk subcommands ────────────────────────────────────────────────


@cli.group()
def disk() -> None:
    """Disk forensics commands."""
    pass


@disk.command()
@click.argument("source", type=click.Path(exists=True, readable=True))
@click.argument("destination", type=click.Path())
@click.option("--log", "log_path", type=click.Path(), help="Path to acquisition log")
@click.option("--no-verify", is_flag=True, help="Skip post-acquisition verification")
def image(
    source: str, destination: str, log_path: Optional[str], no_verify: bool
) -> None:
    """Create a forensic disk image (dd-style bit-for-bit copy)."""
    try:
        imager = DiskImager(
            source=source,
            destination=destination,
            log_path=log_path,
            verify=not no_verify,
            progress_callback=lambda read, total: click.echo(
                f"\r  Progress: {read / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MB "
                f"({read / max(total, 1) * 100:.1f}%)",
                nl=False,
            ),
        )
        result = imager.acquire()
        click.echo()
        click.echo("Acquisition complete!")
        click.echo(f"  Source:      {result['source']}")
        click.echo(f"  Destination: {result['destination']}")
        click.echo(f"  Size:        {result['source_size']} bytes")
        click.echo(f"  SHA256:      {result['sha256']}")
        click.echo(f"  MD5:         {result['md5']}")
        click.echo(f"  Verified:    {result['verified']}")
        click.echo(f"  Duration:    {result['duration_seconds']:.1f}s")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disk.command()
@click.argument("image", type=click.Path(exists=True, readable=True))
@click.option(
    "--output",
    "-o",
    default="carved",
    show_default=True,
    help="Output directory for carved files",
)
@click.option(
    "--types",
    "-t",
    default="",
    help="Comma-separated file types to carve (e.g. jpg,png,pdf)",
)
def carve(image: str, output: str, types: str) -> None:
    """Carve files from a disk image by magic byte signatures."""
    try:
        type_list = (
            [t.strip() for t in types.split(",") if t.strip()] if types else None
        )
        carver = FileCarver(image, output_dir=output)
        results = carver.carve_all(types=type_list)
        if not results:
            click.echo("No files carved.")
            return
        click.echo(f"{'Type':<12} {'Size':<12} {'Offset':<20} {'File':<30}")
        click.echo("-" * 75)
        for r in results:
            click.echo(
                f"{r['file_type']:<12} {r['size']:<12} {r['offset']:<20} {r['path']:<30}"
            )
        click.echo(f"\nTotal: {carver.carved_count} files ({carver.total_size} bytes)")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@disk.command("ls")
@click.argument("image", type=click.Path(exists=True, readable=True))
@click.option("--path", "-p", default="/", help="Directory path to list")
def list_dir(image: str, path: str) -> None:
    """List filesystem entries from a disk image."""
    try:
        nav = FilesystemNavigator(image)
        fs_type = nav.identify_filesystem()
        click.echo(f"Detected filesystem: {fs_type or 'Unknown'}")
        entries = nav.list_directory(path)
        if not entries:
            click.echo(f"No entries found at '{path}'.")
            return
        click.echo(f"{'Type':<6} {'Size':<12} {'Name':<30}")
        click.echo("-" * 50)
        for e in entries:
            t = "DIR" if e.is_directory else "FILE"
            click.echo(f"{t:<6} {e.size:<12} {e.name:<30}")
        click.echo(f"\nTotal: {len(entries)} entries")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ── Timeline subcommands ────────────────────────────────────────────


@cli.group()
def timeline() -> None:
    """Timeline analysis commands."""
    pass


@timeline.command()
@click.argument("image", type=click.Path(exists=True, readable=True))
@click.option(
    "--output", "-o", default="timeline.csv", show_default=True, help="Output CSV path"
)
def build(image: str, output: str) -> None:
    """Build a forensic timeline from a disk image."""
    try:
        builder = TimelineBuilder(image)
        entries = builder.build()
        if not entries:
            click.echo("No timeline entries found.")
            return
        builder.export_csv(entries, output)
        click.echo(f"Timeline built: {len(entries)} entries exported to {output}")
        click.echo(
            f"  Time span: {(entries[-1].timestamp_epoch - entries[0].timestamp_epoch) / 3600:.1f} hours"
        )
        click.echo(f"  Sources: {len(set(e.source for e in entries))}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@timeline.command("analyze")
@click.argument("csv_file", type=click.Path(exists=True, readable=True))
@click.option(
    "--output",
    "-o",
    default="anomalies.json",
    show_default=True,
    help="Output JSON path",
)
def timeline_analyze(csv_file: str, output: str) -> None:
    """Analyze a timeline CSV for anomalies."""
    try:
        entries = TimelineBuilder.load_csv(csv_file)
        if not entries:
            click.echo("No entries loaded from CSV.")
            return
        analyzer = TimelineAnalyzer(entries)
        report = analyzer.analyze()
        click.echo(f"Analysis complete: {len(report.anomalies)} anomalies found")
        click.echo(f"  Total events: {report.total_events}")
        click.echo(f"  Time span: {report.time_span_hours:.1f} hours")

        for anomaly in report.anomalies:
            click.echo(
                f"\n  [{anomaly.severity.upper()}] {anomaly.type}: {anomaly.description}"
            )

        with open(output, "w") as f:
            json.dump(
                {
                    "total_events": report.total_events,
                    "time_span_hours": report.time_span_hours,
                    "statistics": report.statistics,
                    "source_breakdown": report.source_breakdown,
                    "event_type_breakdown": report.event_type_breakdown,
                    "anomalies": [
                        {
                            "type": a.type,
                            "severity": a.severity,
                            "description": a.description,
                            "details": a.details,
                        }
                        for a in report.anomalies
                    ],
                },
                f,
                indent=2,
                default=str,
            )
        click.echo(f"\nAnomalies exported to {output}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ── Hashing subcommand ──────────────────────────────────────────────


@cli.command()
@click.argument(
    "files", nargs=-1, type=click.Path(exists=True, readable=True), required=True
)
@click.option("--sha256", is_flag=True, help="Compute SHA-256 hash")
@click.option("--sha1", is_flag=True, help="Compute SHA-1 hash")
@click.option("--md5", is_flag=True, help="Compute MD5 hash")
@click.option("--output", "-o", type=click.Path(), help="Output file for hash results")
@click.option(
    "--verify", type=str, help="Verify file against a hash (format: algorithm:hash)"
)
def hash(
    files: List[str],
    sha256: bool,
    sha1: bool,
    md5: bool,
    output: Optional[str],
    verify: Optional[str],
) -> None:
    """Compute cryptographic hashes of evidence files."""
    algos = []
    if sha256 or not (sha1 or md5):
        algos.append("sha256")
    if sha1:
        algos.append("sha1")
    if md5:
        algos.append("md5")

    results: List[HashResult] = []

    for fpath in files:
        try:
            hasher = Hasher(fpath)
            if len(algos) > 1:
                result = hasher.hash_all()
            else:
                result = hasher.hash_single(algos[0])
            results.append(result)

            click.echo(f"File: {fpath}")
            click.echo(f"  Size: {result.file_size} bytes")
            if result.sha256:
                click.echo(f"  SHA256: {result.sha256}")
            if result.sha1:
                click.echo(f"  SHA1:   {result.sha1}")
            if result.md5:
                click.echo(f"  MD5:    {result.md5}")
            click.echo()
        except Exception as e:
            click.echo(f"Error hashing {fpath}: {e}", err=True)

    if output:
        Hasher.export_hashset(results, output)
        click.echo(f"Hash results exported to {output}")

    if verify and results:
        try:
            algo, expected = verify.split(":", 1)
            ok = results[0].verify_hash(expected, algo)
            click.echo(f"Verification: {'PASS' if ok else 'FAIL'}")
        except Exception as e:
            click.echo(f"Verification error: {e}", err=True)


# ── Report subcommand ───────────────────────────────────────────────


@cli.group()
def report() -> None:
    """Report generation commands."""
    pass


@report.command()
@click.option("--case", "case_name", required=True, help="Case name")
@click.option("--case-id", "case_id", default="", help="Case identifier")
@click.option("--examiner", default="", help="Examiner name")
@click.option("--description", default="", help="Case description")
@click.option(
    "--findings",
    type=click.Path(exists=True, readable=True),
    help="JSON file with findings array",
)
@click.option(
    "--hash",
    "hash_str",
    multiple=True,
    help="Hash in format algorithm:value (can be repeated)",
)
@click.option(
    "--output",
    "-o",
    default="forensic_report.html",
    show_default=True,
    help="Output file path",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "json", "both"]),
    default="html",
    help="Output format",
)
def generate(
    case_name: str,
    case_id: str,
    examiner: str,
    description: str,
    findings: Optional[str],
    hash_str: List[str],
    output: str,
    fmt: str,
) -> None:
    """Generate a forensic report."""
    try:
        gen = ReportGenerator(
            case_name=case_name,
            case_id=case_id,
            examiner=examiner,
            description=description,
        )

        # Load findings from file
        if findings:
            with open(findings, "r") as f:
                finding_list = json.load(f)
                if isinstance(finding_list, list):
                    for finding in finding_list:
                        gen.add_finding(finding)

        # Add hashes
        for h in hash_str:
            if ":" in h:
                algo, value = h.split(":", 1)
                gen.add_hash(algo, value)

        # Generate output
        if fmt in ("html", "both"):
            out_path = output if fmt == "html" else output.replace(".html", ".html")
            gen.save_html(out_path)
            click.echo(f"HTML report saved: {out_path}")

        if fmt in ("json", "both"):
            json_path = output.replace(".html", ".json") if fmt == "both" else output
            gen.save_json(json_path)
            click.echo(f"JSON report saved: {json_path}")

        click.echo(f"Report generated: {gen.data['report']['title']}")
        click.echo(f"  Findings: {len(gen.data['findings'])}")
        click.echo(f"  Evidence: {len(gen.data['evidence'])}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
