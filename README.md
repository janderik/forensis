# Forensis 🔍

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/forensis/forensis/actions/workflows/ci.yml/badge.svg)](https://github.com/forensis/forensis/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/imports-isort-%231674b1.svg)](https://pycqa.github.io/isort/)

A senior-level digital forensics toolkit for memory analysis, disk forensics, timeline reconstruction, hashing, and report generation — all operating on forensic images with read-only guarantees.

## Features

- **Memory Analysis** — List processes, network connections, and loaded modules from Windows memory dumps (raw, crash, hibernation).
- **Disk Forensics** — Create forensic disk images (dd-style), recover files via signature-based carving (JPEG, PNG, PDF, DOCX, ZIP, ELF), and navigate filesystem structures.
- **Timeline Analysis** — Build super-timelines from filesystem metadata and event logs; detect anomalies using statistical and temporal clustering.
- **Hashing** — Compute SHA-256, SHA-1, and MD5 hashes of evidence files; export in standard hash set formats (NSRL, CSV).
- **Reporting** — Generate HTML and JSON forensic reports with full findings, case metadata, and artifact details.
- **CLI** — Unified command-line interface with intuitive subcommands (`forensis memory`, `forensis disk`, `forensis timeline`, `forensis hash`, `forensis report`).

## Architecture

```
forensis/
├── src/
│   ├── cli.py              # CLI entry point (click/argparse)
│   ├── memory/
│   │   ├── analyzer.py      # Process/module enumeration from dumps
│   │   ├── processes.py     # Process struct parsing (EPROCESS)
│   │   └── network.py       # Network connection enumeration
│   ├── disk/
│   │   ├── imager.py        # dd-style disk imaging
│   │   ├── carver.py        # Signature-based file carving
│   │   └── filesystem.py    # Filesystem navigation (FAT/NTFS/ext4)
│   ├── timeline/
│   │   ├── builder.py       # Timeline construction from metadata
│   │   └── analyzer.py      # Anomaly detection
│   ├── hashing/
│   │   └── hasher.py        # Multi-algorithm hashing
│   └── reporting/
│       └── report.py        # HTML/JSON report generation
└── tests/                   # pytest-based test suite
```

All operations are **read-only** on source evidence. Imaging acquires data without modifying the source; carving and analysis only read from acquired images.

## Installation

### From source

```bash
git clone https://github.com/forensis/forensis.git
cd forensis
pip install -r requirements.txt
pip install -e .
```

### Using Docker

```bash
docker build -t forensis .
docker run --rm -v /path/to/evidence:/data forensis disk image /data/source.dd /data/output.img
```

## Usage

### Memory Analysis

```bash
# List processes from a memory dump
forensis memory processes memdump.raw

# List network connections
forensis memory network memdump.raw

# Full memory analysis
forensis memory analyze memdump.raw
```

### Disk Forensics

```bash
# Create a forensic image (dd-style)
forensis disk image /dev/sda case/images/device.dd --log case/logs/acquisition.log

# Carve files from an image
forensis disk carve evidence.dd --output carved/ --types jpeg,png,pdf

# List filesystem contents
forensis disk ls image.dd --path /home/user
```

### Timeline Analysis

```bash
# Build a timeline from a disk image
forensis timeline build image.dd --output timeline.csv

# Analyze for anomalies
forensis timeline analyze timeline.csv --output anomalies.json
```

### Hashing

```bash
# Hash an evidence file with all algorithms
forensis hash evidence.dd --sha256 --sha1 --md5 --output hashes.txt
```

### Reporting

```bash
# Generate a comprehensive forensic report
forensis report generate --case "CASE-001" --case-id "2024-001" \
  --findings findings.json --evidence evidence.dd \
  --hash sha256:abc123... --output report.html --format html
```

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v --cov=src

# Format code
black src/ tests/
isort src/ tests/
```

## License

MIT License — see [LICENSE](LICENSE).
