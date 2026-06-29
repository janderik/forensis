# Case Study: Investigating Suspicious Activity on a Compromised Workstation

## Scenario

A financial analyst reported unusual system behavior: slow performance, unexpected network connections, and missing files. IT security captured a memory dump (`memdump.raw`) and created a forensic disk image (`workstation.dd`) before the system was taken offline.

## Objectives

1. Identify malicious processes running on the system.
2. Detect unauthorized network connections.
3. Recover deleted files (file carving).
4. Build a timeline of suspicious activity.
5. Generate a comprehensive forensic report.

## Tools Used

- **Forensis** for all analysis
- Memory dump: `memdump.raw` (8 GB)
- Disk image: `workstation.dd` (256 GB)

---

## Step 1: Memory Analysis — Processes

```bash
forensis memory processes memdump.raw
```

**Output (excerpt):**
```
PID      PPID     Name                      Offset
1234     456      svchost.exe               0x8a3f1c00
5678     912      explorer.exe              0x9b2e1000
9012     345      powershell.exe            0x7c1a8000
3456     9012     not_malware.exe           0x6d3f5000
```

**Finding:** `not_malware.exe` (PID 3456) was spawned by `powershell.exe` (PID 9012) — unusual parent-child relationship. Process name is suspiciously generic.

---

## Step 2: Memory Analysis — Network Connections

```bash
forensis memory network memdump.raw
```

**Output (excerpt):**
```
Protocol   Local IP         Port     Remote IP        Port     State
TCP        192.168.1.100    49231    45.33.32.156     8443     ESTABLISHED
TCP        192.168.1.100    49232    45.33.32.156     8443     ESTABLISHED
```

**Finding:** Two persistent connections to `45.33.32.156:8443` — known C2 server (AlienVault OTX). Traffic pattern suggests beaconing.

---

## Step 3: Disk Forensics — File Carving

```bash
forensis disk carve workstation.dd --output carved/ --types jpeg,png,pdf,docx
```

**Output (excerpt):**
```
Type         Size         Offset               File
JPEG         245760       0x1a3f000            carved/jpeg_0000.jpg
PDF         1048576       0x4b2c000            carved/pdf_0000.pdf
PNG         524288        0x7d10000            carved/png_0000.png
DOCX        2097152       0x9e80000            carved/docx_0000.docx
```

**Finding:** A deleted PDF (`pdf_0000.pdf`) contained confidential financial data exfiltrated to the C2 server. The DOCX file had embedded macros.

---

## Step 4: Timeline Analysis

```bash
forensis timeline build workstation.dd --output timeline.csv
forensis timeline analyze timeline.csv --output anomalies.json
```

**Anomalies detected:**
```
[HIGH] time_gap: Time gap of 72.3 hours — possible timeline tampering
[MEDIUM] high_frequency_burst: 15 events in 60s window at 2024-03-14 02:15:00
[MEDIUM] outlier_cluster: 8 events beyond 2.5 standard deviations
[LOW] unusual_hours: 12 events between 00:00-06:00 UTC
```

**Finding:** The 72-hour gap coincides with the date the analyst first reported issues — log files were likely cleared. The burst at 02:15 UTC indicates automated data exfiltration during off-hours.

---

## Step 5: Hashing

```bash
forensis hash workstation.dd memdump.raw --sha256 --md5 --output hashes.txt
```

```
File: workstation.dd
  SHA256: a1b2c3d4...
  MD5:    e5f6g7h8...

File: memdump.raw
  SHA256: i9j0k1l2...
  MD5:    m3n4o5p6...
```

Hashes were added to the report for chain-of-custody documentation.

---

## Step 6: Report Generation

```bash
forensis report generate \
  --case "Workstation Compromise" \
  --case-id "2024-001" \
  --examiner "J. Analyst" \
  --findings findings.json \
  --hash sha256:a1b2c3d4... \
  --hash md5:e5f6g7h8... \
  --output report.html \
  --format html
```

---

## Summary of Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Suspicious process (`not_malware.exe`) | High | Confirmed |
| 2 | C2 connections to 45.33.32.156:8443 | Critical | Confirmed |
| 3 | Deleted PDF with exfiltrated data | Critical | Recovered |
| 4 | 72-hour timeline gap | High | Tampering |
| 5 | Off-hours data burst | Medium | Exfiltration |

## Recommendations

1. Block IP `45.33.32.156` at the firewall.
2. Add `not_malware.exe` hash to blocklist.
3. Initiate incident response for credential rotation.
4. Preserve evidence for legal proceedings.
5. Deploy endpoint detection rules for off-hours beaconing.

## Artifact Retention

All carved files, hashes, timeline CSV, and the HTML report are stored in `/evidence/CASE-2024-001/` with SHA-256 verification manifests.
