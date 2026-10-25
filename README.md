# log-analyzer

[Türkçe](README.tr.md)

A command-line tool that scans authentication logs for signs of attack:
brute force bursts, successful logins that follow them, and slow username scans.
It reads **Linux SSH logs** (`/var/log/auth.log`) and **Windows logon events** exported to CSV,
normalizes both into one event format, and runs the same detectors over them.

Pure Python standard library — no runtime dependencies.

## Example

```console
$ log-analyzer samples/auth.log
=== Log Analysis: samples/auth.log ===
Total events: 66

--- Brute Force Suspects ---
[!] 203.0.113.45: 40 failed attempts (max 21 within 60s)
    Users tried: admin, ahmet, root, test, ubuntu

--- CRITICAL: Successful Login After Brute Force ---
[!!!] 203.0.113.45 -> logged in as 'ahmet' (2026-10-25 11:02:05)

--- Slow Scan Suspects ---
[!] 198.51.100.7: 6 invalid user attempts (oracle)

Report saved: report.csv
```

`report.csv`:

| IP | Detection | Severity | Details |
|---|---|---|---|
| 203.0.113.45 | BRUTE_FORCE | HIGH | 40 failed attempts |
| 203.0.113.45 | POSSIBLE_COMPROMISE | CRITICAL | successful login as ahmet |
| 198.51.100.7 | SLOW_SCAN | MEDIUM | 6 invalid user attempts |

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/AliOsmanToklu/log-analyzer.git
cd log-analyzer
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

## Usage

```bash
log-analyzer <file> [--threshold N] [--window SECONDS] [--output report.csv]
```

| Option | Default | Meaning |
|---|---|---|
| `file` | — | Log to analyze. `.csv` → Windows logon export, anything else → SSH auth log |
| `--threshold` | `10` | Failed attempts inside one window that count as brute force |
| `--window` | `60` | Sliding window length in seconds |
| `--output` | `report.csv` | Where to write the CSV report (overwritten) |

`python -m log_analyzer ...` works too.

### Exporting Windows logon events

Run in an elevated PowerShell to export the last day of logon events (4624 success, 4625 failure):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
      Id   = $_.Id
      User = $d['TargetUserName']
      IP   = $d['IpAddress']
    }
  } | Export-Csv windows_events.csv -NoTypeInformation -Encoding UTF8
```

## How detection works

| Detection | Severity | Rule |
|---|---|---|
| `BRUTE_FORCE` | HIGH | An IP has ≥ `threshold` failed logins inside any `window`-second span (two-pointer sliding window over its sorted attempts) |
| `POSSIBLE_COMPROMISE` | CRITICAL | A brute force IP later has a successful login |
| `SLOW_SCAN` | MEDIUM | An IP tries ≥ 3 non-existent usernames, regardless of timing (SSH only) |

Both parsers emit the same event shape, so detectors don't care where data came from:

```python
{"time": datetime, "type": "failed" | "accepted" | "invalid", "user": str, "ip": str}
```

```
src/log_analyzer/
├── cli.py            # argument parsing, output, CSV report
├── detectors.py      # brute force / compromise / slow scan rules
└── parsers/
    ├── ssh.py        # regex parser for sshd syslog lines
    └── windows.py    # CSV parser for Windows 4624/4625 events
scripts/              # synthetic data generators (fixed seeds)
samples/              # generated sample logs
```

## Sample data

`samples/` contains synthetic logs with a known attack scenario. Regenerate them with:

```bash
python scripts/generate_ssh_log.py        # -> samples/auth.log
python scripts/generate_windows_log.py    # -> samples/windows_events.csv
```

## Roadmap

- [ ] Test suite (pytest) and GitHub Actions CI with lint and type checks
- [ ] Typed event model, configurable year and ISO 8601 syslog timestamps
- [ ] More SSH patterns (public key logins, disconnects) and Windows logon types
- [ ] JSON output
- [ ] REST API (FastAPI) with stored analysis history
- [ ] Docker image
- [ ] Pluggable parsers/detectors and new rules (password spraying, distributed brute force)

## License

[MIT](LICENSE)
