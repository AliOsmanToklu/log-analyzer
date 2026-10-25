# log-analyzer

[![CI](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[Türkçe](README.tr.md)

Scans authentication logs for signs of attack: brute force bursts, successful logins
that follow them, and slow username scans. It reads **Linux SSH logs** (`/var/log/auth.log`)
and **Windows logon events** exported to CSV, normalizes both into one typed event model,
and runs the same detectors over them — from a **command-line tool** or a **REST API**.

- **CLI**: pure standard library, CSV report for spreadsheets, JSON report for other tools
- **REST API**: FastAPI, background analysis, findings stored in PostgreSQL or SQLite
  and searchable across uploads, OpenAPI docs, Docker Compose stack
- Fully type-checked (`mypy --strict`), 99% branch coverage, CI on Linux and Windows
  for Python 3.11–3.14, against PostgreSQL, and on the Docker image

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

With `--output report.json` you get every detail, including timestamps and the parameters used:

```json
{
  "source": "samples/auth.log",
  "total_events": 66,
  "parameters": { "threshold": 10, "window_seconds": 60, "scan_threshold": 3 },
  "findings": [
    { "ip": "203.0.113.45", "detection": "BRUTE_FORCE", "severity": "HIGH", "details": "40 failed attempts" },
    ...
  ],
  "bruteforce": [
    {
      "ip": "203.0.113.45", "total_failed": 40, "max_in_window": 21,
      "first_seen": "2026-10-25T11:00:00", "last_seen": "2026-10-25T11:01:57",
      "users_tried": ["admin", "ahmet", "root", "test", "ubuntu"]
    }
  ],
  "compromises": [
    { "time": "2026-10-25T11:02:05", "type": "accepted", "user": "ahmet", "ip": "203.0.113.45" }
  ],
  "scanners": [ { "ip": "198.51.100.7", "count": 6, "users_tried": ["oracle"] } ]
}
```

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/AliOsmanToklu/log-analyzer.git
cd log-analyzer
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .                 # CLI only, no dependencies
pip install -e ".[api]"          # plus the REST API (add ",postgres" for PostgreSQL)
```

## CLI usage

```bash
log-analyzer <file> [options]
```

| Option | Default | Meaning |
|---|---|---|
| `file` | — | Log to analyze |
| `--format {auto,ssh,windows}` | `auto` | `auto` treats `.csv` as a Windows logon export and anything else as an SSH auth log |
| `--threshold N` | `10` | Failed attempts inside one window that count as brute force |
| `--window SECONDS` | `60` | Sliding window length |
| `--scan-threshold N` | `3` | Invalid-user attempts from one IP that count as a slow scan |
| `--year YEAR` | guessed | Year for classic syslog timestamps, which carry none |
| `--output PATH` | `report.csv` | Report path; `.json` writes JSON, anything else CSV (overwritten) |

`python -m log_analyzer ...` works too. Exit status is `0` on success and `2` on bad
arguments or unreadable input, with a one-line error on stderr.

### Supported SSH log lines

| sshd message | Event |
|---|---|
| `Failed <method> for [invalid user] <user> from <ip>` | failed |
| `Accepted <method> for <user> from <ip>` | accepted |
| `Invalid user <user> from <ip>` | invalid |

`<method>` is any auth method (`password`, `publickey`, `keyboard-interactive/pam`, ...).
Both classic (`Oct 25 11:02:05`) and RFC 3339 (`2026-10-25T11:02:05.123+03:00`) timestamps are read.
Classic timestamps have no year: it is guessed so the log does not end in the future, and
Dec → Jan rollovers are followed. rsyslog's `message repeated N times: [ ... ]` lines count as N events.

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

Logons from local addresses (`-`, `127.0.0.1`, `::1`) are ignored.

## REST API

### Run it

With Docker (API + PostgreSQL):

```bash
docker compose up --build
# Swagger UI: http://localhost:8000/docs
```

Or locally with SQLite:

```bash
pip install -e ".[api]"
log-analyzer-api serve          # migrates the database, then serves on 127.0.0.1:8000
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/analyses` | Upload a log (multipart `file`, optional `format`, `threshold`, `window_seconds`, `scan_threshold`, `year`). Returns `202 Accepted` and a `Location` header; analysis runs in the background |
| `GET` | `/analyses` | List analyses, newest first (`limit`, `offset`, `status`) |
| `GET` | `/analyses/{id}` | Status, parameters and every finding of one analysis |
| `DELETE` | `/analyses/{id}` | Delete an analysis and its findings |
| `GET` | `/findings` | Search findings across all analyses (`ip`, `severity`, `detection`, `limit`, `offset`) |
| `GET` | `/health` | Liveness and database check (`503` if the database is unreachable) |

Errors use standard status codes: `404` unknown id, `413` upload over the size limit,
`422` invalid parameters. A log that cannot be parsed (for example a CSV that is not a
Windows export) still returns `202`; the analysis then ends with `status: "failed"` and an `error`.

### Example

```console
$ curl -F file=@samples/auth.log -F year=2026 http://localhost:8000/analyses
{"id":"4a60b9a6-65a1-4835-8a30-403331e3c851","filename":"auth.log","format":"ssh","status":"pending",
 "created_at":"2026-10-25T12:49:21.876865Z","completed_at":null,"total_events":null,"error":null,
 "parameters":{"threshold":10,"window_seconds":60,"scan_threshold":3,"year":2026}}

$ curl http://localhost:8000/analyses/4a60b9a6-65a1-4835-8a30-403331e3c851
{"id":"4a60b9a6-...","status":"completed","total_events":66,
 "findings":[{"ip":"203.0.113.45","detection":"BRUTE_FORCE","severity":"HIGH","details":"40 failed attempts"}, ...],
 "bruteforce":[...], "compromises":[...], "scanners":[...], ...}

$ curl "http://localhost:8000/findings?severity=CRITICAL"
{"items":[{"ip":"203.0.113.45","detection":"POSSIBLE_COMPROMISE","severity":"CRITICAL",
           "details":"successful login as ahmet","analysis_id":"4a60b9a6-...","filename":"auth.log",
           "analyzed_at":"2026-10-25T12:49:21.876865Z"}],
 "total":1,"limit":20,"offset":0}
```

### Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `LOG_ANALYZER_DATABASE_URL` | `sqlite:///log_analyzer.db` | SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host/db` |
| `LOG_ANALYZER_MAX_UPLOAD_MB` | `20` | Largest accepted upload |

`log-analyzer-api migrate` applies database migrations without starting the server;
`serve --no-migrate` starts it without migrating.

## How detection works

| Detection | Severity | Rule |
|---|---|---|
| `BRUTE_FORCE` | HIGH | An IP has ≥ `threshold` failed logins inside any `window`-second span (two-pointer sliding window over its sorted attempts, O(n log n)) |
| `POSSIBLE_COMPROMISE` | CRITICAL | A brute force IP later has a successful login |
| `SLOW_SCAN` | MEDIUM | An IP tries ≥ `scan-threshold` non-existent usernames, regardless of timing (SSH only) |

## Architecture

```
            ┌─ parsers/ssh.py ─────┐                                                       ┌─► cli (console)
log lines ──┤                      ├─► list[Event] ─► analysis.analyze() ─► AnalysisResult ─┼─► report (CSV / JSON)
            └─ parsers/windows.py ─┘                     │                                  └─► api.service ─► database
                                                    detectors.py                                    ▲
                                                                                      api.app (HTTP routes)
```

```
src/log_analyzer/
├── models.py         # Event, Finding, EventType, Severity, Detection (frozen dataclasses, enums)
├── parsers/
│   ├── ssh.py        # sshd syslog lines: timestamps, year rollover, repeated messages
│   └── windows.py    # Windows 4624/4625 CSV exports
├── detectors.py      # brute force / compromise / slow scan rules
├── analysis.py       # runs all detectors, returns an AnalysisResult
├── report.py         # CSV and JSON writers
├── cli.py            # argument parsing and console output
└── api/
    ├── app.py        # FastAPI app factory, routes, upload limits
    ├── schemas.py    # Pydantic response models (drive the OpenAPI docs)
    ├── service.py    # use cases: create/run/list/search, no HTTP
    ├── orm.py        # SQLAlchemy 2 models: analyses, findings
    ├── db.py         # engine/session setup, Alembic upgrade
    ├── settings.py   # configuration from environment variables
    └── migrations/   # Alembic migrations, shipped inside the package
tests/                # pytest suite; tests/api also runs against PostgreSQL in CI
scripts/              # synthetic data generators (fixed seeds)
samples/              # generated sample logs
```

### Design decisions

- **One detection core, two front ends.** Parsing, detection and output are separate layers;
  the CLI and the API both call the same `analyze()`, and the API's HTTP routes only translate
  requests into calls to `api.service`.
- **The CLI stays dependency-free.** Web, database and migration libraries live in the
  optional `api` extra, so `pip install log-analyzer` pulls in nothing.
- **Asynchronous by contract.** `POST /analyses` returns `202 Accepted` immediately and the
  client polls the resource. Today the work runs in FastAPI background tasks; the same contract
  allows moving it to a queue worker later without changing clients. A background failure never
  leaves an analysis stuck in `pending`.
- **Findings are rows, not just a blob.** The full result is stored as JSON for the detail
  endpoint, and each finding is also a row indexed by IP and severity, so "has this IP shown up
  anywhere?" is a single SQL query.
- **Uploaded logs are not stored.** Logs contain usernames and addresses; only findings are kept.
- **Schema changes go through migrations.** Alembic migrations ship in the package (the Docker
  image migrates itself on start), and a test fails if the models and migrations disagree.
- **Timestamps are always UTC with an offset**, including on SQLite, which drops time zones.

## Development

```bash
pip install -e ".[dev]"
pytest --cov          # tests with coverage
ruff format .         # format
ruff check .          # lint
mypy                  # type check (strict)

# API tests against PostgreSQL instead of SQLite (the database's tables are dropped!)
docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=test postgres:17-alpine
pip install -e ".[dev,postgres]"
LOG_ANALYZER_TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/test pytest tests/api
```

CI runs lint and type checks, the test suite on Python 3.11–3.14 (Linux) and 3.14 (Windows),
the API tests against PostgreSQL, and builds and exercises the Docker image.

`samples/` contains synthetic logs with a known attack scenario. Regenerate them with:

```bash
python scripts/generate_ssh_log.py        # -> samples/auth.log
python scripts/generate_windows_log.py    # -> samples/windows_events.csv
```

## Roadmap

- [x] Test suite and CI with lint and type checks
- [x] Typed event model; year guessing and ISO 8601 syslog timestamps
- [x] All SSH auth methods and rsyslog repeated messages
- [x] JSON output
- [x] REST API (FastAPI) with stored analysis history and cross-analysis search
- [x] Docker image and Compose stack with PostgreSQL
- [ ] Pluggable parsers/detectors and new rules (password spraying, distributed brute force)
- [ ] Windows logon types and direct `.evtx` input
- [ ] Small web UI

## License

[MIT](LICENSE)
