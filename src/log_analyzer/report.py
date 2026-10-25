"""Write analysis findings to report files."""

import csv
import json
from collections.abc import Iterable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .analysis import AnalysisResult
from .models import Finding

CSV_HEADER = ["IP", "Detection", "Severity", "Details"]


def write_csv(findings: Iterable[Finding], path: str | Path) -> None:
    # utf-8-sig so Excel opens the file with the right encoding
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        writer.writerows([x.ip, x.detection, x.severity, x.details] for x in findings)


def to_dict(result: AnalysisResult, source: str) -> dict[str, Any]:
    """Everything the analysis found, as plain JSON-ready data."""
    return {
        "source": source,
        "total_events": result.total_events,
        "parameters": {
            "threshold": result.threshold,
            "window_seconds": result.window_seconds,
            "scan_threshold": result.scan_threshold,
        },
        "findings": [asdict(f) for f in result.findings()],
        "bruteforce": [asdict(s) for s in result.bruteforce],
        "compromises": [asdict(e) for e in result.compromises],
        "scanners": [asdict(s) for s in result.scanners],
    }


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def write_json(result: AnalysisResult, source: str, path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_dict(result, source), f, indent=2, ensure_ascii=False, default=_json_default)
        f.write("\n")
