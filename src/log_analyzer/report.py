"""Write analysis findings to report files."""

import csv
from collections.abc import Iterable
from pathlib import Path

from .models import Finding

CSV_HEADER = ["IP", "Detection", "Severity", "Details"]


def write_csv(findings: Iterable[Finding], path: str | Path) -> None:
    # utf-8-sig so Excel opens the file with the right encoding
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        writer.writerows([x.ip, x.detection, x.severity, x.details] for x in findings)
