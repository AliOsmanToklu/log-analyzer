"""Parsers that turn raw log sources into lists of `log_analyzer.models.Event`."""

from collections.abc import Sequence
from typing import Literal

from ..models import Event
from .ssh import parse_file, parse_ssh_lines
from .windows import parse_windows_csv, parse_windows_lines

LogFormat = Literal["ssh", "windows"]


def detect_format(filename: str) -> LogFormat:
    """Windows logon exports are CSV files; anything else is treated as an SSH auth log."""
    return "windows" if filename.lower().endswith(".csv") else "ssh"


def parse_events(
    lines: Sequence[str], fmt: LogFormat, year: int | None = None, source: str = "input"
) -> list[Event]:
    """Parse already-read log lines in the given format."""
    if fmt == "windows":
        return parse_windows_lines(lines, source)
    return parse_ssh_lines(lines, year)


__all__ = [
    "LogFormat",
    "detect_format",
    "parse_events",
    "parse_file",
    "parse_ssh_lines",
    "parse_windows_csv",
    "parse_windows_lines",
]
