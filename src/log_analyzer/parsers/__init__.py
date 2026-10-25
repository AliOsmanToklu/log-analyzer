"""Parsers that turn raw log sources into lists of `log_analyzer.models.Event`."""

from .ssh import parse_file
from .windows import parse_windows_csv

__all__ = ["parse_file", "parse_windows_csv"]
