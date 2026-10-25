"""Parsers that turn raw log sources into the common event format.

Every parser returns a list of dicts:
    {'time': datetime, 'type': 'failed' | 'accepted' | 'invalid', 'user': str, 'ip': str}
"""

from .ssh import parse_file
from .windows import parse_windows_csv

__all__ = ['parse_file', 'parse_windows_csv']
