"""Run every detector over a list of events and collect the results."""

from collections.abc import Sequence
from dataclasses import dataclass

from .detectors import (
    BruteForceSuspect,
    ScanSuspect,
    detect_bruteforce,
    detect_compromise,
    detect_scanners,
)
from .models import Event, Finding, Severity


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    total_events: int
    threshold: int
    window_seconds: int
    scan_threshold: int
    bruteforce: list[BruteForceSuspect]
    compromises: list[Event]
    scanners: list[ScanSuspect]

    def findings(self) -> list[Finding]:
        """Flatten the detector results into report rows."""
        rows = [
            Finding(s.ip, "BRUTE_FORCE", Severity.HIGH, f"{s.total_failed} failed attempts")
            for s in self.bruteforce
        ]
        rows += [
            Finding(e.ip, "POSSIBLE_COMPROMISE", Severity.CRITICAL, f"successful login as {e.user}")
            for e in self.compromises
        ]
        rows += [
            Finding(s.ip, "SLOW_SCAN", Severity.MEDIUM, f"{s.count} invalid user attempts")
            for s in self.scanners
        ]
        return rows


def analyze(
    events: Sequence[Event],
    threshold: int = 10,
    window_seconds: int = 60,
    scan_threshold: int = 3,
) -> AnalysisResult:
    suspects = detect_bruteforce(events, threshold, window_seconds)
    return AnalysisResult(
        total_events=len(events),
        threshold=threshold,
        window_seconds=window_seconds,
        scan_threshold=scan_threshold,
        bruteforce=list(suspects.values()),
        compromises=detect_compromise(events, suspects),
        scanners=list(detect_scanners(events, scan_threshold).values()),
    )
