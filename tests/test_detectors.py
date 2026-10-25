from log_analyzer.detectors import detect_bruteforce, detect_compromise, detect_scanners
from log_analyzer.models import EventType
from tests.helpers import T0, ev, failures


class TestBruteforce:
    def test_threshold_reached_inside_window(self) -> None:
        suspects = detect_bruteforce(failures(10, every=5), threshold=10, window_seconds=60)

        assert list(suspects) == ["203.0.113.1"]
        s = suspects["203.0.113.1"]
        assert (s.total_failed, s.max_in_window) == (10, 10)
        assert s.first_seen == T0
        assert s.last_seen == failures(10, every=5)[-1].time

    def test_one_below_threshold_is_ignored(self) -> None:
        assert detect_bruteforce(failures(9, every=5), threshold=10) == {}

    def test_attempts_spread_wider_than_window_are_ignored(self) -> None:
        # 20 attempts, but only 6 ever fall inside a 60 s window
        assert detect_bruteforce(failures(20, every=11), threshold=10, window_seconds=60) == {}

    def test_window_edge_is_inclusive(self) -> None:
        # first and last attempt exactly 60 s apart still count as one window
        suspects = detect_bruteforce(failures(3, every=30), threshold=3, window_seconds=60)

        assert suspects["203.0.113.1"].max_in_window == 3

    def test_max_in_window_reports_densest_burst(self) -> None:
        events = failures(5, every=100) + failures(8, every=1, start=1000)

        s = detect_bruteforce(events, threshold=5, window_seconds=60)["203.0.113.1"]

        assert (s.total_failed, s.max_in_window) == (13, 8)

    def test_unsorted_input_and_separate_ips(self) -> None:
        events = list(reversed(failures(5, every=1, ip="a"))) + failures(2, every=1, ip="b")

        assert list(detect_bruteforce(events, threshold=5)) == ["a"]

    def test_only_failed_events_count(self) -> None:
        events = [ev(i, EventType.ACCEPTED) for i in range(10)]
        events += [ev(i, EventType.INVALID) for i in range(10)]

        assert detect_bruteforce(events, threshold=5) == {}

    def test_users_tried_are_unique_and_sorted(self) -> None:
        events = [ev(i, EventType.FAILED, user=u) for i, u in enumerate("cbaab")]

        assert detect_bruteforce(events, threshold=5)["203.0.113.1"].users_tried == ["a", "b", "c"]


class TestCompromise:
    def test_login_after_bruteforce_is_flagged(self) -> None:
        events = failures(10, every=1)
        login = ev(30, EventType.ACCEPTED, user="ahmet")
        events.append(login)

        assert detect_compromise(events, detect_bruteforce(events)) == [login]

    def test_login_before_first_failure_is_not_flagged(self) -> None:
        events = [ev(-60, EventType.ACCEPTED), *failures(10, every=1)]

        assert detect_compromise(events, detect_bruteforce(events)) == []

    def test_logins_from_other_ips_are_not_flagged(self) -> None:
        events = [*failures(10, every=1), ev(30, EventType.ACCEPTED, ip="192.168.1.10")]

        assert detect_compromise(events, detect_bruteforce(events)) == []


class TestScanners:
    def test_threshold(self) -> None:
        events = [ev(i * 3600, EventType.INVALID, user=f"u{i}") for i in range(3)]

        assert detect_scanners(events, threshold=3)["203.0.113.1"].count == 3
        assert detect_scanners(events, threshold=4) == {}

    def test_ignores_non_invalid_events(self) -> None:
        assert detect_scanners(failures(10, every=1)) == {}
