import uuid

import pytest
from fastapi.testclient import TestClient

from log_analyzer.api.app import clean_filename
from tests.api.conftest import UPLOAD_LIMIT, upload


class TestCreate:
    def test_ssh_log_round_trip(self, client: TestClient) -> None:
        response = client.post(
            "/analyses",
            files={"file": ("auth.log", b"")},
            data={"year": "2026"},
        )
        assert response.status_code == 202
        created = response.json()
        assert response.headers["location"] == f"/analyses/{created['id']}"
        assert created["status"] == "pending"
        assert created["format"] == "ssh"
        assert created["parameters"] == {
            "threshold": 10,
            "window_seconds": 60,
            "scan_threshold": 3,
            "year": 2026,
        }

    def test_ssh_sample_is_analyzed(self, client: TestClient) -> None:
        created = upload(client, "auth.log", year=2026)

        detail = client.get(f"/analyses/{created['id']}").json()

        assert detail["status"] == "completed"
        assert detail["error"] is None
        # Read back from the database, timestamps must still say they are UTC
        assert detail["created_at"] == created["created_at"]
        assert detail["created_at"].endswith("Z")
        assert detail["completed_at"].endswith("Z")
        assert client.get("/analyses").json()["items"][0]["created_at"].endswith("Z")
        assert detail["total_events"] == 66
        assert [(f["ip"], f["detection"], f["severity"]) for f in detail["findings"]] == [
            ("203.0.113.45", "BRUTE_FORCE", "HIGH"),
            ("203.0.113.45", "POSSIBLE_COMPROMISE", "CRITICAL"),
            ("198.51.100.7", "SLOW_SCAN", "MEDIUM"),
        ]
        assert detail["bruteforce"][0]["first_seen"] == "2026-10-25T11:00:00"
        assert detail["bruteforce"][0]["max_in_window"] == 21
        assert detail["compromises"] == [
            {
                "time": "2026-10-25T11:02:05",
                "type": "accepted",
                "user": "ahmet",
                "ip": "203.0.113.45",
            }
        ]
        assert detail["scanners"] == [{"ip": "198.51.100.7", "count": 6, "users_tried": ["oracle"]}]

    def test_csv_upload_is_treated_as_windows_export(self, client: TestClient) -> None:
        created = upload(client, "windows_events.csv")

        detail = client.get(f"/analyses/{created['id']}").json()

        assert created["format"] == "windows"
        assert detail["total_events"] == 41
        assert [f["detection"] for f in detail["findings"]] == [
            "BRUTE_FORCE",
            "POSSIBLE_COMPROMISE",
        ]

    def test_format_overrides_the_filename(self, client: TestClient) -> None:
        created = upload(client, "auth.log", filename="ssh_export.csv", format="ssh")

        assert created["format"] == "ssh"
        assert client.get(f"/analyses/{created['id']}").json()["total_events"] == 66

    def test_parameters_are_applied(self, client: TestClient) -> None:
        created = upload(client, threshold=22, scan_threshold=7)

        detail = client.get(f"/analyses/{created['id']}").json()

        assert detail["status"] == "completed"
        assert detail["findings"] == []

    def test_input_that_is_not_a_log_fails_the_analysis(self, client: TestClient) -> None:
        created = upload(client, filename="people.csv", content=b"name,age\nbob,3\n")

        detail = client.get(f"/analyses/{created['id']}").json()

        assert detail["status"] == "failed"
        assert detail["error"] == (
            "people.csv: not a Windows logon export, missing column(s): Time, Id, User, IP"
        )
        assert detail["total_events"] is None
        assert detail["findings"] == []

    def test_undecodable_bytes_are_tolerated(self, client: TestClient) -> None:
        line = b"Oct 25 11:02:05 h sshd[1]: Invalid user \xff\xfe from 1.2.3.4 port 1\n"

        created = upload(client, content=line * 3, year=2026)

        detail = client.get(f"/analyses/{created['id']}").json()
        assert detail["status"] == "completed"
        assert detail["scanners"][0]["users_tried"] == ["\ufffd\ufffd"]

    def test_client_directories_are_stripped_from_the_filename(self, client: TestClient) -> None:
        created = upload(client, filename="C:\\Users\\bob\\auth.log")

        assert created["filename"] == "auth.log"

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("auth.log", "auth.log"),
            ("/var/log/auth.log", "auth.log"),
            ("C:\\logs\\events.csv", "events.csv"),
            ("", "upload"),
            (None, "upload"),
            ("dir/", "upload"),
            ("x" * 300, "x" * 255),
        ],
    )
    def test_clean_filename(self, name: str | None, expected: str) -> None:
        assert clean_filename(name) == expected


class TestUploadLimits:
    def test_upload_just_over_the_limit(self, client: TestClient) -> None:
        response = client.post("/analyses", files={"file": ("a.log", b"x" * (UPLOAD_LIMIT + 1))})

        assert response.status_code == 413
        assert response.json() == {"detail": "upload is larger than the 65536 byte limit"}

    def test_upload_at_the_limit_is_accepted(self, client: TestClient) -> None:
        response = client.post("/analyses", files={"file": ("a.log", b"x" * UPLOAD_LIMIT)})

        assert response.status_code == 202

    def test_huge_request_is_refused_before_parsing(self, client: TestClient) -> None:
        response = client.post("/analyses", files={"file": ("a.log", b"x" * (3 * UPLOAD_LIMIT))})

        assert response.status_code == 413
        assert client.get("/analyses").json()["total"] == 0


class TestValidation:
    @pytest.mark.parametrize(
        "form",
        [
            {"threshold": "0"},
            {"window_seconds": "-1"},
            {"scan_threshold": "many"},
            {"format": "syslog"},
            {"year": "1900"},
        ],
    )
    def test_bad_form_fields(self, client: TestClient, form: dict[str, str]) -> None:
        response = client.post("/analyses", files={"file": ("a.log", b"")}, data=form)

        assert response.status_code == 422

    def test_missing_file(self, client: TestClient) -> None:
        assert client.post("/analyses", data={"threshold": "5"}).status_code == 422


class TestReadAndDelete:
    def test_unknown_id(self, client: TestClient) -> None:
        response = client.get(f"/analyses/{uuid.uuid4()}")

        assert response.status_code == 404
        assert response.json() == {"detail": "analysis not found"}

    def test_malformed_id(self, client: TestClient) -> None:
        assert client.get("/analyses/not-a-uuid").status_code == 422

    def test_delete(self, client: TestClient) -> None:
        created = upload(client)

        assert client.delete(f"/analyses/{created['id']}").status_code == 204
        assert client.get(f"/analyses/{created['id']}").status_code == 404
        assert client.get("/findings").json()["total"] == 0
        assert client.delete(f"/analyses/{created['id']}").status_code == 404


class TestList:
    def test_newest_first_with_pagination(self, client: TestClient) -> None:
        ids = [upload(client, filename=f"{i}.log")["id"] for i in range(3)]

        first = client.get("/analyses", params={"limit": 2}).json()
        second = client.get("/analyses", params={"limit": 2, "offset": 2}).json()

        assert (first["total"], first["limit"], first["offset"]) == (3, 2, 0)
        assert [a["id"] for a in first["items"] + second["items"]] == ids[::-1]

    def test_filter_by_status(self, client: TestClient) -> None:
        upload(client)
        failed = upload(client, filename="bad.csv", content=b"a,b\n")

        page = client.get("/analyses", params={"status": "failed"}).json()

        assert page["total"] == 1
        assert page["items"][0]["id"] == failed["id"]

    @pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 101}, {"offset": -1}])
    def test_bad_paging(self, client: TestClient, params: dict[str, int]) -> None:
        assert client.get("/analyses", params=params).status_code == 422
