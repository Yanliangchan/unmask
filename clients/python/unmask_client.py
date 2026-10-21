"""A small client for the UNMASK API (/api/v1). Standard library only; Python 3.9+.

    from unmask_client import Unmask

    api = Unmask("https://unmask.example.org", "umk_...")
    for case in api.cases():
        print(case["name"], case["findings"])
    run = api.start_scan(case_id)            # needs the scans:write permission
    run = api.wait_for_scan(case_id, run["number"])
    findings = api.findings(case_id)         # needs findings:read and a written assessment

Errors raise UnmaskError with the HTTP status and the server's message.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["Unmask", "UnmaskError"]


class UnmaskError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status, self.message = status, message


class Unmask:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 30, opener=None):
        if urllib.parse.urlsplit(base_url).scheme not in ("http", "https"):
            raise ValueError("base_url must be an http(s) URL")
        self.base = base_url.rstrip("/") + "/api/v1"
        self.key = api_key
        self.timeout = timeout
        self._open = opener or urllib.request.urlopen

    def _call(self, method: str, path: str, params: dict | None = None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"Authorization": f"Bearer {self.key}", "Accept": "application/json"}
        req = urllib.request.Request(url, method=method, headers=headers)  # noqa: S310 — scheme checked in __init__
        try:
            with self._open(req, timeout=self.timeout) as resp:  # noqa: S310 — scheme checked in __init__
                return json.loads(resp.read().decode() or "null")
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read().decode()).get("error", exc.reason)
            except ValueError:
                message = str(exc.reason)
            raise UnmaskError(exc.code, message) from None

    def me(self) -> dict:
        return self._call("GET", "/me")

    def cases(self) -> list[dict]:
        return self._call("GET", "/cases")["cases"]

    def case(self, case_id: str) -> dict:
        return self._call("GET", f"/cases/{case_id}")

    def findings(self, case_id: str, include: str = "visible") -> dict:
        return self._call("GET", f"/cases/{case_id}/findings", {"include": include})

    def graph(self, case_id: str) -> dict:
        return self._call("GET", f"/cases/{case_id}/graph")

    def paths(self, case_id: str, a: str, b: str) -> dict:
        return self._call("GET", f"/cases/{case_id}/paths", {"a": a, "b": b})

    def stix(self, case_id: str, include: str = "visible") -> dict:
        return self._call("GET", f"/cases/{case_id}/stix", {"include": include})

    def start_scan(self, case_id: str) -> dict:
        return self._call("POST", f"/cases/{case_id}/scans")

    def scan(self, case_id: str, number: int) -> dict:
        return self._call("GET", f"/cases/{case_id}/scans/{number}")

    def wait_for_scan(self, case_id: str, number: int, *, every: float = 10, limit: float = 3600) -> dict:
        deadline = time.monotonic() + limit
        while True:
            run = self.scan(case_id, number)
            if run["status"] not in ("queued", "running") or time.monotonic() > deadline:
                return run
            time.sleep(every)
