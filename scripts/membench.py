"""Memory benchmark: RSS of the web process (and its child processes) through a typical session.

Starts uvicorn against the configured database, then measures:

  import   python + ``import app.main`` (separate process)
  idle     10 s after startup
  pages    after N mixed page loads, including a case page and its Suggestions panel
  peak     highest total during a scan (sampled every 100 ms)
  after    5 s after the scan (and its correlation) finished
  quiet    after the idle timeout (UNMASK_IDLE_SECONDS, set to 15 s here)

Usage:  python scripts/membench.py [--python /path/to/python] [--pages 200]
Needs DATABASE_URL (and the usual UNMASK_* variables) in the environment.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time

import httpx

PORT = 8799
ADMIN = ("admin@example.com", "correct-horse-battery")


def rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def children(pid: int) -> list[int]:
    out: list[int] = []
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            kids = [int(p) for p in f.read().split()]
    except OSError:
        return out
    for kid in kids:
        out += [kid, *children(kid)]
    return out


def tree_mb(pid: int) -> tuple[float, float]:
    """(main process MB, main + children MB)."""
    own = rss_kb(pid)
    return own / 1024, (own + sum(rss_kb(c) for c in children(pid))) / 1024


def threads(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return 0


def csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not m:
        raise SystemExit("no csrf token in page")
    return m.group(1)


def login(c: httpx.Client) -> str:
    token = csrf(c.get("/login").text)
    c.post("/login", data={"email": ADMIN[0], "password": ADMIN[1], "csrf_token": token})
    home = c.get("/")
    if home.status_code == 303 and "/legal/accept" in home.headers.get("location", ""):
        t = csrf(c.get("/legal/accept").text)
        c.post("/legal/accept", data={"csrf_token": t, "agree_terms": "on", "agree_responsibility": "on"})
        home = c.get("/")
    return csrf(home.text)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--pages", type=int, default=200)
    args = ap.parse_args()

    env = {**os.environ, "UNMASK_QUEUE": "inline", "UNMASK_IDLE_SECONDS": "15",
           "UNMASK_ADMIN_EMAIL": ADMIN[0], "UNMASK_ADMIN_PASSWORD": ADMIN[1]}  # fmt: skip
    probe = "import app.main,sys;print(open('/proc/self/status').read().split('VmRSS:')[1].split()[0])"
    imported = int(subprocess.check_output([args.python, "-c", probe], env=env).decode().strip()) / 1024

    proc = subprocess.Popen(
        [args.python, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--log-level", "warning"],
        env=env,
    )
    rows: list[tuple[str, float, float, int]] = [("import", imported, imported, 1)]

    def record(label: str) -> None:
        own, total = tree_mb(proc.pid)
        rows.append((label, own, total, threads(proc.pid)))

    try:
        base = f"http://127.0.0.1:{PORT}"
        for _ in range(100):
            try:
                httpx.get(base + "/healthz", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        time.sleep(10)
        record("idle")

        with httpx.Client(base_url=base, timeout=60) as c:
            token = login(c)
            r = c.post("/cases", data={
                "csrf_token": token, "name": f"Bench {int(time.time())}",
                "authorization_note": "Benchmark run on made-up data", "lawful_basis_confirmed": "on",
                "target_value": ["janedoe", "Jane Doe", "Jane M. Doe"], "target_type": ["username", "name", "name"],
                "target_tags": ["", "", ""], "tools": ["gravatar", "github", "keybase"],
            })  # fmt: skip
            case_url = r.headers.get("location", "/")
            # Let the scan the case started (and its follow-ups) finish before the page loop.
            for _ in range(600):
                if "Scanning" not in c.get(case_url).text and not children(proc.pid):
                    break
                time.sleep(0.5)
            pages = ["/", case_url, case_url + "/suggestions", "/tools", "/notifications/badge", case_url + "/entities"]
            for i in range(args.pages):
                c.get(pages[i % len(pages)])
            record("pages")

            peak = [0.0, 0.0]
            done = threading.Event()

            def sample() -> None:
                while not done.is_set():
                    own, total = tree_mb(proc.pid)
                    peak[0], peak[1] = max(peak[0], own), max(peak[1], total)
                    time.sleep(0.1)

            t = threading.Thread(target=sample, daemon=True)
            t.start()
            c.post(case_url + "/scans", data={"csrf_token": token})
            time.sleep(1)
            for _ in range(600):
                if "Scanning" not in c.get(case_url).text:
                    break
                time.sleep(0.5)
            # Correlation (and its embedding child) runs after the tools finish: wait for it.
            for _ in range(600):
                if not children(proc.pid) and "Scanning" not in c.get(case_url).text:
                    break
                time.sleep(0.5)
            time.sleep(2)
            done.set()
            t.join()
            rows.append(("peak", peak[0], peak[1], threads(proc.pid)))
        time.sleep(5)
        record("after")
        time.sleep(20)
        record("quiet")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)

    print(f"{'stage':8s} {'web MB':>8s} {'+kids MB':>9s} {'threads':>8s}")
    for label, own, total, n in rows:
        print(f"{label:8s} {own:8.1f} {total:9.1f} {n:8d}")


if __name__ == "__main__":
    main()
