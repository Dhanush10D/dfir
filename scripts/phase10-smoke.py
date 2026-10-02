#!/usr/bin/env python3
"""Phase 10 live smoke test against the running compose stack (stdlib only).

    python scripts/phase10-smoke.py --admin-email E [--admin-password P] [--base URL]
        [--metrics-token T]   # default: METRICS_TOKEN from the environment

The stack must run with AUTH_REFRESH_RATE_LIMIT_PER_MINUTE <= 60 and METRICS_TOKEN set
(verify-phase10.sh starts it so).

1. parser sandbox container (docker inspect + inside): no network (only `lo`, no DNS, no route),
   read-only root and evidence mount, every capability dropped, no-new-privileges, seccomp
   filtering, non-root user, pids/memory/CPU limits, no credentials or key material inside; no
   service mounts the Docker socket or runs privileged;
2. a parse job runs through the sandbox (run manifest `sandbox.mode=spool`, reason `ok`) and
   stores the expected events; a malformed file fails cleanly with `unusable input`;
3. the API logs in as `dfirbench_app` itself: `RESET ROLE` keeps it, `SET ROLE dfir` is denied,
   it is not a superuser;
4. per-IP limit on token refreshes answers 429 with Retry-After and is audited;
5. `/metrics`: 401 without the token, Prometheus text with the token, not served by the web
   container; security headers on every web location (one include file);
6. `integrity-check` runs read-only in the api image and finds this smoke's evidence clean.
Exits non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra" / "compose.yaml")]
AUTH_LOG = (ROOT / "backend" / "tests" / "fixtures" / "linux" / "auth.log").read_bytes()
SECRET_NAMES = (
    "DATABASE_URL", "DATABASE_MIGRATE_URL", "S3_SECRET_KEY", "JWT_SECRET", "TOTP_ENC_KEY",
    "LLM_API_KEY", "INTEGRATION_KEK", "METRICS_TOKEN", "POSTGRES_PASSWORD", "MINIO_ROOT_PASSWORD",
)
HEADERS = (
    "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy", "permissions-policy",
)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", ROOT / "scripts" / "phase1-smoke.py")
p2 = _load("phase2_smoke", ROOT / "scripts" / "phase2-smoke.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        [*COMPOSE, *args], capture_output=True, text=True, check=check
    )


def in_sandbox(script: str) -> subprocess.CompletedProcess[str]:
    # As the parser child's uid and group: what a compromised parser could do.
    return compose(
        "exec", "-T", "-u", "10002:10001", "parser-sandbox", "python", "-c", script, check=False
    )


def inspect(service: str) -> dict[str, Any]:
    cid = compose("ps", "-q", service).stdout.strip()
    expect(bool(cid), f"{service} container is running")
    out = subprocess.run(  # noqa: S603 - fixed argv
        ["docker", "inspect", cid], capture_output=True, text=True, check=True
    ).stdout
    return dict(json.loads(out)[0])


def raw(url: str, headers: dict[str, str] | None = None, method: str = "GET",
        body: Any = None) -> tuple[int, dict[str, str], bytes]:
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Accept": "*/*", **(headers or {})}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - local URL
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


# ------------------------------------------------------------------ 1. sandbox container


def check_sandbox_container() -> None:
    info = inspect("parser-sandbox")
    host = info["HostConfig"]
    expect(host["NetworkMode"] == "none", "sandbox: network mode none", host["NetworkMode"])
    expect(host["ReadonlyRootfs"] is True, "sandbox: read-only root file system")
    expect([c.upper() for c in host.get("CapDrop") or []] == ["ALL"], "sandbox: CapDrop ALL",
           host.get("CapDrop"))
    cap_add = sorted(c.upper().removeprefix("CAP_") for c in host.get("CapAdd") or [])
    expect(cap_add == ["DAC_OVERRIDE", "KILL", "SETGID", "SETUID"],
           "sandbox: only the capabilities for the uid split", cap_add)
    sec = host.get("SecurityOpt") or []
    expect(any("no-new-privileges" in s for s in sec), "sandbox: no-new-privileges", sec)
    expect(not any("unconfined" in s for s in sec), "sandbox: seccomp/apparmor not disabled", sec)
    expect(host.get("Privileged") is False, "sandbox: not privileged")
    expect(info["Config"]["User"] == "0:0", "sandbox: server starts as root (uid split)",
           info["Config"]["User"])
    expect((host.get("PidsLimit") or 0) > 0, "sandbox: pids limit", host.get("PidsLimit"))
    expect((host.get("Memory") or 0) > 0, "sandbox: memory limit", host.get("Memory"))
    expect((host.get("NanoCpus") or 0) > 0, "sandbox: CPU limit", host.get("NanoCpus"))
    mounts = {m["Destination"]: m for m in info["Mounts"]}
    spool_in = mounts.get("/var/lib/dfirbench/spool/in")
    expect(spool_in is not None and spool_in["RW"] is False, "sandbox: evidence spool read-only")
    expect("/var/lib/dfirbench/keys" not in mounts, "sandbox: no custody key volume")
    expect(not any("docker.sock" in m.get("Source", "") for m in info["Mounts"]),
           "sandbox: no Docker socket")

    probe = in_sandbox(
        "import os, socket, json\n"
        "out = {'uid': os.getuid(), 'gid': os.getgid()}\n"
        "status = open('/proc/self/status').read()\n"
        "out['capeff'] = [l.split()[1] for l in status.splitlines() if l.startswith('CapEff')][0]\n"
        "out['nnp'] = [l.split()[1] for l in status.splitlines() if l.startswith('NoNewPrivs')][0]\n"
        "out['seccomp'] = [l.split()[1] for l in status.splitlines() if l.startswith('Seccomp:')][0]\n"
        "out['ifaces'] = sorted(l.split(':')[0].strip() for l in open('/proc/net/dev').read().splitlines()[2:])\n"
        "def attempt(fn):\n"
        "    try:\n"
        "        fn(); return 'ok'\n"
        "    except OSError as e:\n"
        "        return type(e).__name__ + ':' + str(e.errno)\n"
        "out['dns'] = attempt(lambda: socket.getaddrinfo('postgres', 5432))\n"
        "out['tcp'] = attempt(lambda: socket.create_connection(('1.1.1.1', 53), timeout=3))\n"
        "out['write_root'] = attempt(lambda: open('/sandbox-probe', 'w'))\n"
        "out['spool_ro'] = bool(os.statvfs('/var/lib/dfirbench/spool/in').f_flag & os.ST_RDONLY)\n"
        "out['list_out'] = attempt(lambda: os.listdir('/var/lib/dfirbench/spool/out'))\n"
        "out['write_work'] = attempt(lambda: open('/var/lib/dfirbench/sandbox-work/probe', 'w'))\n"
        "def cmd(p):\n"
        "    try:\n"
        "        return open('/proc/' + p + '/cmdline', 'rb').read()\n"
        "    except OSError:\n"
        "        return b''\n"
        "server = [p for p in os.listdir('/proc') if p.isdigit()\n"
        "          and b'app.sandbox.server' in cmd(p) and b'--health' not in cmd(p)\n"
        "          and b'docker-init' not in cmd(p)]\n"
        "out['servers'] = len(server)\n"
        "st = open('/proc/' + server[0] + '/status').read().splitlines() if server else []\n"
        "out['server_uid'] = [l.split()[1:] for l in st if l.startswith('Uid:')]\n"
        "out['server_capprm'] = [l.split()[1] for l in st if l.startswith('CapPrm')]\n"
        "out['signal_server'] = attempt(lambda: os.kill(int(server[0]), 0))\n"
        "out['secrets'] = sorted(k for k in os.environ if k in %r)\n"
        "out['keys'] = os.path.exists('/var/lib/dfirbench/keys/custody-dev.pem')\n"
        "print(json.dumps(out))\n" % (SECRET_NAMES,)
    )
    expect(probe.returncode == 0, "sandbox: probe ran", probe.stderr)
    out = json.loads(probe.stdout.strip().splitlines()[-1])
    expect(out["uid"] == 10002 and out["gid"] == 10001, "sandbox: child uid 10002", out)
    expect(int(out["capeff"], 16) == 0, "sandbox: no effective capabilities", out["capeff"])
    expect(out["nnp"] == "1", "sandbox: NoNewPrivs set", out["nnp"])
    expect(out["seccomp"] == "2", "sandbox: seccomp filter active", out["seccomp"])
    expect(out["ifaces"] == ["lo"], "sandbox: only the loopback interface", out["ifaces"])
    expect(out["dns"] != "ok" and out["tcp"] != "ok", "sandbox: no DNS and no route out", out)
    expect(out["write_root"].startswith("OSError:30"), "sandbox: root is read-only", out)
    expect(out["spool_ro"] is True, "sandbox: evidence mount is read-only", out)
    expect(out["list_out"].startswith("PermissionError"), "sandbox child: no output spool", out)
    expect(out["write_work"].startswith("PermissionError"), "sandbox child: no work root", out)
    # The server keeps euid 0 and four capabilities; the child cannot signal (stop) it.
    caps = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7)  # DAC_OVERRIDE, KILL, SETGID, SETUID
    expect(out["servers"] == 1 and out["server_uid"] == [["0", "0", "0", "10001"]],
           "sandbox: server euid 0, file uid 10001", out)
    expect([int(c, 16) for c in out["server_capprm"]] == [caps],
           "sandbox: server holds only the uid-split capabilities", out)
    expect(out["signal_server"].startswith("PermissionError"),
           "sandbox child: cannot signal the server", out)
    expect(out["secrets"] == [] and out["keys"] is False, "sandbox: no secrets, no custody key",
           out)

    for service in ("api", "worker", "web", "parser-sandbox"):
        detail = inspect(service)
        binds = [m.get("Source", "") for m in detail["Mounts"]]
        expect(
            detail["HostConfig"].get("Privileged") is False
            and not any("docker.sock" in b for b in binds),
            f"{service}: not privileged, no Docker socket",
        )
    worker = inspect("worker")
    expect(not worker["HostConfig"].get("CapAdd"), "worker: no capability added")


# ------------------------------------------------------------------ 2. parse through the sandbox


def check_sandboxed_parsing(api: Any, admin: str) -> str:
    _, analyst = make_user(api, admin, "analyst")
    status, case, _ = api.call("POST", "/cases", analyst, {"title": "Phase 10 sandbox smoke"})
    expect(status == 201, "analyst creates a case", case)
    cid = case["id"]
    eid = p2.stored(api, analyst, cid, "auth.log", "log", AUTH_LOG)
    status, body, _ = api.call("POST", f"/evidence/{eid}/process", analyst,
                               {"parsers": ["linux_auth"], "params": {"timezone": "UTC"}})
    expect(status == 202, "submit parse job", body)
    job = p2.wait_job(api, analyst, body["jobs"][0]["id"])
    manifest = job.get("run_manifest") or {}
    sandbox = manifest.get("sandbox") or {}
    expect(job["status"] == "succeeded", "sandboxed job succeeded", job)
    expect(sandbox.get("mode") == "spool" and sandbox.get("reason") == "ok",
           "run manifest: parsed in the sandbox", sandbox)
    expect(len(sandbox.get("output_sha256", "")) == 64, "run manifest: sandbox output hash")
    counts = manifest.get("counts", {})
    expect(counts.get("events_emitted") == 22 and counts.get("inserted") == 22,
           "sandboxed job stored 22 events", counts)
    events = p2.timeline(api, analyst, cid)
    expect(len(events) == 22, "timeline shows the sandboxed events", len(events))

    bad = p2.stored(api, analyst, cid, "broken.evtx", "log", b"ElfFile\x00" + b"\xff" * 4000)
    status, body, _ = api.call("POST", f"/evidence/{bad}/process", analyst, {"parsers": ["evtx"]})
    expect(status == 202, "submit a malformed EVTX", body)
    job = p2.wait_job(api, analyst, body["jobs"][0]["id"])
    expect(job["status"] in ("failed", "partial") and (job["run_manifest"] or {}).get(
        "sandbox", {}).get("mode") == "spool", "malformed input ends cleanly in the sandbox",
        job)
    return cid


# ------------------------------------------------------------------ 3. app login


def check_app_login() -> None:
    script = (
        "from sqlalchemy import text\n"
        "from app.db.session import get_engine\n"
        "with get_engine().connect() as c:\n"
        "    a = c.execute(text('SELECT current_user, session_user')).one()\n"
        "    c.execute(text('RESET ROLE'))\n"
        "    b = c.execute(text('SELECT current_user')).scalar_one()\n"
        "    s = c.execute(text('SELECT rolsuper FROM pg_roles WHERE rolname = session_user'))"
        ".scalar_one()\n"
        "    try:\n"
        "        c.execute(text('SET ROLE dfir'))\n"
        "        owner = 'ALLOWED'\n"
        "    except Exception as e:\n"
        "        owner = type(e).__name__\n"
        "print(a[0], a[1], b, s, owner)\n"
    )
    out = compose("exec", "-T", "api", "python", "-c", script, check=False)
    expect(out.returncode == 0, "api: database login probe ran", out.stderr[-2000:])
    current, session, after_reset, superuser, owner = out.stdout.split()[-5:]
    expect(current == session == "dfirbench_app", "api logs in as dfirbench_app itself",
           out.stdout)
    expect(after_reset == "dfirbench_app", "RESET ROLE keeps the least-privilege role")
    expect(superuser == "False", "app login is not a superuser")
    expect(owner == "ProgrammingError", "SET ROLE to the owner is denied", owner)


# ------------------------------------------------------------------ 4. auth rate limit


def check_refresh_limit(api: Any) -> None:
    codes: list[int] = []
    retry_after = ""
    for _ in range(150):
        status, headers, _ = raw(f"{api.base}/auth/refresh", method="POST",
                                 body={"refresh_token": "x" * 40})
        codes.append(status)
        if status == 429:
            retry_after = headers.get("retry-after", "")
            break
    expect(429 in codes and set(codes[:-1]) <= {401}, "refresh limited per IP (401... then 429)",
           codes[-5:])
    expect(retry_after.isdigit(), "429 carries Retry-After", retry_after)
    rows = compose(
        "exec", "-T", "postgres", "psql", "-U", "dfir", "-d", "dfirbench", "-At", "-c",
        "SELECT count(*) FROM audit_log WHERE action = 'auth.rate_limited' "
        "AND ts > now() - interval '5 minutes'",
    ).stdout.strip()
    expect(int(rows or 0) >= 1, "rate limiting is audited", rows)


# ------------------------------------------------------------------ 5. metrics and headers


def check_metrics_and_headers(base: str, web: str, token: str) -> None:
    root = base.rsplit("/api/v1", 1)[0]
    status, _, _ = raw(f"{root}/metrics")
    expect(status == 401, "/metrics without the token: 401", status)
    status, _, _ = raw(f"{root}/metrics", {"Authorization": "Bearer wrong-token"})
    expect(status == 401, "/metrics with a wrong token: 401", status)
    status, headers, body = raw(f"{root}/metrics", {"Authorization": f"Bearer {token}"})
    text = body.decode("utf-8", "replace")
    expect(status == 200 and headers.get("content-type", "").startswith("text/plain"),
           "/metrics with the token: Prometheus text", status)
    for family in ("dfir_http_requests_total", "dfir_jobs", "dfir_queue_depth",
                   "dfir_custody_verification_failures", "dfir_events_ingested_1h"):
        expect(f"# TYPE {family}" in text, f"metrics family {family}")
    expect('dfir_metrics_section_up{section="queues"} 1' in text, "queue depth read from Redis")
    status, _, body = raw(f"{web}/metrics", {"Authorization": f"Bearer {token}"})
    expect(b"dfir_http_requests_total" not in body, "the web container does not serve /metrics",
           status)

    status, _, index = raw(f"{web}/")
    match = re.search(rb'src="(/assets/[^"]+\.js)"', index)
    expect(status == 200 and match is not None, "web index lists a script asset")
    assert match is not None
    for path in ("/", "/cases", match.group(1).decode(), "/api/v1/health", "/healthz"):
        status, headers, _ = raw(f"{web}{path}")
        missing = [h for h in HEADERS if h not in headers]
        expect(status == 200 and not missing, f"security headers on {path}", missing)
        expect("frame-ancestors 'none'" in headers["content-security-policy"],
               f"CSP forbids framing on {path}")


# ------------------------------------------------------------------ 6. integrity check


def check_integrity(case_id: str) -> None:
    out = compose("exec", "-T", "api", "python", "-m", "app.cli", "integrity-check", check=False)
    expect(out.returncode in (0, 1), "integrity-check ran (read-only)", out.stderr[-2000:])
    report = json.loads(out.stdout)
    expect(report["evidence_checked"] > 0 and report["objects_hashed"] > 0,
           "integrity-check verified chains and re-hashed originals",
           {k: report[k] for k in ("evidence_checked", "objects_hashed", "bytes_hashed")})
    ids = compose(
        "exec", "-T", "postgres", "psql", "-U", "dfir", "-d", "dfirbench", "-At", "-c",
        f"SELECT id FROM evidence WHERE case_id = '{case_id}'",
    ).stdout.split()
    mine = [p for p in report["problems"] if p.get("evidence_id") in ids]
    expect(ids and not mine, "this smoke's evidence is intact", mine)
    print(f"     integrity-check: {report['evidence_checked']} items, "
          f"{len(report['problems'])} known findings from earlier tamper demos")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--web", default="http://127.0.0.1:8080")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    parser.add_argument("--metrics-token", default=os.environ.get("METRICS_TOKEN"))
    args = parser.parse_args()
    expect(bool(args.metrics_token), "METRICS_TOKEN is set for the smoke")
    api = Api(args.base)
    check_sandbox_container()
    admin = login(api, args.admin_email, args.admin_password)
    case_id = check_sandboxed_parsing(api, admin)
    check_app_login()
    check_metrics_and_headers(api.base, args.web, args.metrics_token)
    check_integrity(case_id)
    check_refresh_limit(api)  # last: it uses up this address's refresh window
    print("PHASE 10 SMOKE PASSED")
    time.sleep(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
