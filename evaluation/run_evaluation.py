#!/usr/bin/env python3
"""Controlled integration and microbenchmark for the CCAA reference artifacts.

The experiment is intentionally local and non-destructive. It does not contact
public targets and it does not claim production validation or complete
mediation. Results are written to evaluation/results.json.
"""
from __future__ import annotations

import importlib.util
import tempfile
import shutil
import json
import os
import platform
import resource
import socket
import statistics
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pf = load_module("eval_preflight", ROOT / "scripts" / "agent_eval_preflight.py")
ca = load_module("eval_commit_authorization", ROOT / "scripts" / "commit_authorization.py")


def percentiles_ns(samples: list[int]) -> dict[str, float]:
    s = sorted(samples)
    def pct(p: float) -> int:
        idx = max(0, min(len(s) - 1, int(round((len(s) - 1) * p))))
        return s[idx]
    return {
        "n": len(s),
        "median_us": round(statistics.median(s) / 1000.0, 3),
        "mean_us": round(statistics.fmean(s) / 1000.0, 3),
        "stdev_us": round(statistics.pstdev(s) / 1000.0, 3),
        "p95_us": round(pct(0.95) / 1000.0, 3),
        "p99_us": round(pct(0.99) / 1000.0, 3),
    }


def proc_subset(status: dict[str, str]) -> dict[str, str | None]:
    names = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters")
    return {name: status.get(name) for name in names}


def child_posture(prefix: list[str]) -> dict[str, object]:
    code = r'''
import json
from pathlib import Path
names=("CapInh","CapPrm","CapEff","CapBnd","CapAmb","NoNewPrivs","Seccomp","Seccomp_filters")
out={}
for line in Path("/proc/self/status").read_text().splitlines():
    if ":" in line:
        k,v=line.split(":",1)
        if k in names: out[k]=v.strip()
print(json.dumps(out,sort_keys=True))
'''
    proc = subprocess.run(prefix + [sys.executable, "-c", code], text=True, capture_output=True, timeout=10)
    return {
        "returncode": proc.returncode,
        "status": json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout.strip() else None,
        "stderr": proc.stderr.strip(),
    }


def live_loopback_probe() -> dict[str, object]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted: list[tuple[str, int]] = []
    def serve():
        conn, peer = listener.accept()
        accepted.append(peer)
        conn.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    reachable, detail = pf.endpoint_reachable((pf.ipaddress.ip_address("127.0.0.1"),), port, 2.0)
    t.join(2.0)
    listener.close()
    addrs = sorted(str(a) for a in pf.resolve_all("localhost"))
    return {
        "localhost_addresses": addrs,
        "all_loopback": all(pf.canonical_address(a).is_loopback for a in addrs),
        "numeric_probe_reachable": reachable,
        "numeric_probe_detail": detail,
        "accepted_connections": len(accepted),
    }



def _cpu_model() -> str:
    try:
        for line in Path('/proc/cpuinfo').read_text(errors='replace').splitlines():
            if line.lower().startswith('model name') and ':' in line:
                return line.split(':', 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def _memory_total_kib() -> int | None:
    try:
        for line in Path('/proc/meminfo').read_text(errors='replace').splitlines():
            if line.startswith('MemTotal:'):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def seccomp_socket_block_experiment() -> dict[str, object]:
    child = r'''import ctypes, ctypes.util, errno, json, socket
from pathlib import Path
libpath = ctypes.util.find_library("seccomp")
if not libpath:
    print(json.dumps({"supported": False, "reason": "libseccomp not found"}))
    raise SystemExit(0)
lib = ctypes.CDLL(libpath, use_errno=True)
lib.seccomp_init.argtypes = [ctypes.c_uint32]
lib.seccomp_init.restype = ctypes.c_void_p
lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
lib.seccomp_rule_add.restype = ctypes.c_int
lib.seccomp_load.argtypes = [ctypes.c_void_p]
lib.seccomp_load.restype = ctypes.c_int
lib.seccomp_release.argtypes = [ctypes.c_void_p]
ALLOW = 0x7fff0000
ERRNO_EPERM = 0x00050000 | errno.EPERM
ctx = lib.seccomp_init(ALLOW)
if not ctx:
    print(json.dumps({"supported": False, "reason": "seccomp_init failed"}))
    raise SystemExit(0)
try:
    nr = lib.seccomp_syscall_resolve_name(b"socket")
    if nr < 0:
        print(json.dumps({"supported": False, "reason": "socket syscall unresolved"}))
        raise SystemExit(0)
    rc = lib.seccomp_rule_add(ctx, ERRNO_EPERM, nr, 0)
    if rc != 0:
        print(json.dumps({"supported": False, "reason": "seccomp_rule_add=" + str(rc)}))
        raise SystemExit(0)
    rc = lib.seccomp_load(ctx)
    if rc != 0:
        print(json.dumps({"supported": False, "reason": "seccomp_load=" + str(rc)}))
        raise SystemExit(0)
    names = {"NoNewPrivs", "Seccomp", "Seccomp_filters"}
    status = {}
    for line in Path("/proc/self/status").read_text(errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k in names:
                status[k] = v.strip()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.close()
        blocked = False
        socket_errno = None
    except OSError as exc:
        blocked = exc.errno == errno.EPERM
        socket_errno = exc.errno
    print(json.dumps({"supported": True, "status": status, "socket_blocked": blocked, "socket_errno": socket_errno}, sort_keys=True))
finally:
    lib.seccomp_release(ctx)
'''
    proc = subprocess.run([sys.executable, '-c', child], text=True, capture_output=True, timeout=10)
    try:
        payload = json.loads(proc.stdout.strip()) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        payload = {'supported': False, 'reason': 'invalid child JSON'}
    payload.update({'returncode': proc.returncode, 'stderr': proc.stderr.strip()})
    return payload


def cross_run_filesystem_isolation() -> dict[str, object]:
    if os.geteuid() != 0 or not shutil.which('setpriv'):
        return {'supported': False, 'reason': 'requires root plus setpriv in controlled build environment'}
    with tempfile.TemporaryDirectory(prefix='ccaa-cross-run-') as td:
        root = Path(td)
        root.chmod(0o711)
        uids = (65533, 65534)
        dirs = []
        for idx, uid in enumerate(uids):
            d = root / f'run-{idx}'
            d.mkdir(mode=0o700)
            f = d / 'artifact.txt'
            f.write_text(f'run-{idx}-secret\n')
            os.chown(d, uid, uid)
            os.chown(f, uid, uid)
            d.chmod(0o700)
            f.chmod(0o600)
            dirs.append(d)
        child = r'''import json, pathlib, sys
own = pathlib.Path(sys.argv[1])
other = pathlib.Path(sys.argv[2])
out = {"own_read": False, "other_read": False, "other_error": None}
try:
    own.read_text()
    out["own_read"] = True
except Exception as exc:
    out["own_error"] = type(exc).__name__
try:
    other.read_text()
    out["other_read"] = True
except Exception as exc:
    out["other_error"] = type(exc).__name__
print(json.dumps(out, sort_keys=True))
'''
        rows = []
        for idx, uid in enumerate(uids):
            proc = subprocess.run([
                'setpriv', f'--reuid={uid}', f'--regid={uid}', '--clear-groups', '--no-new-privs',
                sys.executable, '-c', child, str(dirs[idx] / 'artifact.txt'), str(dirs[1-idx] / 'artifact.txt')
            ], text=True, capture_output=True, timeout=10)
            row = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout.strip() else {}
            row.update({'uid': uid, 'returncode': proc.returncode, 'stderr': proc.stderr.strip()})
            rows.append(row)
        passed = all(r.get('own_read') is True and r.get('other_read') is False for r in rows)
        return {'supported': True, 'passed': passed, 'runs': rows}

def token_fixture():
    key = bytes(range(32))
    request = {
        "operation": "network_connect",
        "resource": "https://target.internal/resource",
        "protocol": "https",
        "parameters": {"method": "GET"},
        "data_class": "public",
        "purpose": "bounded-evaluation",
        "run_id": "run-eval",
        "coordination_domain": "domain-a",
    }
    binding = {
        "origin": "https://target.internal:443",
        "address_family": 4,
        "numeric_address": "10.60.0.2",
        "port": 443,
        "transport": "tcp",
        "service_identity_rule": "dns:target.internal",
        "route": "direct",
        "lease_epoch": 1,
    }
    state = {
        "run_epoch": 1,
        "scope_digest": "a" * 64,
        "policy_version": "policy-1",
        "generation": 1,
        "budget_digest": "b" * 64,
        "revocation_epoch": 1,
    }
    return key, request, binding, state


def token_benchmark(iterations: int = 2000) -> dict[str, object]:
    key, request, binding, state = token_fixture()
    issue_samples: list[int] = []
    verify_samples: list[int] = []
    commit_samples: list[int] = []
    now = 1_800_000_000
    for i in range(iterations):
        jti = f"{i:032x}"
        t0 = time.perf_counter_ns()
        token = ca.issue_token(key=key, kid="k1", issuer="control", request=request,
                               binding=binding, state=state, now=now, ttl_seconds=60, jti=jti)
        issue_samples.append(time.perf_counter_ns() - t0)
        ctx = ca.VerificationContext(state=dict(state), expected_kid="k1", expected_issuer="control", now=now + 1)
        t0 = time.perf_counter_ns()
        ca.verify_token(token=token, key=key, request=request, binding=binding, context=ctx)
        verify_samples.append(time.perf_counter_ns() - t0)
        gate = ca.AtomicCommitGate(key=key, kid="k1", issuer="control", state=dict(state),
                                   policy=lambda _s, _r, _b: True)
        t0 = time.perf_counter_ns()
        gate.commit(token=token, request=request, binding=binding, callback=lambda: None, now=now + 1)
        commit_samples.append(time.perf_counter_ns() - t0)
    return {
        "iterations": iterations,
        "issue": percentiles_ns(issue_samples),
        "verify": percentiles_ns(verify_samples),
        "atomic_gate_verify_policy_replay_consume_callback": percentiles_ns(commit_samples),
    }


def replay_concurrency_stress(rounds: int = 200, workers: int = 8) -> dict[str, object]:
    key, request, binding, state = token_fixture()
    now = 1_800_000_000
    failures = 0
    total_commits = 0
    for r in range(rounds):
        gate = ca.AtomicCommitGate(key=key, kid="k1", issuer="control", state=dict(state),
                                   policy=lambda _s, _r, _b: True)
        token = ca.issue_token(key=key, kid="k1", issuer="control", request=request,
                               binding=binding, state=state, now=now, ttl_seconds=60,
                               jti=f"{r:032x}")
        barrier = threading.Barrier(workers)
        commits = []
        def worker(_):
            barrier.wait()
            try:
                gate.commit(token=token, request=request, binding=binding,
                            callback=lambda: commits.append(1), now=now + 1)
            except ca.TokenError:
                pass
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(worker, range(workers)))
        total_commits += len(commits)
        if len(commits) != 1:
            failures += 1
    return {
        "rounds": rounds,
        "workers_per_round": workers,
        "expected_commits": rounds,
        "actual_commits": total_commits,
        "rounds_with_invariant_failure": failures,
    }


def count_tests() -> int:
    return unittest.defaultTestLoader.discover(str(ROOT / "tests")).countTestCases()


def main() -> int:
    current = proc_subset(pf.proc_status())
    setpriv = child_posture([
        "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
        "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
    ])
    isolated = child_posture([
        "unshare", "-Urn", "setpriv",
        "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
    ])
    result = {
        "schema_version": "1",
        "purpose": "controlled local integration and reference-artifact characterization; not production validation",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_model": _cpu_model(),
            "cpu_count": os.cpu_count(),
            "memory_total_kib": _memory_total_kib(),
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "test_suite": {"discovered_tests": count_tests()},
        "live_loopback": live_loopback_probe(),
        "linux_posture": {
            "current_process": current,
            "capability_dropped_no_new_privs_child": setpriv,
            "user_and_network_namespace_plus_capability_drop_child": isolated,
            "interpretation": "Observed /proc posture only. Seccomp flags are observed, not simulated; these profiles do not establish complete mediation.",
        },
        "token_microbenchmark": token_benchmark(),
        "replay_concurrency_stress": replay_concurrency_stress(),
        "seccomp_socket_block": seccomp_socket_block_experiment(),
        "cross_run_filesystem_isolation": cross_run_filesystem_isolation(),
        "limitations": [
            "No public target is contacted.",
            "The process profiles are controlled Linux process experiments, not three production container deployments.",
            "The preflight validator observes seccomp posture but does not infer policy semantics; the separate seccomp experiment proves only that one child filter denied socket() in this environment.",
            "The cross-run filesystem experiment covers one local Linux DAC substrate only; it does not establish public-cloud or shared-service isolation.",
            "AtomicCommitGate demonstrates in-process serialization only; it is not an OS reference monitor.",
        ],
    }
    out = ROOT / "evaluation" / "results.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
