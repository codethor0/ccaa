#!/usr/bin/env python3
"""Fail-closed preflight validator for bounded cyber-agent evaluations.

This validator is deliberately conservative. It is a release gate, not a proof
of containment. It checks a signed-scope *digest supplied by a trusted
orchestrator*, validates local runtime posture and selected network invariants,
and emits a machine-readable attestation. Runtime containment still requires a
complete action broker, commit-time authorization, deny-by-default networking,
short-lived identity, immutable telemetry, and an independent kill path.

No third-party packages are required.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1"
PROXY_VARIABLES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)
SECRET_NAME_MARKERS = (
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY",
    "PRIVATE_KEY", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "KUBECONFIG",
    "CREDENTIAL", "BEARER", "COOKIE",
)
SECRET_VALUE_PREFIXES = (
    "AKIA", "ASIA", "ghp_", "github_pat_", "xoxb-", "xoxp-", "sk-",
    "-----BEGIN ",
)
DEFAULT_FORBIDDEN_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/root/.aws/credentials",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
)
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class Result:
    check: str
    passed: bool
    severity: str
    detail: str


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_utc(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    out = dt.datetime.fromisoformat(text)
    if out.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return out.astimezone(dt.timezone.utc)


def load_scope(path: Path) -> tuple[dict[str, Any], bytes, str]:
    raw = path.read_bytes()
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("scope root must be an object")
    return obj, raw, hashlib.sha256(raw).hexdigest()


def add(results: list[Result], check: str, passed: bool, severity: str, detail: str) -> None:
    results.append(Result(check, bool(passed), severity, detail))


def require_shape(scope: dict[str, Any], results: list[Result]) -> None:
    required = (
        "schema_version", "evaluation_id", "run_epoch", "policy_version",
        "valid_until_utc", "allowed_cidrs", "allowed_hosts",
    )
    missing = [k for k in required if k not in scope]
    add(results, "scope_schema", not missing, "CRITICAL",
        "complete" if not missing else "missing=" + ",".join(missing))
    add(results, "schema_version", scope.get("schema_version") == SCHEMA_VERSION,
        "CRITICAL", f"expected={SCHEMA_VERSION} actual={scope.get('schema_version')!r}")
    epoch = scope.get("run_epoch")
    add(results, "run_epoch", isinstance(epoch, int) and epoch >= 1,
        "CRITICAL", f"run_epoch={epoch!r}")
    policy = scope.get("policy_version")
    add(results, "policy_version", isinstance(policy, str) and bool(policy.strip()),
        "CRITICAL", f"policy_version={policy!r}")


def check_trusted_scope_digest(actual: str, expected: str, results: list[Result]) -> None:
    good_format = bool(HEX64.fullmatch(expected or ""))
    add(results, "trusted_scope_digest_format", good_format, "CRITICAL",
        "valid sha256" if good_format else "expected digest must be 64 hex characters")
    add(results, "trusted_scope_digest_match", good_format and actual.lower() == expected.lower(),
        "CRITICAL", f"actual={actual}")


def check_expiry(scope: dict[str, Any], now: dt.datetime, results: list[Result]) -> None:
    raw = scope.get("valid_until_utc")
    try:
        expiry = parse_utc(str(raw))
    except Exception as exc:
        add(results, "scope_expiry", False, "CRITICAL", f"invalid expiry: {exc}")
        return
    remaining = (expiry - now).total_seconds()
    add(results, "scope_expiry", remaining > 0, "CRITICAL",
        f"valid_until={expiry.isoformat()} remaining_seconds={int(remaining)}")


def parse_networks(scope: dict[str, Any], results: list[Result]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    invalid: list[str] = []
    for item in scope.get("allowed_cidrs", []):
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            invalid.append(str(item))
    add(results, "allowed_cidr_syntax", bool(networks) and not invalid, "CRITICAL",
        "valid" if networks and not invalid else "invalid=" + ",".join(invalid))
    broad = [str(n) for n in networks if n.prefixlen == 0]
    add(results, "deny_world_scope", not broad, "CRITICAL",
        "no world routes" if not broad else "overbroad=" + ",".join(broad))
    if not scope.get("allow_public_targets", False):
        public = [str(n) for n in networks if not (n.is_private or n.is_loopback or n.is_link_local)]
        add(results, "private_target_scope", not public, "CRITICAL",
            "all target CIDRs are private/local" if not public else "public=" + ",".join(public))
    return networks


def addr_allowed(addr: ipaddress._BaseAddress, nets: Iterable[ipaddress._BaseNetwork]) -> bool:
    return any(addr.version == n.version and addr in n for n in nets)


def resolve_all(host: str) -> set[ipaddress._BaseAddress]:
    out: set[ipaddress._BaseAddress] = set()
    for family, socktype, proto, canon, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        del family, socktype, proto, canon
        out.add(ipaddress.ip_address(sockaddr[0]))
    return out


def check_scope_binding(scope: dict[str, Any], nets: list[ipaddress._BaseNetwork], results: list[Result]) -> None:
    hosts = scope.get("allowed_hosts", [])
    add(results, "allowed_hosts_nonempty", isinstance(hosts, list) and bool(hosts), "CRITICAL",
        f"count={len(hosts) if isinstance(hosts, list) else 0}")
    for raw_host in hosts if isinstance(hosts, list) else []:
        host = str(raw_host).strip()
        if not host or "*" in host:
            add(results, f"scope_binding:{host or '<empty>'}", False, "CRITICAL", "wildcards/empty host forbidden")
            continue
        try:
            addresses = resolve_all(host)
        except socket.gaierror as exc:
            add(results, f"scope_binding:{host}", False, "CRITICAL", f"DNS failed: {exc}")
            continue
        outside = sorted(str(a) for a in addresses if not addr_allowed(a, nets))
        detail = "resolved=" + ",".join(sorted(str(a) for a in addresses))
        if outside:
            detail += " outside_scope=" + ",".join(outside)
        add(results, f"scope_binding:{host}", bool(addresses) and not outside, "CRITICAL", detail)


def endpoint_reachable(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return False, f"DNS failed: {exc}"
    errors: list[str] = []
    for family, socktype, proto, canon, sockaddr in infos:
        del canon
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return True, f"connected={sockaddr[0]}:{sockaddr[1]}"
        except OSError as exc:
            errors.append(f"{sockaddr[0]}:{sockaddr[1]} {exc.__class__.__name__}")
        finally:
            sock.close()
    return False, "; ".join(errors[:4]) or "unreachable"


def check_endpoints(scope: dict[str, Any], results: list[Result], timeout: float) -> None:
    for endpoint in scope.get("required_endpoints", []):
        host = str(endpoint.get("host", ""))
        for port in endpoint.get("ports", []):
            ok, detail = endpoint_reachable(host, int(port), timeout)
            add(results, f"required_endpoint:{host}:{port}", ok, "CRITICAL", detail)
    for endpoint in scope.get("forbidden_endpoints", []):
        host = str(endpoint.get("host", ""))
        for port in endpoint.get("ports", []):
            reachable, detail = endpoint_reachable(host, int(port), timeout)
            add(results, f"forbidden_endpoint:{host}:{port}", not reachable, "CRITICAL", detail)


def check_environment(scope: dict[str, Any], results: list[Result]) -> None:
    if scope.get("permit_proxy", False):
        add(results, "proxy_environment", True, "INFO", "proxy explicitly permitted")
    else:
        present = sorted(k for k in PROXY_VARIABLES if os.getenv(k))
        add(results, "proxy_environment", not present, "CRITICAL",
            "none" if not present else "present=" + ",".join(present))

    allow = set(map(str, scope.get("secret_name_allowlist", [])))
    suspicious_names = sorted(
        k for k in os.environ
        if k not in allow and any(marker in k.upper() for marker in SECRET_NAME_MARKERS)
    )
    add(results, "secret_bearing_environment_names", not suspicious_names, "CRITICAL",
        "none" if not suspicious_names else "names=" + ",".join(suspicious_names))

    suspicious_values: list[str] = []
    for k, v in os.environ.items():
        if k in allow:
            continue
        if any(v.startswith(prefix) for prefix in SECRET_VALUE_PREFIXES):
            suspicious_values.append(k)
    add(results, "secret_value_signatures", not suspicious_values, "CRITICAL",
        "none" if not suspicious_values else "variable_names=" + ",".join(sorted(suspicious_values)))


def check_local_paths(scope: dict[str, Any], results: list[Result]) -> None:
    forbidden = set(DEFAULT_FORBIDDEN_PATHS)
    forbidden.update(map(str, scope.get("forbidden_paths", [])))
    def _present(path: str) -> bool:
        try:
            return Path(path).exists()
        except PermissionError:
            return True  # fail closed: unverifiable path is treated as present

    present = sorted(p for p in forbidden if _present(p))
    add(results, "local_escape_and_credential_paths", not present, "CRITICAL",
        "none" if not present else "present=" + ",".join(present))

    if scope.get("require_non_root", True):
        if hasattr(os, "geteuid"):
            add(results, "non_root_execution", os.geteuid() != 0, "CRITICAL", f"euid={os.geteuid()}")
        else:
            add(results, "non_root_execution", False, "CRITICAL", "geteuid unavailable")


def proc_status() -> dict[str, str]:
    path = Path("/proc/self/status")
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def check_linux_hardening(scope: dict[str, Any], results: list[Result]) -> None:
    if not scope.get("require_linux_hardening", True):
        add(results, "linux_hardening", True, "INFO", "not required by scope")
        return
    status = proc_status()
    if not status:
        add(results, "linux_proc_status", False, "CRITICAL", "/proc/self/status unavailable")
        return
    cap_eff = status.get("CapEff", "")
    try:
        cap_zero = int(cap_eff, 16) == 0
    except ValueError:
        cap_zero = False
    add(results, "linux_effective_capabilities", cap_zero, "CRITICAL", f"CapEff={cap_eff}")
    nnp = status.get("NoNewPrivs", "")
    add(results, "linux_no_new_privileges", nnp == "1", "CRITICAL", f"NoNewPrivs={nnp}")
    seccomp = status.get("Seccomp", "")
    add(results, "linux_seccomp", seccomp == "2", "CRITICAL", f"Seccomp={seccomp}")


def check_image_digest(scope: dict[str, Any], running: str | None, results: list[Result]) -> None:
    expected = scope.get("image_digest")
    if expected is None:
        add(results, "image_digest_binding", False, "CRITICAL", "scope.image_digest missing")
        return
    if running is None:
        add(results, "image_digest_binding", False, "CRITICAL", "--running-image-digest required")
        return
    add(results, "image_digest_binding", str(expected) == running, "CRITICAL",
        f"expected={expected!r} running={running!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail-closed preflight for bounded cyber-agent evaluations")
    ap.add_argument("scope", type=Path)
    ap.add_argument("--expected-scope-sha256", required=True,
                    help="SHA-256 supplied from a trusted control-plane copy of the approved scope")
    ap.add_argument("--running-image-digest", default=None,
                    help="Runtime image digest supplied by the trusted orchestrator")
    ap.add_argument("--attestation", type=Path, default=Path("preflight-attestation.json"))
    args = ap.parse_args()

    try:
        scope, raw, scope_sha = load_scope(args.scope)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 2

    results: list[Result] = []
    require_shape(scope, results)
    check_trusted_scope_digest(scope_sha, args.expected_scope_sha256, results)
    check_expiry(scope, utc_now(), results)
    nets = parse_networks(scope, results)
    check_scope_binding(scope, nets, results)
    timeout = float(scope.get("connect_timeout_seconds", 1.5))
    check_endpoints(scope, results, timeout)
    check_environment(scope, results)
    check_local_paths(scope, results)
    check_linux_hardening(scope, results)
    check_image_digest(scope, args.running_image_digest, results)

    passed = all(r.passed for r in results if r.severity == "CRITICAL")
    attestation = {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now().isoformat(),
        "evaluation_id": scope.get("evaluation_id", "unknown"),
        "run_epoch": scope.get("run_epoch"),
        "policy_version": scope.get("policy_version"),
        "scope_file": str(args.scope),
        "scope_sha256": scope_sha,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "passed": passed,
        "results": [asdict(r) for r in results],
        "limitations": [
            "Negative endpoint probes do not prove absence of all egress.",
            "DNS results can change; the runtime broker must bind and revalidate the committed destination.",
            "Secret detection is heuristic and cannot prove absence of credentials.",
            "This process can be compromised with the workload; signature and image trust roots must remain outside it.",
        ],
    }
    args.attestation.parent.mkdir(parents=True, exist_ok=True)
    args.attestation.write_text(json.dumps(attestation, indent=2) + "\n")
    print(json.dumps(attestation, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
