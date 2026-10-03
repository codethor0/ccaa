#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "agent_eval_preflight.py"
spec = importlib.util.spec_from_file_location("preflight", MODULE_PATH)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)


class PreflightTests(unittest.TestCase):
    def base_scope(self):
        return {
            "schema_version": "1",
            "evaluation_id": "eval-1",
            "run_epoch": 2,
            "policy_version": "p1",
            "valid_until_utc": "2099-01-01T00:00:00Z",
            "image_digest": "sha256:image",
            "allowed_cidrs": ["10.60.0.0/16"],
            "allowed_hosts": ["target.internal"],
            "required_endpoints": [],
            "forbidden_endpoints": [],
            "permit_proxy": False,
            "allow_public_targets": False,
            "require_non_root": True,
            "require_linux_hardening": True,
        }

    def test_parse_utc_requires_offset(self):
        with self.assertRaises(ValueError):
            pf.parse_utc("2026-10-02T12:00:00")

    def test_expired_scope_fails(self):
        scope = self.base_scope()
        scope["valid_until_utc"] = "2026-01-01T00:00:00Z"
        results = []
        pf.check_expiry(scope, dt.datetime(2026, 10, 2, tzinfo=dt.timezone.utc), results)
        self.assertFalse(results[-1].passed)

    def test_world_route_fails(self):
        scope = self.base_scope()
        scope["allowed_cidrs"] = ["0.0.0.0/0"]
        results = []
        pf.parse_networks(scope, results)
        self.assertFalse(next(r for r in results if r.check == "deny_world_scope").passed)

    def test_public_scope_fails_when_disallowed(self):
        scope = self.base_scope()
        scope["allowed_cidrs"] = ["8.8.8.0/24"]
        results = []
        pf.parse_networks(scope, results)
        self.assertFalse(next(r for r in results if r.check == "private_target_scope").passed)

    def test_scope_digest_mismatch_fails(self):
        results = []
        pf.check_trusted_scope_digest("a" * 64, "b" * 64, results)
        self.assertFalse(next(r for r in results if r.check == "trusted_scope_digest_match").passed)

    def test_wildcard_host_fails_binding(self):
        scope = self.base_scope()
        scope["allowed_hosts"] = ["*.internal"]
        results = []
        nets = pf.parse_networks(scope, results)
        pf.check_scope_binding(scope, nets, results)
        self.assertFalse(next(r for r in results if r.check.startswith("scope_binding:")).passed)

    @mock.patch.object(pf, "resolve_all")
    def test_dns_outside_cidr_fails(self, resolve):
        resolve.return_value = {pf.ipaddress.ip_address("203.0.113.5")}
        scope = self.base_scope()
        results = []
        nets = pf.parse_networks(scope, results)
        pf.check_scope_binding(scope, nets, results)
        self.assertFalse(next(r for r in results if r.check == "scope_binding:target.internal").passed)

    def test_required_non_root_is_critical(self):
        scope = self.base_scope()
        results = []
        with mock.patch.object(pf.os, "geteuid", return_value=0):
            pf.check_local_paths(scope, results)
        item = next(r for r in results if r.check == "non_root_execution")
        self.assertEqual(item.severity, "CRITICAL")
        self.assertFalse(item.passed)

    @mock.patch.object(pf, "proc_status")
    def test_linux_hardening_passes_expected_posture(self, status):
        status.return_value = {
            "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000", "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2",
            "Seccomp_filters": "1",
        }
        results = []
        pf.check_linux_hardening(self.base_scope(), results)
        self.assertTrue(all(r.passed for r in results))

    @mock.patch.object(pf, "proc_status")
    def test_linux_capability_fails(self, status):
        status.return_value = {
            "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
            "CapEff": "0000000000000001", "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2",
            "Seccomp_filters": "1",
        }
        results = []
        pf.check_linux_hardening(self.base_scope(), results)
        self.assertFalse(next(r for r in results if r.check == "linux_effective_capabilities").passed)

    @mock.patch.object(pf, "proc_status")
    def test_linux_bounding_capability_fails(self, status):
        status.return_value = {
            "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000", "CapBnd": "0000000000000001",
            "CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2",
            "Seccomp_filters": "1",
        }
        results = []
        pf.check_linux_hardening(self.base_scope(), results)
        self.assertFalse(next(r for r in results if r.check == "linux_all_capability_sets_zero").passed)

    @mock.patch.object(pf, "proc_status")
    def test_linux_seccomp_filter_count_required(self, status):
        status.return_value = {
            "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000", "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000", "NoNewPrivs": "1", "Seccomp": "2",
            "Seccomp_filters": "0",
        }
        results = []
        pf.check_linux_hardening(self.base_scope(), results)
        self.assertFalse(next(r for r in results if r.check == "linux_seccomp_filter_count").passed)

    def test_linux_hardening_docstring_states_observation_not_simulation(self):
        self.assertIn("do not simulate", pf.check_linux_hardening.__doc__)

    def test_image_digest_binding(self):
        results = []
        pf.check_image_digest(self.base_scope(), "sha256:image", results)
        self.assertTrue(results[-1].passed)

    def test_load_scope_hash(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scope.json"
            p.write_text(json.dumps(self.base_scope(), sort_keys=True))
            obj, raw, digest = pf.load_scope(p)
            self.assertEqual(obj["evaluation_id"], "eval-1")
            self.assertEqual(len(digest), 64)
            self.assertEqual(pf.hashlib.sha256(raw).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
