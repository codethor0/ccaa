"""Adversarial tests for the preflight's numeric connection boundary.

DNS and sockets are mocked; no test contacts a real endpoint. These tests
exercise diagnostic probes, not a production HTTP/TLS action broker.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import ipaddress
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "agent_eval_preflight.py"
spec = importlib.util.spec_from_file_location("binding_preflight", MODULE_PATH)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)


class DestinationBindingTests(unittest.TestCase):
    def scope(self):
        return {
            "schema_version": "1", "evaluation_id": "binding-test",
            "run_epoch": 1, "policy_version": "p1",
            "valid_until_utc": "2099-01-01T00:00:00Z",
            "allowed_hosts": ["target.internal"],
            "allowed_cidrs": ["10.60.0.0/16", "fd00:60::/48"],
            "required_endpoints": [{"host": "target.internal", "ports": [443]}],
            "forbidden_endpoints": [],
            "image_digest": "sha256:test",
        }

    def bind(self, scope, resolved):
        results = []
        nets = pf.parse_networks(scope, results)
        with mock.patch.object(pf, "resolve_all", return_value=resolved):
            bindings = pf.check_scope_binding(scope, nets, results)
        return results, bindings

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all")
    def test_rebinding_cannot_change_required_probe_destination(self, resolve, factory):
        # The hypothetical second resolution is forbidden metadata. It must
        # never be requested or handed to connect after a valid first answer.
        resolve.side_effect = [
            {ipaddress.ip_address("10.60.0.2")},
            {ipaddress.ip_address("169.254.169.254")},
        ]
        factory.return_value.getpeername.return_value = ("10.60.0.2", 443)
        scope = self.scope()
        results = []
        nets = pf.parse_networks(scope, results)
        bindings = pf.check_scope_binding(scope, nets, results)
        with mock.patch.object(pf.socket, "getaddrinfo", side_effect=AssertionError("second DNS lookup")):
            pf.check_endpoints(scope, results, 1.0, bindings)
        resolve.assert_called_once_with("target.internal")
        factory.return_value.connect.assert_called_once_with(("10.60.0.2", 443))
        self.assertTrue(results[-1].passed)

    def test_legacy_hostname_check_does_not_bind_a_later_resolution(self):
        # Minimal negative trace: the unchanged name tells us nothing about
        # whether the next address equals the address policy just approved.
        answers = iter(("10.60.0.2", "169.254.169.254"))
        approved = ipaddress.ip_address(next(answers))
        connected = ipaddress.ip_address(next(answers))
        scope = ipaddress.ip_network("10.60.0.0/16")
        self.assertIn(approved, scope)
        self.assertNotIn(connected, scope)
        self.assertNotEqual(approved, connected)

    @mock.patch.object(pf.socket, "socket")
    def test_required_host_not_in_snapshot_never_connects(self, factory):
        scope = self.scope()
        scope["required_endpoints"][0]["host"] = "unapproved.internal"
        results, bindings = self.bind(scope, {ipaddress.ip_address("10.60.0.2")})
        pf.check_endpoints(scope, results, 1.0, bindings)
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    def test_mixed_ipv4_ipv6_answer_rejects_entire_binding(self, factory):
        scope = self.scope()
        results, bindings = self.bind(scope, {
            ipaddress.ip_address("10.60.0.2"),
            ipaddress.ip_address("2001:db8::2"),
        })
        pf.check_endpoints(scope, results, 1.0, bindings)
        self.assertEqual(bindings, {})
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    def test_empty_resolution_never_connects(self, factory):
        results, bindings = self.bind(self.scope(), set())
        pf.check_endpoints(self.scope(), results, 1.0, bindings)
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    def test_ipv6_probe_uses_numeric_sockaddr(self, factory):
        factory.return_value.getpeername.return_value = ("fd00:60::2", 443, 0, 0)
        results, bindings = self.bind(self.scope(), {ipaddress.ip_address("fd00:60::2")})
        with mock.patch.object(pf.socket, "getaddrinfo", side_effect=AssertionError("unexpected DNS")):
            pf.check_endpoints(self.scope(), results, 1.0, bindings)
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        factory.return_value.connect.assert_called_once_with(("fd00:60::2", 443, 0, 0))
        self.assertTrue(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    def test_address_fallback_uses_only_approved_snapshot(self, factory):
        first = mock.Mock()
        first.connect.side_effect = ConnectionRefusedError()
        second = mock.Mock()
        second.getpeername.return_value = ("fd00:60::2", 443, 0, 0)
        factory.side_effect = [first, second]
        results, bindings = self.bind(self.scope(), {
            ipaddress.ip_address("10.60.0.2"),
            ipaddress.ip_address("fd00:60::2"),
        })
        with mock.patch.object(pf, "resolve_all", side_effect=AssertionError("fallback DNS")):
            pf.check_endpoints(self.scope(), results, 1.0, bindings)
        first.connect.assert_called_once_with(("10.60.0.2", 443))
        second.connect.assert_called_once_with(("fd00:60::2", 443, 0, 0))
        first.close.assert_called_once()
        second.close.assert_called_once()
        self.assertTrue(results[-1].passed)

    @mock.patch.object(pf.socket, "getaddrinfo")
    def test_mapped_ipv6_is_checked_as_ipv4(self, resolve):
        resolve.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:169.254.169.254", 0, 0, 0))
        ]
        results = []
        nets = pf.parse_networks(self.scope(), results)
        bindings = pf.check_scope_binding(self.scope(), nets, results)
        self.assertEqual(bindings, {})
        self.assertFalse(results[-1].passed)
        self.assertIn("169.254.169.254", results[-1].detail)

    def test_scoped_ipv6_requires_an_interface_policy(self):
        with self.assertRaises(ValueError):
            pf.canonical_address("fe80::1%eth0")

    def forbidden_scope(self):
        scope = self.scope()
        scope["required_endpoints"] = []
        scope["forbidden_endpoints"] = [{
            "host": "probe.example", "ports": [443],
            "probe_cidrs": ["203.0.113.2/32"],
        }]
        return scope

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all")
    def test_forbidden_probe_requires_explicit_diagnostic_scope(self, resolve, factory):
        scope = self.forbidden_scope()
        del scope["forbidden_endpoints"][0]["probe_cidrs"]
        results = []
        pf.check_endpoints(scope, results, 1.0, {})
        resolve.assert_not_called()
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all")
    def test_forbidden_probe_rebinding_outside_diagnostic_scope_is_denied(self, resolve, factory):
        resolve.return_value = {ipaddress.ip_address("169.254.169.254")}
        results = []
        pf.check_endpoints(self.forbidden_scope(), results, 1.0, {})
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all", side_effect=socket.gaierror("no DNS answer"))
    def test_forbidden_dns_failure_is_not_evidence_of_blocked_egress(self, resolve, factory):
        results = []
        pf.check_endpoints(self.forbidden_scope(), results, 1.0, {})
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all")
    def test_forbidden_probe_connects_once_to_approved_numeric_address(self, resolve, factory):
        resolve.side_effect = [
            {ipaddress.ip_address("203.0.113.2")},
            {ipaddress.ip_address("169.254.169.254")},
        ]
        factory.return_value.connect.side_effect = ConnectionRefusedError()
        results = []
        pf.check_endpoints(self.forbidden_scope(), results, 1.0, {})
        resolve.assert_called_once()
        factory.return_value.connect.assert_called_once_with(("203.0.113.2", 443))
        self.assertTrue(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all", return_value={ipaddress.ip_address("203.0.113.2")})
    def test_reachable_forbidden_endpoint_fails_gate(self, resolve, factory):
        factory.return_value.getpeername.return_value = ("203.0.113.2", 443)
        results = []
        pf.check_endpoints(self.forbidden_scope(), results, 1.0, {})
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all", return_value={ipaddress.ip_address("203.0.113.2")})
    def test_peer_mismatch_is_not_a_successful_negative_probe(self, resolve, factory):
        factory.return_value.getpeername.return_value = ("169.254.169.254", 443)
        results = []
        pf.check_endpoints(self.forbidden_scope(), results, 1.0, {})
        self.assertFalse(results[-1].passed)
        self.assertIn("peer mismatch", results[-1].detail)
        factory.return_value.close.assert_called_once()

    @mock.patch.object(pf.socket, "socket")
    @mock.patch.object(pf, "resolve_all")
    def test_world_route_probe_scope_never_resolves_or_connects(self, resolve, factory):
        scope = self.forbidden_scope()
        scope["forbidden_endpoints"][0]["probe_cidrs"] = ["0.0.0.0/0"]
        results = []
        pf.check_endpoints(scope, results, 1.0, {})
        resolve.assert_not_called()
        factory.assert_not_called()
        self.assertFalse(results[-1].passed)

    @mock.patch.object(pf.socket, "socket")
    def test_invalid_ports_and_timeouts_never_connect(self, factory):
        for ports in ([True], [0], [65536], ["443"], []):
            with self.subTest(ports=ports):
                scope = self.scope()
                scope["required_endpoints"][0]["ports"] = ports
                results, bindings = self.bind(scope, {ipaddress.ip_address("10.60.0.2")})
                pf.check_endpoints(scope, results, 1.0, bindings)
                self.assertFalse(results[-1].passed)
        for timeout in (float("nan"), float("inf"), 0, -1, 31):
            self.assertIsNone(pf.endpoint_reachable((ipaddress.ip_address("10.60.0.2"),), 443, timeout)[0])
        factory.assert_not_called()

    @mock.patch.object(pf.socket, "socket")
    def test_literal_hosts_do_not_use_dns(self, factory):
        scope = self.scope()
        scope["allowed_hosts"] = ["10.60.0.2"]
        scope["required_endpoints"][0]["host"] = "10.60.0.2"
        factory.return_value.getpeername.return_value = ("10.60.0.2", 443)
        results = []
        with mock.patch.object(pf.socket, "getaddrinfo", side_effect=AssertionError("literal DNS")):
            nets = pf.parse_networks(scope, results)
            bindings = pf.check_scope_binding(scope, nets, results)
            pf.check_endpoints(scope, results, 1.0, bindings)
        self.assertTrue(results[-1].passed)

    def run_invalid_scope(self, scope, expected_digest):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "scope.json"
            path.write_text(json.dumps(scope))
            argv = ["preflight", str(path), "--expected-scope-sha256", expected_digest,
                    "--attestation", str(Path(td) / "attestation.json")]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(pf, "resolve_all") as resolve, \
                    mock.patch.object(pf.socket, "socket") as factory, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pf.main(), 2)
                resolve.assert_not_called()
                factory.assert_not_called()

    def test_digest_mismatch_skips_all_network_effects(self):
        self.run_invalid_scope(self.scope(), "0" * 64)

    def test_expired_scope_skips_all_network_effects(self):
        scope = self.scope()
        scope["valid_until_utc"] = "2000-01-01T00:00:00Z"
        digest = hashlib.sha256(json.dumps(scope).encode()).hexdigest()
        self.run_invalid_scope(scope, digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
