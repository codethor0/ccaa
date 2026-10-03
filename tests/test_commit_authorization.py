#!/usr/bin/env python3
from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import importlib.util
import sys

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "commit_authorization.py"
spec = importlib.util.spec_from_file_location("commit_authorization", MODULE_PATH)
assert spec and spec.loader
ca = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ca
spec.loader.exec_module(ca)


class CommitAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.kid = "test-key-1"
        self.issuer = "ccaa-control-plane"
        self.now = 1_800_000_000
        self.request = {
            "operation": "network_connect",
            "resource": "https://target.internal/resource",
            "protocol": "https",
            "parameters": {"method": "GET"},
            "data_class": "public",
            "purpose": "bounded-evaluation",
            "run_id": "run-123",
            "coordination_domain": "domain-a",
        }
        self.binding = {
            "origin": "https://target.internal:443",
            "address_family": 4,
            "numeric_address": "10.60.0.2",
            "port": 443,
            "transport": "tcp",
            "service_identity_rule": "dns:target.internal",
            "route": "direct",
            "lease_epoch": 7,
        }
        self.state = {
            "run_epoch": 9,
            "scope_digest": "a" * 64,
            "policy_version": "policy-9",
            "generation": 14,
            "budget_digest": "b" * 64,
            "revocation_epoch": 3,
        }

    def issue(self, **kwargs):
        args = dict(
            key=self.key,
            kid=self.kid,
            issuer=self.issuer,
            request=self.request,
            binding=self.binding,
            state=self.state,
            now=self.now,
            ttl_seconds=60,
            jti="0123456789abcdef0123456789abcdef",
        )
        args.update(kwargs)
        return ca.issue_token(**args)

    def context(self, **kwargs):
        args = dict(
            state=dict(self.state),
            expected_kid=self.kid,
            expected_issuer=self.issuer,
            now=self.now + 1,
            clock_skew_seconds=5,
        )
        args.update(kwargs)
        return ca.VerificationContext(**args)

    def verify(self, token=None, **kwargs):
        args = dict(
            token=self.issue() if token is None else token,
            key=self.key,
            request=self.request,
            binding=self.binding,
            context=self.context(),
        )
        args.update(kwargs)
        return ca.verify_token(**args)

    def test_canonical_json_is_order_independent_for_objects(self):
        self.assertEqual(ca.canonical_json_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_canonical_json_preserves_array_order(self):
        self.assertNotEqual(ca.canonical_json_bytes([1, 2]), ca.canonical_json_bytes([2, 1]))

    def test_canonical_json_rejects_float(self):
        with self.assertRaises(ca.TokenError):
            ca.canonical_json_bytes({"x": 1.0})

    def test_canonical_json_rejects_non_string_key(self):
        with self.assertRaises(ca.TokenError):
            ca.canonical_json_bytes({1: "x"})

    def test_canonical_loads_rejects_duplicate_keys(self):
        with self.assertRaises(ca.TokenError):
            ca.canonical_loads(b'{"a":1,"a":2}')

    def test_canonical_loads_rejects_whitespace_noncanonical_form(self):
        with self.assertRaises(ca.TokenError):
            ca.canonical_loads(b'{"a": 1}')

    def test_request_requires_exact_fields(self):
        bad = dict(self.request)
        bad.pop("purpose")
        with self.assertRaises(ca.TokenError):
            ca.normalize_request(bad)

    def test_request_rejects_unknown_field(self):
        bad = dict(self.request, extra="x")
        with self.assertRaises(ca.TokenError):
            ca.normalize_request(bad)

    def test_binding_requires_exact_fields(self):
        bad = dict(self.binding)
        bad.pop("route")
        with self.assertRaises(ca.TokenError):
            ca.normalize_binding(bad)

    def test_binding_rejects_invalid_address_family(self):
        bad = dict(self.binding, address_family=5)
        with self.assertRaises(ca.TokenError):
            ca.normalize_binding(bad)

    def test_binding_rejects_boolean_port(self):
        bad = dict(self.binding, port=True)
        with self.assertRaises(ca.TokenError):
            ca.normalize_binding(bad)

    def test_binding_rejects_out_of_range_port(self):
        bad = dict(self.binding, port=65536)
        with self.assertRaises(ca.TokenError):
            ca.normalize_binding(bad)

    def test_issue_rejects_short_key(self):
        with self.assertRaises(ca.TokenError):
            self.issue(key=b"x" * 31)

    def test_issue_rejects_empty_kid(self):
        with self.assertRaises(ca.TokenError):
            self.issue(kid="")

    def test_issue_rejects_empty_issuer(self):
        with self.assertRaises(ca.TokenError):
            self.issue(issuer="")

    def test_issue_rejects_zero_ttl(self):
        with self.assertRaises(ca.TokenError):
            self.issue(ttl_seconds=0)

    def test_issue_rejects_excessive_ttl(self):
        with self.assertRaises(ca.TokenError):
            self.issue(ttl_seconds=ca.MAX_TTL_SECONDS + 1)

    def test_issue_rejects_short_jti(self):
        with self.assertRaises(ca.TokenError):
            self.issue(jti="short")

    def test_issue_and_verify_success(self):
        payload = self.verify()
        self.assertEqual(payload["domain"], ca.DOMAIN)
        self.assertEqual(payload["request_hash"], ca.digest_obj(self.request))
        self.assertEqual(payload["binding_hash"], ca.digest_obj(self.binding))

    def test_token_is_canonical_json(self):
        token = self.issue()
        self.assertEqual(ca.canonical_json_bytes(json.loads(token)).decode(), token)

    def test_mac_tamper_rejected(self):
        obj = json.loads(self.issue())
        obj["mac"] = "0" * 64
        token = ca.canonical_json_bytes(obj).decode()
        with self.assertRaisesRegex(ca.TokenError, "MAC"):
            self.verify(token)

    def test_wrong_key_rejected(self):
        with self.assertRaisesRegex(ca.TokenError, "MAC"):
            self.verify(key=b"z" * 32)

    def test_wrong_domain_rejected_even_with_valid_mac(self):
        obj = json.loads(self.issue())
        obj["payload"]["domain"] = "other-domain"
        obj["mac"] = ca._mac(self.key, obj["payload"])
        with self.assertRaisesRegex(ca.TokenError, "domain"):
            self.verify(ca.canonical_json_bytes(obj).decode())

    def test_unknown_algorithm_rejected_even_with_valid_mac(self):
        obj = json.loads(self.issue())
        obj["payload"]["alg"] = "HMAC-SHA1"
        obj["mac"] = ca._mac(self.key, obj["payload"])
        with self.assertRaisesRegex(ca.TokenError, "algorithm"):
            self.verify(ca.canonical_json_bytes(obj).decode())

    def test_wrong_kid_rejected(self):
        with self.assertRaisesRegex(ca.TokenError, "key identifier"):
            self.verify(context=self.context(expected_kid="other"))

    def test_wrong_issuer_rejected(self):
        with self.assertRaisesRegex(ca.TokenError, "issuer"):
            self.verify(context=self.context(expected_issuer="other"))

    def test_future_iat_rejected(self):
        token = self.issue(now=self.now + 100)
        with self.assertRaisesRegex(ca.TokenError, "future"):
            self.verify(token, context=self.context(now=self.now))

    def test_expired_token_rejected(self):
        token = self.issue(ttl_seconds=10)
        with self.assertRaisesRegex(ca.TokenError, "expired"):
            self.verify(token, context=self.context(now=self.now + 20, clock_skew_seconds=0))

    def test_clock_skew_is_explicit(self):
        token = self.issue(ttl_seconds=10)
        payload = self.verify(token, context=self.context(now=self.now + 12, clock_skew_seconds=5))
        self.assertEqual(payload["exp"], self.now + 10)

    def test_negative_clock_skew_rejected(self):
        with self.assertRaisesRegex(ca.TokenError, "clock skew"):
            self.verify(context=self.context(clock_skew_seconds=-1))

    def test_request_substitution_rejected(self):
        req = dict(self.request, resource="https://other.internal/")
        with self.assertRaisesRegex(ca.TokenError, "request binding"):
            self.verify(request=req)

    def test_destination_ip_substitution_rejected(self):
        binding = dict(self.binding, numeric_address="169.254.169.254")
        with self.assertRaisesRegex(ca.TokenError, "destination binding"):
            self.verify(binding=binding)

    def test_destination_port_substitution_rejected(self):
        binding = dict(self.binding, port=8443)
        with self.assertRaisesRegex(ca.TokenError, "destination binding"):
            self.verify(binding=binding)

    def test_route_substitution_rejected(self):
        binding = dict(self.binding, route="proxy:egress-1")
        with self.assertRaisesRegex(ca.TokenError, "destination binding"):
            self.verify(binding=binding)

    def test_service_identity_substitution_rejected(self):
        binding = dict(self.binding, service_identity_rule="dns:other.internal")
        with self.assertRaisesRegex(ca.TokenError, "destination binding"):
            self.verify(binding=binding)

    def test_lease_epoch_substitution_rejected(self):
        binding = dict(self.binding, lease_epoch=8)
        with self.assertRaisesRegex(ca.TokenError, "destination binding"):
            self.verify(binding=binding)

    def test_state_field_mismatches_fail_closed(self):
        for field, value in (
            ("run_epoch", 10),
            ("scope_digest", "c" * 64),
            ("policy_version", "policy-10"),
            ("generation", 15),
            ("budget_digest", "d" * 64),
            ("revocation_epoch", 4),
        ):
            with self.subTest(field=field):
                state = dict(self.state)
                state[field] = value
                with self.assertRaisesRegex(ca.TokenError, f"state mismatch: {field}"):
                    self.verify(context=self.context(state=state))

    def test_jti_revocation_rejected(self):
        token = self.issue()
        jti = json.loads(token)["payload"]["jti"]
        with self.assertRaisesRegex(ca.TokenError, "identifier revoked"):
            self.verify(token, context=self.context(revoked_jti={jti}))

    def test_token_digest_revocation_rejected(self):
        token = self.issue()
        digest = ca.token_digest(token)
        with self.assertRaisesRegex(ca.TokenError, "digest revoked"):
            self.verify(token, context=self.context(revoked_token_digests={digest}))

    def test_missing_token_field_rejected(self):
        obj = json.loads(self.issue())
        obj["payload"].pop("jti")
        obj["mac"] = ca._mac(self.key, obj["payload"])
        with self.assertRaisesRegex(ca.TokenError, "missing or unknown"):
            ca.parse_token(ca.canonical_json_bytes(obj).decode())

    def test_extra_token_field_rejected(self):
        obj = json.loads(self.issue())
        obj["payload"]["extra"] = "x"
        obj["mac"] = ca._mac(self.key, obj["payload"])
        with self.assertRaisesRegex(ca.TokenError, "missing or unknown"):
            ca.parse_token(ca.canonical_json_bytes(obj).decode())

    def test_truncated_mac_rejected(self):
        obj = json.loads(self.issue())
        obj["mac"] = obj["mac"][:-2]
        with self.assertRaisesRegex(ca.TokenError, "64 hexadecimal"):
            ca.parse_token(ca.canonical_json_bytes(obj).decode())

    def test_invalid_exp_order_rejected(self):
        obj = json.loads(self.issue())
        obj["payload"]["exp"] = obj["payload"]["iat"]
        obj["mac"] = ca._mac(self.key, obj["payload"])
        with self.assertRaisesRegex(ca.TokenError, "greater"):
            ca.parse_token(ca.canonical_json_bytes(obj).decode())

    def test_replay_cache_rejects_second_consume(self):
        cache = ca.ReplayCache()
        cache.consume("0123456789abcdef")
        with self.assertRaisesRegex(ca.TokenError, "replay"):
            cache.consume("0123456789abcdef")

    def make_gate(self, policy=None):
        return ca.AtomicCommitGate(
            key=self.key,
            kid=self.kid,
            issuer=self.issuer,
            state=dict(self.state),
            policy=(policy if policy is not None else lambda state, req, binding: True),
        )

    def test_atomic_gate_commits_valid_callback(self):
        gate = self.make_gate()
        calls = []
        out = gate.commit(
            token=self.issue(), request=self.request, binding=self.binding,
            callback=lambda: calls.append("committed") or 42, now=self.now + 1,
        )
        self.assertEqual(out, 42)
        self.assertEqual(calls, ["committed"])

    def test_atomic_gate_policy_denial_prevents_callback(self):
        gate = self.make_gate(policy=lambda state, req, binding: False)
        called = False
        def callback():
            nonlocal called
            called = True
        with self.assertRaisesRegex(ca.TokenError, "policy denies"):
            gate.commit(token=self.issue(), request=self.request, binding=self.binding,
                        callback=callback, now=self.now + 1)
        self.assertFalse(called)

    def test_atomic_gate_rejects_replay(self):
        gate = self.make_gate()
        token = self.issue()
        gate.commit(token=token, request=self.request, binding=self.binding,
                    callback=lambda: True, now=self.now + 1)
        with self.assertRaisesRegex(ca.TokenError, "replay"):
            gate.commit(token=token, request=self.request, binding=self.binding,
                        callback=lambda: True, now=self.now + 1)

    def test_atomic_gate_state_change_invalidates_old_token(self):
        gate = self.make_gate()
        token = self.issue()
        gate.update_state(generation=self.state["generation"] + 1)
        with self.assertRaisesRegex(ca.TokenError, "generation"):
            gate.commit(token=token, request=self.request, binding=self.binding,
                        callback=lambda: True, now=self.now + 1)

    def test_atomic_gate_budget_change_invalidates_old_token(self):
        gate = self.make_gate()
        token = self.issue()
        gate.update_state(budget_digest="f" * 64)
        with self.assertRaisesRegex(ca.TokenError, "budget_digest"):
            gate.commit(token=token, request=self.request, binding=self.binding,
                        callback=lambda: True, now=self.now + 1)

    def test_atomic_gate_two_threads_same_authorization_only_one_commits(self):
        gate = self.make_gate()
        token = self.issue()
        barrier = threading.Barrier(2)
        commits = []
        errors = []
        def worker():
            barrier.wait()
            try:
                gate.commit(token=token, request=self.request, binding=self.binding,
                            callback=lambda: commits.append(1), now=self.now + 1)
            except ca.TokenError as exc:
                errors.append(str(exc))
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("replay", errors[0])

    def test_atomic_gate_distinct_authorizations_can_commit(self):
        gate = self.make_gate()
        for jti in ("a" * 32, "b" * 32):
            token = self.issue(jti=jti)
            self.assertTrue(gate.commit(token=token, request=self.request, binding=self.binding,
                                        callback=lambda: True, now=self.now + 1))

    def test_token_digest_changes_with_request(self):
        token1 = self.issue(jti="a" * 32)
        req2 = dict(self.request, operation="http_get")
        token2 = self.issue(jti="a" * 32, request=req2)
        self.assertNotEqual(ca.token_digest(token1), ca.token_digest(token2))

    def test_token_digest_changes_with_binding(self):
        token1 = self.issue(jti="a" * 32)
        binding2 = dict(self.binding, numeric_address="10.60.0.3")
        token2 = self.issue(jti="a" * 32, binding=binding2)
        self.assertNotEqual(ca.token_digest(token1), ca.token_digest(token2))

    def test_token_payload_binds_budget_digest(self):
        token = self.issue()
        self.assertEqual(json.loads(token)["payload"]["budget_digest"], self.state["budget_digest"])

    def test_token_payload_binds_revocation_epoch(self):
        token = self.issue()
        self.assertEqual(json.loads(token)["payload"]["revocation_epoch"], self.state["revocation_epoch"])

    def test_token_payload_binds_generation(self):
        token = self.issue()
        self.assertEqual(json.loads(token)["payload"]["generation"], self.state["generation"])

    def test_token_payload_binds_origin_and_numeric_peer_via_binding_hash(self):
        payload = json.loads(self.issue())["payload"]
        self.assertEqual(payload["binding_hash"], ca.digest_obj(self.binding))

    def test_callback_exception_does_not_mark_successful_return(self):
        gate = self.make_gate()
        with self.assertRaisesRegex(RuntimeError, "effect failed"):
            gate.commit(token=self.issue(), request=self.request, binding=self.binding,
                        callback=lambda: (_ for _ in ()).throw(RuntimeError("effect failed")),
                        now=self.now + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
