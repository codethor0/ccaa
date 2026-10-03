#!/usr/bin/env python3
"""Reference commit-authorization token and atomic gate for CCAA.

This module is deliberately small and dependency-free. It demonstrates the
canonical binding, freshness, revocation, replay, and in-process atomicity
semantics described in the paper. It is *not* an operating-system reference
monitor and does not establish complete mediation (A1).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

DOMAIN = "ccaa.commit-auth/v1"
ALGORITHM = "HMAC-SHA256"
MIN_KEY_BYTES = 32
MAX_TTL_SECONDS = 300
PAYLOAD_FIELDS = {
    "domain", "alg", "kid", "issuer", "jti", "request_hash", "run_epoch",
    "scope_digest", "policy_version", "generation", "budget_digest",
    "binding_hash", "revocation_epoch", "iat", "exp",
}


class TokenError(ValueError):
    """Fail-closed token validation error."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise TokenError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _validate_json_value(value: Any) -> None:
    # This profile intentionally excludes floats so canonicalization does not
    # depend on implementation-specific floating-point formatting.
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TokenError("JSON object keys must be strings")
            _validate_json_value(item)
        return
    raise TokenError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic UTF-8 JSON profile used by the reference artifact.

    Objects are recursively key-sorted, arrays preserve order, whitespace is
    removed, non-finite/floating values are rejected, and strings are preserved
    byte-for-byte as supplied. The paper recommends RFC 8785 JCS for production
    interoperability; this stricter integer/string subset is sufficient for the
    included reference token.
    """
    _validate_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_loads(raw: str | bytes) -> Any:
    try:
        obj = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenError(f"invalid JSON: {exc}") from exc
    _validate_json_value(obj)
    if canonical_json_bytes(obj) != (raw.encode("utf-8") if isinstance(raw, str) else raw):
        raise TokenError("non-canonical JSON encoding")
    return obj


def digest_obj(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise TokenError(f"reference HMAC key must be at least {MIN_KEY_BYTES} bytes")


def _mac(key: bytes, payload: dict[str, Any]) -> str:
    _require_key(key)
    return hmac.new(bytes(key), canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def normalize_request(request: dict[str, Any]) -> dict[str, Any]:
    required = {
        "operation", "resource", "protocol", "parameters", "data_class",
        "purpose", "run_id", "coordination_domain",
    }
    if not isinstance(request, dict) or set(request) != required:
        raise TokenError(f"request fields must equal {sorted(required)}")
    _validate_json_value(request)
    return json.loads(canonical_json_bytes(request))


def normalize_binding(binding: dict[str, Any]) -> dict[str, Any]:
    required = {
        "origin", "address_family", "numeric_address", "port", "transport",
        "service_identity_rule", "route", "lease_epoch",
    }
    if not isinstance(binding, dict) or set(binding) != required:
        raise TokenError(f"binding fields must equal {sorted(required)}")
    if binding["address_family"] not in (4, 6):
        raise TokenError("address_family must be 4 or 6")
    if type(binding["port"]) is not int or not 1 <= binding["port"] <= 65535:
        raise TokenError("port must be an integer in 1..65535")
    if type(binding["lease_epoch"]) is not int or binding["lease_epoch"] < 0:
        raise TokenError("lease_epoch must be a nonnegative integer")
    _validate_json_value(binding)
    return json.loads(canonical_json_bytes(binding))


def token_digest(token: str | bytes) -> str:
    raw = token.encode("utf-8") if isinstance(token, str) else token
    return hashlib.sha256(raw).hexdigest()


def issue_token(
    *,
    key: bytes,
    kid: str,
    issuer: str,
    request: dict[str, Any],
    binding: dict[str, Any],
    state: dict[str, Any],
    now: int | None = None,
    ttl_seconds: int = 60,
    jti: str | None = None,
) -> str:
    _require_key(key)
    if not isinstance(kid, str) or not kid:
        raise TokenError("kid must be nonempty")
    if not isinstance(issuer, str) or not issuer:
        raise TokenError("issuer must be nonempty")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise TokenError(f"ttl_seconds must be in 1..{MAX_TTL_SECONDS}")
    req = normalize_request(request)
    bind = normalize_binding(binding)
    required_state = {
        "run_epoch", "scope_digest", "policy_version", "generation",
        "budget_digest", "revocation_epoch",
    }
    if not isinstance(state, dict) or not required_state.issubset(state):
        raise TokenError(f"state missing required fields: {sorted(required_state - set(state or {}))}")
    issued = int(time.time()) if now is None else now
    if type(issued) is not int:
        raise TokenError("now must be an integer epoch second")
    token_id = secrets.token_hex(16) if jti is None else jti
    if not isinstance(token_id, str) or len(token_id) < 16:
        raise TokenError("jti must be a nonempty high-entropy identifier")
    payload = {
        "domain": DOMAIN,
        "alg": ALGORITHM,
        "kid": kid,
        "issuer": issuer,
        "jti": token_id,
        "request_hash": digest_obj(req),
        "run_epoch": state["run_epoch"],
        "scope_digest": state["scope_digest"],
        "policy_version": state["policy_version"],
        "generation": state["generation"],
        "budget_digest": state["budget_digest"],
        "binding_hash": digest_obj(bind),
        "revocation_epoch": state["revocation_epoch"],
        "iat": issued,
        "exp": issued + ttl_seconds,
    }
    _validate_payload_shape(payload)
    token = {"payload": payload, "mac": _mac(key, payload)}
    return canonical_json_bytes(token).decode("utf-8")


def _validate_payload_shape(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise TokenError("token payload has missing or unknown fields")
    string_fields = {
        "domain", "alg", "kid", "issuer", "jti", "request_hash",
        "scope_digest", "policy_version", "budget_digest", "binding_hash",
    }
    for name in string_fields:
        if not isinstance(payload[name], str) or not payload[name]:
            raise TokenError(f"payload.{name} must be a nonempty string")
    for name in ("run_epoch", "generation", "revocation_epoch", "iat", "exp"):
        if type(payload[name]) is not int:
            raise TokenError(f"payload.{name} must be an integer")
    for name in ("request_hash", "scope_digest", "budget_digest", "binding_hash"):
        if len(payload[name]) != 64 or any(c not in "0123456789abcdef" for c in payload[name].lower()):
            raise TokenError(f"payload.{name} must be a SHA-256 hex digest")
    if payload["exp"] <= payload["iat"]:
        raise TokenError("token exp must be greater than iat")
    if payload["exp"] - payload["iat"] > MAX_TTL_SECONDS:
        raise TokenError("token lifetime exceeds maximum")


def parse_token(token: str | bytes) -> dict[str, Any]:
    obj = canonical_loads(token)
    if not isinstance(obj, dict) or set(obj) != {"payload", "mac"}:
        raise TokenError("token must contain exactly payload and mac")
    payload = obj["payload"]
    _validate_payload_shape(payload)
    mac = obj["mac"]
    if not isinstance(mac, str) or len(mac) != 64 or any(c not in "0123456789abcdef" for c in mac.lower()):
        raise TokenError("mac must be 64 hexadecimal characters")
    return obj


@dataclass
class ReplayCache:
    _used: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def contains(self, jti: str) -> bool:
        with self._lock:
            return jti in self._used

    def consume(self, jti: str) -> None:
        with self._lock:
            if jti in self._used:
                raise TokenError("authorization replay detected")
            self._used.add(jti)


@dataclass
class VerificationContext:
    state: dict[str, Any]
    expected_kid: str
    expected_issuer: str
    now: int
    clock_skew_seconds: int = 5
    revoked_jti: set[str] = field(default_factory=set)
    revoked_token_digests: set[str] = field(default_factory=set)


def verify_token(
    *,
    token: str | bytes,
    key: bytes,
    request: dict[str, Any],
    binding: dict[str, Any],
    context: VerificationContext,
) -> dict[str, Any]:
    _require_key(key)
    obj = parse_token(token)
    payload = obj["payload"]
    expected_mac = _mac(key, payload)
    if not hmac.compare_digest(expected_mac, obj["mac"]):
        raise TokenError("MAC verification failed")
    if payload["domain"] != DOMAIN:
        raise TokenError("wrong token domain")
    if payload["alg"] != ALGORITHM:
        raise TokenError("unsupported token algorithm")
    if payload["kid"] != context.expected_kid:
        raise TokenError("unexpected key identifier")
    if payload["issuer"] != context.expected_issuer:
        raise TokenError("unexpected issuer")
    if context.clock_skew_seconds < 0:
        raise TokenError("clock skew cannot be negative")
    if payload["iat"] > context.now + context.clock_skew_seconds:
        raise TokenError("token issued in the future")
    if context.now > payload["exp"] + context.clock_skew_seconds:
        raise TokenError("token expired")
    req = normalize_request(request)
    bind = normalize_binding(binding)
    if not hmac.compare_digest(payload["request_hash"], digest_obj(req)):
        raise TokenError("request binding mismatch")
    if not hmac.compare_digest(payload["binding_hash"], digest_obj(bind)):
        raise TokenError("destination binding mismatch")
    state = context.state
    for field_name in (
        "run_epoch", "scope_digest", "policy_version", "generation",
        "budget_digest", "revocation_epoch",
    ):
        if payload[field_name] != state[field_name]:
            raise TokenError(f"state mismatch: {field_name}")
    if payload["jti"] in context.revoked_jti:
        raise TokenError("authorization identifier revoked")
    if token_digest(token) in context.revoked_token_digests:
        raise TokenError("authorization digest revoked")
    return payload


@dataclass
class AtomicCommitGate:
    """In-process conformance demonstrator for a single linearization point.

    The lock is not a substitute for OS-level complete mediation. It only makes
    the reference state check, nonce consumption, and callback invocation one
    serialized transaction for the tests and examples in this bundle.
    """

    key: bytes
    kid: str
    issuer: str
    state: dict[str, Any]
    policy: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], bool]
    replay_cache: ReplayCache = field(default_factory=ReplayCache)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def update_state(self, **updates: Any) -> None:
        with self._lock:
            self.state.update(updates)

    def commit(
        self,
        *,
        token: str,
        request: dict[str, Any],
        binding: dict[str, Any],
        callback: Callable[[], Any],
        now: int,
        clock_skew_seconds: int = 5,
        revoked_jti: set[str] | None = None,
        revoked_token_digests: set[str] | None = None,
    ) -> Any:
        with self._lock:
            context = VerificationContext(
                state=dict(self.state),
                expected_kid=self.kid,
                expected_issuer=self.issuer,
                now=now,
                clock_skew_seconds=clock_skew_seconds,
                revoked_jti=set() if revoked_jti is None else set(revoked_jti),
                revoked_token_digests=(
                    set() if revoked_token_digests is None else set(revoked_token_digests)
                ),
            )
            payload = verify_token(
                token=token,
                key=self.key,
                request=request,
                binding=binding,
                context=context,
            )
            if not self.policy(context.state, normalize_request(request), normalize_binding(binding)):
                raise TokenError("current deterministic policy denies request")
            self.replay_cache.consume(payload["jti"])
            # The callback represents exactly one effect primitive in this
            # demonstrator. A production system must place *all* effect paths
            # behind an independent gate to satisfy complete mediation.
            return callback()
