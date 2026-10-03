#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import ipaddress
import socket
import sys
import threading
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "agent_eval_preflight.py"
spec = importlib.util.spec_from_file_location("preflight_live", MODULE_PATH)
assert spec and spec.loader
pf = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pf
spec.loader.exec_module(pf)


class LiveLoopbackIntegrationTests(unittest.TestCase):
    def test_real_localhost_resolution_returns_only_loopback_addresses(self):
        addresses = pf.resolve_all("localhost")
        self.assertTrue(addresses)
        self.assertTrue(all(a.is_loopback for a in addresses))

    def test_real_numeric_loopback_probe_reaches_local_listener_without_dns(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted = []
        def serve():
            conn, peer = listener.accept()
            accepted.append(peer)
            conn.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        reachable, detail = pf.endpoint_reachable((ipaddress.ip_address("127.0.0.1"),), port, 2.0)
        thread.join(2.0)
        self.assertTrue(reachable, detail)
        self.assertEqual(len(accepted), 1)
        self.assertIn("numeric_binding=verified", detail)

    def test_live_proc_status_exposes_linux_posture_fields_when_proc_exists(self):
        status = pf.proc_status()
        if not status:
            self.skipTest("/proc/self/status unavailable on this platform")
        for name in ("CapEff", "NoNewPrivs", "Seccomp"):
            self.assertIn(name, status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
