"""Offline private-network and one-use runner contracts; never launches Docker."""

import io
from contextlib import redirect_stdout
import unittest
from unittest import mock

import runner


class RunnerTests(unittest.TestCase):
    def test_numeric_subnet_parser_catches_vpn_and_short_routes(self):
        sample = """Routing tables
Internet:
Destination Gateway Flags Netif Expire
default 192.168.1.1 UGScg en0
10.47.11/24 utun8 USc utun8
10.254.251/24 link#9 UC en9
192.168.1 link#14 UC en0
"""
        networks = runner.route_networks(sample)
        self.assertTrue(any(net.overlaps(runner.SUBNET) for net in networks))
        self.assertIn("192.168.1.0/24", [str(net) for net in networks])
        self.assertFalse(any(net.prefixlen == 0 for net in networks))
        with self.assertRaises(ValueError):
            runner.route_networks("Destination Gateway Flags Netif\n")

    def test_host_snapshot_comparison_ignores_arp_but_keeps_vpn_changes(self):
        original = """Routing tables
Internet:
Destination Gateway Flags Netif Expire
default 192.168.1.1 UGScg en0
10.47.11/24 utun8 USc utun8
192.168.1.13 00:00 UHLWI en0 999
"""
        changed_neighbor = original.replace("192.168.1.13 00:00 UHLWI en0 999",
                                             "192.168.1.14 00:01 UHLWI en0 77")
        self.assertEqual(runner.normalized(original, "inet"), runner.normalized(changed_neighbor, "inet"))
        self.assertNotEqual(runner.normalized(original, "inet"),
                            runner.normalized(original.replace("10.47.11/24", "10.254.251/24"), "inet"))

    def test_qemu_guest_proc_routes_catch_private_subnet_overlap(self):
        guest = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                 "eth0\t00000000\t01FBFE0A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                 "eth0\t00FBFE0A\t00000000\t0001\t0\t4\t0\t00FFFFFF\t0\t0\t0\n")
        routes = runner.route_networks(guest)
        self.assertIn(runner.SUBNET, routes)
        self.assertEqual(runner.normalized(guest, "inet"),
                         runner.normalized(guest.replace("\t0\t4\t0\t", "\t0\t10\t0\t"), "inet"))
        owned = guest + "br-abcdef123456\t00FBFE0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        self.assertEqual(runner.normalized(guest, "inet"),
                         runner.normalized(owned, "inet", "br-abcdef123456"))
        self.assertNotEqual(runner.normalized(guest, "inet"), runner.normalized(owned, "inet"))
        with self.assertRaises(ValueError):
            runner.route_networks("Iface\tDestination\tGateway\neth0 INVALID 00\n")

    def test_default_dry_run_does_not_inspect_secrets_or_docker(self):
        with mock.patch.object(runner, "docker_identity", side_effect=AssertionError("Docker accessed")), \
             mock.patch.object(runner, "state", side_effect=AssertionError("private state accessed")), \
             mock.patch("sys.argv", ["runner.py"]), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runner.main(), 0)
            self.assertIn("DRY_RUN", out.getvalue())

    def test_browser_receives_only_minimal_intent_not_ari_material(self):
        values = {"phase": "invite-intent", "owner": "a" * 32, "nonce": "b" * 32,
                  "browser_sha": "c" * 64, "bundle_sha": "d" * 64, "cert_sha": "e" * 64,
                  "ari_password": "PRIVATE-SYNTHETIC-ARI-SECRET", "mock_env": "do-not-mount"}
        visible = runner.browser_intent(values)
        self.assertEqual(set(visible), {"phase", "owner", "nonce", "browser_sha", "bundle_sha", "cert_sha"})
        self.assertNotIn("PRIVATE-SYNTHETIC-ARI-SECRET", str(visible))
        self.assertNotIn("mock_env", str(visible))

    def test_invalid_run_id_is_rejected_before_private_state_or_network(self):
        with mock.patch.object(runner, "state", side_effect=AssertionError("state accessed")), \
             mock.patch.object(runner, "apply", side_effect=AssertionError("network accessed")), \
             mock.patch("sys.argv", ["runner.py", "--apply"]), \
             mock.patch.object(runner, "RUN_ID", "../../unsafe"), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runner.main(), 2)
            self.assertIn("REFUSED_INVALID_RUN_ID", out.getvalue())


if __name__ == "__main__":
    unittest.main()
