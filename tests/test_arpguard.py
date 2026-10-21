import contextlib
import io
import json
import logging
import logging.handlers
import os
import runpy
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "arpguard.py")
GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:dd:ee:ff"
OTHER_MAC = "11:22:33:44:55:66"
IPV6_GATEWAY_IP = "fe80::1"


class FakeARP:
    def __init__(self, op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, pdst=None, **kwargs):
        self.op = op
        self.psrc = psrc
        self.hwsrc = hwsrc
        self.pdst = pdst


class FakeEther:
    def __init__(self, src=None, **kwargs):
        self.src = src

    def __truediv__(self, payload):
        return payload


class FakeIPv6:
    def __init__(self, src="fe80::1", **kwargs):
        self.src = src


class FakeRouterAdvertisement:
    pass


class FakeNeighborAdvertisement:
    def __init__(self, tgt=IPV6_GATEWAY_IP, **kwargs):
        self.tgt = tgt


class FakeSourceLLAddress:
    def __init__(self, lladdr=GATEWAY_MAC, **kwargs):
        self.lladdr = lladdr


class FakeDestinationLLAddress:
    def __init__(self, lladdr=GATEWAY_MAC, **kwargs):
        self.lladdr = lladdr


class FakePacket:
    def __init__(self, arp=None, ethernet=None, ipv6=None, ra=None, na=None, src_ll=None, dst_ll=None, sniffed_on="eth0"):
        self.layers = {
            FakeARP: arp,
            FakeEther: ethernet or FakeEther(src=GATEWAY_MAC),
            FakeIPv6: ipv6,
            FakeRouterAdvertisement: ra,
            FakeNeighborAdvertisement: na,
            FakeSourceLLAddress: src_ll,
            FakeDestinationLLAddress: dst_ll,
        }
        self.sniffed_on = sniffed_on

    def haslayer(self, layer):
        return self.layers.get(layer) is not None

    def __getitem__(self, layer):
        return self.layers[layer]


class FakeReply:
    def __init__(self, ip):
        self.arp = FakeARP(psrc=ip, hwsrc=GATEWAY_MAC)

    def haslayer(self, layer):
        return layer is FakeARP

    def __getitem__(self, layer):
        return self.arp


class FakeRoute:
    def __init__(self, state):
        self.state = state

    def route(self, destination, dev=None):
        self.state["route_interface"] = dev or "eth0"
        if self.state.get("offline"):
            raise AssertionError("offline replay must not inspect live routes")
        interface = dev or "eth0"
        gateway = "10.0.0.1" if interface == "eth1" else GATEWAY_IP
        return interface, "192.168.1.10", gateway


class FakeCaptureSocket:
    def __init__(self, state):
        self.state = state

    def close(self):
        self.state["capture_socket_closed"] = True


class RecordingSyslogHandler(logging.Handler):
    records = []
    addresses = []

    def __init__(self, address):
        super().__init__()
        self.address = address
        self.addresses.append(address)

    def emit(self, record):
        self.records.append(self.format(record))


def make_scapy(state, packets):
    scapy = types.ModuleType("scapy")
    scapy_all = types.ModuleType("scapy.all")
    symbols = {
        "ARP": FakeARP,
        "Ether": FakeEther,
        "IPv6": FakeIPv6,
        "ICMPv6ND_RA": FakeRouterAdvertisement,
        "ICMPv6ND_NA": FakeNeighborAdvertisement,
        "ICMPv6NDOptSrcLLAddr": FakeSourceLLAddress,
        "ICMPv6NDOptDstLLAddr": FakeDestinationLLAddress,
    }
    scapy_all.__all__ = list(symbols) + ["conf", "get_if_list", "srp", "sniff"]
    for name, value in symbols.items():
        setattr(scapy_all, name, value)
    def l2listen(**kwargs):
        state["capture_preflight"] = kwargs
        if state.get("capture_preflight_error"):
            raise PermissionError("packet capture permission denied")
        return FakeCaptureSocket(state)

    scapy_all.conf = types.SimpleNamespace(route=FakeRoute(state), L2listen=l2listen)
    scapy_all.get_if_list = lambda: ["eth0", "eth1"]

    def srp(query, **kwargs):
        if state.get("offline"):
            raise AssertionError("offline replay must not send an ARP probe")
        state["probe_interface"] = kwargs.get("iface")
        return [(None, FakeReply(query.pdst))], []

    def sniff(**kwargs):
        state["sniff_options"] = kwargs
        for packet in packets:
            kwargs["prn"](packet)
        if not kwargs.get("offline"):
            raise KeyboardInterrupt

    scapy_all.srp = srp
    scapy_all.sniff = sniff
    scapy.all = scapy_all
    return scapy, scapy_all


class ArpGuardTests(unittest.TestCase):
    def run_agent(self, arguments, packets=(), confirmation="y", offline=False, log_path=None):
        state = {"offline": offline}
        scapy, scapy_all = make_scapy(state, packets)
        output = io.StringIO()
        root_logger = logging.getLogger()
        previous_handlers = root_logger.handlers[:]
        previous_level = root_logger.level
        temp_dir = tempfile.TemporaryDirectory() if log_path is None else None
        if log_path is None:
            log_path = os.path.join(temp_dir.name, "alerts.jsonl")
        arguments = [*arguments, "--log-file", log_path]
        try:
            with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}), \
                 patch.object(sys, "argv", [SCRIPT, *arguments]), \
                 patch("builtins.input", return_value=confirmation):
                try:
                    with contextlib.redirect_stdout(output):
                        runpy.run_path(SCRIPT, run_name="__main__")
                except SystemExit as exc:
                    code = exc.code
                else:
                    code = 0
            return code, output.getvalue(), state, log_path
        finally:
            for handler in root_logger.handlers[:]:
                if handler not in previous_handlers:
                    root_logger.removeHandler(handler)
                    handler.close()
            root_logger.handlers = previous_handlers
            root_logger.setLevel(previous_level)
            if temp_dir is not None:
                temp_dir.cleanup()

    def assert_event(self, output, marker="Suspicious ARP activity detected:"):
        line = next(line for line in output.splitlines() if marker in line)
        return json.loads(line.split(marker, 1)[1].strip())

    def test_configured_gateway_mac_mismatch_stops_before_capture(self):
        code, output, state, *_ = self.run_agent(["--gateway-mac", OTHER_MAC])
        self.assertEqual(code, 1)
        self.assertIn("does not match configured MAC", output)
        self.assertNotIn("sniff_options", state)

    def test_declining_baseline_confirmation_stops_before_capture(self):
        code, output, state, *_ = self.run_agent([], confirmation="n")
        self.assertEqual(code, 1)
        self.assertIn("Baseline not confirmed", output)
        self.assertNotIn("sniff_options", state)

    def test_interface_is_used_for_route_probe_and_capture(self):
        code, output, state, *_ = self.run_agent(["--interface", "eth1", "--gateway-mac", GATEWAY_MAC])
        self.assertEqual(code, 0)
        self.assertEqual(state["route_interface"], "eth1")
        self.assertEqual(state["probe_interface"], "eth1")
        self.assertEqual(state["sniff_options"]["iface"], "eth1")
        self.assertIn("10.0.0.1", output)

    def test_unknown_interface_is_rejected(self):
        code, output, state, *_ = self.run_agent(["--interface", "eth9"])
        self.assertEqual(code, 2)
        self.assertIn("was not found", output)
        self.assertNotIn("sniff_options", state)

    def test_check_only_validates_capture_then_exits_without_sniffing(self):
        code, output, state, *_ = self.run_agent(["--gateway-mac", GATEWAY_MAC, "--check-only"])
        self.assertEqual(code, 0)
        self.assertEqual(state["capture_preflight"], {"iface": "eth0", "filter": "arp"})
        self.assertTrue(state["capture_socket_closed"])
        self.assertNotIn("sniff_options", state)
        self.assertIn("Configuration check passed", output)

    def test_offline_check_only_validates_capture_without_replaying(self):
        with tempfile.NamedTemporaryFile() as capture:
            code, output, state, *_ = self.run_agent(
                ["--pcap", capture.name, "--gateway-ip", GATEWAY_IP, "--gateway-mac", GATEWAY_MAC,
                 "--check-only"],
                offline=True,
            )
        self.assertEqual(code, 0)
        self.assertIn("offline PCAP and trusted baselines are ready", output)
        self.assertNotIn("sniff_options", state)

    def test_check_only_reports_capture_permission_failure(self):
        state = {"capture_preflight_error": True}
        scapy, scapy_all = make_scapy(state, [])
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir, \
             patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}), \
             patch.object(sys, "argv", [SCRIPT, "--gateway-mac", GATEWAY_MAC, "--check-only",
                                        "--log-file", os.path.join(temp_dir, "alerts.jsonl")]), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as exc:
                runpy.run_path(SCRIPT, run_name="__main__")
        self.assertEqual(exc.exception.code, 1)
        self.assertIn("Capture preflight failed", output.getvalue())
        self.assertNotIn("sniff_options", state)

    def test_arp_gateway_request_is_reported_as_json(self):
        packet = FakePacket(
            arp=FakeARP(op=1, psrc=GATEWAY_IP, hwsrc=OTHER_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
        )
        code, output, *_ = self.run_agent([], [packet])
        self.assertEqual(code, 0)
        event = self.assert_event(output)
        self.assertEqual(event["packet_type"], "request")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["expected_gateway_mac"], GATEWAY_MAC)
        self.assertEqual(event["arp_sender_mac"], OTHER_MAC)
        self.assertTrue(event["timestamp"])

    def test_trusted_gateway_failover_mac_is_not_reported(self):
        packet = FakePacket(
            arp=FakeARP(op=2, psrc=GATEWAY_IP, hwsrc=OTHER_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
        )
        code, output, *_ = self.run_agent(["--trusted-gateway-mac", OTHER_MAC], [packet])
        self.assertEqual(code, 0)
        self.assertNotIn("Suspicious ARP activity detected:", output)

    def test_ethernet_only_mismatch_is_medium_severity(self):
        packet = FakePacket(
            arp=FakeARP(psrc="192.168.1.20", hwsrc=GATEWAY_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
        )
        code, output, *_ = self.run_agent([], [packet])
        self.assertEqual(code, 0)
        self.assertEqual(self.assert_event(output)["severity"], "medium")

    def test_syslog_forwards_json_alerts_to_local_socket(self):
        packet = FakePacket(
            arp=FakeARP(op=2, psrc=GATEWAY_IP, hwsrc=OTHER_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
        )
        RecordingSyslogHandler.records = []
        RecordingSyslogHandler.addresses = []
        with patch.object(logging.handlers, "SysLogHandler", RecordingSyslogHandler):
            code, _, *_ = self.run_agent(["--syslog"], [packet])
        self.assertEqual(code, 0)
        self.assertEqual(len(RecordingSyslogHandler.records), 1)
        event = json.loads(RecordingSyslogHandler.records[0])
        self.assertEqual(event["event"], "suspicious_arp")
        self.assertEqual(RecordingSyslogHandler.addresses, ["/dev/log"])

    def test_ethernet_arp_mismatch_alerts_but_normal_reply_does_not(self):
        mismatch = FakePacket(
            arp=FakeARP(psrc="192.168.1.20", hwsrc=GATEWAY_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
        )
        code, output, *_ = self.run_agent([], [mismatch])
        self.assertEqual(code, 0)
        event = self.assert_event(output)
        self.assertIn("does not match ARP sender MAC", event["reasons"][0])

        normal = FakePacket(
            arp=FakeARP(op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC),
            ethernet=FakeEther(src=GATEWAY_MAC),
        )
        code, output, *_ = self.run_agent([], [normal])
        self.assertEqual(code, 0)
        self.assertNotIn("Suspicious ARP activity detected:", output)

    def test_offline_replay_skips_live_discovery_and_uses_same_detector(self):
        packet = FakePacket(
            arp=FakeARP(op=1, psrc=GATEWAY_IP, hwsrc=OTHER_MAC),
            ethernet=FakeEther(src=OTHER_MAC),
            sniffed_on=None,
        )
        with tempfile.NamedTemporaryFile() as capture:
            code, output, state, *_ = self.run_agent(
                ["--pcap", capture.name, "--gateway-ip", GATEWAY_IP, "--gateway-mac", GATEWAY_MAC],
                [packet],
                offline=True,
            )
        self.assertEqual(code, 0)
        self.assertNotIn("route_interface", state)
        self.assertNotIn("probe_interface", state)
        self.assertEqual(state["sniff_options"]["offline"], capture.name)
        event = self.assert_event(output)
        self.assertEqual(event["capture_mode"], "offline")
        self.assertIsNone(event["interface"])

    def test_offline_replay_requires_gateway_pair(self):
        with tempfile.NamedTemporaryFile() as capture:
            code, output, state, *_ = self.run_agent(
                ["--pcap", capture.name, "--gateway-ip", GATEWAY_IP], offline=True
            )
        self.assertEqual(code, 2)
        self.assertIn("requires both --gateway-ip and --gateway-mac", output)
        self.assertNotIn("sniff_options", state)

    def test_ipv6_router_and_neighbor_advertisement_checks(self):
        def ndp_packet(source, source_mac, target_mac, router_advertisement=True, target=IPV6_GATEWAY_IP):
            layers = {
                "ipv6": FakeIPv6(src=source),
                "ethernet": FakeEther(src=source_mac),
            }
            if router_advertisement:
                layers["ra"] = FakeRouterAdvertisement()
                layers["src_ll"] = FakeSourceLLAddress(lladdr=target_mac)
            else:
                layers["na"] = FakeNeighborAdvertisement(tgt=target)
                layers["dst_ll"] = FakeDestinationLLAddress(lladdr=target_mac)
            return FakePacket(**layers)

        rogue_ra = ndp_packet("fe80::bad", OTHER_MAC, OTHER_MAC)
        good_ra = ndp_packet(IPV6_GATEWAY_IP, GATEWAY_MAC, GATEWAY_MAC)
        rogue_na = ndp_packet(IPV6_GATEWAY_IP, OTHER_MAC, OTHER_MAC, router_advertisement=False)
        unrelated_na = ndp_packet("fe80::bad", OTHER_MAC, OTHER_MAC, router_advertisement=False, target="fe80::99")
        with tempfile.NamedTemporaryFile() as capture:
            code, output, *_ = self.run_agent(
                ["--pcap", capture.name, "--gateway-ip", GATEWAY_IP, "--gateway-mac", GATEWAY_MAC,
                 "--ipv6-gateway-ip", IPV6_GATEWAY_IP, "--ipv6-gateway-mac", GATEWAY_MAC],
                [rogue_ra, good_ra, rogue_na, unrelated_na], offline=True,
            )
        self.assertEqual(code, 0)
        marker = "Suspicious IPv6 NDP activity detected:"
        events = [json.loads(line.split(marker, 1)[1].strip()) for line in output.splitlines() if marker in line]
        self.assertEqual([event["packet_type"] for event in events], ["router_advertisement", "neighbor_advertisement"])
        self.assertEqual([event["expected_router_ipv6"] for event in events], ["fe80::bad", IPV6_GATEWAY_IP])
        self.assertTrue(all(event["severity"] == "high" for event in events))
        self.assertIn("Suspicious IPv6 NDP activity detected:", output)
        self.assertEqual(len(events), 2)

    def test_additional_trusted_ipv6_router_is_accepted(self):
        alternate_ip = "fe80::2"
        packet = FakePacket(
            ipv6=FakeIPv6(src=alternate_ip),
            ethernet=FakeEther(src=OTHER_MAC),
            ra=FakeRouterAdvertisement(),
            src_ll=FakeSourceLLAddress(lladdr=OTHER_MAC),
        )
        with tempfile.NamedTemporaryFile() as capture:
            code, output, state, *_ = self.run_agent(
                ["--pcap", capture.name, "--gateway-ip", GATEWAY_IP, "--gateway-mac", GATEWAY_MAC,
                 "--ipv6-gateway-ip", IPV6_GATEWAY_IP, "--ipv6-gateway-mac", GATEWAY_MAC,
                 "--trusted-ipv6-router", f"{alternate_ip}={OTHER_MAC}"],
                [packet], offline=True,
            )
        self.assertEqual(code, 0)
        self.assertNotIn("Suspicious IPv6 NDP activity detected:", output)
        self.assertEqual(state["sniff_options"]["offline"], capture.name)

    def test_trusted_ipv6_router_requires_valid_pair(self):
        code, output, state, *_ = self.run_agent(["--trusted-ipv6-router", "fe80::2=invalid"])
        self.assertEqual(code, 2)
        self.assertIn("Invalid MAC in --trusted-ipv6-router", output)
        self.assertNotIn("sniff_options", state)

    def test_live_ipv6_monitoring_captures_icmpv6(self):
        code, _, state, *_ = self.run_agent([
            "--ipv6-gateway-ip", IPV6_GATEWAY_IP,
            "--ipv6-gateway-mac", GATEWAY_MAC,
            "--gateway-mac", GATEWAY_MAC,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(state["sniff_options"]["filter"], "arp or icmp6")

    def test_ipv6_monitoring_requires_both_trusted_values(self):
        code, output, state, *_ = self.run_agent(["--ipv6-gateway-ip", IPV6_GATEWAY_IP])
        self.assertEqual(code, 2)
        self.assertIn("requires both --ipv6-gateway-ip and --ipv6-gateway-mac", output)
        self.assertNotIn("sniff_options", state)

    def test_rotating_log_keeps_alerts_in_configured_files(self):
        packets = [
            FakePacket(
                arp=FakeARP(op=2, psrc=GATEWAY_IP, hwsrc=OTHER_MAC),
                ethernet=FakeEther(src=OTHER_MAC),
            )
            for _ in range(3200)
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "events.jsonl")
            with contextlib.redirect_stdout(io.StringIO()):
                code, _, _, _ = self.run_agent(
                    ["--pcap", __file__, "--gateway-ip", GATEWAY_IP, "--gateway-mac", GATEWAY_MAC,
                     "--log-size-mb", "1"],
                    packets,
                    offline=True,
                    log_path=log_path,
                )
            self.assertEqual(code, 0)
            rotated = [path for path in os.listdir(temp_dir) if path.startswith("events.jsonl")]
            self.assertGreaterEqual(len(rotated), 2)
            records = []
            for name in rotated:
                with open(os.path.join(temp_dir, name), encoding="utf-8") as log_file:
                    records.extend(json.loads(line) for line in log_file if line.strip())
            self.assertEqual(len(records), 3200)


if __name__ == "__main__":
    unittest.main()
