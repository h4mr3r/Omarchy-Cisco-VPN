import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / "tunnel-helper.py"
loader = importlib.machinery.SourceFileLoader("tunnel_helper", str(PATH))
spec = importlib.util.spec_from_loader("tunnel_helper", loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)

PIN = "pin-sha256:" + "A" * 43 + "="
REQUEST = {"url": "https://gw.example.com", "cookie": "webvpn=abc", "fingerprint": PIN,
           "resolve": "gw.example.com:192.0.2.1", "proxy": "", "version": "5.1.21.2728",
           "hostname": "NB-5CG4504T36", "os": "win", "routes": ["172.16.0.0/16", "10.0.0.0/8"]}


class TunnelHelperTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        run_dir = self.dir.name
        self.patches = [patch.object(helper, name, os.path.join(run_dir, file)) for name, file in (
            ("PID_FILE", "openconnect.pid"), ("ROUTES_FILE", "routes.json"),
            ("INFO_FILE", "info.json"), ("LOG_FILE", "openconnect.log"))]
        self.patches.append(patch.object(helper, "RUN_DIR", run_dir))
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.dir.cleanup()

    def up(self, request, returncode=0, log=""):
        def fake_run(args, **kwargs):
            kwargs["stdout"].write(log)
            if not returncode:
                with open(helper.PID_FILE, "w") as handle:
                    handle.write("4242\n")
            return subprocess.CompletedProcess(args, returncode)
        with patch.object(helper.sys, "stdin", io.StringIO(json.dumps(request))), patch.object(
                helper.subprocess, "run", side_effect=fake_run) as runner, patch.object(
                helper, "running_pid", side_effect=lambda: 4242 if os.path.exists(helper.PID_FILE) else 0):
            result = helper.up()
        return result, runner

    def test_up_runs_openconnect_with_vpnc_script_wrapper(self):
        result, runner = self.up(REQUEST)
        self.assertEqual(result, {"ok": True, "pid": 4242})
        args = runner.call_args.args[0]
        self.assertEqual(args, [
            "/usr/bin/openconnect", "--protocol=anyconnect", "--cookie-on-stdin",
            "--servercert", PIN, "--script", "/usr/local/libexec/omarchy-cisco-vpn-tunnel script",
            "--background", "--pid-file", helper.PID_FILE, "--disable-ipv6", "--no-proxy",
            "--resolve=gw.example.com:192.0.2.1", "--version-string=5.1.21.2728",
            "--local-hostname=NB-5CG4504T36", "--os=win", "https://gw.example.com"])
        self.assertEqual(runner.call_args.kwargs["input"], "webvpn=abc\n")
        with open(helper.ROUTES_FILE) as handle:
            routes = json.load(handle)
        self.assertEqual(routes, ["172.16.0.0/16", "10.0.0.0/8"])
        # The wrapper must be able to read back exactly what up() wrote.
        self.assertEqual(helper.parse_routes(routes), [["172.16.0.0", "255.255.0.0", 16],
                                                       ["10.0.0.0", "255.0.0.0", 8]])

    def test_up_rejects_values_that_could_become_options(self):
        for key, value in (("url", "--script=/tmp/x"), ("url", "http://gw.example.com"),
                           ("fingerprint", "--servercert"), ("proxy", "--script=x"),
                           ("version", "-x"), ("hostname", "-x"), ("os", "--script"),
                           ("resolve", "--x:1.2.3.4"), ("cookie", "a\nb"),
                           ("routes", ["0.0.0.0/0"]), ("routes", ["fd00::/8"]), ("routes", "10.0.0.0/8")):
            with self.subTest(key=key, value=value), self.assertRaises(helper.HelperError):
                self.up({**REQUEST, key: value})

    def test_up_reports_failure_without_raw_log(self):
        with self.assertRaisesRegex(helper.HelperError, "Could not reach the VPN server"):
            self.up(REQUEST, returncode=1, log="Failed to connect to host gw.example.com\nsecret-detail\n")

    def test_split_environment_replaces_gateway_includes(self):
        gateway = {"reason": "connect", "TUNDEV": "tun0", "CISCO_SPLIT_INC": "3",
                   "CISCO_SPLIT_INC_0_ADDR": "192.168.0.0", "CISCO_SPLIT_INC_2_MASKLEN": "24",
                   "CISCO_SPLIT_EXC": "1", "INTERNAL_IP4_DNS": "172.16.1.205"}
        env = helper.split_environment(gateway, [["172.16.0.0", "255.255.0.0", 16],
                                                 ["10.0.0.0", "255.0.0.0", 8]])
        self.assertEqual(env["CISCO_SPLIT_INC"], "2")
        self.assertEqual((env["CISCO_SPLIT_INC_0_ADDR"], env["CISCO_SPLIT_INC_0_MASK"],
                          env["CISCO_SPLIT_INC_0_MASKLEN"]), ("172.16.0.0", "255.255.0.0", "16"))
        self.assertEqual(env["CISCO_SPLIT_INC_1_ADDR"], "10.0.0.0")
        self.assertNotIn("CISCO_SPLIT_INC_2_MASKLEN", env)
        # Everything else (DNS, exclusions) is left to vpnc-script untouched.
        self.assertEqual((env["CISCO_SPLIT_EXC"], env["INTERNAL_IP4_DNS"]), ("1", "172.16.1.205"))

    def test_split_environment_without_routes_keeps_gateway_routes(self):
        gateway = {"CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "192.168.0.0"}
        self.assertEqual(helper.split_environment(gateway, []), gateway)

    def test_script_records_tunnel_info_and_execs_vpnc_script(self):
        with open(helper.ROUTES_FILE, "w") as handle:
            json.dump(["10.0.0.0/8"], handle)
        environ = {"reason": "connect", "TUNDEV": "tun0", "CISCO_DEF_DOMAIN": "corp.example.com",
                   "INTERNAL_IP4_DNS": "172.16.1.205", "INTERNAL_IP4_ADDRESS": "172.16.195.3"}
        with patch.dict(helper.os.environ, environ, clear=True), patch.object(
                helper.os, "execve") as execve:
            helper.script()
        path, argv, env = execve.call_args.args
        self.assertEqual((path, argv), ("/etc/vpnc/vpnc-script", ["/etc/vpnc/vpnc-script"]))
        self.assertEqual(env["CISCO_SPLIT_INC_0_ADDR"], "10.0.0.0")
        with open(helper.INFO_FILE) as handle:
            self.assertEqual(json.load(handle), {"device": "tun0", "domain": "corp.example.com",
                                                 "dns": ["172.16.1.205"], "address": "172.16.195.3"})


if __name__ == "__main__":
    unittest.main()
