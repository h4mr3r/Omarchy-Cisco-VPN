import io
import json
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import backend


class BackendTest(unittest.TestCase):
    def test_run_limits_combined_subprocess_output(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(
                    backend.VpnError, "produced too much output"):
                backend.run([sys.executable, "-c",
                             f"import sys; sys.{stream}.buffer.write(b'x' * (2 * 1024 * 1024))"],
                            timeout=5)

    def test_run_enforces_exact_combined_limit(self):
        script = ("import sys; sys.stdout.buffer.write(b'x' * 524288); "
                  "sys.stderr.buffer.write(b'y' * int(sys.argv[1]))")
        result = backend.run([sys.executable, "-c", script, "524288"], timeout=5)
        self.assertEqual(len(result.stdout) + len(result.stderr), backend.MAX_OUTPUT_BYTES)
        with self.assertRaisesRegex(backend.VpnError, "produced too much output"):
            backend.run([sys.executable, "-c", script, "524289"], timeout=5)

    def test_run_preserves_stdin_and_both_output_streams(self):
        result = backend.run(
            [sys.executable, "-c",
             "import sys; print(sys.stdin.readline().strip()); print('warning', file=sys.stderr)"],
            input="secret\n", timeout=5,
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, "secret\n", "warning\n"))

    def test_run_still_times_out_without_output(self):
        with self.assertRaisesRegex(backend.VpnError, "timed out"):
            backend.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.1)

    def test_status_reads_gateway_and_proxy_from_vpn_data(self):
        settings = {"vpn": {"user-name": "name", "data": {
            "gateway": "https://vpn.example.com", "proxy": "http://proxy.example.com:8080"}}}
        with patch.object(backend, "profile_uuid", return_value="test-uuid"), patch.object(
                backend, "profile_settings", return_value=settings), patch.object(
                backend, "nmcli", return_value="test-uuid"), patch.object(
                backend, "load_settings", return_value={}), patch.object(
                backend.NM.Client, "new") as client:
            self.assertEqual(backend.state(), {
                "connected": True, "server": "https://vpn.example.com", "username": "name",
                "proxy": "http://proxy.example.com:8080", "settings": {}, "certificatePinned": False,
            })
        client.assert_not_called()

    def profile_mocks(self, data, permissions=0):
        vpn = backend.NM.SettingVpn.new()
        for key, value in data.items():
            vpn.add_data_item(key, value)
        setting = Mock()
        setting.get_num_permissions.return_value = permissions
        connection = Mock()
        connection.get_setting_vpn.return_value = vpn
        connection.get_setting_connection.return_value = setting
        connection.commit_changes.return_value = True
        client = Mock()
        client.get_connection_by_uuid.return_value = connection
        return vpn, setting, connection, client

    def test_existing_profile_merges_owned_keys_and_keeps_others(self):
        vpn, setting, connection, client = self.profile_mocks(
            {"gateway": "https://old.example.com", "cacert": "/etc/ca.pem",
             "proxy": "http://old:1"})
        with patch.object(backend, "profile_uuid", return_value="test-uuid"), patch.object(
                backend.NM.Client, "new", return_value=client), patch.object(
                backend, "current_user", return_value="me"):
            backend.ensure_profile("https://vpn.example.com/a,b", "name", "")
        self.assertEqual(vpn.get_data_item("gateway"), "https://vpn.example.com/a,b")
        self.assertEqual(vpn.get_data_item("cacert"), "/etc/ca.pem")
        self.assertIsNone(vpn.get_data_item("proxy"))
        self.assertEqual(vpn.get_user_name(), "name")
        setting.add_permission.assert_called_once_with("user", "me", None)
        connection.commit_changes.assert_called_once_with(True, None)

    def test_profile_stores_proxy_and_keeps_existing_permissions(self):
        vpn, setting, _, client = self.profile_mocks({}, permissions=1)
        with patch.object(backend, "profile_uuid", return_value="test-uuid"), patch.object(
                backend.NM.Client, "new", return_value=client):
            backend.ensure_profile("https://vpn.example.com", "name", "http://proxy.example.com:8080")
        self.assertEqual(vpn.get_data_item("proxy"), "http://proxy.example.com:8080")
        setting.add_permission.assert_not_called()

    def test_proxy_url_validation(self):
        self.assertEqual(backend.proxy_url("proxy.example.com:8080"), "http://proxy.example.com:8080")
        self.assertEqual(backend.proxy_url("socks5://10.0.0.1:1080/"), "socks5://10.0.0.1:1080")
        self.assertEqual(backend.proxy_url("http://[::1]:3128"), "http://[::1]:3128")
        for value in ("", "proxy.example.com", "ftp://proxy:21", "http://proxy:bad",
                      "http://proxy:8080/path", "http://a:8080,b:8080", "http://proxy:8080?x=1"):
            with self.subTest(value=value), self.assertRaises(backend.VpnError):
                backend.proxy_url(value)
        with self.assertRaisesRegex(backend.VpnError, "other local users"):
            backend.proxy_url("http://user:secret@proxy.example.com:8080")

    def test_environment_proxy_prefers_https_proxy(self):
        self.assertEqual(backend.environment_proxy(
            {"http_proxy": "http://plain:1", "https_proxy": "http://secure:3128"}),
            "http://secure:3128")
        with self.assertRaisesRegex(backend.VpnError, "No proxy"):
            backend.environment_proxy({})

    def test_resolve_proxy_modes(self):
        self.assertEqual(backend.resolve_proxy("off", "http://ignored:1"), "")
        self.assertEqual(backend.resolve_proxy("manual", "proxy:8080"), "http://proxy:8080")
        with self.assertRaises(backend.VpnError):
            backend.resolve_proxy("bogus", "")

    def test_authenticate_passes_proxy_and_drops_resolve(self):
        text = ("COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\n"
                "FINGERPRINT='sha256:abc'\nRESOLVE='vpn.example.com:10.0.0.1'\n")
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            values = backend.authenticate("https://vpn.example.com", "name", "pw",
                                          "http://proxy.example.com:8080")
        argv = runner.call_args.args[0]
        self.assertEqual(argv[argv.index("--proxy") + 1], "http://proxy.example.com:8080")
        self.assertNotIn("RESOLVE", values)

    def test_authenticate_without_proxy_disables_proxy(self):
        text = "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n"
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            backend.authenticate("https://vpn.example.com", "name", "pw")
        self.assertIn("--no-proxy", runner.call_args.args[0])

    def test_proxy_errors_are_classified(self):
        cases = (
            ("Proxy CONNECT request failed: 407", "requires a login"),
            ("Proxy requested Basic authentication which is disabled by default", "requires a login"),
            ("Failed to parse proxy 'x'", "proxy address is invalid"),
            ("Failed to reconnect to proxy proxy.example.com: Connection refused", "through the proxy"),
        )
        for stderr, expected in cases:
            with self.subTest(stderr=stderr):
                self.assertIn(expected, backend.authentication_error(stderr))

    def test_server_requires_https_without_userinfo(self):
        self.assertEqual(backend.server_url("vpn.example.com/path"), "https://vpn.example.com/path")
        # vpn.data is written through libnm now, so commas are no longer special.
        self.assertEqual(backend.server_url("vpn.example.com/a,b"), "https://vpn.example.com/a,b")
        for address in ("http://vpn.example.com", "https://user:pass@vpn.example.com",
                        "https://vpn.example.com:bad", "vpn.example.com\nbad"):
            with self.subTest(address=address), self.assertRaises(backend.VpnError):
                backend.server_url(address)

    def test_authenticate_parses_only_expected_fields(self):
        text = ("COOKIE='private-cookie'\nHOST='10.0.0.1'\n"
                "CONNECT_URL='https://vpn.example.com/+vpn'\n"
                "FINGERPRINT='sha256:abc'\nRESOLVE='vpn.example.com:10.0.0.1'\n")
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            values = backend.authenticate("https://vpn.example.com", "name", "private-password")
        self.assertEqual(values["COOKIE"], "private-cookie")
        self.assertEqual(values["CONNECT_URL"], "https://vpn.example.com/+vpn")
        self.assertNotIn("HOST", values)
        self.assertNotIn("private-password", runner.call_args.args[0])
        self.assertEqual(runner.call_args.kwargs["input"], "private-password\n")

    def test_activation_passes_secrets_only_to_nm_memory(self):
        values = {"COOKIE": "private-cookie", "CONNECT_URL": "https://vpn.example.com",
                  "FINGERPRINT": "sha256:abc"}
        setting = Mock()
        connection = Mock()
        connection.get_setting_vpn.return_value = setting
        connection.commit_changes.return_value = True
        client = Mock()
        client.get_connection_by_uuid.return_value = connection
        bus = Mock()
        with patch.object(backend.NM.Client, "new", return_value=client), patch.object(
                backend.Gio, "bus_get_sync", return_value=bus), patch.object(
                backend, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as runner:
            backend.activate("00000000-0000-0000-0000-000000000000", values)
        setting.add_secret.assert_any_call("cookie", "private-cookie")
        self.assertEqual(bus.call_sync.call_args.args[3], "ClearSecrets")
        self.assertEqual(connection.commit_changes.call_count, 1)
        self.assertEqual(connection.commit_changes.call_args.args, (False, None))
        self.assertNotIn("private-cookie", " ".join(runner.call_args.args[0]))

    def test_cancel_during_activation_brings_tunnel_down_and_clears_secrets(self):
        values = {"COOKIE": "c", "CONNECT_URL": "https://vpn.example.com", "FINGERPRINT": "f"}
        connection = Mock()
        connection.get_setting_vpn.return_value = Mock()
        connection.commit_changes.return_value = True
        client = Mock()
        client.get_connection_by_uuid.return_value = connection
        bus = Mock()
        with patch.object(backend.NM.Client, "new", return_value=client), patch.object(
                backend.Gio, "bus_get_sync", return_value=bus), patch.object(
                backend, "run", side_effect=backend.VpnCancelled("Connection cancelled")), patch.object(
                backend, "is_active", return_value=True), patch.object(
                backend, "nmcli") as nmcli:
            with self.assertRaises(backend.VpnCancelled):
                backend.activate("00000000-0000-0000-0000-000000000000", values)
        nmcli.assert_called_once_with("connection", "down", "uuid",
                                      "00000000-0000-0000-0000-000000000000", cancellable=False)
        self.assertEqual(bus.call_sync.call_args.args[3], "ClearSecrets")

    def test_clear_secrets_failure_does_not_mask_errors(self):
        bus = Mock()
        bus.call_sync.side_effect = backend.GLib.Error("boom")
        with patch.object(backend.Gio, "bus_get_sync", return_value=bus), patch.object(
                sys, "stderr", io.StringIO()):
            backend.clear_secrets(Mock())

    def test_failed_authentication_never_exposes_cookie(self):
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 2, "", "private-password")):
            with self.assertRaisesRegex(backend.VpnError, "OpenConnect authentication failed") as error:
                backend.authenticate("https://vpn.example.com", "name", "private-password")
            self.assertNotIn("private-password", str(error.exception))

    def test_authentication_error_classifies_without_exposing_server_output(self):
        cases = (
            ("Server certificate verify failed: vpn.example.com", "certificate"),
            ("Failed to connect to vpn.example.com: Connection refused", "Could not reach"),
            ("Failed to resolve host vpn.example.com", "name could not be resolved"),
            ("Authentication failed: wrong password for user name", "rejected the credentials"),
            ("Authentication requires form entry: token for user name", "additional sign-in step"),
        )
        for stderr, expected in cases:
            with self.subTest(stderr=stderr):
                message = backend.authentication_error(stderr)
                self.assertIn(expected, message)
                self.assertNotIn("vpn.example.com", message)
                self.assertNotIn("user name", message)

    def test_connect_reads_one_line_without_waiting_for_eof(self):
        request = {"server": "vpn.example.com", "username": "name", "password": "secret"}
        stdin = io.StringIO(json.dumps(request) + "\nextra input")
        with patch.object(sys, "argv", ["backend.py", "connect"]), patch.object(
                sys, "stdin", stdin), patch.object(
                backend, "ensure_profile", return_value="uuid"), patch.object(
                backend, "authenticate", return_value={"COOKIE": "cookie"}), patch.object(
                backend, "activate"), patch.object(
                backend, "state", return_value={"connected": True}) as state:
            self.assertEqual(backend.main(), state.return_value)
        self.assertEqual(stdin.read(), "extra input")

    def test_cancel_stops_cancellable_child_without_raising(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(backend, "active_child", child), patch.object(
                backend, "active_cancellable", True), patch.object(backend, "cancel_requested", False):
            backend.cancel(None, None)
            self.assertTrue(backend.cancel_requested)
        child.terminate.assert_called_once()

    def test_cancel_leaves_cleanup_child_running(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(backend, "active_child", child), patch.object(
                backend, "active_cancellable", False), patch.object(backend, "cancel_requested", False):
            backend.cancel(None, None)
        child.terminate.assert_not_called()

    def test_run_raises_cancelled_after_sigterm(self):
        import signal, threading, os as _os
        timer = threading.Timer(0.3, _os.kill, (_os.getpid(), signal.SIGTERM))
        with patch.object(backend, "cancel_requested", False):
            timer.start()
            with self.assertRaises(backend.VpnCancelled):
                backend.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=10)
        timer.join()

    def test_pac_and_wpad_helpers(self):
        script = ('function FindProxyForURL(u, h) { if (isPlainHostName(h)) return "DIRECT";'
                  ' if (x) return "PROXY a.corp:8080; PROXY b.corp:8080";'
                  ' return "PROXY a.corp:8080"; }')
        self.assertEqual(backend.pac_proxy(script), "a.corp:8080")
        self.assertEqual(backend.pac_proxy('return "DIRECT";'), "")
        self.assertEqual(backend.wpad_candidates(["eu.corp.example.com"]),
                         ["wpad.eu.corp.example.com", "wpad.corp.example.com", "wpad.example.com"])

    def test_probe_proxy_reports_auth_schemes(self):
        import socket, threading
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        def answer():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Negotiate\r\n"
                         b"Proxy-Authenticate: NTLM\r\n"
                         b"Proxy-Authenticate: Basic realm=\"corp\"\r\n\r\n")
            conn.close()
        thread = threading.Thread(target=answer)
        thread.start()
        result = backend.probe_proxy(f"127.0.0.1:{server.getsockname()[1]}")
        thread.join()
        server.close()
        self.assertEqual(result, {"status": 407, "schemes": ["Negotiate", "NTLM", "Basic"]})

    def test_settings_round_trip_is_private_and_validated(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}):
            self.assertEqual(backend.load_settings(), backend.SETTINGS_DEFAULTS)
            saved = backend.save_settings({"corporateProxy": "http://proxy.corp.local:80/",
                                           "proxyLogin": "me@corp.example", "password": "never"})
            self.assertEqual(saved["corporateProxy"], "proxy.corp.local:80")
            path = backend.settings_path()
            self.assertEqual(backend.os.stat(path).st_mode & 0o777, 0o600)
            with open(path) as handle:
                self.assertNotIn("never", handle.read())
            with self.assertRaises(backend.VpnError):
                backend.save_settings({"corporateProxy": "user:pw@proxy:80"})

    def test_apps_proxy_writes_and_removes_environment_without_credentials(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home, "XDG_CONFIG_HOME": home}), patch.object(
                backend, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as runner:
            self.assertTrue(backend.set_apps_proxy(True)["appsProxy"])
            with open(backend.env_file_path()) as handle:
                text = handle.read()
            for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                self.assertIn(f"{name}=http://127.0.0.1:3128\n", text)
            self.assertIn("no_proxy=localhost,127.0.0.1,::1\n", text)
            self.assertIn("set-environment", runner.call_args.args[0])
            self.assertFalse(backend.set_apps_proxy(False)["appsProxy"])
            self.assertFalse(backend.os.path.exists(backend.env_file_path()))
            self.assertIn("unset-environment", runner.call_args.args[0])

    def test_environment_proxy_ignores_own_forwarder(self):
        with self.assertRaises(backend.VpnError):
            backend.environment_proxy({"https_proxy": "http://127.0.0.1:3128/"})
        self.assertEqual(backend.environment_proxy(
            {"https_proxy": "http://127.0.0.1:3128", "http_proxy": "http://gw-proxy:8080"}),
            "http://gw-proxy:8080")

    PIN = "pin-sha256:9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8="
    UNTRUSTED_STDERR = (
        'Certificate from VPN server "vpn.example.com" failed verification.\n'
        "Reason: signer not found\n"
        "To trust this server in future, perhaps add this to your command line:\n"
        "    --servercert pin-sha256:9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=\n"
        "SSL connection failure: Error in the certificate.\n")

    def test_untrusted_certificate_is_offered_for_pinning(self):
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 1, "", self.UNTRUSTED_STDERR)):
            with self.assertRaises(backend.CertificateUntrusted) as raised:
                backend.authenticate("https://VPN.example.com", "name", "private-password")
        self.assertEqual(raised.exception.details, {
            "host": "vpn.example.com:443", "fingerprint": self.PIN,
            "reason": "signer not found", "changed": False})
        self.assertIn("signer not found", str(raised.exception))
        self.assertNotIn("private-password", repr(raised.exception.details))

    def test_changed_pinned_certificate_warns(self):
        stderr = ("None of the 1 fingerprint(s) specified via --servercert match server's "
                  f"certificate: {self.PIN}\n")
        error = backend.certificate_failure(stderr, "https://vpn.example.com:8443")
        self.assertTrue(error.details["changed"])
        self.assertEqual(error.details["host"], "vpn.example.com:8443")
        self.assertIn("CHANGED", str(error))

    def test_pinned_certificate_is_passed_to_openconnect(self):
        text = "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n"
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            backend.authenticate("https://vpn.example.com", "name", "pw", servercert=self.PIN)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[argv.index("--servercert") + 1], self.PIN)

    def test_accepted_pin_does_not_blame_certificate(self):
        stderr = ("Server certificate verify failed: signer not found\n"
                  "Connected to HTTPS on vpn.example.com with ciphersuite (TLS1.3)\n"
                  "Login failed.\n")
        self.assertIn("rejected the credentials", backend.authentication_error(stderr))

    def test_trust_and_forget_certificate_per_host(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}):
            backend.trust_certificate({"server": "vpn.example.com/group", "fingerprint": self.PIN})
            self.assertEqual(backend.trusted_certificate("https://VPN.example.com"), self.PIN)
            self.assertEqual(backend.trusted_certificate("https://vpn.example.com:8443"), "")
            self.assertEqual(backend.trusted_certificate("https://other.example.com"), "")
            with self.assertRaisesRegex(backend.VpnError, "Invalid certificate"):
                backend.trust_certificate({"server": "vpn.example.com", "fingerprint": "nope"})
            backend.forget_certificate({"server": "vpn.example.com"})
            self.assertEqual(backend.trusted_certificate("https://vpn.example.com"), "")

    def test_generic_save_settings_cannot_set_trusted_certificates(self):
        import tempfile
        request = {"trustedCertificates": {"evil.example.com:443": self.PIN}, "proxyLogin": "me"}
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                sys, "argv", ["backend.py", "save-settings"]), patch.object(
                sys, "stdin", io.StringIO(json.dumps(request) + "\n")):
            settings = backend.main()["settings"]
        self.assertEqual(settings["trustedCertificates"], {})
        self.assertEqual(settings["proxyLogin"], "me")


if __name__ == "__main__":
    unittest.main()
