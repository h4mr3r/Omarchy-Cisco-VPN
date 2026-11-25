import io
import os
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
            ("Authentication requires form entry: token for user name", "more sign-in input"),
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
                backend, "tunnel_pid", return_value=0), patch.object(
                backend, "helper_state", return_value="installed"), patch.object(
                backend, "save_settings", return_value=dict(backend.SETTINGS_DEFAULTS)), patch.object(
                backend, "authenticate", return_value={"COOKIE": "cookie"}), patch.object(
                backend, "tunnel_up"), patch.object(
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

    def test_ignore_mode_retries_with_presented_certificate(self):
        import tempfile
        untrusted = subprocess.CompletedProcess([], 1, "", self.UNTRUSTED_STDERR)
        ok = subprocess.CompletedProcess(
            [], 0, "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n", "")
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}):
            with patch.object(backend, "run", return_value=untrusted), self.assertRaises(
                    backend.CertificateUntrusted):
                backend.authenticate_server("https://vpn.example.com", "name", "pw", "")
            backend.ignore_certificate({"server": "vpn.example.com"})
            self.assertTrue(backend.ignored_for("https://vpn.example.com"))
            self.assertFalse(backend.ignored_for("https://other.example.com"))
            with patch.object(backend, "run", side_effect=[untrusted, ok]) as runner:
                values = backend.authenticate_server("https://vpn.example.com", "name", "pw", "")
            self.assertEqual(values["COOKIE"], "c")
            retry = runner.call_args_list[1].args[0]
            self.assertEqual(retry[retry.index("--servercert") + 1], self.PIN)
            backend.forget_certificate({"server": "vpn.example.com"})
            self.assertFalse(backend.ignored_for("https://vpn.example.com"))

    def test_client_identity_is_passed_to_openconnect(self):
        text = "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n"
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            backend.authenticate("https://vpn.example.com", "name", "pw",
                                 version="5.1.15.287", hostname="my-laptop.corp")
        argv = runner.call_args.args[0]
        self.assertIn("--version-string=5.1.15.287", argv)
        self.assertIn("--local-hostname=my-laptop.corp", argv)
        self.assertLess(argv.index("--version-string=5.1.15.287"), argv.index("--user"))
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            backend.authenticate("https://vpn.example.com", "name", "pw")
        self.assertFalse(any(arg.startswith(("--version-string", "--local-hostname"))
                             for arg in runner.call_args.args[0]))

    def test_client_identity_validation(self):
        self.assertEqual(backend.version_string(" 5.1.15.287 "), "5.1.15.287")
        self.assertEqual(backend.local_hostname("hostname"), "hostname")
        for value in ("5.1 beta", "--os=win", "5;rm", "x" * 65):
            with self.subTest(value=value), self.assertRaises(backend.VpnError):
                backend.version_string(value)
        for value in ("-host", "host name", "host..corp", "host_name", "host.", "a" * 254):
            with self.subTest(value=value), self.assertRaises(backend.VpnError):
                backend.local_hostname(value)

    def test_connect_saves_identity_and_uses_it(self):
        import tempfile
        request = {"server": "vpn.example.com", "username": "name", "password": "secret",
                   "versionString": "5.1.15.287", "localHostname": "hostname"}
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                sys, "argv", ["backend.py", "connect"]), patch.object(
                sys, "stdin", io.StringIO(json.dumps(request) + "\n")), patch.object(
                backend, "tunnel_pid", return_value=0), patch.object(
                backend, "helper_state", return_value="installed"), patch.object(
                backend, "authenticate", return_value={"COOKIE": "c"}) as auth, patch.object(
                backend, "tunnel_up"), patch.object(backend, "state", return_value={}):
            backend.main()
            self.assertEqual(auth.call_args.kwargs, {"version": "5.1.15.287", "hostname": "hostname",
                                                     "no_xmlpost": False, "reported_os": ""})
            saved = backend.load_settings()
        self.assertEqual((saved["versionString"], saved["localHostname"]), ("5.1.15.287", "hostname"))

    def test_extra_prompt_is_answered_with_enter_on_retry(self):
        import tempfile
        stalled = subprocess.CompletedProcess(
            [], 1, "", "Username:Password:\nUser input required in non-interactive mode\n")
        ok = subprocess.CompletedProcess(
            [], 0, "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n", "")
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                backend, "run", side_effect=[stalled, ok]) as runner:
            values = backend.authenticate_server("https://vpn.example.com", "name", "pw", "")
        self.assertEqual(values["COOKIE"], "c")
        first, second = (call.args[0] for call in runner.call_args_list)
        self.assertIn("--non-inter", first)
        self.assertNotIn("--non-inter", second)
        self.assertEqual(runner.call_args_list[0].kwargs["input"], "pw\n")
        self.assertEqual(runner.call_args_list[1].kwargs["input"], "pw\n\n\n\n")

    def test_failed_retry_reports_login_failure(self):
        import tempfile
        stalled = subprocess.CompletedProcess(
            [], 1, "", "User input required in non-interactive mode\n")
        failed = subprocess.CompletedProcess(
            [], 1, "", "Login failed.\nUsername:Password:\nfgets (stdin): Inappropriate ioctl\n")
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                backend, "run", side_effect=[stalled, failed]) as runner:
            with self.assertRaisesRegex(backend.VpnError, "rejected the credentials"):
                backend.authenticate_server("https://vpn.example.com", "name", "pw", "")
        self.assertEqual(runner.call_count, 2)


    def test_no_xmlpost_is_passed_only_when_enabled(self):
        text = "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n"
        for enabled in (True, False):
            with self.subTest(enabled=enabled), patch.object(
                    backend, "run",
                    return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
                backend.authenticate("https://vpn.example.com", "name", "pw", no_xmlpost=enabled)
                argv = runner.call_args.args[0]
                self.assertEqual("--no-xmlpost" in argv, enabled)
                if enabled:
                    self.assertLess(argv.index("--no-xmlpost"), argv.index("--user"))

    def test_split_routes_validation(self):
        networks = backend.split_routes(" 10.1.2.3/8, 172.16.0.0/16;10.0.0.0/8 ")
        self.assertEqual([str(n) for n in networks], ["10.0.0.0/8", "172.16.0.0/16"])
        self.assertEqual(backend.split_routes(""), [])
        # IPv6 is disabled in the tunnel, so only IPv4 networks are accepted.
        for value in ("10.0.0.0/33", "not-a-net", "0.0.0.0/0", "fd00::/8", "--script=x"):
            with self.subTest(value=value), self.assertRaises(backend.VpnError):
                backend.split_routes(value)
        with self.assertRaises(backend.VpnError):
            backend.split_routes(",".join(f"10.{i}.0.0/16" for i in range(65)))

    def test_reported_os_is_validated_and_passed(self):
        import tempfile
        text = "COOKIE='c'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='f'\n"
        with patch.object(backend, "run",
                          return_value=subprocess.CompletedProcess([], 0, text, "")) as runner:
            backend.authenticate("https://vpn.example.com", "name", "pw", reported_os="win")
        argv = runner.call_args.args[0]
        self.assertLess(argv.index("--os=win"), argv.index("--user"))
        with self.assertRaises(backend.VpnError):
            backend.authenticate("https://vpn.example.com", "name", "pw", reported_os="--script=x")
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}):
            self.assertEqual(backend.save_settings({"reportedOs": "win"})["reportedOs"], "win")
            with self.assertRaises(backend.VpnError):
                backend.save_settings({"reportedOs": "windows; rm"})


    # --- tunnel through the root helper -----------------------------------

    AUTH = {"COOKIE": "webvpn=abc", "CONNECT_URL": "https://gw.example.com",
            "FINGERPRINT": "pin-sha256:" + "A" * 43 + "=", "RESOLVE": "gw.example.com:192.0.2.1"}

    def test_connect_logs_in_as_user_then_starts_tunnel_with_settings(self):
        import tempfile
        request = {"server": "gw.example.com", "username": "name", "password": "secret",
                   "noXmlPost": True, "reportedOs": "win", "versionString": "5.1.21.2728",
                   "splitRoutes": "172.16.0.0/16, 10.0.0.0/8"}
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                sys, "argv", ["backend.py", "connect"]), patch.object(
                sys, "stdin", io.StringIO(json.dumps(request) + "\n")), patch.object(
                backend, "tunnel_pid", return_value=0), patch.object(
                backend, "helper_state", return_value="installed"), patch.object(
                backend, "authenticate", return_value=dict(self.AUTH)) as auth, patch.object(
                backend, "run_helper", return_value={"ok": True}) as helper, patch.object(
                backend, "state", return_value={}):
            backend.main()
            saved = backend.load_settings()
        self.assertEqual(auth.call_args.kwargs["reported_os"], "win")
        self.assertTrue(auth.call_args.kwargs["no_xmlpost"])
        action, tunnel = helper.call_args.args
        self.assertEqual(action, "up")
        self.assertEqual(tunnel, {
            "url": "https://gw.example.com", "cookie": "webvpn=abc",
            "fingerprint": self.AUTH["FINGERPRINT"], "resolve": "gw.example.com:192.0.2.1",
            "proxy": "", "version": "5.1.21.2728", "hostname": "", "os": "win",
            "routes": ["172.16.0.0/16", "10.0.0.0/8"]})
        self.assertNotIn("secret", json.dumps(tunnel))
        self.assertEqual((saved["server"], saved["username"]), ("https://gw.example.com", "name"))

    def test_connect_requires_installed_helper_before_login(self):
        request = {"server": "gw.example.com", "username": "name", "password": "secret"}
        with patch.object(sys, "argv", ["backend.py", "connect"]), patch.object(
                sys, "stdin", io.StringIO(json.dumps(request) + "\n")), patch.object(
                backend, "tunnel_pid", return_value=0), patch.object(
                backend, "helper_state", return_value="missing"), patch.object(
                backend, "authenticate") as auth:
            with self.assertRaisesRegex(backend.VpnError, "Install the VPN helper"):
                backend.main()
        auth.assert_not_called()

    def test_invalid_split_routes_stop_before_login(self):
        import tempfile
        request = {"server": "gw.example.com", "username": "name", "password": "secret",
                   "splitRoutes": "10.0.0.0/99"}
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                sys, "argv", ["backend.py", "connect"]), patch.object(
                sys, "stdin", io.StringIO(json.dumps(request) + "\n")), patch.object(
                backend, "tunnel_pid", return_value=0), patch.object(
                backend, "helper_state", return_value="installed"), patch.object(
                backend, "authenticate") as auth:
            with self.assertRaisesRegex(backend.VpnError, "Invalid network"):
                backend.main()
        auth.assert_not_called()

    def test_cancel_during_tunnel_start_brings_it_down(self):
        with patch.object(backend, "run_helper", return_value={"ok": True}) as helper, patch.object(
                backend, "cancel_requested", True):
            with self.assertRaises(backend.VpnCancelled):
                backend.tunnel_up(dict(self.AUTH), dict(backend.SETTINGS_DEFAULTS), [], "")
        self.assertEqual([call.args[0] for call in helper.call_args_list], ["up", "down"])

    def test_run_helper_uses_pkexec_and_reports_helper_errors(self):
        reply = subprocess.CompletedProcess([], 1, '{"ok": false, "error": "Could not reach the VPN server"}\n', "")
        with patch.object(backend, "helper_state", return_value="installed"), patch.object(
                backend, "run", return_value=reply) as runner:
            with self.assertRaisesRegex(backend.VpnError, "Could not reach the VPN server"):
                backend.run_helper("up", {"url": "x"})
        argv = runner.call_args.args[0]
        self.assertEqual(argv, ["pkexec", backend.TUNNEL_HELPER, "up"])
        self.assertEqual(json.loads(runner.call_args.kwargs["input"]), {"url": "x"})
        self.assertFalse(runner.call_args.kwargs["cancellable"])

    def test_run_helper_explains_refused_authorization(self):
        with patch.object(backend, "helper_state", return_value="installed"), patch.object(
                backend, "run", return_value=subprocess.CompletedProcess([], 126, "", "")):
            with self.assertRaisesRegex(backend.VpnError, "reinstall the VPN helper"):
                backend.run_helper("down")

    def test_status_reads_saved_server_and_tunnel_state(self):
        import tempfile
        with tempfile.TemporaryDirectory() as home, patch.dict(
                backend.os.environ, {"XDG_STATE_HOME": home}), patch.object(
                backend, "tunnel_pid", return_value=1234), patch.object(
                backend, "tunnel_info", return_value={"device": "tun0", "address": "172.16.195.3"}), patch.object(
                backend, "helper_state", return_value="installed"):
            backend.save_settings({"server": "gw.example.com", "username": "name",
                                   "gatewayProxy": "http://proxy.example.com:8080"})
            status = backend.state()
        self.assertEqual({k: status[k] for k in ("connected", "server", "username", "proxy",
                                                 "tunnelHelper", "vpnDevice", "vpnAddress")},
                         {"connected": True, "server": "https://gw.example.com", "username": "name",
                          "proxy": "http://proxy.example.com:8080", "tunnelHelper": "installed",
                          "vpnDevice": "tun0", "vpnAddress": "172.16.195.3"})

    def test_tunnel_pid_requires_a_live_openconnect(self):
        import tempfile
        with tempfile.TemporaryDirectory() as run_dir, patch.object(backend, "TUNNEL_RUN_DIR", run_dir):
            self.assertEqual(backend.tunnel_pid(), 0)
            with open(os.path.join(run_dir, "openconnect.pid"), "w") as handle:
                handle.write(f"{os.getpid()}\n")  # alive, but not openconnect
            self.assertEqual(backend.tunnel_pid(), 0)

    def test_helper_state_compares_installed_copy(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            source, target = os.path.join(tmp, "source.py"), os.path.join(tmp, "target")
            with open(source, "w") as handle:
                handle.write("v2\n")
            with patch.object(backend, "TUNNEL_HELPER_SOURCE", source), patch.object(
                    backend, "TUNNEL_HELPER", target):
                self.assertEqual(backend.helper_state(), "missing")
                with open(target, "w") as handle:
                    handle.write("v1\n")
                self.assertEqual(backend.helper_state(), "outdated")
                with open(target, "w") as handle:
                    handle.write("v2\n")
                self.assertEqual(backend.helper_state(), "installed")


if __name__ == "__main__":
    unittest.main()
