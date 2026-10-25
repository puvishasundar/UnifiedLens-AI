"""
Security tests for the UnifiedLens URL Scanner.

Run from the project root:   python -m unittest tests.test_url_security -v

Strategy
  * 127.0.0.1 is temporarily treated as "public" so a local server can play the
    part of an internet host; 127.0.0.2 (also this machine) stays blocked and
    plays the part of an internal service. A hit-counter on the "internal"
    path proves the scanner never actually contacted it.
  * analyzer.py needs ML modules that are not part of this repo snapshot, so
    they are replaced with tiny stubs — the security code under test is real.
"""
import ast
import gzip
import http.server
import io
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request
from collections import Counter, deque
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import requests
import url_security as sec

_REAL_IS_PUBLIC = sec._ip_is_public


def _allow_127_0_0_1(ip):
    """Test double: pretend 127.0.0.1 (and ::1, for 'localhost') is a public host."""
    return str(ip) in ("127.0.0.1", "::1") or _REAL_IS_PUBLIC(ip)


# ─── local test servers ─────────────────────────────────────────────────────
class _Handler(http.server.BaseHTTPRequestHandler):
    hits = Counter()
    port = 0

    def log_message(self, *a):
        pass

    def _redirect(self, location, code=302):
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        type(self).hits[self.path] += 1
        p = self.path
        if p == "/ok":
            body = ("<html><head><title>Test page</title></head><body><p>hello world. "
                    + "This is an ordinary static page with enough visible text to be analysed. " * 4
                    + "</p></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif p == "/secret":                               # the "internal service"
            body = b"INTERNAL SECRET"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif p == "/to-internal":
            self._redirect(f"http://127.0.0.2:{self.port}/secret")
        elif p == "/to-metadata":
            self._redirect("http://169.254.169.254/latest/meta-data/")
        elif p == "/to-file":
            self._redirect("file:///etc/passwd")
        elif p == "/to-ok":
            self._redirect("/ok")
        elif p == "/loop":
            self._redirect("/loop")
        elif p.startswith("/chain/"):
            n = int(p.rsplit("/", 1)[1])
            self._redirect("/ok" if n <= 0 else f"/chain/{n - 1}")
        elif p == "/big":
            size = 10 * 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            try:
                for _ in range(size // 65536):
                    self.wfile.write(b"A" * 65536)
            except OSError:
                pass
        elif p == "/bomb":                                 # ~100 MB of zeros, tiny on the wire
            comp = io.BytesIO()
            with gzip.GzipFile(fileobj=comp, mode="wb") as gz:
                for _ in range(100):
                    gz.write(b"\0" * (1024 * 1024))
            data = comp.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except OSError:
                pass
        elif p == "/slow":                                 # slow-drip: 1 byte / 0.2 s
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100000")
            self.end_headers()
            try:
                for _ in range(300):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def _start_server(handler_cls=_Handler, tls_ctx=None):
    handler = type("H", (handler_cls,), {"hits": Counter()})
    srv = _Server(("0.0.0.0", 0), handler)
    handler.port = srv.server_address[1]
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler


class SecurityTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.H = _start_server()
        cls.port = cls.H.port
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.H.hits.clear()
        sec._rl_hits.clear()
        p = mock.patch.object(sec, "_ip_is_public", _allow_127_0_0_1)
        p.start()
        self.addCleanup(p.stop)


# ─── 1. address classification ──────────────────────────────────────────────
class TestIpClassification(unittest.TestCase):
    def test_non_public_addresses_rejected(self):
        for ip in ["127.0.0.1", "127.8.9.10", "10.0.0.5", "172.16.0.1", "172.31.255.255",
                   "192.168.1.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.100.100.200",
                   "0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1", "192.0.2.1",
                   "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
                   "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
                   "2002:7f00:1::", "2002:0a00:0001::", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"]:
            self.assertFalse(_REAL_IS_PUBLIC(ip), f"{ip} should be blocked")

    def test_public_addresses_allowed(self):
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888"]:
            self.assertTrue(_REAL_IS_PUBLIC(ip), f"{ip} should be allowed")


# ─── 2. URL validation (pre-flight) ─────────────────────────────────────────
class TestUrlValidation(unittest.TestCase):
    def _blocked(self, url):
        with self.assertRaises(sec.BlockedTargetError, msg=url):
            sec.check_public_url(url)

    def test_private_hosts_and_alternate_spellings(self):
        for url in ["http://127.0.0.1/", "http://localhost/",
                    "http://10.1.2.3/", "http://192.168.0.1:8080/admin",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fe80::1]/",
                    "http://2130706433/", "http://0x7f000001/", "http://017700000001/",
                    "http://127.1/", "http://0/", "http://0.0.0.0/",
                    "http://example.com@127.0.0.1/", "http://127.0.0.1#@example.com/",
                    "https://127.0.0.1:8501/"]:
            self._blocked(url)

    def test_trailing_dot_localhost(self):
        try:
            socket.getaddrinfo("localhost.", 80)
        except socket.gaierror:
            self.skipTest("resolver does not resolve 'localhost.'; request would fail anyway")
        self._blocked("http://localhost./")

    def test_bad_schemes_and_shapes(self):
        for url in ["file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/",
                    "javascript:alert(1)", "data:text/html,hi", "http://", "http:///path",
                    "http://example.com:99999/", "http://exa mple.com/",
                    "http://example.com/" + "a" * 3000]:
            self._blocked(url)

    def test_unresolvable_host_is_not_blocked(self):
        # Fails later with a normal connection error, exactly like before.
        sec.check_public_url("http://this-host-does-not-exist.invalid/")


# ─── 3. safe_get: redirects, size, time ─────────────────────────────────────
class TestSafeGet(SecurityTestBase):
    def test_normal_fetch_still_works(self):
        r = sec.safe_get(f"{self.base}/ok", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn("hello world", r.text)                  # .text / .content / headers intact
        self.assertEqual(r.headers["Content-Type"], "text/html")
        self.assertEqual(len(r.content), len(r.text))

    def test_private_target_never_contacted(self):
        with mock.patch.object(sec, "_ip_is_public", _REAL_IS_PUBLIC):   # real rules
            with self.assertRaises(sec.BlockedTargetError):
                sec.safe_get(f"{self.base}/ok", timeout=5)
        self.assertEqual(sum(self.H.hits.values()), 0)

    def test_redirect_to_internal_blocked(self):
        with self.assertRaises(sec.BlockedTargetError) as cm:
            sec.safe_get(f"{self.base}/to-internal", timeout=5)
        self.assertIn("Redirect", str(cm.exception))
        self.assertEqual(self.H.hits["/secret"], 0, "internal service must not be contacted")

    def test_redirect_to_cloud_metadata_blocked(self):
        with self.assertRaises(sec.BlockedTargetError):
            sec.safe_get(f"{self.base}/to-metadata", timeout=5)

    def test_redirect_to_file_scheme_blocked(self):
        with self.assertRaises(sec.BlockedTargetError):
            sec.safe_get(f"{self.base}/to-file", timeout=5)

    def test_safe_redirect_is_followed(self):
        r = sec.safe_get(f"{self.base}/to-ok", timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertIn("hello world", r.text)

    def test_redirect_loop_and_long_chain_stop(self):
        with self.assertRaises(requests.exceptions.TooManyRedirects):
            sec.safe_get(f"{self.base}/loop", timeout=5)
        self.assertLessEqual(self.H.hits["/loop"], sec.MAX_REDIRECTS + 1)
        with self.assertRaises(requests.exceptions.TooManyRedirects):
            sec.safe_get(f"{self.base}/chain/20", timeout=5)
        r = sec.safe_get(f"{self.base}/chain/3", timeout=5)      # within the limit
        self.assertEqual(r.status_code, 200)

    def test_oversized_body_is_capped(self):
        t0 = time.time()
        r = sec.safe_get(f"{self.base}/big", timeout=10)
        self.assertEqual(len(r.content), sec.MAX_RESPONSE_BYTES)
        self.assertLess(time.time() - t0, 10)

    def test_gzip_bomb_is_capped(self):
        t0 = time.time()
        r = sec.safe_get(f"{self.base}/bomb", timeout=10)
        self.assertLessEqual(len(r.content), sec.MAX_RESPONSE_BYTES)   # 100 MB decoded -> 2 MB
        self.assertLess(time.time() - t0, 10)

    def test_slow_drip_is_cut_off_at_deadline(self):
        t0 = time.time()
        r = sec.safe_get(f"{self.base}/slow", timeout=30, total_timeout=2)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 5, f"slow-drip held the scan for {elapsed:.1f}s")
        self.assertLess(len(r.content), 100)


# ─── 4. connect-time guard (DNS rebinding / parser differentials) ───────────
class TestConnectGuard(SecurityTestBase):
    def test_guard_blocks_even_if_preflight_is_bypassed(self):
        # Simulates DNS rebinding: the pre-flight saw a public IP, but the real
        # connection is to an internal one (127.0.0.2).
        url = f"http://127.0.0.2:{self.port}/secret"
        with sec.ssrf_guard():
            with self.assertRaises(requests.exceptions.ConnectionError):
                requests.get(url, timeout=3)
        self.assertEqual(self.H.hits["/secret"], 0)

    def test_guard_covers_stdlib_urllib(self):
        # e.g. a model module that fetches pages with urllib instead of requests
        url = f"http://127.0.0.2:{self.port}/secret"
        with sec.ssrf_guard():
            with self.assertRaises(Exception):
                urllib.request.urlopen(url, timeout=3).read()
        self.assertEqual(self.H.hits["/secret"], 0)

    def test_no_guard_outside_a_scan(self):
        r = requests.get(f"http://127.0.0.2:{self.port}/secret", timeout=3)   # unrelated app traffic
        self.assertEqual(r.text, "INTERNAL SECRET")

    def test_guard_is_thread_local(self):
        out = {}

        def other_thread():
            out["r"] = requests.get(f"http://127.0.0.2:{self.port}/secret", timeout=3).text

        with sec.ssrf_guard():
            t = threading.Thread(target=other_thread)
            t.start(); t.join()
        self.assertEqual(out.get("r"), "INTERNAL SECRET")

    def test_guard_is_reentrant_and_releases(self):
        with sec.ssrf_guard():
            with sec.ssrf_guard():
                self.assertTrue(sec._guard_active())
            self.assertTrue(sec._guard_active())
        self.assertFalse(sec._guard_active())

    def _tls_server(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        d = tempfile.mkdtemp()
        key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", crt, "-subj", "/CN=localhost", "-days", "1"],
                       check=True, capture_output=True)
        seen = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        ctx.sni_callback = lambda sock, name, c: seen.append(name)
        srv, H = _start_server(tls_ctx=ctx)
        return srv, H, seen

    def test_https_slow_drip_is_cut_off(self):
        srv, H, _ = self._tls_server()
        try:
            t0 = time.time()
            with mock.patch.object(sec, "_ip_is_public", _allow_127_0_0_1):
                r = sec.safe_get(f"https://127.0.0.1:{H.port}/slow", timeout=30, total_timeout=2)
            self.assertLess(time.time() - t0, 6, "TLS slow-drip must also hit the deadline")
            self.assertLess(len(r.content), 100)
        finally:
            srv.shutdown()

    def test_https_sni_preserved_when_pinned_to_ip(self):
        srv, H, seen = self._tls_server()
        try:
            with mock.patch.object(sec, "_ip_is_public", _allow_127_0_0_1):
                with sec.ssrf_guard():
                    r = requests.get(f"https://localhost:{H.port}/ok", timeout=5, verify=False)
            self.assertEqual(r.status_code, 200)
            self.assertIn("localhost", seen, "SNI hostname must survive IP pinning")
        finally:
            srv.shutdown()


# ─── 5. rate limiting + scan gate ───────────────────────────────────────────
class TestRateLimit(unittest.TestCase):
    def setUp(self):
        sec._rl_hits.clear()

    def test_per_session_limit_and_recovery(self):
        t = 1000.0
        for i in range(sec.RATE_MAX_PER_SESSION):
            self.assertTrue(sec.check_rate_limit("s1", now=t + i * 0.1)[0])
        ok, retry = sec.check_rate_limit("s1", now=t + 2)
        self.assertFalse(ok)
        self.assertTrue(1 <= retry <= sec.RATE_WINDOW_S + 1)
        self.assertTrue(sec.check_rate_limit("s2", now=t + 2)[0], "other sessions unaffected")
        self.assertTrue(sec.check_rate_limit("s1", now=t + sec.RATE_WINDOW_S + 5)[0], "window expires")

    def test_global_limit_across_sessions(self):
        t = 5000.0
        for i in range(sec.RATE_MAX_GLOBAL):
            self.assertTrue(sec.check_rate_limit(f"user{i}", now=t)[0])
        self.assertFalse(sec.check_rate_limit("brand-new-user", now=t + 1)[0])

    def test_rejected_attempts_do_not_extend_lockout(self):
        t = 9000.0
        for _ in range(sec.RATE_MAX_PER_SESSION):
            sec.check_rate_limit("s", now=t)
        for i in range(200):
            self.assertFalse(sec.check_rate_limit("s", now=t + 1 + i * 0.1)[0])
        self.assertTrue(sec.check_rate_limit("s", now=t + sec.RATE_WINDOW_S + 1)[0])

    def test_memory_is_bounded(self):
        t = 20000.0
        for i in range(sec._RL_MAX_KEYS + 50):
            sec._rl_hits[f"old{i}"] = deque([t - 500])
        sec.check_rate_limit("trigger", now=t)
        self.assertLess(len(sec._rl_hits), 100)

    def test_scan_gate_decorator(self):
        calls = []

        @sec.scan_gate
        def scan(url):
            calls.append((url, sec._guard_active()))
            return {"ok": True}

        for _ in range(sec.RATE_MAX_PER_SESSION):
            self.assertEqual(scan("http://a.example"), {"ok": True})
        self.assertTrue(all(active for _, active in calls), "scan must run inside the SSRF guard")
        limited = scan("http://a.example")
        self.assertIn("error", limited)
        self.assertIn("Too many scan requests", limited["error"])
        self.assertEqual(scan(""), {"ok": True})            # empty URL is not rate limited


# ─── 6. browser helpers (Playwright is mocked: no Chromium in the test env) ─
class TestBrowserHelpers(unittest.TestCase):
    class _Req:
        def __init__(self, url, rtype="document"):
            self.url, self.resource_type = url, rtype

    class _Route:
        def __init__(self, req):
            self.request, self.result = req, None

        def continue_(self): self.result = "continue"
        def abort(self): self.result = "abort"

    def _decide(self, handler, url, rtype="document"):
        route = self._Route(self._Req(url, rtype))
        handler(route)
        return route.result

    def test_route_guard_decisions(self):
        with mock.patch.object(sec, "_ip_is_public", _allow_127_0_0_1):
            h = sec.make_route_guard()
            self.assertEqual(self._decide(h, "http://127.0.0.1:1/x"), "continue")
            self.assertEqual(self._decide(h, "http://127.0.0.2:1/x"), "abort")          # internal
            self.assertEqual(self._decide(h, "http://169.254.169.254/latest"), "abort")  # metadata
            self.assertEqual(self._decide(h, "http://[::1]:1/"), "continue")             # patched public
            self.assertEqual(self._decide(h, "file:///etc/passwd"), "abort")
            self.assertEqual(self._decide(h, "ftp://example.com/"), "abort")
            self.assertEqual(self._decide(h, "data:text/html,hi"), "continue")
            self.assertEqual(self._decide(h, "about:blank"), "continue")
            self.assertEqual(self._decide(h, "http://127.0.0.1:1/a.woff", "font"), "abort")
            self.assertEqual(self._decide(h, "http://127.0.0.1:1/v.mp4", "media"), "abort")

    def test_route_guard_fails_closed_on_errors(self):
        h = sec.make_route_guard()

        class Broken:
            @property
            def request(self): raise RuntimeError("boom")
            def abort(self): self.aborted = True

        b = Broken()
        h(b)
        self.assertTrue(getattr(b, "aborted", False))

    def test_browser_concurrency_limit(self):
        release = threading.Event()
        started = threading.Barrier(sec.MAX_CONCURRENT_BROWSERS + 1, timeout=5)

        @sec.limit_browser_concurrency
        def render():
            started.wait()
            release.wait(5)
            return "<html/>", 200, None

        threads = [threading.Thread(target=render) for _ in range(sec.MAX_CONCURRENT_BROWSERS)]
        for t in threads:
            t.start()
        started.wait()                                       # all slots now busy
        with mock.patch.object(sec, "BROWSER_SLOT_WAIT_S", 0.2):
            html, status, err = render()
        self.assertIsNone(html)
        self.assertIn("busy", err)
        release.set()
        for t in threads:
            t.join()
        # slots are released again afterwards
        for _ in range(sec.MAX_CONCURRENT_BROWSERS):
            self.assertTrue(sec._BROWSER_SLOTS.acquire(timeout=1))
        for _ in range(sec.MAX_CONCURRENT_BROWSERS):
            sec._BROWSER_SLOTS.release()


# ─── 7. analyzer.py integration (heavy ML modules stubbed) ──────────────────
def _install_stubs():
    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m

    risk = lambda s: {"level": "SAFE" if s < 20 else "HIGH", "color": "#0f0", "emoji": "x"}
    mod("pytesseract", pytesseract=types.SimpleNamespace(tesseract_cmd=""),
        get_languages=lambda config="": ["eng"])
    mod("utils",
        score_keywords=lambda t: {"score": 0, "found": []},
        compute_risk_level=risk, normalise_score=lambda s, ceiling=20.0: 0,
        analyse_url=lambda u: {"risk_score": 5, "risk_level": "SAFE", "is_https": False, "has_ip": False,
                               "is_long": False, "suspicious_kw": [], "tld_risk": 0, "tld": "com",
                               "typosquat_risk": False, "is_known_legit": False, "flags": [],
                               "domain": "127.0.0.1"},
        analyse_recruiter_email=None, analyse_company_name=None, analyse_email_full=None,
        verify_company_identity=None, _domain_core=None, SCAM_KEYWORDS={}, SHORTENER_DOMAINS=[],
        PUBLIC_EMAIL_PROVIDERS=set(), DISPOSABLE_EMAIL_DOMAINS=set(),
        detect_domain_typosquat=lambda d: {"detected": False})
    mod("ml_model", predict=lambda t: {"label": "safe", "probability": 0.1, "confidence": 0.9},
        get_feature_importance=lambda t, top_n=8: [], rule_based_scam_score=lambda t: 0)

    fetched_by_model = []

    def url_ml_predict(url):                      # a "model" that fetches the page itself
        try:
            requests.get(url, timeout=3)
            fetched_by_model.append("FETCHED")
        except Exception as e:
            fetched_by_model.append(type(e).__name__)
        return {"label": "unknown", "probability": 0.0, "fetched": False}

    mod("url_model", predict_url=url_ml_predict, get_feature_importance_url=lambda u, top_n=5: [])
    mod("language_utils", detect_and_translate=lambda t: {}, tag_segments=lambda t: [])
    mod("trusted_companies", match_trusted_domain=lambda d: None, detect_brand_impersonation=lambda d: None,
        company_name_matches_brand=lambda n: None)
    return fetched_by_model


class TestAnalyzerIntegration(SecurityTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.model_fetches = _install_stubs()
        import importlib
        sys.modules.pop("analyzer", None)
        cls.an = importlib.import_module("analyzer")

    def setUp(self):
        super().setUp()
        self.model_fetches.clear()

    def test_private_url_is_not_fetched_and_explained(self):
        with mock.patch.object(sec, "_ip_is_public", _REAL_IS_PUBLIC):
            res = self.an.analyse_url_full(f"{self.base}/ok")
        self.assertEqual(sum(self.H.hits.values()), 0, "scanner must not touch a private target")
        self.assertFalse(res["content_analysis"]["fetched"])
        self.assertIn("Blocked", res["content_analysis"]["error"])
        self.assertTrue(any("private/internal" in i for i in res["indicators"]))
        self.assertEqual(self.model_fetches, ["ConnectionError"], "URL-model fetch must also be blocked")
        self.assertEqual(res["risk_score"], 5)                   # scoring pipeline still ran, no page bonus

    def test_public_url_still_scanned_normally(self):
        res = self.an.analyse_url_full(f"{self.base}/ok")
        self.assertTrue(res["content_analysis"]["fetched"], res["content_analysis"]["error"])
        self.assertIn("hello world", res["content_analysis"]["extracted_text"])
        self.assertFalse(any("private/internal" in i for i in res["indicators"]))
        # Same formula as before the security work: heuristic 5 + text-model bonus round(0.1*35)=4.
        # (A blocked target keeps the bare heuristic score of 5 — see the private-URL test.)
        self.assertEqual(res["risk_score"], 5 + round(0.1 * 35))

    def test_redirect_to_internal_through_full_pipeline(self):
        res = self.an.analyse_url_full(f"{self.base}/to-internal")
        self.assertEqual(self.H.hits["/secret"], 0)
        self.assertFalse(res["content_analysis"]["fetched"])
        self.assertIn("Redirect", res["content_analysis"]["error"])

    def test_rate_limit_through_public_entry_point(self):
        for _ in range(sec.RATE_MAX_PER_SESSION):
            self.assertNotIn("error", self.an.analyse_url_full(f"{self.base}/ok"))
        res = self.an.analyse_url_full(f"{self.base}/ok")
        self.assertIn("Too many scan requests", res["error"])

    def test_text_scanner_path_is_protected_and_error_escaped(self):
        # Embedded link -> analyse_text_full -> analyse_url_full -> blocked.
        with mock.patch.object(self.an, "analyse_text", return_value={"urls_found": [f"{self.base}/ok"]}):
            with mock.patch.object(sec, "_ip_is_public", _REAL_IS_PUBLIC):
                out = self.an.analyse_text_full("see " + self.base + "/ok")
        self.assertEqual(sum(self.H.hits.values()), 0)
        self.assertFalse(out["url_results"][0]["content_analysis"]["fetched"])
        # exception text is HTML-escaped before it can reach the page
        with mock.patch.object(self.an, "analyse_text", return_value={"urls_found": ["http://x.test/"]}), \
             mock.patch.object(self.an, "analyse_url_full", side_effect=RuntimeError("<img src=x onerror=alert(1)>")):
            out = self.an.analyse_text_full("x")
        self.assertNotIn("<img", out["url_results"][0]["error"])
        self.assertIn("&lt;img", out["url_results"][0]["error"])

    def test_qr_style_private_payload_blocked(self):
        res = self.an.analyse_url_full("http://169.254.169.254/latest/meta-data/")   # as decoded from a QR
        self.assertFalse(res["content_analysis"]["fetched"])
        self.assertIn("Blocked", res["content_analysis"]["error"])

    def test_playwright_hardening_wiring(self):
        """fetch_via_playwright with a fake Playwright: checks the real option wiring."""
        calls = {}

        class Page:
            url = "http://example.com/"
            def goto(self, *a, **k): return types.SimpleNamespace(status=200)
            def wait_for_load_state(self, *a, **k): pass
            def wait_for_timeout(self, *a): pass
            def content(self): return "<html>" + "x" * (sec.MAX_RESPONSE_BYTES + 500) + "</html>"

        class Ctx:
            def set_default_timeout(self, t): calls["timeout"] = t
            def route(self, pattern, handler): calls["route"] = (pattern, handler)
            def new_page(self): return Page()

        class Browser:
            closed = False
            def new_context(self, **kw): calls["ctx_kwargs"] = kw; return Ctx()
            def close(self): Browser.closed = True

        class PW:
            chromium = types.SimpleNamespace(launch=lambda **k: Browser())
            def __enter__(self): return self
            def __exit__(self, *a): pass

        fake = types.ModuleType("playwright.sync_api")
        fake.sync_playwright = lambda: PW()
        with mock.patch.dict(sys.modules, {"playwright": types.ModuleType("playwright"),
                                           "playwright.sync_api": fake}):
            html, status, err = self.an.fetch_via_playwright("http://example.com/", timeout_ms=8000)
        self.assertIs(calls["ctx_kwargs"]["accept_downloads"], False)
        self.assertEqual(calls["ctx_kwargs"]["service_workers"], "block")
        self.assertEqual(calls["route"][0], "**/*")
        self.assertEqual(calls["timeout"], 8000)
        self.assertTrue(Browser.closed)
        self.assertEqual(len(html), sec.MAX_RESPONSE_BYTES)      # DOM dump is bounded

        # browser is closed even when reading the page blows up
        Browser.closed = False
        Page.content = lambda self: (_ for _ in ()).throw(RuntimeError("renderer crashed"))
        with mock.patch.dict(sys.modules, {"playwright": types.ModuleType("playwright"),
                                           "playwright.sync_api": fake}):
            html, status, err = self.an.fetch_via_playwright("http://example.com/")
        self.assertIsNone(html)
        self.assertTrue(Browser.closed, "browser must be closed on error")

        # navigation that ends on a non-http(s) page (e.g. blocked redirect) is discarded
        Page.content = lambda self: "<html>" + "x" * 200 + "</html>"
        Page.url = "chrome-error://chromewebdata/"
        with mock.patch.dict(sys.modules, {"playwright": types.ModuleType("playwright"),
                                           "playwright.sync_api": fake}):
            html, status, err = self.an.fetch_via_playwright("http://example.com/")
        self.assertIsNone(html)
        self.assertIn("blocked", err.lower())


# ─── 8. app.py escaping (functions extracted from the real file) ────────────
def _load_app_function(name, extra_globals):
    with open(os.path.join(ROOT, "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    node = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = dict(extra_globals)
    exec(compile(ast.Module([node], []), "app.py", "exec"), ns)
    return ns[name]


class TestAppEscaping(unittest.TestCase):
    PAYLOAD = '"><img src=x onerror=alert(1)><script>alert(2)</script>'

    def _capture(self):
        captured = []
        st = types.ModuleType("streamlit")
        comps = types.ModuleType("streamlit.components")
        v1 = types.ModuleType("streamlit.components.v1")
        v1.html = lambda html, **kw: captured.append(html)
        st.components, comps.v1 = comps, v1
        return captured, {"streamlit": st, "streamlit.components": comps, "streamlit.components.v1": v1}

    def test_render_full_result_escapes_everything_untrusted(self):
        import html as html_mod
        captured, mods = self._capture()
        fn = _load_app_function("render_full_result", {
            "_html": html_mod, "H": lambda *a, **k: None, "st": mock.MagicMock(),
            "select_display_indicators": lambda kws, result=None: kws})
        result = {
            "risk_level": "HIGH", "risk_score": 70, "confidence": 80, "scan_type": "URL Scanner",
            "verdict": f"bad {self.PAYLOAD}", "recommendations": ["be careful"],
            "suspicious_kws": [self.PAYLOAD], "url": f"http://x.test/{self.PAYLOAD}",
            "domain": self.PAYLOAD, "tld": "com", "flags": [self.PAYLOAD],
            "content_analysis": {"fetched": True, "extracted_text": self.PAYLOAD},
            "debug_logs": {},
        }
        with mock.patch.dict(sys.modules, mods):
            fn(result)
        page = captured[0]
        self.assertNotIn("<img", page)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;img", page)

    def test_popup_cannot_break_out_of_script_block(self):
        import hashlib, json
        captured, mods = self._capture()
        fn = _load_app_function("render_threat_popup", {
            "json": json, "H": lambda *a, **k: None, "st": mock.MagicMock(), "hashlib": hashlib})
        result = {"risk_level": "SAFE", "risk_score": 1, "open_url": "http://x.test/</script><script>alert(1)</script>"}
        with mock.patch.dict(sys.modules, mods):
            fn(result, "")
        page = "".join(captured)
        self.assertTrue(page, "popup produced no HTML")
        self.assertNotIn("</script><script>alert(1)", page)

    def test_raw_echo_sites_are_escaped_in_source(self):
        with open(os.path.join(ROOT, "app.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn('class="url-display">{url_val}', src)
        self.assertNotIn('class="url-display">{result["qr_data"]}', src)
        self.assertNotIn('text-preview">{result["extracted_text"][:600]}', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
