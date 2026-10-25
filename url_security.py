# url_security.py — UnifiedLens AI
# Network-safety layer for the URL Scanner: SSRF / private-IP protection
# (including redirects and DNS rebinding), response-size and time limits,
# browser concurrency limits, and scan rate limiting.
#
# Self-contained on purpose: analyzer.py only calls into this module, so the
# scanning/scoring logic itself is untouched.

import contextlib
import functools
import ipaddress
import logging
import socket
import threading
import time
from collections import deque
from urllib.parse import urljoin, urlsplit

import requests
import urllib3.util.connection as _u3conn

logger = logging.getLogger("Unifiedlens.security")

# ─── Tunable limits ─────────────────────────────────────────────────────────
MAX_URL_LENGTH          = 2048              # longer URLs are not fetched
MAX_REDIRECTS           = 5                 # each hop is re-validated
MAX_RESPONSE_BYTES      = 2 * 1024 * 1024   # decoded bytes kept per page (2 MB)
FETCH_TOTAL_TIMEOUT_S   = 20                # wall-clock cap for one static fetch
MAX_CONCURRENT_BROWSERS = 2                 # simultaneous headless Chromium runs
BROWSER_SLOT_WAIT_S     = 10                # how long a scan waits for a free slot
RATE_WINDOW_S           = 60
RATE_MAX_PER_SESSION    = 10                # URL scans per session per window
RATE_MAX_GLOBAL         = 60                # URL scans for the whole server per window


class BlockedTargetError(OSError):
    """Raised when a scan target is not a public http(s) address."""


# ═════════════════════════════════════════════════════════════════════════════
# 1. SSRF protection — decide whether an address / URL is safe to contact
# ═════════════════════════════════════════════════════════════════════════════
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _ip_is_public(ip) -> bool:
    """True only for globally routable unicast addresses.

    Rejects loopback, RFC1918 private, link-local (incl. the 169.254.169.254
    cloud-metadata address), CGNAT 100.64/10, reserved, multicast and
    unspecified ranges, and unwraps IPv6 forms that embed an IPv4 address
    (::ffff:a.b.c.d, 6to4, NAT64) so they cannot smuggle a private IPv4 past
    the check.
    """
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip.split("%", 1)[0])    # drop IPv6 scope id
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return _ip_is_public(ip.ipv4_mapped)
        if ip.sixtofour is not None and not _ip_is_public(ip.sixtofour):
            return False
        if ip in _NAT64 and not _ip_is_public(ipaddress.IPv4Address(ip.packed[-4:])):
            return False
    return bool(
        ip.is_global
        and not (ip.is_private or ip.is_loopback or ip.is_link_local
                 or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    )


def resolve_public_ips(host: str, port: int) -> list:
    """Resolve *host* and return its IPs, raising BlockedTargetError if ANY
    resolved address is non-public (strict: mixed public/private DNS answers
    are refused). Decimal/hex/octal IP spellings such as http://2130706433/
    are resolved by the OS resolver, so they are checked by their real value."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = []
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if not _ip_is_public(ip):
            raise BlockedTargetError(
                "Blocked: the address resolves to a private, loopback or otherwise non-public network."
            )
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise socket.gaierror("no addresses returned")
    return ips


def _check_url_shape(url: str):
    """Validate scheme / length / host / port. Returns (host, port)."""
    if len(url) > MAX_URL_LENGTH:
        raise BlockedTargetError("Blocked: URL is too long to scan safely.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise BlockedTargetError("Blocked: malformed URL.") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise BlockedTargetError("Blocked: only http(s) URLs can be scanned.")
    host = parts.hostname
    if not host:
        raise BlockedTargetError("Blocked: URL has no host.")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in host):
        raise BlockedTargetError("Blocked: malformed host name.")   # parser-differential guard
    return host, port or (443 if scheme == "https" else 80)


def check_public_url(url: str) -> None:
    """Raise BlockedTargetError unless *url* is http(s) to a public address.
    An unresolvable hostname is NOT blocked here — the request will simply
    fail with its normal 'could not connect' error."""
    host, port = _check_url_shape(url)
    try:
        resolve_public_ips(host, port)
    except socket.gaierror:
        pass


# ── Connect-time guard (defeats DNS rebinding and URL-parser differentials) ──
# The pre-flight check above can be raced: a hostile DNS server can answer
# "public" to our check and "127.0.0.1" to the real connection. So while a scan
# is running (thread-local flag), every outgoing connection made through
# urllib3/requests or the stdlib socket.create_connection resolves the host
# ONCE, validates every address, and connects to that exact validated IP.
_state = threading.local()


def _guard_active() -> bool:
    return getattr(_state, "depth", 0) > 0


def _make_guarded(orig):
    orig = getattr(orig, "_ul_orig", orig)       # never wrap twice on re-import

    def guarded(address, *args, **kwargs):
        if _guard_active():
            host, port = address[0], address[1]
            ips = resolve_public_ips(host, port)
            last = None
            for ip in ips:
                try:
                    return orig((ip, port), *args, **kwargs)
                except OSError as e:
                    last = e
            raise last
        return orig(address, *args, **kwargs)

    guarded._ul_orig = orig
    return guarded


_u3conn.create_connection = _make_guarded(_u3conn.create_connection)
socket.create_connection = _make_guarded(socket.create_connection)


@contextlib.contextmanager
def ssrf_guard():
    """Enable the connect-time guard for the current thread (re-entrant)."""
    _state.depth = getattr(_state, "depth", 0) + 1
    try:
        yield
    finally:
        _state.depth -= 1


# ═════════════════════════════════════════════════════════════════════════════
# 2. Safe static fetch — manual redirects, size cap, total time cap
# ═════════════════════════════════════════════════════════════════════════════
def _raw_socket(resp):
    """Best-effort lookup of the live socket behind a streaming response.
    http.client drops conn.sock once headers are read on 'Connection: close'
    responses, so the response's own file object is tried as well."""
    raw = resp.raw
    for getter in (lambda: raw._connection.sock,
                   lambda: raw._fp.fp.raw._sock):
        try:
            sock = getter()
            if sock is not None:
                return sock
        except Exception:
            pass
    return None


def _read_capped(resp, max_bytes: int, deadline: float) -> bytes:
    """Read at most *max_bytes* of DECODED body (so gzip bombs are capped too)
    and stop at the wall-clock *deadline*, even if the server drips bytes."""
    fired = threading.Event()

    def _kill():
        fired.set()
        sock = _raw_socket(resp)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)   # wakes a blocked recv()
            except Exception:
                pass

    timer = threading.Timer(max(0.0, deadline - time.monotonic()), _kill)
    timer.daemon = True
    timer.start()
    chunks, total = [], 0
    try:
        for chunk in resp.iter_content(chunk_size=4096):
            if not chunk:
                continue
            room = max_bytes - total
            if len(chunk) >= room:
                chunks.append(chunk[:room])
                logger.warning("[Security] Response truncated at %d bytes: %s", max_bytes, resp.url)
                break
            chunks.append(chunk)
            total += len(chunk)
            if time.monotonic() > deadline:
                logger.warning("[Security] Read deadline reached, truncating: %s", resp.url)
                break
    except Exception:
        if not fired.is_set():
            raise                      # a genuine network error — let caller handle it
        logger.warning("[Security] Slow response cut off at deadline: %s", resp.url)
    finally:
        timer.cancel()
        try:
            resp.close()
        except Exception:
            pass
    return b"".join(chunks)


def safe_get(url: str, headers=None, timeout: float = 12, *, verify: bool = False,
             max_bytes: int = MAX_RESPONSE_BYTES, max_redirects: int = MAX_REDIRECTS,
             total_timeout: float = FETCH_TOTAL_TIMEOUT_S) -> requests.Response:
    """Drop-in replacement for requests.get(url, allow_redirects=True) that:
      • validates the target AND every redirect hop (BlockedTargetError),
      • follows at most *max_redirects* redirects,
      • caps the body at *max_bytes* and the whole fetch at *total_timeout* s.
    The returned Response has its (capped) body loaded, so .text / .content /
    .headers / .status_code behave exactly as before."""
    deadline = time.monotonic() + total_timeout
    session = requests.Session()
    current = url
    try:
        for hop in range(max_redirects + 1):
            try:
                check_public_url(current)
            except BlockedTargetError as e:
                if hop:
                    raise BlockedTargetError(f"Redirect {e}") from None
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise requests.exceptions.Timeout("Overall scan time limit reached.")
            resp = session.get(current, headers=headers, timeout=min(timeout, max(remaining, 1.0)),
                               allow_redirects=False, verify=verify, stream=True)
            if resp.is_redirect:
                nxt = urljoin(current, resp.headers.get("Location", ""))
                resp.close()
                current = nxt
                continue
            resp._content = _read_capped(resp, max_bytes, deadline)
            resp._content_consumed = True
            return resp
        raise requests.exceptions.TooManyRedirects(f"More than {max_redirects} redirects.")
    finally:
        session.close()


# ═════════════════════════════════════════════════════════════════════════════
# 3. Headless-browser helpers (used by analyzer.fetch_via_playwright)
# ═════════════════════════════════════════════════════════════════════════════
_BROWSER_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_BROWSERS)


def limit_browser_concurrency(fn):
    """Decorator: at most MAX_CONCURRENT_BROWSERS renders run at once; extra
    callers wait briefly, then skip JS rendering instead of piling up Chromium
    processes. Keeps fetch_via_playwright's (html, status, error) contract."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _BROWSER_SLOTS.acquire(timeout=BROWSER_SLOT_WAIT_S):
            return None, None, "Browser rendering is busy — skipped to protect the server."
        try:
            return fn(*args, **kwargs)
        finally:
            _BROWSER_SLOTS.release()
    return wrapper


_INLINE_SCHEMES = ("data", "about", "blob")
_SKIPPED_RESOURCE_TYPES = ("media", "font")     # bandwidth only; no effect on page text


def make_route_guard():
    """Playwright route handler: every request the page makes (document,
    subresources, XHR, and each redirect hop) must target a public http(s)
    host; everything else is aborted."""
    host_ok = {}

    def handler(route):
        try:
            request = route.request
            url = request.url
            scheme = urlsplit(url).scheme.lower()
            if scheme in _INLINE_SCHEMES:
                return route.continue_()
            if request.resource_type in _SKIPPED_RESOURCE_TYPES:
                return route.abort()
            host, port = _check_url_shape(url)        # http(s) only, sane length/host
            ok = host_ok.get(host)
            if ok is None:
                try:
                    resolve_public_ips(host, port)
                    ok = True
                except socket.gaierror:
                    ok = True                          # unresolvable: it will just fail
                except BlockedTargetError:
                    ok = False
                host_ok[host] = ok
            if ok:
                return route.continue_()
            logger.warning("[Security] Browser request blocked (non-public target): %s", url[:200])
            return route.abort()
        except Exception:
            try:
                route.abort()
            except Exception:
                pass
    return handler


# ═════════════════════════════════════════════════════════════════════════════
# 4. Rate limiting — per session and server-wide, sliding window
# ═════════════════════════════════════════════════════════════════════════════
_rl_lock = threading.Lock()
_rl_hits = {}                 # key -> deque of monotonic timestamps
_RL_MAX_KEYS = 2000


def _session_key() -> str:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        try:
            ctx = get_script_run_ctx(suppress_warning=True)
        except TypeError:
            ctx = get_script_run_ctx()
        if ctx is not None:
            return f"session:{ctx.session_id}"
    except Exception:
        pass
    return "session:unknown"


def check_rate_limit(session_key=None, now=None):
    """Record one scan if allowed. Returns (allowed, retry_after_seconds).
    Rejected attempts are not recorded, so hammering never extends a lockout."""
    now = time.monotonic() if now is None else now
    key = session_key or _session_key()
    cutoff = now - RATE_WINDOW_S
    with _rl_lock:
        if len(_rl_hits) > _RL_MAX_KEYS:                       # bound memory
            for k in [k for k, d in _rl_hits.items() if not d or d[-1] <= cutoff]:
                del _rl_hits[k]
        g = _rl_hits.setdefault("__global__", deque())
        s = _rl_hits.setdefault(key, deque())
        for dq in (g, s):
            while dq and dq[0] <= cutoff:
                dq.popleft()
        blocked_by = None
        if len(s) >= RATE_MAX_PER_SESSION:
            blocked_by = s
        elif len(g) >= RATE_MAX_GLOBAL:
            blocked_by = g
        if blocked_by is not None:
            retry = max(1, int(blocked_by[0] + RATE_WINDOW_S - now) + 1)
            return False, retry
        g.append(now)
        s.append(now)
        return True, 0


def scan_gate(fn):
    """Decorator for analyse_url_full: rate-limit, then run the whole scan
    (URL model fetches included) under the connect-time SSRF guard. Because
    the URL Scanner tab, Text Analyzer, QR Scanner and Company Verifier all
    funnel through analyse_url_full, one decorator protects every entry point."""
    @functools.wraps(fn)
    def wrapper(url, *args, **kwargs):
        if url and str(url).strip():
            allowed, retry = check_rate_limit()
            if not allowed:
                logger.warning("[Security] Scan rate limit hit (retry in %ss)", retry)
                return {"error": f"Too many scan requests. Please wait about {retry} seconds and try again."}
        with ssrf_guard():
            return fn(url, *args, **kwargs)
    return wrapper
