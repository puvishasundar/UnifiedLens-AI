# app.py — UnifiedLens AI  ·  Premium Redesign
# AI-powered cybersecurity intelligence dashboard
# Run: streamlit run app.py

import os, re as _re, time, datetime, json, html as _html
import streamlit as st
import plotly.graph_objects as go
from streamlit_local_storage import LocalStorage

# Local modules
from analyzer import (
    analyse_text, analyse_text_full, analyse_url_full, analyse_qr,
    analyse_ocr_image, analyse_pdf, analyse_company
)
from utils import update_stats, avg_risk, make_empty_stats, compute_risk_level, SCAM_KEYWORDS
from language_utils import language_badge_html, SUPPORTED_LANGUAGES


# ══════════════════════════════════════════════════════════════════
# H — defined immediately after imports so every call below works
# ══════════════════════════════════════════════════════════════════
def H(html: str) -> None:
    st.markdown(html, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="UnifiedLens AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Inject CSS (cache-busted via file mtime) ─────────────────────
_CSS_PATH = os.path.join(os.path.dirname(__file__), "styles.css")
if os.path.exists(_CSS_PATH):
    _css_version = int(os.path.getmtime(_CSS_PATH))
    with open(_CSS_PATH, encoding="utf-8") as f:
        _css_content = f.read()
    st.markdown(f"<style>/* v={_css_version} */\n{_css_content}</style>", unsafe_allow_html=True)

# ── Additional UI improvements CSS ───────────────────────────────
st.markdown("""<style>
/* ── Unified nav hidden-buttons override ── */
.cl-nav-hidden-btns {
    height: 0 !important;
    overflow: hidden !important;
    display: block;
}
.cl-nav-hidden-btns > div,
.cl-nav-hidden-btns [data-testid="stHorizontalBlock"] {
    height: 0 !important;
    min-height: 0 !important;
    overflow: hidden !important;
    padding: 0 !important;
    margin: 0 !important;
    gap: 0 !important;
}
.cl-nav-hidden-btns button {
    height: 0 !important;
    min-height: 0 !important;
    padding: 0 !important;
    margin: 0 !important;
    border: none !important;
    overflow: hidden !important;
    opacity: 0 !important;
    font-size: 0 !important;
}

/* ── Neural Risk Ring Result Card ── */
.ai-result-card {
    background:rgba(255,255,255,0.025);
    border:1px solid rgba(var(--rc,0,212,255),0.18);
    border-radius:20px;
    padding:1.75rem 2rem;
    margin-top:1.25rem;
    box-shadow:0 0 40px var(--glow,rgba(0,212,255,0.1));
    animation:resultFadeIn .5s ease both;
    position:relative;
    overflow:hidden;
}
.ai-result-card::before {
    content:'';
    position:absolute;
    top:-60px;right:-60px;
    width:200px;height:200px;
    background:radial-gradient(circle,var(--glow,rgba(0,212,255,.08)),transparent 70%);
    pointer-events:none;
}
@keyframes resultFadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}

.arc-row {
    display:flex;
    align-items:flex-start;
    gap:2rem;
    flex-wrap:wrap;
}

/* Neural ring */
.neural-ring-wrap {
    display:flex;
    flex-direction:column;
    align-items:center;
    flex-shrink:0;
    position:relative;
}
.neural-ring {
    width:130px;height:130px;
    transform:rotate(-90deg);
    filter:drop-shadow(0 0 8px var(--rc,#00d4ff));
    animation:ringDraw 1.2s cubic-bezier(.4,0,.2,1) both .1s;
}
@keyframes ringDraw{from{opacity:0;transform:rotate(-90deg) scale(.85)}to{opacity:1;transform:rotate(-90deg) scale(1)}}
.neural-ring-inner {
    position:absolute;
    top:50%;left:50%;
    transform:translate(-50%,-52%);
    text-align:center;
}
.neural-score {
    font-family:var(--font-display,Orbitron,monospace);
    font-size:1.75rem;
    font-weight:800;
    line-height:1;
    text-shadow:0 0 12px currentColor;
}
.neural-label {
    font-family:var(--font-mono,monospace);
    font-size:0.65rem;
    color:var(--text-dim,#5a7a9a);
    letter-spacing:.06em;
}
.neural-ring-caption {
    margin-top:.4rem;
    font-family:var(--font-display,Rajdhani,sans-serif);
    font-size:.58rem;
    letter-spacing:.18em;
    color:var(--text-dim,#5a7a9a);
    text-transform:uppercase;
}

/* Verdict column */
.verdict-col { flex:1;min-width:220px; }

.ai-verdict-badge {
    display:flex;
    align-items:center;
    gap:1rem;
    padding:.9rem 1.2rem;
    background:rgba(255,255,255,.03);
    border:1px solid rgba(255,255,255,.06);
    border-left:3px solid var(--c,#00d4ff);
    border-radius:12px;
    box-shadow:0 0 20px var(--g,rgba(0,212,255,.1));
    margin-bottom:1rem;
    animation:badgeIn .5s ease both .25s;
}
@keyframes badgeIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:none}}
.verdict-level {
    font-family:var(--font-display,Rajdhani,sans-serif);
    font-size:1.1rem;
    font-weight:800;
    letter-spacing:.1em;
    text-shadow:0 0 10px currentColor;
}
.verdict-status {
    font-family:var(--font-mono,monospace);
    font-size:.75rem;
    color:var(--text-dim,#5a7a9a);
    margin-top:2px;
}

.result-meta-grid {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:.75rem;
    margin-bottom:1rem;
}
.result-meta-item {
    background:rgba(255,255,255,.025);
    border:1px solid rgba(255,255,255,.05);
    border-radius:10px;
    padding:.6rem .8rem;
    animation:metaIn .4s ease both;
}
.result-meta-item:nth-child(2){animation-delay:.07s}
.result-meta-item:nth-child(3){animation-delay:.14s}
@keyframes metaIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.rmi-label {
    font-family:var(--font-mono,monospace);
    font-size:.6rem;
    letter-spacing:.1em;
    color:var(--text-dim,#5a7a9a);
    text-transform:uppercase;
    margin-bottom:.25rem;
}
.rmi-val {
    font-family:var(--font-display,Rajdhani,sans-serif);
    font-size:.85rem;
    font-weight:700;
    color:var(--text,#c8d8e8);
    line-height:1.2;
}

.ai-scan-summary {
    background:rgba(0,212,255,.03);
    border:1px solid rgba(0,212,255,.08);
    border-radius:10px;
    padding:.75rem 1rem;
}
.scan-summary-label {
    font-family:var(--font-display,Rajdhani,sans-serif);
    font-size:.65rem;
    font-weight:700;
    letter-spacing:.1em;
    color:var(--primary,#00d4ff);
    text-transform:uppercase;
    margin-bottom:.4rem;
}
.scan-summary-text {
    font-family:var(--font-body,Inter,sans-serif);
    font-size:.88rem;
    line-height:1.7;
    color:var(--text,#c8d8e8);
}

/* Pulse animations */
@keyframes pulseSafe{0%,100%{box-shadow:0 0 40px rgba(0,255,157,.10)}50%{box-shadow:0 0 55px rgba(0,255,157,.22)}}
@keyframes pulseLow{0%,100%{box-shadow:0 0 40px rgba(59,130,246,.10)}50%{box-shadow:0 0 55px rgba(59,130,246,.22)}}
@keyframes pulseMedium{0%,100%{box-shadow:0 0 40px rgba(255,179,64,.12)}50%{box-shadow:0 0 60px rgba(255,179,64,.28)}}
@keyframes pulseHigh{0%,100%{box-shadow:0 0 40px rgba(249,115,22,.12)}50%{box-shadow:0 0 60px rgba(249,115,22,.28)}}
@keyframes pulseCritical{0%,100%{box-shadow:0 0 40px rgba(255,51,102,.15)}50%{box-shadow:0 0 70px rgba(255,51,102,.40)}}
.pulse-safe{animation:pulseSafe 3s ease-in-out infinite}
.pulse-low{animation:pulseLow 3s ease-in-out infinite}
.pulse-medium{animation:pulseMedium 2.5s ease-in-out infinite}
.pulse-high{animation:pulseHigh 2s ease-in-out infinite}
.pulse-critical{animation:pulseCritical 1.5s ease-in-out infinite}

/* ── Hidden localStorage bridge textarea ── */
div:has(> div > textarea[aria-label="__cls_bridge__"]) {
    position: absolute !important;
    width: 0 !important; height: 0 !important;
    overflow: hidden !important; opacity: 0 !important;
    pointer-events: none !important; z-index: -9999 !important;
    top: 0 !important; left: 0 !important;
}

/* ── Scan History Table ── */
.scan-history-table {
    border:1px solid rgba(0,212,255,.1);
    border-radius:12px;
    overflow:hidden;
    font-family:var(--font-body,Inter,sans-serif);
    font-size:.82rem;
}
.sht-header,.sht-row {
    display:grid;
    grid-template-columns:40px 1fr 90px 70px 1fr;
    gap:.5rem;
    padding:.6rem 1rem;
    align-items:center;
}
.sht-header {
    background:rgba(0,212,255,.06);
    font-family:var(--font-display,Rajdhani,sans-serif);
    font-size:.62rem;
    letter-spacing:.1em;
    text-transform:uppercase;
    color:var(--primary,#00d4ff);
    border-bottom:1px solid rgba(0,212,255,.1);
}
.sht-row {
    border-bottom:1px solid rgba(255,255,255,.03);
    transition:background .2s;
}
.sht-row:hover{background:rgba(0,212,255,.03)}
.sht-row:last-child{border-bottom:none}
</style>""", unsafe_allow_html=True)

H("""
<canvas id="cl-matrix" style="
    position:fixed;top:0;left:0;width:100vw;height:100vh;
    pointer-events:none;z-index:0;opacity:0.06;"></canvas>
<script>
(function(){
    var c = document.getElementById('cl-matrix');
    if (!c) return;
    var ctx = c.getContext('2d');
    c.width  = window.innerWidth;
    c.height = window.innerHeight;
    var cols = Math.floor(c.width / 20);
    var drops = Array(cols).fill(1);
    var chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ⊕⊗⊘◈◉';
    function draw() {
        ctx.fillStyle = 'rgba(2,4,9,0.05)';
        ctx.fillRect(0, 0, c.width, c.height);
        ctx.fillStyle = '#00d4ff';
        ctx.font = '14px JetBrains Mono, monospace';
        for (var i = 0; i < drops.length; i++) {
            var ch = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillStyle = Math.random() > 0.95 ? '#ffffff' : (Math.random() > 0.8 ? '#7c3aed' : '#00d4ff');
            ctx.fillText(ch, i * 20, drops[i] * 20);
            if (drops[i] * 20 > c.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }
    setInterval(draw, 60);
    window.addEventListener('resize', function(){
        c.width  = window.innerWidth;
        c.height = window.innerHeight;
        cols  = Math.floor(c.width / 20);
        drops = Array(cols).fill(1);
    });
})();
</script>
""")

# ══════════════════════════════════════════════════════════════════
# SESSION STATE — history stored in browser localStorage ONLY.
# ✅ 100% private to this browser/device — other users NEVER see it.
# ✅ Persists across tab closes, refreshes, and browser restarts.
# ✅ Never appears in the URL — completely invisible to anyone else.
# ✅ Only cleared when the user clicks "Clear All History".
# Uses streamlit-local-storage for reliable JS↔Python bridging.
# ══════════════════════════════════════════════════════════════════

_LS_KEY  = "cyberlens_stats"
_localS  = LocalStorage()

# ── Read persisted stats from browser localStorage ───────────────
if "stats" not in st.session_state:
    _stored = _localS.getItem(_LS_KEY)
    if isinstance(_stored, dict):
        st.session_state.stats = _stored
    elif isinstance(_stored, str) and _stored.strip().startswith("{"):
        try:
            st.session_state.stats = json.loads(_stored)
        except Exception:
            st.session_state.stats = make_empty_stats()
    else:
        st.session_state.stats = make_empty_stats()

if "current_page"  not in st.session_state: st.session_state.current_page  = "Dashboard"
if "result_text"   not in st.session_state: st.session_state.result_text   = None
if "result_ocr"    not in st.session_state: st.session_state.result_ocr    = None
if "result_pdf"    not in st.session_state: st.session_state.result_pdf    = None
if "result_url"    not in st.session_state: st.session_state.result_url    = None
if "result_qr"     not in st.session_state: st.session_state.result_qr     = None
if "result_co"     not in st.session_state: st.session_state.result_co     = None
if "_ls_key_ctr"   not in st.session_state: st.session_state._ls_key_ctr   = 0


def _save_to_localstorage(stats: dict) -> None:
    """Save scan history to this browser's localStorage only.
    Private to this device — no URL params, no server files."""
    st.session_state._ls_key_ctr += 1
    _localS.setItem(_LS_KEY, stats, key=f"_ls_set_{st.session_state._ls_key_ctr}")


def _clear_localstorage() -> None:
    """Wipe this user's CyberLens history from localStorage only."""
    try:
        st.session_state._ls_key_ctr += 1
        _localS.deleteItem(_LS_KEY, key=f"_ls_del_{st.session_state._ls_key_ctr}")
    except (KeyError, Exception):
        pass

# ══════════════════════════════════════════════════════════════════
# PLOTLY THEME
# ══════════════════════════════════════════════════════════════════
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor ="rgba(0,0,0,0)",
    font_color   ="#5a7a9a",
    font_family  ="Rajdhani",
    margin       =dict(l=20, r=20, t=40, b=20),
)
CYBER_COLORS = ["#00d4ff", "#7c3aed", "#00ff9d", "#ffb340", "#ff3366", "#3b82f6"]

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def section_header(text: str, icon: str = "◆") -> None:
    H(f'<div class="section-header">{icon} {text}</div>')

def card(content: str, extra: str = "") -> None:
    H(f'<div class="glass-card" style="{extra}">{content}</div>')

def threat_banner(result: dict) -> None:
    level = result.get("risk_level", "SAFE")
    emoji = result.get("risk_emoji", "🟢")
    score = round(result.get("risk_score", 0))
    conf  = round(result.get("confidence", 0))
    H(f'''
    <div class="threat-banner threat-{level}">
        <span style="font-size:2rem">{emoji}</span>
        <div>
            <div style="font-family:var(--font-display);font-size:1.3rem;font-weight:700;
                        color:var(--text);letter-spacing:0.08em">{level} THREAT</div>
            <div style="font-size:0.8rem;color:var(--text-dim);font-family:var(--font-mono);margin-top:2px">
                Risk Score: <strong style="color:var(--primary)">{score}/100</strong>
                &nbsp;·&nbsp; Confidence: <strong style="color:var(--primary)">{conf}%</strong>
            </div>
        </div>
    </div>''')

def risk_gauge(score: float, label: str = "Risk Score") -> go.Figure:
    ri    = compute_risk_level(score)
    color = ri["color"]
    fig   = go.Figure(go.Indicator(
        mode  ="gauge+number",
        value = score,
        title ={"text": label, "font": {"size": 13, "color": "#5a7a9a", "family": "Rajdhani"}},
        number={"font": {"size": 30, "color": color, "family": "Orbitron"}, "suffix": "/100"},
        gauge ={
            "axis":       {"range": [0, 100], "tickcolor": "#1a2a3a", "tickfont": {"size": 9}},
            "bar":        {"color": color, "thickness": 0.25},
            "bgcolor":    "rgba(0,0,0,0)",
            "bordercolor":"rgba(255,255,255,0.04)",
            "steps": [
                {"range": [0,  20],  "color": "rgba(0,255,157,0.08)"},
                {"range": [20, 40],  "color": "rgba(59,130,246,0.08)"},
                {"range": [40, 65],  "color": "rgba(255,179,64,0.08)"},
                {"range": [65, 85],  "color": "rgba(255,179,64,0.12)"},
                {"range": [85, 100], "color": "rgba(255,51,102,0.12)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "value": score},
        }
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=210)
    return fig

# ══════════════════════════════════════════════════════════════════
# SUSPICIOUS INDICATORS — display-only prioritisation layer
# ══════════════════════════════════════════════════════════════════
# The backend still detects, scores and returns EVERY keyword in
# result["suspicious_kws"] (that list is never modified). This layer only
# decides which few are worth SHOWING, so generic words (instagram, bank,
# login, urgent, click …) don't drown out the real red flags.
# Used by render_full_result() — i.e. Text, OCR, PDF, URL, QR and Company.
_IND_MAX = 5

# Lower tier number = shown first. Order follows the display priority:
# 1 scam/phishing phrases · 2 credential/OTP/payment/sensitive requests ·
# 3 account/security verification · 4 financial/fraud · 5 threats/urgency.
_IND_TIERS = [
    (1, _re.compile(
        r"digital arrest|arrest|money laundering|illegal (international|transactions?)|lottery|"
        r"lucky (winner|draw)|you (have )?won|(claim|selected)[a-z ]*(prize|reward|winner)|jackpot|"
        r"gift card|customs|courier|(parcel|package|shipment)[a-z ]*(held|hold|destroy)|"
        r"pay to (release|collect|receive)|scan (and win|to (receive|claim|unlock)|qr|the qr|this qr)|"
        r"refund qr|qr (to receive|for refund)|remote access|screen sharing|download apk|"
        r"guaranteed (returns?|profit|income|placement|selection)|(double|triple) your money|risk[- ]free|"
        r"(placement|joining|registration|activation|processing|training|release|clearance|offer letter) "
        r"(fee|charges?)|no interview|without interview|whatsapp hr|telegram manager|deepfake|"
        r"voice clon|cloned voice|virus detected|call microsoft|cyber ?crime|"
        r"(police|cbi|court|income tax|trai|rbi) (notice|order)|enforcement directorate|"
        r"fir (filed|registration|will)|legal (action|notice|complaint)|free iphone|"
        r"foreign inheritance|fake customer care")),
    (2, _re.compile(
        r"\botp\b|one[- ]time password|\bupi pin\b|\bpin\b|\bcvv\b|\bssn\b|password|"
        r"bank (account )?details|banking details|card (number|details)|send (aadhaar|pan)|"
        r"mother maiden|sensitive information|personal documents|share documents|biometric|"
        r"collect request|payment request|approve request|kyc")),
    (3, _re.compile(
        r"verify|verification|confirm (your )?(account|password|identity)|"
        r"account[- ](suspend|block|frozen|freeze|disabl|deactivat|hack)|"
        r"(card|upi|sim|pan|net banking|aadhaar|passport|bank|mobile number|upi id) "
        r"(blocked|suspended|frozen|deactivated)|unauthorized login|suspicious (activity|transaction)|"
        r"security alert|login (expired|immediately)|identity (mismatch|suspension)|reactivate|"
        r"freeze account|document mismatch|kyc")),
    (4, _re.compile(
        r"fee\b|charges?\b|payment|deposit|wire transfer|western union|moneygram|hawala|bitcoin|"
        r"crypto|refund|tax|loan|returns?|profit|invest|winnings|cashback|salary|money|reward|bonus|earn")),
    (5, _re.compile(
        r"final (notice|warning)|last (chance|attempt|opportunity)|do not (ignore|delay)|"
        r"within \d+ (minutes?|hours?)|(respond|reply|act|login|renew|activate) immediately|"
        r"immediate (response|escalation)|failure to|if not paid|non-payment|legal consequences|"
        r"avoid (suspension|arrest)|strict action|legal escalation|respond within|name will be removed")),
]
# Single words that are still worth showing on their own (very high-risk).
_IND_SINGLE_OK = {"otp", "kyc", "cvv", "lottery", "jackpot"}
_IND_ACRONYMS = {"otp", "kyc", "upi", "pin", "id", "pan", "sim", "fir", "cbi", "rbi", "ssn", "cvv",
                 "apk", "qr", "ai", "hr", "it", "sbi", "trai", "epfo", "tds", "gst", "un", "sebi"}

# Company Verifier returns full-sentence flags (not keywords) — ranked by meaning.
_IND_COMPANY_RULES = [
    (90, _re.compile(r"impersonat|mimic|typosquat|look-?alike")),
    (80, _re.compile(r"disposable|fraud|scam|phishing")),
    (70, _re.compile(r"suspicious keyword")),
    (60, _re.compile(r"unrelated to the company|do not match|does not match|does not clearly match|"
                     r"does not resemble|was not found in the website")),
    (55, _re.compile(r"free/public email")),
    (50, _re.compile(r'ip address|"@" character|shortened url')),
]

# URL results only carry bare tokens (login, verify, pay …). Alone they are
# generic, so they are shown only as a meaningful combined phrase.
_URL_CRED  = {"login", "signin", "verify", "confirm", "update", "secure", "account", "reset"}
_URL_CORE  = {"login", "signin", "verify", "confirm"}
_URL_MONEY = {"banking", "pay", "money", "cash", "deposit", "refund", "card", "loan", "crypto", "wallet"}
_URL_LURE  = {"lucky", "win", "prize", "gift", "reward", "bonus", "claim", "giving", "free", "earn"}

# ══════════════════════════════════════════════════════════════════
# DISPLAY-ONLY semantic de-duplication for Analysis Highlights.
#
# The detector above (tiers, SCAM_KEYWORDS, regexes) is untouched — it can
# still match as many near-identical phrasings as it likes ("Verify your
# account", "Verify account", "Please verify your account", …). This block
# only decides which of those matches are SHOWN to the user, so Highlights
# reads as a set of distinct *signals* rather than repeats of one signal in
# different words. Nothing here feeds back into detection or scoring.
# ══════════════════════════════════════════════════════════════════

# Filler words stripped before comparing phrases for similarity — these
# don't carry meaning on their own ("please verify" vs "verify" is the
# same underlying signal).
_IND_STOPWORDS = {
    "the", "a", "an", "to", "is", "are", "was", "were", "be", "been", "being",
    "your", "you", "please", "kindly", "now", "immediately", "asap", "urgently",
    "required", "requested", "request", "requests", "needs", "need", "must",
    "will", "should", "this", "that", "these", "those", "of", "for", "on",
    "in", "at", "and", "or", "as", "with", "do", "does", "did", "has",
    "have", "had", "it", "its", "not", "right", "away",
}

# Known concept clusters: when a displayed phrase matches one of these, it
# is shown using the clearer canonical label instead of the raw variant —
# purely cosmetic renaming, it does not change what was detected.
_IND_CONCEPT_LABELS = [
    (_re.compile(r"verify|verification|confirm[a-z ]*(account|identity|password|details)"),
     "Account verification requested"),
    (_re.compile(r"\botp\b|\bupi pin\b|\bpin\b|\bcvv\b|card (number|details)|"
                 r"bank (account )?details|banking details|password|mother maiden|biometric"),
     "Payment/credential information requested"),
    (_re.compile(r"final (notice|warning)|last (chance|attempt|opportunity)|"
                 r"do not (ignore|delay)|within \d+ (minutes?|hours?)|"
                 r"(respond|reply|act|login|renew|activate) immediately|"
                 r"immediate (response|escalation)|respond within"),
     "Urgent action requested"),
    (_re.compile(r"suspicious (activity|transaction)|unauthorized login|security alert|"
                 r"account[- ](suspend|block|frozen|freeze|disabl|deactivat)"),
     "Suspicious account activity flagged"),
    (_re.compile(r"shortened url|suspicious link|malicious link|phishing link"),
     "Suspicious link detected"),
]


def _ind_signature(text: str) -> frozenset:
    """Crude, dependency-free 'meaning fingerprint' for a display phrase.

    Strips filler words and truncates the rest to a short prefix (cheap
    stemming: 'verify'/'verification'/'verified' all collapse to 'verif').
    Two phrases sharing a signature are treated as the same underlying
    signal for DISPLAY purposes only — detection itself is unaffected.
    """
    words = [w for w in _re.findall(r"[a-z]+", text.lower()) if w not in _IND_STOPWORDS]
    return frozenset(w[:5] if len(w) > 5 else w for w in words)


def _ind_relabel(text: str) -> str:
    """Swap a raw matched phrase for its canonical concept label, if any."""
    low = text.lower()
    for rx, label in _IND_CONCEPT_LABELS:
        if rx.search(low):
            return label
    return _ind_pretty(text)


def _diversify_indicators(ranked_texts: list) -> list:
    """Given phrases already ordered by display priority, drop later ones
    that are near-duplicates (same signature) of an earlier one, relabel the
    survivors with their canonical concept name where one applies, and drop
    any resulting duplicate labels (two different raw phrasings can map to
    the same concept, e.g. 'final notice' and 'act immediately' both become
    'Urgent action requested')."""
    seen_sigs = set()
    seen_labels = set()
    out = []
    for t in ranked_texts:
        sig = _ind_signature(t)
        if sig and sig in seen_sigs:
            continue
        label = _ind_relabel(t)
        if label in seen_labels:
            if sig:
                seen_sigs.add(sig)
            continue
        if sig:
            seen_sigs.add(sig)
        seen_labels.add(label)
        out.append(label)
    return out


def _ind_pretty(text: str) -> str:
    """Sentence-case a lowercase keyword ('kyc verification' -> 'KYC verification')."""
    if text != text.lower():
        return text                       # already formatted (e.g. Company flags)
    words = [w.upper() if w in _IND_ACRONYMS else w for w in text.split(" ")]
    if words and words[0] == text.split(" ")[0]:
        words[0] = words[0].capitalize()
    return " ".join(words)


def select_display_indicators(kws: list, result: dict = None, max_items: int = _IND_MAX) -> list:
    """Return the few strongest indicators to DISPLAY. Never mutates `kws`."""
    result = result or {}
    if not kws:
        return []

    # ── Company Verifier: sentence flags, ranked by meaning ──────────────
    if result.get("scan_type") == "Company Verifier":
        ranked = []
        for i, f in enumerate(dict.fromkeys(str(k) for k in kws)):
            if f.lstrip()[:1] == "✓":     # positive finding, not a suspicious indicator
                continue
            score = next((sc for sc, rx in _IND_COMPANY_RULES if rx.search(f.lower())), 0)
            if score:
                ranked.append((-score, i, f))
        ranked_texts = [f for _, _, f in sorted(ranked)]
        # Display-only: collapse near-duplicate flags (e.g. multiple
        # "suspicious keyword" style flags) down to distinct signals.
        return _diversify_indicators(ranked_texts)[:max_items]

    # ── Keyword / phrase results (Text, OCR, PDF, QR text, URL) ──────────
    cands = []
    seen = set()
    for i, raw in enumerate(kws):
        t = " ".join(str(raw).lower().split())
        if not t or t in seen:
            continue
        seen.add(t)
        weight = SCAM_KEYWORDS.get(t, 0)              # backend's own severity
        multiword = " " in t or "-" in t
        tier = next((n for n, rx in _IND_TIERS if rx.search(t)), 0)
        if tier in (1, 2, 3):
            ok = multiword or t in _IND_SINGLE_OK or weight >= 4
        elif tier in (4, 5):
            ok = weight >= 4
        else:
            tier, ok = 6, weight >= 4                 # unmatched but rated severe by backend
        if ok:
            cands.append((tier, -weight, -len(t.split()), i, t))

    # Drop a phrase already contained in a stronger/longer one ('otp' vs 'share otp')
    texts = [c[4] for c in cands]
    cands = [c for c in cands
             if not any(o != c[4] and _re.search(r"\b" + _re.escape(c[4]) + r"\b", o) for o in texts)]
    # Display-only: collapse near-duplicate phrasings of the same signal
    # ("verify your account" / "verify account" / "account verification
    # required" …) down to one clear representative per signal.
    picked = _diversify_indicators([c[4] for c in sorted(cands)])

    # URL tokens: surface a meaningful combination instead of generic words
    if "domain" in result and "tld" in result:
        toks = {str(k).lower() for k in kws}
        combos = []
        if len(toks & _URL_CRED) >= 2 and toks & _URL_CORE:
            combos.append("Login / verification keywords in URL")
        if toks & _URL_CORE and toks & _URL_MONEY:
            combos.append("Verification with payment / banking keywords in URL")
        if len(toks & _URL_LURE) >= 2 or (toks & _URL_LURE and toks & _URL_MONEY):
            combos.append("Prize / reward / free-money keywords in URL")
        elif len(toks & _URL_MONEY) >= 2:
            combos.append("Payment / banking keywords in URL")
        picked += combos

    return picked[:max_items]


def keyword_chips(keywords: list) -> None:
    keywords = select_display_indicators(keywords)
    if not keywords:
        H('<span style="color:#5a7a9a;font-size:0.82rem;font-family:monospace">Nothing notable detected.</span>')
        return
    chips = "".join(f'<span class="kw-chip">{kw}</span>' for kw in keywords)
    H(f'<div style="line-height:2.4">{chips}</div>')

def recommendation_list(recs: list) -> None:
    for i, rec in enumerate(recs):
        H(f'<div class="rec-item" style="animation-delay:{i*0.07}s">{rec}</div>')

def render_full_result(result: dict) -> None:
    if "error" in result:
        H(f'<div class="alert-error">⚠️ {result["error"]}</div>')
        return

    level  = result.get("risk_level", "SAFE")
    score  = round(result.get("risk_score", 0))
    conf   = round(result.get("confidence", 0))
    emoji  = result.get("risk_emoji", "🟢")
    verdict_text = result.get("verdict", "No verdict available.")
    recs   = result.get("recommendations", [])
    kws    = result.get("suspicious_kws", [])          # full backend list (untouched)
    kws    = select_display_indicators(kws, result)     # display-only: strongest few

    # color palette by level
    level_meta = {
        "SAFE":     {"color": "#00ff9d", "glow": "rgba(0,255,157,0.35)", "label": "SAFE",     "status": "✅ No Threat Detected",     "pulse": "pulse-safe"},
        "LOW":      {"color": "#3b82f6", "glow": "rgba(59,130,246,0.35)",  "label": "LOW",      "status": "🔵 Low Risk — Monitor",      "pulse": "pulse-low"},
        "MEDIUM":   {"color": "#ffb340", "glow": "rgba(255,179,64,0.40)",  "label": "MEDIUM",   "status": "⚠️ Suspicious Content Found", "pulse": "pulse-medium"},
        "HIGH":     {"color": "#f97316", "glow": "rgba(249,115,22,0.40)",  "label": "HIGH",     "status": "🔴 High Risk — Avoid",        "pulse": "pulse-high"},
        "CRITICAL": {"color": "#ff3366", "glow": "rgba(255,51,102,0.45)",  "label": "CRITICAL", "status": "🚨 Critical Threat Detected", "pulse": "pulse-critical"},
    }
    meta   = level_meta.get(level, level_meta["SAFE"])
    color  = meta["color"]
    glow   = meta["glow"]
    pulse  = meta["pulse"]
    status = meta["status"]

    # Build HTML fragments used inside the big f-string below
    if kws:
        kw_chips_html = "".join(f'<span class="kw-chip">{kw}</span>' for kw in kws)
    else:
        kw_chips_html = '<span style="color:#5a7a9a;font-size:0.82rem;font-family:monospace">Nothing notable detected.</span>'

    rec_html = "".join(
        f'<div class="rec-item" style="animation-delay:{i*0.07}s">{rec}</div>'
        for i, rec in enumerate(recs)
    )

    # Build URL details panel from known URL result keys (present on URL/QR scans)
    _url_field_labels = {
        "url":            ("🔗", "Scanned URL"),
        "domain":         ("🌐", "Domain"),
        "tld":            ("📌", "TLD"),
        "is_https":       ("🔒", "HTTPS"),
        "has_ip":         ("🖥️", "IP as Domain"),
        "is_long":        ("📏", "Long URL"),
        "is_known_legit": ("✅", "Known Legit Domain"),
        "typosquat_risk": ("⚠️", "Typosquatting Risk"),
        "trust_score":    ("💯", "Trust Score"),
    }
    url_detail_items = {
        label: (icon, result[key])
        for key, (icon, label) in _url_field_labels.items()
        if key in result
    }

    # NOTE: The AI URL model still runs fully in the backend (see
    # analyzer.analyse_url_full() / url_model.predict_url() /
    # get_feature_importance_url(), Stage 2) and its outputs (url_ml_label,
    # url_ml_probability, url_ml_fetched, url_ml_fetch_error, fetch_note,
    # url_ml_top_signals) remain in `result` and feed the risk score below.
    # They are intentionally not rendered in the UI anymore.
    _ai_rows_count = 0

    if url_detail_items:
        url_rows = "".join(
            f'<div class="data-row"><span class="dr-icon">{icon}</span>'
            f'<span class="dr-label">{label}</span>'
            f'<span class="dr-val">{val}</span></div>'
            for label, (icon, val) in url_detail_items.items()
        )
        # Also show URL flags if any
        url_flags = result.get("flags", [])
        if url_flags:
            url_rows += "".join(
                f'<div class="data-row"><span class="dr-icon">🚩</span>'
                f'<span class="dr-label">Flag</span>'
                f'<span class="dr-val" style="color:#f97316">{f}</span></div>'
                for f in url_flags
            )
        url_details_html = (
            f'<div class="cyber-divider" style="margin:1.25rem 0"></div>'
            f'<div class="section-header">🌐 URL Details</div>'
            f'<div style="margin-top:0.5rem">{url_rows}</div>'
        )
    else:
        url_details_html = ""

    # ── Website Content Analysis (live fetch + text ML) ─────────────────────────
    # Uses the real fetch performed in analyzer.analyse_webpage_content() /
    # analyse_url_full() — content_analysis holds the fetched page data.
    #
    # UI-ONLY RESTRICTION: this section is only ever built when the current
    # result came from the URL Scanner page (result["scan_type"] == "URL
    # Scanner"). analyse_url_full() also gets invoked from inside QR Scanner
    # and Company Verifier, but those overwrite `scan_type` to their own page
    # name before render_full_result() ever sees the result, so this check
    # cleanly limits the section to the URL Scanner without touching any
    # analysis/scoring logic.
    content_analysis_html = ""
    _raw_text = ""
    if result.get("scan_type") == "URL Scanner":
        _content       = result.get("content_analysis", {}) or {}
        _dbg           = result.get("debug_logs", {}) or {}
        _site_opened   = bool(_content.get("fetched"))
        _access_color  = "#00ff9d" if _site_opened else "#ff3366"
        _access_icon   = "✅" if _site_opened else "❌"
        _access_text   = "Opened successfully" if _site_opened else "Failed to open"

        _raw_text      = (_content.get("extracted_text") or "").strip()
        _kw_score      = _content.get("keyword_score_normalised", _content.get("keyword_score_raw", 0))
        _text_ml_label = result.get("text_model_label") or "N/A"
        _text_ml_prob  = result.get("text_model_probability", 0)
        _final_combined= _dbg.get("final_hybrid_score", score)

        if _raw_text:
            _preview_len   = 300
            _text_escaped  = _html.escape(_raw_text)
            _preview_html  = _html.escape(_raw_text[:_preview_len])
            _remainder_html= _html.escape(_raw_text[_preview_len:])
            if len(_raw_text) > _preview_len:
                _text_block = (
                    f'{_preview_html}…'
                    f'<details style="display:inline">'
                    f'<summary style="cursor:pointer;color:#00d4ff;font-family:monospace;'
                    f'font-size:.72rem;display:inline;margin-left:.4rem">Show More</summary>'
                    f'<span>{_remainder_html}</span></details>'
                )
            else:
                _text_block = _text_escaped
        else:
            _text_block = '<span style="color:#5a7a9a">No text could be extracted from this page.</span>'

        content_analysis_html = f'''
  <div class="divider"></div>
  <div class="section-hdr">🌐 Website Content Analysis</div>
  <div class="data-row"><span class="dr-icon">{_access_icon}</span>
    <span class="dr-label">Website Access</span>
    <span class="dr-val" style="color:{_access_color};font-weight:700">{_access_text}</span></div>
  <div class="data-row" style="flex-direction:column;align-items:flex-start">
    <span class="dr-label" style="margin-bottom:.4rem">Extracted Website Text</span>
    <div style="color:#c8d8e8;font-size:.82rem;line-height:1.65">{_text_block}</div>
  </div>
  <div class="data-row"><span class="dr-icon">📊</span>
    <span class="dr-label">Final Combined Score</span>
    <span class="dr-val" style="color:{color};font-weight:700">{round(_final_combined)}/100</span></div>
'''

    # ── SVG ring math ────────────────────────────────────────────────────────────
    radius = 52
    circ   = round(2 * 3.14159 * radius, 2)   # ≈ 326.73
    dash   = round(circ * score / 100, 2)
    gap    = round(circ - dash, 2)
    status_text = status.split(" ", 1)[1] if " " in status else status
    label_str   = meta["label"]

    # ── Use st.components to render the full result card (SVG safe) ───────────
    # Dynamic height: base + extras for keywords and recommendations
    _kw_rows  = max(1, len(kws) // 4)
    _rec_rows = len(recs)
    _url_rows = len(url_detail_items) if url_detail_items else 0
    _text_extra = min(240, len(_raw_text) // 4) if _raw_text else 40
    _height   = 700 + (_kw_rows * 40) + (_rec_rows * 65) + (_url_rows * 48) + (_ai_rows_count * 48) + 260 + _text_extra

    import streamlit.components.v1 as components
    components.html(f"""
<!DOCTYPE html>
<html>
<head>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  body {{ margin:0; padding:0; background:transparent; font-family:'Rajdhani',sans-serif; }}
  .result-card {{
    background:rgba(255,255,255,0.025);
    border:1px solid {color}44;
    border-radius:20px;
    padding:1.75rem 2rem;
    box-shadow:0 0 40px {glow};
    position:relative;
    overflow:hidden;
    animation:resultFadeIn .5s ease both;
  }}
  @keyframes resultFadeIn{{from{{opacity:0;transform:translateY(14px)}}to{{opacity:1;transform:none}}}}
  .top-row {{ display:flex; align-items:flex-start; gap:2rem; flex-wrap:wrap; }}
  .ring-col {{ display:flex; flex-direction:column; align-items:center; flex-shrink:0; }}
  .verdict-col {{ flex:1; min-width:220px; }}
  .badge {{
    display:flex; align-items:center; gap:1rem;
    padding:.9rem 1.2rem;
    background:rgba(255,255,255,.03);
    border:1px solid rgba(255,255,255,.06);
    border-left:3px solid {color};
    border-radius:12px;
    box-shadow:0 0 20px {glow};
    margin-bottom:1rem;
  }}
  .badge-level {{ font-size:1.1rem; font-weight:800; letter-spacing:.1em; color:{color}; text-shadow:0 0 10px {color}; }}
  .badge-status {{ font-family:monospace; font-size:.75rem; color:#5a7a9a; margin-top:2px; }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:.75rem; margin-bottom:1rem; }}
  .meta-cell {{
    background:rgba(255,255,255,.025);
    border:1px solid rgba(255,255,255,.05);
    border-radius:10px; padding:.6rem .8rem;
  }}
  .meta-label {{ font-family:monospace; font-size:.6rem; letter-spacing:.1em; color:#5a7a9a; text-transform:uppercase; margin-bottom:.25rem; }}
  .meta-val {{ font-size:.85rem; font-weight:700; color:{color}; }}
  .verdict-box {{
    background:rgba(0,212,255,.03);
    border:1px solid rgba(0,212,255,.08);
    border-radius:10px; padding:.75rem 1rem;
  }}
  .verdict-label {{ font-size:.65rem; font-weight:700; letter-spacing:.1em; color:#00d4ff; text-transform:uppercase; margin-bottom:.4rem; }}
  .verdict-text {{ font-size:.88rem; line-height:1.7; color:#c8d8e8; }}
  .divider {{ height:1px; background:linear-gradient(90deg,transparent,rgba(0,212,255,.15),transparent); margin:1.25rem 0; }}
  .section-hdr {{ font-family:'Rajdhani',sans-serif; font-size:.65rem; font-weight:700; letter-spacing:.12em; color:#00d4ff; text-transform:uppercase; margin-bottom:.6rem; }}
  .kw-chip {{
    display:inline-block; margin:.25rem .3rem;
    padding:.3rem .75rem;
    background:rgba(0,212,255,.07);
    border:1px solid rgba(0,212,255,.2);
    border-radius:20px;
    font-family:monospace; font-size:.75rem; color:#00d4ff;
  }}
  .rec-item {{
    display:flex; align-items:flex-start; gap:.75rem;
    padding:.6rem .9rem; margin-bottom:.4rem;
    background:rgba(255,255,255,.02);
    border:1px solid rgba(255,255,255,.05);
    border-left:2px solid {color}88;
    border-radius:0 8px 8px 0;
    font-size:.88rem; color:#c8d8e8; line-height:1.5;
  }}
  .data-row {{
    display:flex; align-items:center; gap:.75rem;
    padding:.5rem .75rem; margin-bottom:.3rem;
    background:rgba(255,255,255,.02);
    border:1px solid rgba(255,255,255,.04);
    border-radius:8px; font-size:.82rem;
  }}
  .dr-label {{ color:#5a7a9a; min-width:130px; font-family:monospace; font-size:.75rem; }}
  .dr-val {{ color:#c8d8e8; }}
  .ring-caption {{ margin-top:.4rem; font-size:.58rem; letter-spacing:.18em; color:#5a7a9a; text-transform:uppercase; }}
  .score-num {{ font-family:'Orbitron',monospace; font-size:1.7rem; font-weight:800; line-height:1; color:{color}; text-shadow:0 0 14px {color}; }}
  .score-sub {{ font-family:monospace; font-size:.65rem; color:#5a7a9a; letter-spacing:.06em; margin-top:2px; }}
</style>
</head>
<body>
<div class="result-card">

  <div class="top-row">
    <!-- Neural Risk Ring -->
    <div class="ring-col">
      <div style="position:relative;width:130px;height:130px;">
        <svg viewBox="0 0 130 130" width="130" height="130" xmlns="http://www.w3.org/2000/svg">
          <circle cx="65" cy="65" r="{radius}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
          <circle cx="65" cy="65" r="{radius}" fill="none"
            stroke="{color}" stroke-width="10" stroke-linecap="round"
            stroke-dasharray="{dash} {gap}"
            transform="rotate(-90 65 65)"
            style="filter:drop-shadow(0 0 10px {color})"/>
        </svg>
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;">
          <div class="score-num">{score}</div>
          <div class="score-sub">/ 100</div>
        </div>
      </div>
      <div class="ring-caption">RISK SCORE</div>
    </div>

    <!-- Verdict + Meta -->
    <div class="verdict-col">
      <div class="badge">
        <span style="font-size:1.5rem">{emoji}</span>
        <div>
          <div class="badge-level">{label_str} THREAT</div>
          <div class="badge-status">{status}</div>
        </div>
      </div>

      <div class="meta-grid">
        <div class="meta-cell">
          <div class="meta-label">THREAT LEVEL</div>
          <div class="meta-val">{label_str}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-label">RISK %</div>
          <div class="meta-val">{score}%</div>
        </div>
        <div class="meta-cell">
          <div class="meta-label">SAFETY STATUS</div>
          <div class="meta-val" style="color:#c8d8e8;font-weight:600;">{status_text}</div>
        </div>
      </div>

      <div class="verdict-box">
        <div class="verdict-label">🔍 AI Verdict</div>
        <div class="verdict-text">{verdict_text}</div>
      </div>
    </div>
  </div>

  <div class="divider"></div>

  <!-- Suspicious Indicators -->
  <div class="section-hdr">⚡ Analysis Highlights</div>
  <div style="line-height:2.4;margin-top:.25rem">{kw_chips_html}</div>

  {url_details_html}

  {content_analysis_html}

  <div class="divider"></div>

  <!-- Recommendations -->
  <div class="section-hdr">🛡️ Recommendations</div>
  <div style="margin-top:.25rem">{rec_html}</div>

</div>
</body>
</html>
""", height=_height, scrolling=True)

def log_scan(result: dict, scan_type: str) -> None:
    if "error" not in result:
        st.session_state.stats = update_stats(
            st.session_state.stats,
            verdict   =result.get("risk_level", "SAFE"),
            risk_score=result.get("risk_score", 0),
            scan_type =scan_type,
        )
        # Save to user's browser localStorage — private, persistent, device-only
        _save_to_localstorage(st.session_state.stats)

# ══════════════════════════════════════════════════════════════════
# ✚ ADD-ON FEATURE: Post-Scan Threat Popup + "Open Website" Action
# ══════════════════════════════════════════════════════════════════
# This is a pure enhancement layered on top of the existing URL Scanner.
# It does NOT alter analyse_url_full(), render_full_result(), risk scoring,
# threat levels, or any other existing UI/backend behaviour. It only adds:
#   1. A new "Open Website" action button (didn't exist before).
#   2. An animated cyber-themed warning popup shown after a scan completes.
# Rendered via components.html (a real iframe, so its <script> actually runs —
# st.markdown()/unsafe_allow_html silently ignores <script> tags, which is why
# an earlier version of this popup never appeared). The popup markup is then
# relocated into the parent page's own DOM so position:fixed covers the full
# browser viewport — the same window.parent.document technique this app
# already relies on for its custom nav bar (see NAVIGATION section below).
def render_threat_popup(result: dict, url_val: str) -> None:
    if not result or "error" in result:
        return

    import hashlib as _hashlib
    import streamlit.components.v1 as components

    level = result.get("risk_level", "SAFE")
    score = result.get("risk_score", 0)
    open_target = result.get("open_url") or (url_val or "").strip()

    LEVEL_CONFIG = {
        "SAFE": dict(
            color="#00ff9d", glow="rgba(0,255,157,.55)", icon="✅",
            title="ACCESS GRANTED", shake="", sound="success", blocked=False,
            lines=["✅ This website appears safe."],
        ),
        "LOW": dict(
            color="#3b82f6", glow="rgba(59,130,246,.55)", icon="🔵",
            title="LOW RISK DETECTED", shake="", sound="success", blocked=False,
            lines=["🔵 This link looks mostly safe.",
                   "Still verify the source before entering any details."],
        ),
        "MEDIUM": dict(
            color="#ffb340", glow="rgba(255,179,64,.6)", icon="⚠️",
            title="CAUTION ADVISED", shake="", sound="warning", blocked=True,
            lines=["⚠️ Think before you click.",
                   "This link contains suspicious elements."],
        ),
        "HIGH": dict(
            color="#f97316", glow="rgba(249,115,22,.65)", icon="🚨",
            title="HIGH THREAT DETECTED", shake="cl-twp-shake-soft", sound="alert", blocked=True,
            lines=["🚨 Multiple high-risk indicators detected.",
                   "Proceeding is strongly discouraged."],
        ),
        "CRITICAL": dict(
            color="#ff3366", glow="rgba(255,51,102,.75)", icon="🛑",
            title="DANGER — SCAM DETECTED", shake="cl-twp-shake-hard", sound="alert", blocked=True,
            lines=["🛑 STOP! Potential scam detected.",
                   "Don't risk your data.",
                   "This website has been blocked for your safety."],
        ),
    }
    cfg = LEVEL_CONFIG.get(level, LEVEL_CONFIG["SAFE"])

    lines_html = "".join(f'<div class="cl-twp-line">{ln}</div>' for ln in cfg["lines"])
    blocked          = cfg["blocked"]
    btn_label        = "BLOCKED" if blocked else "Open Website"
    btn_class        = "cl-owb-blocked" if blocked else "cl-owb-active"
    btn_disabled_att = "disabled aria-disabled=\"true\"" if blocked else ""
    note_html        = ('<div class="cl-owb-note">🔒 This action has been locked by '
                         'CyberLens AI for your protection.</div>') if blocked else ""

    _uid = _hashlib.md5(f"{open_target}|{level}|{score}".encode("utf-8")).hexdigest()[:10]
    _open_target_js = json.dumps(open_target)
    _shake_class_js = json.dumps(cfg["shake"])
    _blocked_js      = "true" if blocked else "false"

    # NOTE ON IMPLEMENTATION: st.markdown()/unsafe_allow_html never executes
    # <script> tags (browsers ignore scripts inserted via innerHTML — this is
    # a web-platform rule, not a Streamlit bug). components.html() renders a
    # real iframe document, so its <script> DOES execute. To still get a
    # TRUE full-page overlay (not one boxed inside the iframe's small height),
    # the script below relocates the popup markup + its stylesheet into the
    # parent page's own DOM — the same window.parent.document technique this
    # app already relies on for its custom nav bar further down this file.
    components.html(f"""
<!DOCTYPE html><html><head>
<style>
html,body{{margin:0;padding:0;background:transparent;font-family:'Rajdhani',sans-serif;overflow:hidden;}}
.cl-owb-wrap {{
    display: flex; flex-direction: column; align-items: center; gap: .5rem;
    padding-top: 4px;
}}
.cl-owb-active, .cl-owb-blocked {{
    font-family: 'Rajdhani', sans-serif; font-weight: 700; letter-spacing: .08em;
    text-transform: uppercase; font-size: .85rem; padding: .8rem 2.2rem;
    border-radius: 12px; display: inline-flex; align-items: center; gap: .6rem;
    transition: all .25s ease; border: 1px solid transparent;
}}
.cl-owb-active {{
    cursor: pointer;
    background: linear-gradient(135deg, rgba(0,255,157,.18), rgba(0,212,255,.18));
    border-color: rgba(0,255,157,.45); color: #00ff9d;
    box-shadow: 0 0 24px rgba(0,255,157,.25);
}}
.cl-owb-active:hover {{ transform: translateY(-2px); box-shadow: 0 0 34px rgba(0,255,157,.45); }}
.cl-owb-blocked {{
    cursor: not-allowed; background: rgba(255,51,102,.08);
    border-color: rgba(255,51,102,.45); color: #ff3366; opacity: .9;
    animation: clOwbBlockedPulse 2.2s ease-in-out infinite;
}}
@keyframes clOwbBlockedPulse {{
    0%,100% {{ box-shadow: 0 0 14px rgba(255,51,102,.2); }}
    50%     {{ box-shadow: 0 0 26px rgba(255,51,102,.45); }}
}}
.cl-owb-note {{
    font-family: monospace; font-size: .68rem; letter-spacing: .04em;
    color: #5a7a9a; text-align: center;
}}
</style>
</head>
<body>

<div class="cl-owb-wrap">
    <button id="cl-owb-btn-{_uid}" class="{btn_class}" {btn_disabled_att} onclick="clOwbOpen_{_uid}();return false;">
        <span>{"🔒" if blocked else "🌐"}</span><span>{btn_label}</span>
    </button>
    {note_html}
</div>

<!-- Popup markup — relocated into the top-level page by the script below so
     position:fixed covers the WHOLE viewport, not just this small iframe. -->
<div id="cl-twp-overlay-{_uid}" class="cl-twp-global-item cl-twp-overlay">
    <div id="cl-twp-card-{_uid}" class="cl-twp-card" style="--twp-color:{cfg['color']};--twp-glow:{cfg['glow']}">
        <div class="cl-twp-scanbar"></div>
        <div class="cl-twp-icon">{cfg['icon']}</div>
        <div class="cl-twp-title">{cfg['title']}</div>
        <div class="cl-twp-msg">{lines_html}</div>
        <button class="cl-twp-ok" type="button">✓ OK</button>
    </div>
</div>

<style id="__cl_twp_style_src_{_uid}">
.cl-twp-overlay {{
    position: fixed; inset: 0; width: 100vw; height: 100vh;
    background: rgba(2,4,9,.78);
    backdrop-filter: blur(9px); -webkit-backdrop-filter: blur(9px);
    display: flex; align-items: center; justify-content: center;
    z-index: 999999; opacity: 0; pointer-events: none;
    transition: opacity .35s ease;
    font-family: 'Rajdhani', sans-serif;
}}
.cl-twp-overlay.cl-twp-show {{ opacity: 1; pointer-events: auto; }}
.cl-twp-card {{
    --twp-color: #00d4ff; --twp-glow: rgba(0,212,255,.5);
    position: relative; width: min(430px, 88vw);
    background: rgba(6,12,24,.97); border: 1px solid var(--twp-color);
    border-radius: 22px; padding: 2.3rem 1.9rem 1.9rem; text-align: center;
    box-shadow: 0 0 70px var(--twp-glow), inset 0 0 30px rgba(255,255,255,.02);
    transform: scale(.82) translateY(24px); opacity: 0;
    transition: transform .42s cubic-bezier(.2,.9,.3,1.35), opacity .3s ease;
    overflow: hidden;
}}
.cl-twp-overlay.cl-twp-show .cl-twp-card {{ transform: scale(1) translateY(0); opacity: 1; }}
.cl-twp-card::before, .cl-twp-card::after {{
    content: ''; position: absolute; width: 22px; height: 22px; border-color: var(--twp-color);
}}
.cl-twp-card::before {{ top: 10px; left: 10px; border-top: 2px solid var(--twp-color); border-left: 2px solid var(--twp-color); }}
.cl-twp-card::after  {{ bottom: 10px; right: 10px; border-bottom: 2px solid var(--twp-color); border-right: 2px solid var(--twp-color); }}
.cl-twp-scanbar {{
    position: absolute; top: 0; left: 0; right: 0; height: 3px;
    background: linear-gradient(90deg, transparent, var(--twp-color), transparent);
    animation: clTwpScan 2s linear infinite;
}}
@keyframes clTwpScan {{ 0%,100% {{ opacity:.25; }} 50% {{ opacity:1; }} }}
.cl-twp-icon {{
    font-size: 3rem; margin-bottom: .7rem;
    filter: drop-shadow(0 0 18px var(--twp-glow));
    animation: clTwpPulse 1.6s ease-in-out infinite;
}}
@keyframes clTwpPulse {{ 0%,100% {{ transform: scale(1); }} 50% {{ transform: scale(1.15); }} }}
.cl-twp-title {{
    font-family: 'Orbitron', monospace; font-size: 1rem; font-weight: 800;
    letter-spacing: .14em; color: var(--twp-color);
    text-shadow: 0 0 14px var(--twp-glow); margin-bottom: .9rem;
}}
.cl-twp-msg {{ margin-bottom: 1.6rem; }}
.cl-twp-line {{ font-family: 'Inter', sans-serif; font-size: .92rem; color: #c8d8ea; line-height: 1.7; }}
.cl-twp-ok {{
    font-family: 'Rajdhani', sans-serif; font-weight: 800; letter-spacing: .1em;
    text-transform: uppercase; font-size: .85rem; padding: .65rem 2.5rem;
    border-radius: 10px; border: 1px solid var(--twp-color);
    background: rgba(255,255,255,.04); color: var(--twp-color); cursor: pointer;
    box-shadow: 0 0 20px var(--twp-glow); transition: all .2s ease;
}}
.cl-twp-ok:hover {{ background: var(--twp-color); color: #020409; box-shadow: 0 0 32px var(--twp-glow); }}
@keyframes clTwpShakeSoft {{
    0%,100% {{ transform: translateX(0); }} 25% {{ transform: translateX(-5px); }} 75% {{ transform: translateX(5px); }}
}}
.cl-twp-shake-soft {{ animation: clTwpShakeSoft .45s ease 2; }}
@keyframes clTwpShakeHard {{
    10%,90% {{ transform: translate3d(-2px,0,0); }} 20%,80% {{ transform: translate3d(4px,0,0); }}
    30%,50%,70% {{ transform: translate3d(-8px,0,0); }} 40%,60% {{ transform: translate3d(8px,0,0); }}
}}
.cl-twp-shake-hard {{ animation: clTwpShakeHard .6s cubic-bezier(.36,.07,.19,.97) 2; }}
</style>

<script>
(function() {{
    try {{
        var parentDoc = window.parent.document;

        // 1) Clean up any popup(s) injected by earlier renders in this session
        //    so they don't silently pile up in the parent page across reruns.
        var stale = parentDoc.querySelectorAll('.cl-twp-global-item');
        for (var i = 0; i < stale.length; i++) {{ stale[i].parentNode.removeChild(stale[i]); }}

        var staleStyle = parentDoc.getElementById('cl-twp-global-style');
        if (staleStyle) staleStyle.parentNode.removeChild(staleStyle);

        // 2) Re-install the popup's stylesheet in the parent page's <head>
        var styleSrc = document.getElementById('__cl_twp_style_src_{_uid}');
        var styleNode = parentDoc.createElement('style');
        styleNode.id = 'cl-twp-global-style';
        styleNode.textContent = styleSrc ? styleSrc.textContent : '';
        parentDoc.head.appendChild(styleNode);

        // 3) Move the overlay node itself into the parent page's <body>
        //    so position:fixed covers the full browser viewport.
        var overlay = document.getElementById('cl-twp-overlay-{_uid}');
        parentDoc.body.appendChild(overlay);

        var card  = overlay.querySelector('.cl-twp-card');
        var okBtn = overlay.querySelector('.cl-twp-ok');
        if (okBtn) {{
            okBtn.onclick = function() {{ overlay.classList.remove('cl-twp-show'); }};
        }}

        // 4) Local "Open Website" button (stays inside this small iframe)
        //    calls this to either open the link or show/shake the relocated popup.
        window.clOwbOpen_{_uid} = function() {{
            if ({_blocked_js}) {{
                overlay.classList.add('cl-twp-show');
                if (card) {{
                    card.classList.remove('cl-twp-shake-soft', 'cl-twp-shake-hard');
                    void card.offsetWidth;
                    var sc = {_shake_class_js};
                    if (sc) card.classList.add(sc);
                }}
                return;
            }}
            window.open({_open_target_js}, '_blank', 'noopener,noreferrer');
        }};

        // 5) Lightweight synthesized sound cues (Web Audio API — no audio files).
        function clPlaySound(kind) {{
            try {{
                var Ctx = window.parent.AudioContext || window.parent.webkitAudioContext;
                var ctx = new Ctx();
                function tone(freq, start, dur, type, vol) {{
                    var o = ctx.createOscillator();
                    var g = ctx.createGain();
                    o.type = type || 'sine';
                    o.frequency.setValueAtTime(freq, ctx.currentTime + start);
                    g.gain.setValueAtTime(0, ctx.currentTime + start);
                    g.gain.linearRampToValueAtTime(vol || 0.15, ctx.currentTime + start + 0.02);
                    g.gain.linearRampToValueAtTime(0, ctx.currentTime + start + dur);
                    o.connect(g); g.connect(ctx.destination);
                    o.start(ctx.currentTime + start);
                    o.stop(ctx.currentTime + start + dur + 0.02);
                }}
                if (kind === 'success') {{
                    tone(660, 0, 0.12, 'sine', 0.12); tone(880, 0.12, 0.18, 'sine', 0.14);
                }} else if (kind === 'warning') {{
                    tone(720, 0, 0.10, 'square', 0.10); tone(480, 0.14, 0.12, 'square', 0.10);
                    tone(720, 0.30, 0.10, 'square', 0.10); tone(480, 0.44, 0.12, 'square', 0.10);
                }} else if (kind === 'alert') {{
                    tone(900, 0, 0.15, 'sawtooth', 0.13); tone(500, 0.16, 0.15, 'sawtooth', 0.13);
                    tone(900, 0.34, 0.15, 'sawtooth', 0.13); tone(500, 0.50, 0.18, 'sawtooth', 0.13);
                }}
            }} catch (e) {{}}
        }}

        // 6) Auto-show once per distinct scan result (dedup via the parent
        //    page's own sessionStorage so switching tabs doesn't re-trigger it).
        var thisKey = 'cl_twp_{_uid}';
        var lastKey = null;
        try {{ lastKey = window.parent.sessionStorage.getItem('cl_twp_last_shown'); }} catch (e) {{}}
        if (lastKey !== thisKey) {{
            try {{ window.parent.sessionStorage.setItem('cl_twp_last_shown', thisKey); }} catch (e) {{}}
            setTimeout(function() {{
                overlay.classList.add('cl-twp-show');
                clPlaySound('{cfg["sound"]}');
            }}, 300);
        }}
    }} catch (e) {{
        // If the browser ever blocks parent-document access, fail silently —
        // the existing scan results / risk scoring are completely unaffected.
    }}
}})();
</script>
</body></html>
""", height=150)

# ══════════════════════════════════════════════════════════════════
# NAVIGATION
# ══════════════════════════════════════════════════════════════════
NAV_ICONS = {
    "Dashboard":        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    "Analyzer":         '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><circle cx="11" cy="11" r="7"/><path d="M11 8v3l2 2"/><line x1="16.5" y1="16.5" x2="21" y2="21"/></svg>',
    "URL Scanner":      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><circle cx="12" cy="12" r="9"/><path d="M12 3c-2.5 4-2.5 14 0 18M12 3c2.5 4 2.5 14 0 18M3 12h18"/></svg>',
    "QR Scanner":       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="17" width="1.5" height="4"/><rect x="18.5" y="14" width="1.5" height="4"/><rect x="14" y="14" width="4" height="1.5"/></svg>',
    "Company Verifier": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><rect x="3" y="7" width="18" height="14" rx="1.5"/><path d="M7 7V5a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>',
    "Analytics":        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>',
    "About":            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="20" height="20"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="8.5" stroke-linecap="round" stroke-width="2"/><line x1="12" y1="11" x2="12" y2="16"/></svg>',
}
NAV_ITEMS = [
    ("Dashboard",       "Dashboard"),
    ("Analyzer",        "AI Analyzer"),
    ("URL Scanner",     "URL Scanner"),
    ("QR Scanner",      "QR Scanner"),
    ("Company Verifier","Company Verify"),
    ("Analytics",       "Analytics"),
    ("About",           "About"),
]

# ── Top Bar + Nav rendered via components.html (avoids Streamlit HTML stripping) ──
import streamlit.components.v1 as components

cur = st.session_state.current_page
_total_scans = st.session_state.stats.get("total_scans", 0)
_threats     = st.session_state.stats.get("threats_found", 0)

# Build nav items HTML
_nav_items_html = ""
for key, label in NAV_ITEMS:
    active_cls = "cl-nav-active" if cur == key else ""
    icon_svg   = NAV_ICONS.get(key, "")
    _nav_items_html += f'''<div class="cl-nav-item {active_cls}" onclick="navClick(this,'{label}')">
        <div class="cl-nav-icon">{icon_svg}</div>
        <div class="cl-nav-label">{label}</div>
    </div>'''

components.html(f"""
<!DOCTYPE html><html><head>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800&family=Rajdhani:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#020409;font-family:'Rajdhani',sans-serif;overflow:hidden}}
:root{{--primary:#00d4ff;--success:#00ff9d;--danger:#ff3366;--text-dim:#5a7a9a;--text:#c8d8ea}}

/* ── Topbar ── */
.cl-topbar{{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 2rem;height:62px;
  background:rgba(2,4,9,0.96);
  border-bottom:1px solid rgba(0,212,255,0.12);
  overflow:hidden;position:relative;
}}
.cl-topbar::before{{
  content:'';position:absolute;top:0;left:-100%;width:60%;height:100%;
  background:linear-gradient(105deg,transparent 40%,rgba(0,212,255,0.04) 50%,rgba(124,58,237,0.04) 55%,transparent 65%);
  animation:topbarShimmer 8s linear infinite;pointer-events:none;
}}
@keyframes topbarShimmer{{0%{{left:-60%}}100%{{left:160%}}}}
.cl-topbar::after{{
  content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(0,212,255,0.4) 20%,rgba(124,58,237,0.5) 50%,rgba(0,212,255,0.4) 80%,transparent);
  animation:topbarLine 4s ease-in-out infinite alternate;
}}
@keyframes topbarLine{{0%{{opacity:0.5}}100%{{opacity:1}}}}

.cl-brand{{display:flex;align-items:center;gap:12px;position:relative;z-index:1}}
.cl-brand-icon{{
  width:38px;height:38px;border-radius:10px;
  background:linear-gradient(135deg,rgba(0,212,255,0.2),rgba(124,58,237,0.2));
  border:1px solid rgba(0,212,255,0.4);
  display:flex;align-items:center;justify-content:center;font-size:1.15rem;
  box-shadow:0 0 18px rgba(0,212,255,0.25),inset 0 0 12px rgba(0,212,255,0.05);
  animation:iconPulse 3s ease-in-out infinite;
}}
@keyframes iconPulse{{
  0%,100%{{box-shadow:0 0 18px rgba(0,212,255,0.25),inset 0 0 12px rgba(0,212,255,0.05)}}
  50%{{box-shadow:0 0 28px rgba(0,212,255,0.45),inset 0 0 16px rgba(0,212,255,0.10)}}
}}
.cl-brand-name{{font-family:'Orbitron',monospace;font-size:1rem;font-weight:700;color:#e8f4ff;letter-spacing:0.08em}}
.cl-brand-name span{{color:#00d4ff;text-shadow:0 0 14px #00d4ff}}

.cl-ticker-wrap{{flex:1;margin:0 2rem;overflow:hidden;height:100%;display:flex;align-items:center;position:relative;z-index:1}}
.cl-ticker{{
  display:flex;gap:3rem;
  animation:tickerScroll 30s linear infinite;
  white-space:nowrap;font-family:'JetBrains Mono',monospace;
  font-size:0.65rem;letter-spacing:0.06em;color:#5a7a9a;
}}
.cl-ticker span{{display:inline-block}}
.t-warn{{color:#ffb340}}.t-danger{{color:#ff3366}}.t-safe{{color:#00ff9d}}
.t-sep{{color:rgba(0,212,255,0.3);margin:0 0.5rem}}
@keyframes tickerScroll{{0%{{transform:translateX(0)}}100%{{transform:translateX(-50%)}}}}

.cl-status{{
  display:flex;align-items:center;gap:8px;
  background:rgba(0,255,157,0.07);border:1px solid rgba(0,255,157,0.25);
  border-radius:20px;padding:.3rem 1rem;
  font-size:.72rem;font-family:'JetBrains Mono',monospace;
  color:#00ff9d;font-weight:500;letter-spacing:.06em;
  position:relative;z-index:1;white-space:nowrap;
}}
.cl-status-dot{{
  width:7px;height:7px;border-radius:50%;
  background:#00ff9d;box-shadow:0 0 10px #00ff9d;
  animation:clPulse 2s infinite;
}}
@keyframes clPulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.4;transform:scale(.8)}}}}

/* ── Nav ── */
.cl-nav-row{{
  display:flex;gap:4px;padding:.55rem .5rem 0;
  background:rgba(3,8,20,0.85);
  border-bottom:1px solid rgba(0,212,255,0.08);
}}
.cl-nav-item{{
  flex:1;display:flex;flex-direction:column;align-items:center;gap:5px;
  padding:9px 4px 11px;border-radius:10px 10px 0 0;cursor:pointer;
  color:#5a7a9a;transition:all .2s ease;background:transparent;
  border:1px solid transparent;border-bottom:none;user-select:none;position:relative;
}}
.cl-nav-item:hover{{color:#00d4ff;background:rgba(0,212,255,0.05);border-color:rgba(0,212,255,0.18)}}
.cl-nav-item:hover svg{{filter:drop-shadow(0 0 5px rgba(0,212,255,.5))}}
.cl-nav-active{{color:#00d4ff!important;background:rgba(0,212,255,0.08)!important;border-color:rgba(0,212,255,0.28)!important;box-shadow:0 -2px 16px rgba(0,212,255,.1) inset!important}}
.cl-nav-active svg{{filter:drop-shadow(0 0 6px rgba(0,212,255,.6))!important}}
.cl-nav-active::after{{
  content:'';position:absolute;bottom:0;left:50%;transform:translateX(-50%);
  width:50%;height:2px;background:#00d4ff;border-radius:2px 2px 0 0;
  box-shadow:0 0 10px #00d4ff;
}}
.cl-nav-icon{{line-height:1;display:flex;align-items:center;justify-content:center}}
.cl-nav-label{{font-family:'Rajdhani',sans-serif;font-size:.6rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}}

/* ── MOBILE ONLY: swipe nav ── */
@media(max-width:768px){{
  .cl-nav-row{{
    overflow-x:auto !important;
    overflow-y:visible !important;
    -webkit-overflow-scrolling:touch !important;
    scrollbar-width:none !important;
    flex-wrap:nowrap !important;
  }}
  .cl-nav-row::-webkit-scrollbar{{display:none}}
  .cl-nav-item{{
    flex:0 0 auto !important;
    min-width:68px !important;
  }}
  .cl-ticker-wrap{{display:none !important}}
  .cl-topbar{{padding:0 0.75rem !important;height:52px !important}}
  .cl-brand-name{{font-size:0.82rem !important}}
  .cl-brand-icon{{width:30px !important;height:30px !important;font-size:0.9rem !important}}
  .cl-status{{font-size:0.6rem !important;padding:0.2rem 0.6rem !important}}
}}
</style>
</head>
<body>

<div class="cl-topbar">
  <div class="cl-brand">
    <div class="cl-brand-icon">🛡️</div>
    <div class="cl-brand-name">UnifiedLens <span>AI</span></div>
  </div>
  <div class="cl-ticker-wrap">
    <div class="cl-ticker">
      <span>⚡ AI Threat Engine <span class="t-safe">ACTIVE</span></span>
      <span class="t-sep">//</span>
      <span>📊 Session Scans: <span class="t-safe">{_total_scans}</span></span>
      <span class="t-sep">//</span>
      <span>⚠️ Threats Detected: <span class="t-warn">{_threats}</span></span>
      <span class="t-sep">//</span>
      <span>⚡ AI Threat Engine <span class="t-safe">ACTIVE</span></span>
      <span class="t-sep">//</span>
      <span>📊 Session Scans: <span class="t-safe">{_total_scans}</span></span>
      <span class="t-sep">//</span>
      <span>⚠️ Threats Detected: <span class="t-warn">{_threats}</span></span>
      <span class="t-sep">//</span>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:.6rem">
    <div class="cl-status"><div class="cl-status-dot"></div>SYSTEMS ONLINE</div>
  </div>
</div>

<div class="cl-nav-row">
  {_nav_items_html}
</div>

<script>
var _navLock=false;
function navClick(el,label){{
  if(_navLock)return;
  _navLock=true;
  document.querySelectorAll('.cl-nav-item').forEach(function(n){{n.classList.remove('cl-nav-active')}});
  el.classList.add('cl-nav-active');
  try{{
    var btns=window.parent.document.querySelectorAll('button');
    for(var i=0;i<btns.length;i++){{
      if(btns[i].innerText.trim()===label){{btns[i].click();break;}}
    }}
  }}catch(e){{}}
  setTimeout(function(){{_navLock=false;}},800);
}}
</script>
</body></html>
""", height=130, scrolling=False)

# Hidden nav buttons — zero-height container so they don't appear visually
# but remain in the DOM so the JS onclick in components.html can trigger them
with st.container():
    H('''<style>
    div[data-testid="stHorizontalBlock"]:has(button[kind="secondary"]) {
        height: 0 !important;
        min-height: 0 !important;
        overflow: hidden !important;
        padding: 0 !important;
        margin: 0 !important;
        gap: 0 !important;
        opacity: 0 !important;
        pointer-events: none !important;
        position: absolute !important;
    }
    </style>''')
    nav_cols = st.columns(len(NAV_ITEMS))
    for i, (key, label) in enumerate(NAV_ITEMS):
        with nav_cols[i]:
            if st.button(label, key=f"nav_{i}", use_container_width=True):
                st.session_state.current_page = key
                for _k in ("result_text","result_ocr","result_pdf","result_url","result_qr","result_co"):
                    st.session_state[_k] = None
                st.rerun()

H('<div class="cl-navdivider"></div>')
selected = st.session_state.current_page

# ══════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════
if selected == "Dashboard":

    _live_threats = st.session_state.stats.get("threats_found", 0)
    H(f'''
    <div class="page-enter" style="text-align:center;padding:2.5rem 0 1.5rem">
        <div class="radar-container">
            <div class="radar-ring"></div>
            <div class="radar-ring"></div>
            <div class="radar-ring"></div>
            <div class="radar-crosshair"></div>
            <div class="radar-sweep"></div>
            <div class="radar-center">🛡️</div>
        </div>
        <div class="cyber-title" style="margin-bottom:0.5rem">UnifiedLens AI</div>
        <div class="cyber-subtitle" style="margin-bottom:1.25rem">
             Multimodal AI Platform for Real-Time Cyber Scam Detection
        </div>
        <div style="display:flex;align-items:center;justify-content:center;gap:0.5rem;flex-wrap:wrap">
            <span class="badge-active">● Intelligence Engine Active</span>
            <span class="live-counter">
                <span class="live-dot"></span>
                {_live_threats} THREAT{"S" if _live_threats != 1 else ""} DETECTED
            </span>
        </div>
    </div>
    ''')

    H('<div class="cyber-divider"></div>')

    # ── 4 Stat Cards ─────────────────────────────────────────────
    stats   = st.session_state.stats
    s_total = stats["total_scans"]
    s_threat= stats["threats_found"]
    s_safe  = stats["safe_scans"]
    s_crit  = stats["critical"]

    cols = st.columns(4)
    stat_data = [
        ("🔍", str(s_total),  "Total Scans",      "#00d4ff"),
        ("⚠️", str(s_threat), "Threats Detected",  "#ffb340"),
        ("✅", str(s_safe),   "Safe Scans",        "#00ff9d"),
        ("🔴", str(s_crit),   "Critical Threats",  "#ff3366"),
    ]
    for col, (icon, val, lbl, color) in zip(cols, stat_data):
        with col:
            H(f'''
            <div class="stat-card">
                <div style="font-size:1.6rem">{icon}</div>
                <div class="stat-value" style="background:linear-gradient(135deg,{color},{color}88);
                     -webkit-background-clip:text">{val}</div>
                <div class="stat-label">{lbl}</div>
            </div>''')

    st.write("")
    H('<div class="cyber-divider"></div>')

    # ── Quick Actions ─────────────────────────────────────────────
    H('''<div style="text-align:center;margin-bottom:1.5rem">
        <div style="font-family:var(--font-display);font-size:0.65rem;letter-spacing:0.2em;
                    color:var(--text-dim);text-transform:uppercase">Quick AI Actions</div>
    </div>''')

    import streamlit.components.v1 as components
    components.html("""
<!DOCTYPE html><html><head>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:transparent;}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:0 2px}
.card{
  background:rgba(8,18,38,0.85);
  border:1px solid rgba(0,212,255,0.12);
  border-radius:16px;
  width:100%;padding:1.4rem 1rem;
  display:flex;flex-direction:column;
  align-items:center;justify-content:center;
  gap:10px;cursor:pointer;
  transition:all 0.25s ease;
  position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;
  top:7px;left:7px;width:12px;height:12px;
  border-top:2px solid rgba(0,212,255,0.4);
  border-left:2px solid rgba(0,212,255,0.4);
  border-radius:2px 0 0 0;
}
.card:hover{
  border-color:rgba(0,212,255,0.45);
  background:rgba(0,212,255,0.06);
  box-shadow:0 0 30px rgba(0,212,255,0.12);
  transform:translateY(-3px);
}
.card-emoji{font-size:1.6rem;line-height:1;font-family:'Segoe UI Emoji','Apple Color Emoji','Noto Color Emoji',sans-serif}
.card-name{
  font-family:'Orbitron',monospace;
  font-size:0.55rem;font-weight:700;
  letter-spacing:0.12em;text-transform:uppercase;
  color:#00d4ff;text-align:center;
  text-shadow:0 0 10px rgba(0,212,255,0.4);
  line-height:1.5;padding:0 6px;
}
</style>
</head><body>
<div class="grid">
  <div class="card" onclick="window.parent.document.querySelectorAll('button').forEach(b=>{if(b.innerText.trim()==='AI Analyzer')b.click()})">
    <div class="card-emoji">&#x1F52C;</div><div class="card-name">AI ANALYZER</div>
  </div>
  <div class="card" onclick="window.parent.document.querySelectorAll('button').forEach(b=>{if(b.innerText.trim()==='URL Scanner')b.click()})">
    <div class="card-emoji">&#x1F310;</div><div class="card-name">URL SCANNER</div>
  </div>
  <div class="card" onclick="window.parent.document.querySelectorAll('button').forEach(b=>{if(b.innerText.trim()==='QR Scanner')b.click()})">
    <div class="card-emoji">&#x1F4F7;</div><div class="card-name">QR SCANNER</div>
  </div>
  <div class="card" onclick="window.parent.document.querySelectorAll('button').forEach(b=>{if(b.innerText.trim()==='Company Verify')b.click()})">
    <div class="card-emoji">&#x1F3E2;</div><div class="card-name">COMPANY VERIFIER</div>
  </div>
</div>
</body></html>
""", height=130)

    st.write("")
    H('<div class="cyber-divider"></div>')

    H('''<div style="display:flex;align-items:center;gap:0.75rem;margin:1.5rem 0 0.75rem">
        <div class="section-header" style="margin:0">🕘 Recent Threat History</div>
        <span style="font-family:var(--font-mono);font-size:0.6rem;letter-spacing:0.1em;
                     color:var(--success);background:rgba(0,255,157,0.08);
                     border:1px solid rgba(0,255,157,0.2);border-radius:10px;padding:0.15rem 0.6rem">
            LIVE FEED
        </span>
    </div>''')

    history = st.session_state.stats.get("scan_history", [])
    if history:
        for item in reversed(history[-8:]):
            level = item.get("level", "SAFE")
            stype = item.get("type",  "—")
            score = item.get("score", 0)
            ts    = item.get("ts",    "—")
            verdicts = {
                "SAFE":     "No threat detected",
                "LOW":      "Low-risk content found",
                "MEDIUM":   "Suspicious activity flagged",
                "HIGH":     "High-risk threat detected",
                "CRITICAL": "Critical threat — action required",
            }
            title_str = verdicts.get(level, "Scan complete")
            H(f'''
            <div class="threat-feed-item {level}">
                <span class="feed-level-badge badge-{level}">{level}</span>
                <span class="feed-title">{title_str}</span>
                <span class="feed-type">{stype}</span>
                <span style="font-family:var(--font-mono);font-size:0.72rem;
                             color:var(--text-dim);margin-left:auto">{score}/100 · {ts}</span>
            </div>''')
    else:
        H('''
        <div style="text-align:center;padding:2.5rem;color:var(--text-dim);
                    font-family:var(--font-mono);font-size:0.82rem;
                    border:1px dashed rgba(0,212,255,0.12);border-radius:12px">
            No scans yet. Run your first analysis above.
        </div>''')


# ══════════════════════════════════════════════════════════════════
# PAGE: ANALYZER
# ══════════════════════════════════════════════════════════════════
elif selected == "Analyzer":

    H('''<div class="page-enter">
        <div class="cyber-title" style="font-size:1.9rem;margin-bottom:0.3rem">🔬 AI Threat Analyzer</div>
        <div class="cyber-subtitle typing-cursor" style="margin-bottom:1rem" id="analyzer-sub">
            Analyse text · images (OCR) · PDF documents
        </div>
    </div>''')
    H('<div class="cyber-divider"></div>')

    tab_text, tab_image, tab_pdf = st.tabs(["📝  Text / Message", "🖼️  Image (OCR)", "📄  PDF Document"])

    with tab_text:
        st.write("")
        section_header("Quick Examples", "⚡")

        # ── Multilingual example tabs ────────────────────────────────────────
        EXAMPLES = {
            "Fake Internship (EN)":  "Urgent! You have been selected for a premium internship. Earn Rs 30,000/month from home. Pay Rs 1500 registration fee immediately via UPI. Limited seats.",
            "Phishing Email (EN)":   "Dear user, your account has been suspended due to suspicious activity. Click here to verify your account and enter your password and bank details within 24 hours.",
            "Scam Job (EN)":         "Work from home data entry job. Earn $500/day guaranteed. No experience needed. Pay $100 security deposit via Bitcoin to start immediately.",
            "போலி வேலை (Tamil)":     "அவசரம்! உங்களுக்கு ஒரு சிறப்பு இன்டர்ன்ஷிப் வழங்கப்பட்டுள்ளது. மாதம் ரூ 30,000 வீட்டிலிருந்தே சம்பாதியுங்கள். உடனடியாக ரூ 1500 பதிவு கட்டணம் செலுத்துங்கள்.",
            "नकली नौकरी (Hindi)":   "अर्जेंट! आपको एक प्रीमियम इंटर्नशिप के लिए चुना गया है। घर से काम करें और महीने में ₹30,000 कमाएं। तुरंत ₹1500 रजिस्ट्रेशन फीस UPI से भेजें।",
            "Trabajo Falso (ES)":    "¡Urgente! Ha sido seleccionado para una pasantía premium. Gane $500 por día desde casa. No necesita experiencia. Pague $100 de depósito de seguridad vía Bitcoin.",
            "నకిలీ ఉద్యోగం (Telugu)": "అర్జెంట్! మీకు ప్రీమియం ఇంటర్న్‌షిప్ కోసం ఎంపిక చేయబడ్డారు. నెలకు ₹30,000 ఇంటి నుండి సంపాదించండి. వెంటనే ₹1500 రిజిస్ట్రేషన్ ఫీజు చెల్లించండి.",
            "ವಂಚನೆ ಕೆಲಸ (Kannada)": "ತುರ್ತು! ನೀವು ಪ್ರೀಮಿಯಂ ಇಂಟರ್ನ್‌ಶಿಪ್‌ಗಾಗಿ ಆಯ್ಕೆಯಾಗಿದ್ದೀರಿ. ಮನೆಯಿಂದ ₹30,000 ತಿಂಗಳಿಗೆ ಸಂಪಾದಿಸಿ. ತಕ್ಷಣ ₹1500 ನೋಂದಣಿ ಶುಲ್ಕ ಪಾವತಿಸಿ.",
            "വ്യാജ ജോലി (Malayalam)": "അടിയന്തരം! നിങ്ങൾ ഒരു പ്രീമിയം ഇന്റേൺഷിപ്പിനായി തിരഞ്ഞെടുക്കപ്പെട്ടു. വീട്ടിൽ നിന്ന് ₹30,000 പ്രതിമാസം നേടൂ. ഉടൻ ₹1500 രജിസ്ട്രേഷൻ ഫീ അടക്കുക.",
        }

        # ── Language support banner ──────────────────────────────────────────
        lang_list = " · ".join(
            f'{v["flag"]} {v["name"]}' for v in SUPPORTED_LANGUAGES.values()
        )
        H(f'''<div style="
            background:rgba(124,58,237,0.07);
            border:1px solid rgba(124,58,237,0.25);
            border-radius:10px;padding:0.6rem 1rem;
            font-family:var(--font-mono);font-size:0.72rem;
            color:#a78bfa;margin-bottom:0.75rem;
            display:flex;align-items:center;gap:0.6rem">
            <span style="font-size:1rem">🌐</span>
            <span><strong style="letter-spacing:0.06em">MULTILINGUAL AI</strong>
            &nbsp;·&nbsp; Auto-detects &amp; translates:
            <span style="color:#7c3aed;opacity:0.85">{lang_list}</span></span>
        </div>''')

        # Row 1: English examples
        ecols = st.columns(3)
        eng_examples = [(k, v) for k, v in EXAMPLES.items() if '(EN)' in k]
        for i, (label, txt) in enumerate(eng_examples):
            with ecols[i]:
                if st.button(label, key=f"ex_{i}", use_container_width=True):
                    st.session_state["analyzer_text"] = txt

        # Row 2: Multilingual examples
        H('<div style="margin-top:0.5rem"></div>')
        lang_examples = [(k, v) for k, v in EXAMPLES.items() if '(EN)' not in k]
        mcols = st.columns(len(lang_examples))
        for i, (label, txt) in enumerate(lang_examples):
            with mcols[i]:
                if st.button(label, key=f"mex_{i}", use_container_width=True):
                    st.session_state["analyzer_text"] = txt

        st.write("")
        text_input = st.text_area(
            "Paste suspicious content here",
            value      =st.session_state.get("analyzer_text", ""),
            height     =160,
            placeholder="Paste a suspicious job offer, recruiter message, email, or any text to analyse — in any supported language...",
            key        ="analyzer_ta",
            label_visibility="collapsed",
        )
        H(f'<div style="text-align:right;font-size:0.75rem;color:var(--text-dim);'
          f'font-family:var(--font-mono);margin-top:4px">{len(text_input)} chars</div>')

        st.write("")
        H('<div class="cta-btn">')
        analyse_clicked = st.button("⚡ Analyze Threat", use_container_width=True, key="analyze_btn")
        H("</div>")

        if analyse_clicked:
            if not text_input.strip():
                H('<div class="alert-warning">⚠️ Please enter some text to analyse.</div>')
            else:
                steps = [
                    "🌐 Detecting language...",
                    "🔄 Translating to English (if needed)...",
                    "🧠 Running NLP analysis...",
                    "🕵️ Detecting threat patterns...",
                    "📊 Calculating risk score...",
                    "📋 Generating intelligence report...",
                ]
                pb = st.progress(0); ph = st.empty()
                for i, step in enumerate(steps):
                    ph.markdown(f'<div style="color:var(--primary);font-family:var(--font-mono);'
                                f'font-size:0.82rem">{step}</div>', unsafe_allow_html=True)
                    pb.progress((i + 1) / len(steps)); time.sleep(0)
                ph.empty(); pb.empty()

                # Combined pipeline: always run Text Analysis; if the pasted
                # text contains one or more URLs, also run the FULL URL
                # Analysis pipeline on each one (website content extraction,
                # threat score, scam explanation, suspicious indicators,
                # extracted website text) -- automatically, no module switch.
                combined = analyse_text_full(text_input)
                result   = combined["text_result"]
                log_scan(result, "AI Analyzer")

                # ── Language detection badge (safe HTML only) ────────────────
                if result.get('lang_code') and result['lang_code'] not in ('unknown', 'en'):
                    badge_html = language_badge_html({
                        'flag':               result.get('lang_flag', '🏳️'),
                        'lang_name':          result.get('lang_name', ''),
                        'native_name':        result.get('lang_native', ''),
                        'confidence':         result.get('lang_confidence', 0),
                        'was_translated':     result.get('was_translated', False),
                        'translation_method': result.get('translation_method', ''),
                        'translation_success':result.get('translation_success', False),
                    })
                    H(badge_html)

                    # Original text in a native Streamlit expander (no HTML needed)
                    if result.get('original_text') and result['original_text'] != result.get('translated_text'):
                        with st.expander(f"📄 Original {result.get('lang_name', '')} text"):
                            st.text(result['original_text'])
                    if result.get('was_translated') and result.get('translated_text'):
                        with st.expander("🔤 Translated text used for analysis"):
                            st.text(result['translated_text'])

                elif result.get('lang_code') == 'en':
                    H(language_badge_html({
                        'flag': '🇬🇧', 'lang_name': 'English', 'native_name': 'English',
                        'confidence': result.get('lang_confidence', 0.9),
                        'was_translated': False, 'translation_method': '',
                        'translation_success': False,
                    }))
                
                render_full_result(result)

                # ── Auto-triggered URL Analysis for every link found in the text ──
                for url_res in combined["url_results"]:
                    st.write("")
                    H('<div class="cyber-divider"></div>')
                    section_header(f"🔗 URL Analysis — {url_res.get('url')}", "🌐")
                    log_scan(url_res, "URL Scanner (auto, from Text)")
                    render_full_result(url_res)

    with tab_image:
        st.write("")
        uploaded_img = st.file_uploader(
            "Upload Image for OCR",
            type=["png","jpg","jpeg","bmp","tiff"],
            label_visibility="collapsed",
            key="ocr_uploader",
        )
        if uploaded_img:
            col1, col2 = st.columns([1, 1])
            with col1:
                st.image(uploaded_img, caption="Uploaded Image", use_container_width=True)
            with col2:
                pb = st.progress(0); ph = st.empty()
                for i, msg in enumerate(["🔍 Loading image…", "🔠 Running OCR…", "🧠 Analysing content…"]):
                    ph.markdown(f'<div style="color:var(--primary);font-family:var(--font-mono);'
                                f'font-size:0.82rem">{msg}</div>', unsafe_allow_html=True)
                    pb.progress((i + 1) / 3); time.sleep(0)
                ph.empty(); pb.empty()
                try:
                    result = analyse_ocr_image(uploaded_img.read())
                except Exception as _ocr_err:
                    err_msg = str(_ocr_err)
                    if "tesseract" in err_msg.lower() or "TesseractNotFound" in err_msg:
                        result = {"error": "⚠️ Tesseract-OCR is not installed or not found in PATH. "
                                           "To fix this, install it on your server: "
                                           "<code>sudo apt-get install tesseract-ocr</code> "
                                           "then restart Streamlit."}
                    else:
                        result = {"error": f"⚠️ OCR failed: {err_msg}"}
                if "extracted_text" in result:
                    section_header("Extracted Text", "📄")
                    H(f'<div class="text-preview">{result["extracted_text"][:600]}</div>')
                    H(f'<div style="font-size:0.75rem;color:var(--text-dim);margin-top:4px;font-family:var(--font-mono)">'
                      f'{result["word_count"]} words · {result["char_count"]} chars</div>')
            log_scan(result, "OCR Scanner")
            st.write("")
            render_full_result(result)

    with tab_pdf:
        st.write("")
        uploaded_pdf = st.file_uploader(
            "Upload PDF Document",
            type=["pdf"],
            label_visibility="collapsed",
            key="pdf_uploader",
        )
        if uploaded_pdf:
            section_header("Document Info", "📋")
            info_cols = st.columns(3)
            with info_cols[0]:
                H(f'<div class="stat-card"><div style="font-size:1.4rem">📄</div>'
                  f'<div class="stat-value" style="font-size:1rem;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text">{uploaded_pdf.name[:24]}</div>'
                  f'<div class="stat-label">Filename</div></div>')
            with info_cols[1]:
                H(f'<div class="stat-card"><div style="font-size:1.4rem">💾</div>'
                  f'<div class="stat-value" style="font-size:1.3rem;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text">{round(uploaded_pdf.size/1024,1)} KB</div>'
                  f'<div class="stat-label">File Size</div></div>')

            pb = st.progress(0); ph = st.empty()
            raw = uploaded_pdf.read()
            for i, msg in enumerate(["📂 Reading PDF…", "📃 Extracting pages…", "🧠 Analysing content…"]):
                ph.markdown(f'<div style="color:var(--primary);font-family:var(--font-mono);font-size:0.82rem">{msg}</div>', unsafe_allow_html=True)
                pb.progress((i + 1) / 3); time.sleep(0)
            ph.empty(); pb.empty()

            result = analyse_pdf(raw)
            if "page_count" in result:
                with info_cols[2]:
                    H(f'<div class="stat-card"><div style="font-size:1.4rem">📑</div>'
                      f'<div class="stat-value" style="font-size:1.3rem;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text">{result["page_count"]}</div>'
                      f'<div class="stat-label">Pages</div></div>')
            if "preview_text" in result:
                st.write("")
                section_header("Document Preview", "👁️")
                _safe_preview = _html.escape(result["preview_text"])
                H(f'<div class="text-preview">{_safe_preview}</div>')
                H(f'<div style="font-size:0.75rem;color:var(--text-dim);margin-top:4px;font-family:var(--font-mono)">'
                  f'{result.get("word_count",0)} words analysed</div>')
            log_scan(result, "PDF Scanner")
            st.write("")
            render_full_result(result)


# ══════════════════════════════════════════════════════════════════
# PAGE: URL SCANNER
# ══════════════════════════════════════════════════════════════════
elif selected == "URL Scanner":

    H('''<div class="page-enter">
        <div class="cyber-title" style="font-size:1.9rem;margin-bottom:0.3rem">🌐 URL Scanner</div>
        <div class="cyber-subtitle" style="margin-bottom:1rem">Detect phishing, typosquatting, and malicious domains</div>
    </div>''')
    H('<div class="cyber-divider"></div>')

    section_header("Quick Examples", "⚡")
    URL_EXAMPLES = {
        "Phishing Login": "http://g00gle-secure-login.xyz/signin?user=verify&redirect=bank",
        "IP Domain":      "http://192.168.1.1/paypal-login/confirm-account.php",
        "Legit URL":      "https://www.linkedin.com/jobs/search/?keywords=software+engineer",
    }
    ucols = st.columns(3)
    for i, (lbl, url) in enumerate(URL_EXAMPLES.items()):
        with ucols[i]:
            if st.button(lbl, key=f"uex_{i}", use_container_width=True):
                st.session_state["url_input"] = url

    st.write("")
    url_val = st.text_input(
        "Enter URL",
        value      =st.session_state.get("url_input", ""),
        placeholder="https://example.com/path?param=value",
        label_visibility="collapsed",
    )
    if url_val:
        H(f'<div class="url-display">{url_val}</div>')

    st.write("")
    H('<div class="cta-btn">')
    scan_url = st.button("⚡ Scan URL", use_container_width=True, key="scan_url_btn")
    H("</div>")

    if scan_url:
        if not url_val.strip():
            H('<div class="alert-warning">⚠️ Please enter a URL to scan.</div>')
        else:
            steps = ["🔗 Parsing URL structure…", "🛡️ Checking domain reputation…",
                     "🔍 Scanning for phishing patterns…", "🌐 Analysing webpage content…",
                     "📊 Calculating risk score…"]
            pb = st.progress(0); ph = st.empty()
            for i, step in enumerate(steps):
                ph.markdown(f'<div style="color:var(--primary);font-family:var(--font-mono);'
                            f'font-size:0.82rem">{step}</div>', unsafe_allow_html=True)
                pb.progress((i + 1) / len(steps)); time.sleep(0)
            ph.empty(); pb.empty()
            result = analyse_url_full(url_val.strip())
            log_scan(result, "URL Scanner")
            st.session_state.result_url = result

    if st.session_state.result_url:
        # ✚ ADD-ON: animated cyber-security popup + "Open Website"/"Blocked"
        # action button — rendered directly above the result card (near the
        # threat status, before the user has to scroll) so the safe/blocked
        # state is visible immediately. Purely additive — does not affect
        # render_full_result() or scoring below.
        render_threat_popup(st.session_state.result_url, url_val)

        render_full_result(st.session_state.result_url)

        # ── SYSTEM CONSOLE LOGGER (Detailed log requirements) ──────────────────
        _logs = st.session_state.result_url.get("debug_logs", {})
        print("\n" + "="*50)
        print("[UnifiedLens AI - Live URL Scraper Debugger]")
        print(f"URL String Checked  : {url_val}")
        print(f"HTTP Return Status  : {_logs.get('http_status') or 'N/A'}")
        print(f"Response Body Size  : {_logs.get('response_size')} bytes")
        print(f"HTML Payload Size   : {_logs.get('html_size')} bytes")
        print(f"Extracted Text Len  : {_logs.get('extracted_text_len')} characters")
        print(f"Extraction Method   : {_logs.get('extraction_method')}")
        print(f"JS Engine Run State : {_logs.get('js_rendering_used')}")
        print(f"Scam Model Handoff  : {_logs.get('reached_text_model')}")
        print(f"Text ML Probability : {_logs.get('text_ml_prob')}")
        print(f"Text Rule Score     : {_logs.get('rule_score')}")
        print(f"URL Heuristics Score: {_logs.get('url_heuristic_score')}")
        print(f"URL Model Prob      : {_logs.get('url_ml_prob')}")
        print(f"URL Model Top Signals: {_logs.get('url_ml_top_signals')}")
        print(f"URL Model Fetch Note: {_logs.get('url_ml_fetch_note')}")
        print(f"Final Combined Score: {_logs.get('final_hybrid_score')}/100")
        print("="*50 + "\n")

        # NOTE: Website Access, Extracted Website Text, Text Keyword Score,
        # Text ML Result, and Final Combined Score are now rendered directly
        # inside the main result card by render_full_result() (see the
        # "Website Content Analysis" section, next to the Recommendations
        # block) — no separate sections needed here.

# ══════════════════════════════════════════════════════════════════
# PAGE: QR SCANNER
# ══════════════════════════════════════════════════════════════════
elif selected == "QR Scanner":

    H('''<div class="page-enter">
        <div class="cyber-title" style="font-size:1.9rem;margin-bottom:0.3rem">📷 QR Scanner</div>
        <div class="cyber-subtitle" style="margin-bottom:1rem">Upload a QR code image to decode and analyse for hidden threats</div>
    </div>''')
    H('<div class="cyber-divider"></div>')

    uploaded = st.file_uploader(
        "Upload QR Code Image",
        type=["png","jpg","jpeg","bmp","gif"],
        label_visibility="collapsed",
    )
    if uploaded:
        col1, col2 = st.columns([1, 2])
        with col1:
            H('<div class="scan-line">')
            st.image(uploaded, caption="Uploaded QR Code", use_container_width=True)
            H("</div>")
        with col2:
            with st.spinner("Decoding QR code…"):
                time.sleep(0)
                result = analyse_qr(uploaded.read())
            if "qr_data" in result:
                section_header("Decoded Content", "🔓")
                H(f'<div class="url-display">{result["qr_data"]}</div>')
                _qr_type_meta = {
                    "URL":   ("🔗", "URL — routed through the URL Scanner pipeline"),
                    "EMAIL": ("📧", "Email address — routed through Text Scam Detection"),
                    "PHONE": ("📞", "Phone number — routed through Text Scam Detection"),
                    "TEXT":  ("📝", "Plain text — routed through Text Scam Detection"),
                }
                _icon, _desc = _qr_type_meta.get(result.get("qr_type", "TEXT"), ("❔", "Unknown content type"))
                H(f'<div style="font-size:0.75rem;color:var(--text-dim);margin-top:4px;font-family:var(--font-mono)">'
                  f'{_icon} Type: {result.get("qr_type","UNKNOWN")} — {_desc}</div>')
            log_scan(result, "QR Scanner")
            st.session_state.result_qr = result
        if st.session_state.result_qr:
            st.write("")
            render_full_result(st.session_state.result_qr)


# ══════════════════════════════════════════════════════════════════
# PAGE: COMPANY VERIFIER
# ══════════════════════════════════════════════════════════════════
elif selected == "Company Verifier":

    H('''<div class="page-enter">
        <div class="cyber-title" style="font-size:1.9rem;margin-bottom:0.3rem">🏢 Company Verifier</div>
        <div class="cyber-subtitle" style="margin-bottom:1rem">Verify the legitimacy of a company, recruiter email, and website</div>
    </div>''')
    H('<div class="cyber-divider"></div>')

    c1, c2 = st.columns(2)
    with c1:
        company_name    = st.text_input("Company Name",    placeholder="e.g. Royal Overseas Jobs Pvt. Ltd.")
    with c2:
        recruiter_email = st.text_input("Recruiter Email", placeholder="e.g. hr@companyjobs.gmail.com")
    website_url = st.text_input("Company Website", placeholder="e.g. https://royaloverseasjobs.xyz")

    st.write("")
    H('<div class="cta-btn">')
    verify_clicked = st.button("⚡ Verify Company", use_container_width=True, key="verify_btn")
    H("</div>")

    if verify_clicked:
        if not company_name.strip():
            H('<div class="alert-warning">⚠️ Please enter a company name.</div>')
        else:
            steps = ["🏢 Analysing company profile…", "📧 Checking recruiter email domain…",
                     "🌐 Scanning website URL…", "🔍 Computing trust score…"]
            pb = st.progress(0); ph = st.empty()
            for i, step in enumerate(steps):
                ph.markdown(f'<div style="color:var(--primary);font-family:var(--font-mono);'
                            f'font-size:0.82rem">{step}</div>', unsafe_allow_html=True)
                pb.progress((i + 1) / len(steps)); time.sleep(0)
            ph.empty(); pb.empty()
            result = analyse_company(company_name, recruiter_email, website_url)

            trust = result.get("trust_score", 0)
            st.write("")
            section_header("Trust Score", "🔒")
            H(f'''
            <div class="glass-card" style="padding:1.25rem 1.5rem">
                <div style="display:flex;justify-content:space-between;margin-bottom:0.75rem">
                    <span style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.75rem;letter-spacing:0.08em">LEGITIMACY SCORE</span>
                    <span style="color:var(--primary);font-family:var(--font-display);font-weight:700;font-size:1rem">{trust}/100</span>
                </div>
                <div class="trust-meter-bar">
                    <div class="trust-meter-fill" style="width:{trust}%"></div>
                </div>
            </div>''')

            log_scan(result, "Company Verifier")
            st.session_state.result_co = result

    if st.session_state.result_co:
        st.write("")
        render_full_result(st.session_state.result_co)


# ══════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ══════════════════════════════════════════════════════════════════
elif selected == "Analytics":

    H('''<div class="page-enter">
        <div class="cyber-title" style="font-size:1.9rem;margin-bottom:0.3rem">📊 Analytics</div>
        <div class="cyber-subtitle" style="margin-bottom:1rem">Real-time threat intelligence from your session scans</div>
    </div>''')
    H('<div class="cyber-divider"></div>')

    # ── Clear History Button ─────────────────────────────────────────
    if st.button("🗑️ Clear All History", key="clear_history_btn"):
        st.session_state.stats = make_empty_stats()
        _clear_localstorage()   # wipe from browser storage too
        st.rerun()

    stats   = st.session_state.stats
    history = stats.get("scan_history", [])
    total   = stats.get("total_scans", 0)

    if total == 0:
        H('''
        <div style="text-align:center;padding:4rem 2rem;color:var(--text-dim);
                    font-family:var(--font-mono);font-size:0.88rem;
                    border:1px dashed rgba(0,212,255,0.12);border-radius:16px;margin:2rem 0">
            <div style="font-size:2.5rem;margin-bottom:1rem;opacity:0.4">📊</div>
            No scan data yet.<br>
            <span style="color:var(--primary);font-size:0.8rem">Run some analyses first — analytics will populate automatically.</span>
        </div>''')
    else:
        # ── Summary Stat Cards ──────────────────────────────────────
        s_threat = stats.get("threats_found", 0)
        s_safe   = stats.get("safe_scans", 0)
        s_crit   = stats.get("critical", 0)
        s_susp   = stats.get("suspicious", 0)

        cols = st.columns(4)
        stat_data = [
            ("🔍", str(total),    "Total Scans",      "#00d4ff"),
            ("⚠️", str(s_threat), "Threats Detected",  "#ffb340"),
            ("✅", str(s_safe),   "Safe Scans",        "#00ff9d"),
            ("🔴", str(s_crit),   "Critical Threats",  "#ff3366"),
        ]
        for col, (icon, val, lbl, color) in zip(cols, stat_data):
            with col:
                H(f'''
                <div class="stat-card">
                    <div style="font-size:1.6rem">{icon}</div>
                    <div class="stat-value" style="background:linear-gradient(135deg,{color},{color}88);
                         -webkit-background-clip:text">{val}</div>
                    <div class="stat-label">{lbl}</div>
                </div>''')

        st.write("")
        H('<div class="cyber-divider"></div>')

        c1, c2 = st.columns(2)

        with c1:
            section_header("Threat Distribution", "📊")
            level_counts = {}
            for item in history:
                lv = item.get("level", "SAFE")
                level_counts[lv] = level_counts.get(lv, 0) + 1
            if level_counts:
                levels_ordered = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                colors_ordered = ["#00ff9d", "#3b82f6", "#ffb340", "#f97316", "#ff3366"]
                lv_labels = [l for l in levels_ordered if l in level_counts]
                lv_vals   = [level_counts[l] for l in lv_labels]
                lv_colors = [colors_ordered[levels_ordered.index(l)] for l in lv_labels]

                fig = go.Figure(go.Pie(
                    labels=lv_labels, values=lv_vals,
                    marker=dict(colors=lv_colors, line=dict(color="#020409", width=2)),
                    hole=0.5, textinfo="label+percent",
                    textfont=dict(family="Rajdhani", size=12, color="#c8d8e8"),
                    hovertemplate="%{label}: %{value} scan(s)<extra></extra>",
                ))
                fig.update_layout(**PLOTLY_LAYOUT, height=280)
                st.plotly_chart(fig, use_container_width=True)
            else:
                H('<div style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.82rem;padding:2rem">No distribution data yet.</div>')

        with c2:
            section_header("Scan Category Breakdown", "🗂️")
            type_counts = {}
            for item in history:
                t = item.get("type", "Unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            if type_counts:
                types  = list(type_counts.keys())
                tcounts = [type_counts[t] for t in types]
                fig = go.Figure(go.Bar(
                    x=tcounts, y=types, orientation="h",
                    marker=dict(color=CYBER_COLORS[:len(types)], opacity=0.85,
                                line=dict(color="rgba(0,0,0,0)", width=0)),
                    text=tcounts, textposition="outside", textfont_color="#5a7a9a",
                ))
                fig.update_layout(**PLOTLY_LAYOUT, height=280,
                    xaxis=dict(showgrid=True, gridcolor="rgba(0,212,255,0.05)", color="#5a7a9a"),
                    yaxis=dict(showgrid=False, color="#5a7a9a"))
                st.plotly_chart(fig, use_container_width=True)
            else:
                H('<div style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.82rem;padding:2rem">No category data yet.</div>')

        H('<div class="cyber-divider"></div>')

        c3, c4 = st.columns([3, 2])

        with c3:
            section_header("Scan History Table", "📋")
            if history:
                H('''<div class="scan-history-table">
                <div class="sht-header">
                    <span>#</span><span>Type</span><span>Level</span><span>Score</span><span>Time</span>
                </div>''')
                for idx, item in enumerate(reversed(history[-20:]), 1):
                    lv    = item.get("level", "SAFE")
                    stype = item.get("type",  "—")
                    score = item.get("score", 0)
                    ts    = item.get("ts",    "—")
                    lv_colors_map = {
                        "SAFE": "#00ff9d", "LOW": "#3b82f6",
                        "MEDIUM": "#ffb340", "HIGH": "#f97316", "CRITICAL": "#ff3366"
                    }
                    lv_color = lv_colors_map.get(lv, "#5a7a9a")
                    H(f'''<div class="sht-row">
                        <span style="color:var(--text-dim)">{idx}</span>
                        <span style="color:var(--text)">{stype}</span>
                        <span><span class="feed-level-badge badge-{lv}" style="font-size:0.65rem">{lv}</span></span>
                        <span style="color:{lv_color};font-family:var(--font-mono)">{score}/100</span>
                        <span style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.72rem">{ts}</span>
                    </div>''')
                H('</div>')

        with c4:
            section_header("Risk Score Timeline", "📈")
            if len(history) >= 2:
                scores = [item.get("score", 0) for item in history[-15:]]
                idxs   = list(range(1, len(scores)+1))
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=idxs, y=scores, mode="lines+markers",
                    line=dict(color="#00d4ff", width=2.5),
                    marker=dict(size=7, color="#00d4ff", line=dict(color="#020409", width=2)),
                    fill="tozeroy", fillcolor="rgba(0,212,255,0.05)",
                    hovertemplate="Scan %{x}: %{y}/100<extra></extra>",
                ))
                fig.update_layout(**PLOTLY_LAYOUT, height=280,
                    xaxis=dict(showgrid=False, color="#5a7a9a", title="Scan #"),
                    yaxis=dict(showgrid=True, gridcolor="rgba(0,212,255,0.05)", color="#5a7a9a", range=[0,100]))
                st.plotly_chart(fig, use_container_width=True)
            else:
                H('<div style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.82rem;padding:2rem">Need at least 2 scans for timeline.</div>')


# ══════════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ══════════════════════════════════════════════════════════════════
elif selected == "About":

    H('''
    <div class="about-hero page-enter">
        <div style="font-size:3.5rem;margin-bottom:1rem;
                    filter:drop-shadow(0 0 25px rgba(0,212,255,0.5));
                    animation:iconFloat 4s ease-in-out infinite;display:inline-block">🛡️</div>
        <div class="cyber-title" style="margin-bottom:0.75rem">Defending Users Against<br>Digital Threats</div>
        <div class="cyber-subtitle">An AI-powered platform built to protect everyday users from online scams</div>
    </div>
    ''')
    H('<div class="cyber-divider"></div>')

    section_header("What UnifiedLens AI Protects Against", "🎯")
    st.write("")
    protect_items = [
        ("🧠", "Smart Threat Scan", "Analyzes messages for\nhidden scam patterns"),
        ("🔗", "Phishing Links",  "Malicious URLs designed\nto steal credentials"),
        ("📷", "QR Scams",        "QR codes redirecting\nto fraud sites"),
        ("👤", "Fake Recruiters", "Impersonated HR &\nrecruiter identities"),
        ("📄", "Fraud PDFs",      "Documents with embedded\nmalicious payloads"),
    ]
    pcols = st.columns(5)
    for col, (icon, title, desc) in zip(pcols, protect_items):
        with col:
            H(f'''
            <div class="protect-card">
                <div style="font-size:1.8rem;margin-bottom:0.6rem;
                            filter:drop-shadow(0 0 8px rgba(0,212,255,0.3))">{icon}</div>
                <div style="font-family:var(--font-display);font-size:0.65rem;font-weight:700;
                            color:var(--primary);letter-spacing:0.1em;text-transform:uppercase;
                            margin-bottom:0.4rem">{title}</div>
                <div style="font-size:0.78rem;color:var(--text-dim);line-height:1.5">{desc}</div>
            </div>''')

    st.write("")
    H('<div class="cyber-divider"></div>')

    section_header("How It Works", "⚙️")
    st.write("")
    flow_steps = [
        ("01", "📤", "Upload",       "Submit text, URL, QR image, or document"),
        ("02", "🧠", "AI Analysis",  "NLP + ML engine scans for threat signals"),
        ("03", "📊", "Risk Scoring", "Multi-factor risk score calculated (0–100)"),
        ("04", "📋", "Threat Report","Detailed verdict with recommendations"),
    ]
    fcols = st.columns(4)
    for col, (num, icon, title, desc) in zip(fcols, flow_steps):
        with col:
            H(f'''
            <div style="text-align:center;padding:1.5rem 0.5rem">
                <div style="font-family:var(--font-display);font-size:0.6rem;letter-spacing:0.2em;
                            color:var(--text-dim);margin-bottom:0.75rem">STEP {num}</div>
                <div style="font-size:2rem;margin-bottom:0.6rem;
                            filter:drop-shadow(0 0 8px rgba(0,212,255,0.3))">{icon}</div>
                <div style="font-family:var(--font-display);font-size:0.7rem;font-weight:700;
                            color:var(--primary);letter-spacing:0.08em;text-transform:uppercase;
                            margin-bottom:0.4rem">{title}</div>
                <div style="font-size:0.82rem;color:var(--text-dim);line-height:1.5">{desc}</div>
            </div>''')

    st.write("")
    H('<div class="cyber-divider"></div>')

    section_header("Why This Project Matters", "❤️")
    st.write("")
    card('''
    <div style="text-align:center;padding:1rem 0">
        <div style="font-size:2.5rem;margin-bottom:1rem">⚠️</div>
        <div style="font-family:var(--font-display);font-size:0.85rem;font-weight:700;
                    color:var(--primary);letter-spacing:0.08em;text-transform:uppercase;
                    margin-bottom:1rem">The Problem Is Real</div>
        <div style="font-size:1rem;color:var(--text);line-height:1.9;max-width:680px;
                    margin:0 auto;font-family:var(--font-body)"> 
            Online scams are becoming increasingly sophisticated, targeting people through 
            suspicious messages, phishing links, fake websites, QR codes, images, documents, 
            and other digital channels.<br><br> 
            <strong style="color:var(--primary)">UnifiedLens AI was built to help identify suspicious 
            digital threats before they can cause harm</strong> — combining machine learning, 
            natural language processing, OCR, URL analysis, and cybersecurity heuristics 
            into an accessible, real-time threat detection platform.
        </div>
    </div>
    ''')

    st.write("")
    H('<div class="cyber-divider"></div>')

    section_header("Future Vision", "🚀")
    st.write("")
    roadmap = [
    ("📱", "Mobile Application – Develop a mobile-responsive application so users can detect scams anytime, anywhere."),
    ("💬", "AI Chatbot – Guide users and answer questions about the website."),
    ("🌍", "Complete multilingual website interface."),
    ("🎙️", "Voice scam detection using uploaded audio recordings."),
    ("👤", "User login and personal accounts to save scan history."),
]
    for icon, item in roadmap:
        H(f'''
        <div style="display:flex;align-items:center;gap:1rem;padding:0.65rem 1rem;
                    background:rgba(0,212,255,0.02);border:1px solid rgba(0,212,255,0.07);
                    border-left:2px solid rgba(124,58,237,0.5);border-radius:0 8px 8px 0;
                    margin-bottom:0.5rem;font-family:var(--font-body);font-size:0.9rem;color:var(--text)">
            <span style="font-size:1.1rem">{icon}</span> {item}
        </div>''')

    st.write("")
    H('''
    <div style="text-align:center;padding:2.5rem 0 1rem;color:var(--text-dim);
                font-family:var(--font-mono);font-size:0.75rem;letter-spacing:0.06em">
        <span style="color:var(--primary);font-family:var(--font-display);
                     font-size:0.65rem;letter-spacing:0.15em">UnifiedLens AI</span>
        &nbsp;—&nbsp; Data Science Project by Puvisha S , Vidhya Priya P , Hemanthika M
    </div>
    ''')