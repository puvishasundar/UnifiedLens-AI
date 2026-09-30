# analyzer.py — CyberLens AI
# High-level analysis wrappers used by app.py

import io
import logging
import os
import re
import time
import numpy as np
import pytesseract
import requests
import urllib3
from bs4 import BeautifulSoup

# Disable insecure request warning for verify=False on dodgy domains
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Logging ────────────────────────────────────────────────────────────────────
# Uses the root logging config set up in app.py (logging.basicConfig). If this
# module is ever imported standalone (e.g. in a test script), it still logs to
# the console at INFO level by default.
logger = logging.getLogger("cyberlens.analyzer")

_WIN_TESS = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = _WIN_TESS

from utils import (
    score_keywords, compute_risk_level, normalise_score,
    analyse_url, analyse_recruiter_email, analyse_company_name,
    analyse_email_full, verify_company_identity, _domain_core,
    SCAM_KEYWORDS, SHORTENER_DOMAINS,
    PUBLIC_EMAIL_PROVIDERS, DISPOSABLE_EMAIL_DOMAINS, detect_domain_typosquat,
)
from ml_model import predict as ml_predict, get_feature_importance
from url_model import predict_url as url_ml_predict, get_feature_importance_url
from language_utils import detect_and_translate, tag_segments
from trusted_companies import (
    match_trusted_domain, detect_brand_impersonation, company_name_matches_brand,
)

_RECS = {
    'CRITICAL': [
        '🚨 Do NOT respond to or engage with this message.',
        '🔒 Never share personal information, bank details, or OTPs.',
        '📢 Report this to cybercrime.gov.in or your local cyber cell.',
        '🗑️  Block and delete the sender immediately.',
        '🔍 Warn others in your network about this scam.',
    ],
    'HIGH': [
        '⚠️  Exercise extreme caution — multiple red flags detected.',
        '🔎 Independently verify the company via official channels.',
        '💳 Never pay any fee to secure a job or internship.',
        '📞 Call the company directly using a number from their official website.',
        '📧 Check if the email domain matches the official company domain.',
    ],
    'MEDIUM': [
        '🧐 Treat with moderate caution — some suspicious elements found.',
        '🔍 Research the company on LinkedIn and Glassdoor.',
        '❓ Ask for an official offer letter on company letterhead.',
        '🏦 Never transfer money without verified paperwork.',
    ],
    'LOW': [
        '✅ Low risk — still perform basic due diligence.',
        '🔍 Cross-check recruiter details on LinkedIn.',
        '📋 Request a formal job description and offer letter.',
    ],
    'SAFE': [
        '✅ Content appears legitimate.',
        '📝 Keep documentation of all communications.',
        '🔒 Always protect your personal information.',
    ],
}

def get_recommendations(level: str) -> list:
    return _RECS.get(level, _RECS['SAFE'])


def analyse_text(text: str) -> dict:
    if not text or not text.strip():
        return {'error': 'No text provided'}

    # ── Requirements 1 & 2: detect language → translate non-English ────────
    # detect_and_translate() handles: English → passthrough;
    # ta/te/ml/kn/hi/es → full English translation (chunked for long texts);
    # total translation failure → original returned so analysis still runs.
    lang_result   = detect_and_translate(text)
    analysis_text = lang_result['translated_text']   # English, or original if en/failed
    original_text = lang_result['original_text']

    ml_result    = ml_predict(analysis_text)
    ml_scam_prob = ml_result['probability']
    print("ML Scam Probability:", ml_scam_prob)
    logger.info("[Text] lang=%s translated=%s via=%s ml_prob=%.4f",
                lang_result['lang_code'], lang_result['was_translated'],
                lang_result['translation_method'], ml_scam_prob)

    # ── Requirements 2/4/5: the English translation is THE input to the exact
    # same analysis used for English text. The original-language text is no
    # longer scored separately. If translation failed, translated_text IS the
    # original text, so the suspicious-content analysis is never skipped. ───
    kw_result = score_keywords(analysis_text)
    kw_raw    = kw_result['score']
    kw_norm   = normalise_score(kw_raw, ceiling=20.0)

    if kw_norm >= 60:
        ml_weight, kw_weight = 0.30, 0.70
    elif kw_norm <= 10:
        ml_weight, kw_weight = 0.70, 0.30
    else:
        ml_weight, kw_weight = 0.45, 0.55

    blended = (ml_scam_prob * 100 * ml_weight) + (kw_norm * kw_weight)
    blended = min(round(blended, 1), 100.0)

    # ── Requirement 3: unified suspicious indicators across the WHOLE
    # content — main text, embedded URLs, QR/UPI payloads, email addresses
    # and phone numbers — pulled from BOTH the original and the translated
    # text (links are never translated, and translators sometimes mangle
    # or drop them). ────────────────────────────────────────────────────────
    signals         = _extract_contact_signals(original_text, analysis_text)
    text_indicators = _build_text_indicators(signals, kw_result['found'], analysis_text)

    indicator_bonus = 0   # display-only default — keeps scoring untouched
    # ── OPTIONAL but recommended: let hard signals (UPI/QR payment payload,
    # masked/shortened link, disposable or lookalike email domain) feed the
    # score, capped at +40. Applied IDENTICALLY to English input and to the
    # English translation of non-English input. Delete just this block if
    # you want indicators to be display-only. ──────────────────────────────
    _SEV_BONUS = {'critical': 25, 'high': 12, 'medium': 4, 'low': 0}
    indicator_bonus = min(sum(_SEV_BONUS.get(i.get('severity'), 0)
                              for i in text_indicators), 40)
    if indicator_bonus:
        blended = min(round(blended + indicator_bonus, 1), 100.0)

    # Zero-floor for completely safe text — structured indicators still count,
    # so a detected payment payload / masked link is never silently erased.
    ML_SAFE_THRESHOLD = 15.0
    if kw_raw == 0 and (ml_scam_prob * 100) < ML_SAFE_THRESHOLD:
        blended = min(float(indicator_bonus), 100.0)

    risk_info  = compute_risk_level(blended)
    level      = risk_info['level']
    confidence = round(ml_result['confidence'] * 100, 1)

    top_features  = get_feature_importance(analysis_text, top_n=8)
    feature_words = [f[0] for f in top_features]

    all_suspicious = list(set(kw_result['found'] + feature_words))[:12]
    top_kw_hits    = kw_result['found'][:4]

    if level == 'CRITICAL':
        verdict = (
            f"🚨 This content shows strong indicators of a scam or phishing attempt, "
            f"including: {', '.join(top_kw_hits)}. Do not act on any requests within it."
            if top_kw_hits else
            "🚨 This content shows strong indicators of a scam or phishing attempt based on AI pattern analysis. "
            "Do not act on any requests within it."
        )
    elif level == 'HIGH':
        verdict = (
            f"⚠️ This content shows strong indicators of a scam or phishing attempt, "
            f"such as: {', '.join(top_kw_hits)}. Treat it with serious caution."
            if top_kw_hits else
            "⚠️ This content shows strong indicators of a scam or phishing attempt. Treat it with serious caution."
        )
    elif level == 'MEDIUM':
        verdict = (
            f"🧐 This content contains some suspicious elements worth investigating, "
            f"including: {', '.join(top_kw_hits)}. Verify before taking any action."
            if top_kw_hits else
            "🧐 This content contains some suspicious elements worth investigating. Verify before taking any action."
        )
    elif level == 'LOW':
        verdict = (
            "🔵 Only minor risk factors were identified. This content appears largely legitimate "
            "but still warrants basic verification."
        )
    else:
        verdict = "✅ No major suspicious indicators were detected. This content appears to be safe."

    # Requirement 3: surface non-keyword detections in the verdict itself
    extra_parts = []
    if signals['payment_uris']: extra_parts.append('a UPI/QR payment payload')
    if signals['urls']:         extra_parts.append(f"{len(signals['urls'])} embedded link(s)")
    if signals['emails']:       extra_parts.append('embedded email address(es)')
    if signals['phones']:       extra_parts.append('phone number(s) to contact')
    if extra_parts and level != 'SAFE':
        verdict += (" The content also contains " + ", ".join(extra_parts) +
                    " — see the suspicious indicators for details.")

    return {
        'risk_score':       blended,
        'confidence':       confidence,
        'ml_probability':   round(ml_scam_prob * 100, 1),
        'risk_level':       level,
        'risk_color':       risk_info['color'],
        'risk_emoji':       risk_info['emoji'],
        'verdict':          verdict,
        'suspicious_kws':   all_suspicious,
        'keyword_hits':     kw_result['found'],
        'recommendations':  get_recommendations(level),
        'ml_label':         ml_result['label'],
        'scan_type':        'Text Analysis',
        # language / translation (existing keys — UI depends on them)
        'lang_code':        lang_result['lang_code'],
        'lang_name':        lang_result['lang_name'],
        'lang_native':      lang_result['native_name'],
        'lang_flag':        lang_result['flag'],
        'lang_confidence':  lang_result['confidence'],
        'was_translated':   lang_result['was_translated'],
        'translated_text':  lang_result['translated_text'],
        'original_text':    lang_result['original_text'],
        'translation_method': lang_result['translation_method'],
        'translation_success': lang_result['translation_success'],
        'translation_error': lang_result.get('translation_error'),
        # NEW — unified indicators + extracted signals
        'text_indicators':  text_indicators,
        'urls_found':       signals['urls'],
        'contact_info': {
            'emails':       signals['emails'],
            'phones':       signals['phones'],
            'payment_uris': signals['payment_uris'],
        },
    }

# ─── URL detection inside free-form text (Requirement: TEXT ANALYSIS) ───────
# Matches explicit schemes (http/https), "www."-prefixed hosts, and bare
# domain-like tokens (e.g. "bit.ly/xyz", "amaz0n-secure.com") so pasted
# messages, emails, and SMS content all get their embedded links caught.
_TEXT_URL_RE = re.compile(
    r'(?:(?:https?://)[^\s<>"\')]+)'          # explicit http(s)://...
    r'|(?:www\.[^\s<>"\')]+)'                 # www.example.com/...
    r'|(?:\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'\.[a-zA-Z]{2,24}(?:/[^\s<>"\')]*)?\b)',  # bare domain[/path]
    re.IGNORECASE,
)

# Trailing punctuation that regularly gets swept up when a URL ends a
# sentence ("visit http://evil.com." or "...secure.com!").
_URL_TRAILING_PUNCT = '.,;:!?)"\''

# Used to strip full email addresses out of the text *before* URL scanning,
# so "john.doe@example.com" isn't mis-split into two fake bare-domain hits
# ("john.doe" and "example.com").
_EMAIL_INLINE_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


def extract_urls_from_text(text: str) -> list:
    """
    Find and return every distinct URL/domain mentioned inside a block of
    free text, in first-seen order. Filters out email addresses and
    obvious non-URL numeric tokens (e.g. "3.14", "v2.0") that would
    otherwise match the bare-domain fallback pattern.
    """
    if not text:
        return []

    text_no_emails = _EMAIL_INLINE_RE.sub(' ', text)
    candidates = _TEXT_URL_RE.findall(text_no_emails)
    seen, urls = set(), []

    for raw in candidates:
        u = raw.strip().rstrip(_URL_TRAILING_PUNCT)
        if not u:
            continue

        # Belt-and-braces: skip anything that still looks email-shaped.
        if _EMAIL_RE.match(u) or ('@' in u):
            continue

        host_part = re.sub(r'^https?://', '', u, flags=re.IGNORECASE).split('/')[0]
        tld_candidate = host_part.rsplit('.', 1)[-1] if '.' in host_part else ''

        # Reject bare numeric-only "domains" (version numbers, decimals, IDs)
        # unless it's a proper http(s)/www URL, which we always trust.
        if not u.lower().startswith(('http://', 'https://', 'www.')):
            if not tld_candidate.isalpha() or len(tld_candidate) < 2:
                continue
            if host_part.replace('.', '').isdigit():
                continue

        normalised = u if u.lower().startswith(('http://', 'https://')) else f'http://{u}'

        key = normalised.lower()
        if key not in seen:
            seen.add(key)
            urls.append(normalised)

    return urls


# ─── Contact-info & QR-payment-payload extraction (Requirement 3) ──────────
# The Text Analyzer must check EVERY relevant part of the content: main
# text, URLs/links, QR-code payloads, contact information, phone numbers,
# email addresses and other suspicious elements — not just keywords.

_PHONE_CAND_RE = re.compile(r'\+?\d[\d \t\-().]{7,16}\d')

# QR codes pasted as text encode payloads like 'upi://pay?pa=...&am=5000'
# (the classic collect-request scam QR) or crypto payment URIs.
_QR_PAYLOAD_RE = re.compile(
    r'\bupi://[^\s<>"\')]+'
    r'|\b(?:bitcoin|ethereum|bitcoincash):[^\s<>"\')]+',
    re.IGNORECASE,
)


def _extract_phones(text: str) -> list:
    """
    Plausible phone numbers found in *text* (Indian 10-digit mobiles with
    optional +91, plus generic international formats), de-duplicated in
    first-seen order. Pure-digit noise — version numbers, prices, OTPs,
    dates — is rejected by the length/prefix validation below.
    """
    phones, seen = [], set()
    for raw in _PHONE_CAND_RE.findall(text or ''):
        digits = re.sub(r'\D', '', raw)
        has_plus = raw.lstrip().startswith('+')
        if len(digits) == 12 and digits.startswith('91'):
            digits = digits[2:]                          # +91 → 10-digit Indian
        ok = (len(digits) == 10 and digits[0] in '6789')      # Indian mobile
        ok = ok or (has_plus and 10 <= len(digits) <= 15)     # +country format
        ok = ok or (len(digits) == 11 and digits[0] == '0')   # landline style
        if not ok or digits in seen:
            continue
        seen.add(digits)
        phones.append(raw.strip())
    return phones


def _extract_contact_signals(original_text: str, analysis_text: str) -> dict:
    """
    Pull URLs, emails, phone numbers and QR/UPI payment payloads from BOTH
    the original-language text and the English translation (links are never
    translated, and translators occasionally mangle or drop them), then
    de-duplicate everything in first-seen order.
    """
    return {
        'urls':         list(dict.fromkeys(extract_urls_from_text(original_text) +
                                           extract_urls_from_text(analysis_text))),
        'emails':       list(dict.fromkeys(_EMAIL_INLINE_RE.findall(original_text) +
                                           _EMAIL_INLINE_RE.findall(analysis_text))),
        'phones':       list(dict.fromkeys(_extract_phones(original_text) +
                                           _extract_phones(analysis_text))),
        'payment_uris': list(dict.fromkeys(_QR_PAYLOAD_RE.findall(original_text) +
                                           _QR_PAYLOAD_RE.findall(analysis_text))),
    }


def _build_text_indicators(signals: dict, kw_hits: list, analysis_text: str) -> list:
    """
    Requirement 3: build ONE unified list of suspicious indicators covering
    the main text, embedded URLs, QR/UPI payloads, email addresses and phone
    numbers. Every entry explains WHAT was detected and WHY it may be
    suspicious, so the UI can render a consistent explanation across all
    parts of the content.
    """
    indicators = []
    text_lower = analysis_text.lower()

    # 1 ── Scam keywords / phrases (scored on the English translation)
    if kw_hits:
        indicators.append({
            'category': 'Scam Keywords',
            'icon': '🧩',
            'item': ', '.join(kw_hits[:5]) + (' …' if len(kw_hits) > 5 else ''),
            'why': ('These words/phrases match known scam and social-engineering '
                    'language: urgency pressure, fee demands, credential/OTP requests, '
                    'fake offers or authority impersonation.'),
            'severity': 'high' if len(kw_hits) >= 3 else 'medium',
        })

    # 2 ── Embedded URLs / links
    for u in signals['urls']:
        is_short = any(sd in u.lower() for sd in SHORTENER_DOMAINS)
        indicators.append({
            'category': 'Embedded Link',
            'icon': '🔗',
            'item': u,
            'why': ('Shortened/masked link — hides its real destination, a classic '
                    'phishing technique. See the full URL analysis below.' if is_short else
                    'The message contains a link. Scam messages often lead to fake '
                    'login, payment or "verification" pages. See the URL analysis below.'),
            'severity': 'high' if is_short else 'medium',
        })

    # 3 ── QR-code style payment payloads (what most scam QR codes encode)
    for u in signals['payment_uris']:
        indicators.append({
            'category': 'QR / Payment Payload',
            'icon': '📱',
            'item': u[:90],
            'why': ('UPI/crypto payment URI — the exact payload encoded by many scam '
                    'QR codes. Scanning or approving it sends money to the fraudster, '
                    'often disguised as a "receive/refund" request.'),
            'severity': 'critical',
        })

    # 4 ── Email addresses (contact info)
    for e in signals['emails']:
        domain = e.split('@')[-1].lower()
        if domain in DISPOSABLE_EMAIL_DOMAINS:
            ind = {'severity': 'high',
                   'why': f'Disposable/temporary email domain ("{domain}") — commonly '
                          'used by scammers to stay untraceable.'}
        elif domain in PUBLIC_EMAIL_PROVIDERS:
            ind = {'severity': 'medium',
                   'why': f'Free public email provider ("{domain}"). Legitimate companies '
                          'use their own corporate domain — a "recruiter" or "bank '
                          'official" on free mail is a classic red flag.'}
        else:
            typo = detect_domain_typosquat(domain)
            if typo['detected']:
                ind = {'severity': 'high',
                       'why': f'Domain appears to impersonate "{typo["target"]}" '
                              '(typosquatting / lookalike domain).'}
            else:
                ind = {'severity': 'low',
                       'why': 'Reply-to email present. Verify the domain really belongs '
                              'to the claimed organisation before responding.'}
        indicators.append({'category': 'Email Address', 'icon': '📧', 'item': e, **ind})

    # 5 ── Phone numbers (contact info)
    asks_to_contact = any(w in text_lower for w in
                          ('call ', 'whatsapp', 'contact ', 'helpline', 'telegram'))
    for p in signals['phones']:
        indicators.append({
            'category': 'Phone Number',
            'icon': '📞',
            'item': p,
            'why': ('The message directs you to call / WhatsApp a number — moving '
                    'victims to a private phone or WhatsApp chat is a hallmark of '
                    'fake customer-care, "WhatsApp HR" and digital-arrest scams.'
                    if asks_to_contact else
                    'A phone number is embedded in the message. Scam messages often '
                    'move victims off-platform to a phone/WhatsApp conversation.'),
            'severity': 'medium' if asks_to_contact else 'low',
        })

    return indicators


def analyse_text_full(text: str, max_urls: int = 3) -> dict:
    """
    Orchestrator for the Text Analysis module.

    Requirement: if the pasted text contains one or more URLs, run BOTH
    Text Analysis (on the full message — translated to English first when
    the input is non-English) and full URL Analysis (on each embedded
    link — website content extraction, threat score, scam explanation,
    suspicious indicators, extracted website text), then return everything
    needed to display a single combined report, without the user having
    to switch modules.

    The URL list is reused from analyse_text(), which already pulled links
    from BOTH the original and the translated text — so the indicator list
    and the URL result cards always agree.

    Returns:
        {
            'text_result':  <dict from analyse_text()>,
            'urls_found':   [<str>, ...],
            'url_results':  [{'url': <str>, **<dict from analyse_url_full()>}, ...],
            'has_urls':     bool,
            'scan_type':    'Text Analysis',
        }
    """
    text_result = analyse_text(text)

    # Reuse the union of URLs extracted from original + translated text.
    urls_found = text_result.get('urls_found') or extract_urls_from_text(text)
    url_results = []
    for u in urls_found[:max_urls]:
        try:
            r = analyse_url_full(u)
        except Exception as e:
            r = {'error': f'URL analysis failed for {u}: {e}'}
        r = dict(r)
        r['url'] = r.get('url', u)
        r['scan_type'] = 'URL Scanner'   # so the UI renders the full URL card
        url_results.append(r)

    return {
        'text_result':  text_result,
        'urls_found':   urls_found,
        'url_results':  url_results,
        'has_urls':     bool(urls_found),
        'scan_type':    'Text Analysis',
    }


# ═════════════════════════════════════════════════════════════════════════════
# ⛔ STOP — EVERYTHING BELOW THIS POINT IS UNCHANGED.
# Keep YOUR existing analyzer.py exactly as it is, starting from the line:
#
#     SCAM_CONTENT_PHRASES = [
#
# all the way to the end of the file (SCAM_CONTENT_PHRASES, _BOILERPLATE_TAGS,
# _NAV_JUNK, _extract_visible_text, fetch_via_playwright,
# analyse_webpage_content, analyse_url_full, detect_qr_content_type,
# _deskew_image, _enhance_image_for_ocr, analyse_qr, analyse_ocr_image,
# analyse_pdf, analyse_company, and anything else in your file).
# None of that code is modified by this update.
# ═════════════════════════════════════════════════════════════════════════════

SCAM_CONTENT_PHRASES = [
    "congratulations! you won", "congratulations, you won", "you have won",
    "you've won", "claim your prize", "win an iphone", "win a free",
    "registration fee", "processing fee required", "verify your account",
    "update your bank details", "update your payment details",
    "limited time offer", "urgent action required", "click here now",
    "act now", "account has been suspended", "confirm your identity",
    "you have been selected", "free gift", "lottery winner",
    "otp verification required", "bank account blocked", "confirm your password",
    "unusual activity detected", "your account will be closed",
    "enter your upi pin", "scan to receive", "scan qr to receive",
    "accept collect request", "upi id blocked", "upi deactivated",
    "scan and win", "scan to claim", "qr code expired",
    "complete your kyc", "kyc expired", "aadhaar blocked", "pan card suspended",
    "digital arrest", "arrest warrant", "cbi notice", "cyber crime notice",
    "legal action will be taken", "court notice", "fir has been filed",
    "income tax notice", "tds refund", "gst refund",
    "pre-approved loan", "instant loan approved", "guaranteed returns",
    "double your money", "risk free investment", "crypto trading signal",
    "sure shot profit", "multibagger stock",
    "no interview required", "joining fee", "offer letter fee",
    "work from home earning", "captcha typing job", "whatsapp hr",
    "customs clearance fee", "parcel on hold", "pay to release your parcel",
    "delivery failed pay", "package will be destroyed",
    "electricity disconnected tonight", "pay electricity bill immediately",
    "power disconnection notice", "update your meter details",
    "scholarship approved", "scholarship processing fee", "fee waiver offer",
    "pay to confirm your order", "order refund pending", "huge discount today only",
    "mega sale 90% off",
    "this is your son", "emergency accident money", "kidnapped call now",
    "voice message urgent",
    "withdraw your winnings", "refer app earn cash", "spin and win",
    "click and earn daily",
    "call this number for refund", "fake customer care agent",
]

_BOILERPLATE_TAGS = ['script', 'style', 'noscript', 'head', 'svg', 'iframe',
                     'nav', 'footer', 'header', 'aside', 'form']

# Short, generic nav/menu strings that add noise but no signal. Anything
# exactly matching one of these (case-insensitive) after stripping is dropped.
_NAV_JUNK = {
    'home', 'menu', 'search', 'login', 'sign in', 'sign up', 'cart', 'close',
    'skip to content', 'toggle navigation', 'privacy policy', 'terms of service',
    'cookie policy', 'accept', 'accept all', 'accept cookies', 'reject all',
    'subscribe', 'back to top', '×', '»', '«',
}


def _extract_visible_text(html_content: str) -> str:
    """
    Single-pass, de-duplicated visible-text extraction.

    Walks the DOM ONCE using BeautifulSoup's own text-node iteration
    (soup.find_all(string=True)) rather than re-querying nested tags like
    div/span/p/li separately — the old approach called get_text() on a <div>
    AND on every <span> inside it, double- and triple-counting the same text
    and corrupting the "how much real content did we get" length check.
    """
    if not html_content:
        return ""

    soup = BeautifulSoup(html_content, 'html.parser')
    for tag in soup(_BOILERPLATE_TAGS):
        tag.decompose()

    pieces = []

    if soup.title and soup.title.string:
        pieces.append(soup.title.string.strip())

    meta_desc = soup.find('meta', attrs={'name': 'description'})
    if meta_desc and meta_desc.get('content'):
        pieces.append(meta_desc.get('content').strip())
    meta_og = soup.find('meta', attrs={'property': 'og:description'})
    if meta_og and meta_og.get('content'):
        pieces.append(meta_og.get('content').strip())

    # One walk over real text nodes — no double counting from parent/child tags.
    for node in soup.find_all(string=True):
        parent_name = getattr(node.parent, 'name', None)
        if parent_name in ('script', 'style', 'title'):
            continue
        style = (node.parent.get('style', '') if node.parent else '') or ''
        style = style.replace(' ', '').lower()
        if 'display:none' in style or 'visibility:hidden' in style:
            continue
        txt = node.strip()
        if not txt:
            continue
        if txt.lower() in _NAV_JUNK:
            continue
        pieces.append(txt)

    # Attributes that carry visible/meaningful text but aren't text nodes.
    for inp in soup.find_all('input'):
        placeholder = inp.get('placeholder')
        if placeholder:
            pieces.append(placeholder.strip())
        if inp.get('type') in ('button', 'submit') and inp.get('value'):
            pieces.append(inp.get('value').strip())

    for img in soup.find_all('img'):
        alt = img.get('alt')
        if alt and len(alt.strip()) > 2:
            pieces.append(alt.strip())

    text = ' '.join(pieces)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def fetch_via_playwright(url: str, timeout_ms: int = 15000) -> tuple:
    """
    Render a page with a real headless browser for JS-heavy / bot-gated sites.

    Key robustness choices:
      - 'domcontentloaded' first: this resolves as soon as the DOM is parsed,
        instead of 'networkidle', which many real-world sites (ads, analytics
        beacons, chat widgets, websockets) never satisfy, causing a hard
        Playwright TimeoutError and a totally empty result under the old code.
      - We then best-effort wait for network idle for a short grace period,
        but a timeout there is NOT treated as failure — whatever DOM exists
        at that point is still returned.
      - A small fixed settle delay lets lazy-loaded / hydrated content paint.
      - Extra headers + a realistic viewport/UA reduce basic bot-blocking.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--disable-blink-features=AutomationControlled'],
            )
            context = browser.new_context(
                user_agent=('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'),
                viewport={'width': 1366, 'height': 900},
                locale='en-US',
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                },
            )
            page = context.new_page()

            status = None
            try:
                response = page.goto(url, timeout=timeout_ms, wait_until='domcontentloaded')
                status = response.status if response else None
            except Exception as goto_err:
                # Even a slow/failed goto often leaves a usable partial DOM
                # (e.g. redirected, or the request itself hung after the
                # document started rendering). Keep going instead of bailing.
                logger.warning("[Playwright] goto() raised for %s: %s", url, goto_err)

            # Best-effort settle: don't fail the whole fetch if this times out.
            try:
                page.wait_for_load_state('networkidle', timeout=4000)
            except Exception:
                pass
            page.wait_for_timeout(1200)  # let hydration/lazy content paint

            html = page.content()
            browser.close()

            if not html or len(html) < 50:
                return None, status, "Playwright returned an empty page"
            return html, status or 200, None
    except Exception as e:
        return None, None, str(e)

def analyse_webpage_content(url: str, timeout: int = 12) -> dict:
    """
    Safely fetch HTML, parses, runs JS execution if needed, checks keywords, 
    and passes extracted text directly to the text scam model.
    """
    result = {
        'fetched':            False,
        'url_used':           url,
        'suspicious_phrases': [],
        'content_snippet':    '',
        'extracted_text':     '',
        'error':              None,
        'text_model_label':       None,
        'text_model_probability': 0.0,
        'extracted_text_len':     0,
        'keyword_score_raw':          0.0,
        'keyword_score_normalised':   0.0,
        'keyword_hits':               [],
        'debug_logs': {
            'http_status': None,
            'response_size': 0,
            'html_size': 0,
            'extracted_text_len': 0,
            'extraction_method': 'None',
            'js_rendering_used': False,
            'reached_text_model': False,
            'text_ml_prob': 0.0,
            'rule_score': 0.0,
            'keyword_score_raw': 0.0,
            'keyword_score_normalised': 0.0,
            'keyword_hits': [],
            'final_hybrid_score': 0.0,
        }
    }

    fetch_url = url.strip()
    if not fetch_url.startswith(('http://', 'https://')):
        fetch_url = 'http://' + fetch_url
    result['url_used'] = fetch_url

    logger.info("[URL Scanner] Step 1/5 — starting fetch for %s", fetch_url)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    }

    html_content = ""
    status_code = None
    extraction_method = "Static HTML + BeautifulSoup"
    js_rendering_used = False

    try:
        resp = requests.get(fetch_url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        status_code = resp.status_code
        result['debug_logs']['http_status'] = status_code
        result['debug_logs']['response_size'] = len(resp.content)
        result['debug_logs']['html_size'] = len(resp.text)
        logger.info(
            "[URL Scanner] Fetch complete — status=%s response_bytes=%s html_bytes=%s",
            status_code, len(resp.content), len(resp.text),
        )

        is_cloudflare = False
        server_header = resp.headers.get('Server', '').lower()
        if 'cloudflare' in server_header or 'cloudflare' in resp.text.lower() or 'ray id' in resp.text.lower():
            is_cloudflare = True

        content_type = resp.headers.get('Content-Type', '').lower()
        is_html_like = ('html' in content_type) or (not content_type and resp.text.lstrip().startswith('<'))

        if status_code == 403:
            if is_cloudflare:
                result['error'] = "Access blocked by Cloudflare bot protection (HTTP 403)."
            else:
                result['error'] = "Access denied by website server (HTTP 403 Forbidden)."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        elif status_code == 404:
            result['error'] = "The website was not found (HTTP 404 Not Found)."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        elif status_code >= 500:
            result['error'] = f"The website server returned an error (HTTP {status_code})."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        elif not is_html_like:
            # Non-HTML response (PDF, image, JSON, binary download, etc.) — no
            # point running BeautifulSoup/Playwright on it.
            result['error'] = f"This URL did not return an HTML page (Content-Type: {content_type or 'unknown'})."
            logger.info("[URL Scanner] Skipping non-HTML content for %s (%s)", fetch_url, content_type)
        else:
            resp.raise_for_status()
            html_content = resp.text

    except requests.exceptions.Timeout:
        result['error'] = "The website took too long to respond (timeout)."
        logger.warning("[URL Scanner] Timeout fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.SSLError:
        result['error'] = "Could not verify the site's SSL certificate."
        logger.warning("[URL Scanner] SSL error fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.ConnectionError:
        result['error'] = "Could not connect to the website — it may be down, blocking requests, or connection refused."
        logger.warning("[URL Scanner] Connection error fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.HTTPError:
        status = resp.status_code if 'resp' in locals() else '?'
        result['error'] = f"The website returned an error (HTTP {status})."
        logger.warning("[URL Scanner] HTTPError (status=%s) fetching %s", status, fetch_url, exc_info=True)
    except Exception as e:
        result['error'] = f"Unable to fetch this website: {str(e)}"
        logger.error("[URL Scanner] Unexpected error fetching %s: %s", fetch_url, e, exc_info=True)

    visible_text = ""
    if html_content:
        visible_text = _extract_visible_text(html_content)
        logger.info(
            "[URL Scanner] Step 2/5 — static extraction: %d chars of visible text (method=%s)",
            len(visible_text), extraction_method,
        )

        # JS Detection and rendering trigger
        text_len = len(visible_text)
        js_required = False
        if text_len < 150:
            js_required = True
        else:
            html_lower = html_content.lower()
            if 'id="root"' in html_lower or 'id="app"' in html_lower or 'id="__next"' in html_lower or '<app-root>' in html_lower:
                js_required = True

        if js_required or result['error']:
            logger.info(
                "[URL Scanner] JS rendering triggered (js_required=%s, prior_error=%s) — invoking Playwright",
                js_required, result['error'],
            )
            try:
                pw_html, pw_status, pw_err = fetch_via_playwright(fetch_url, timeout_ms=8000)
                if pw_err:
                    logger.warning("[URL Scanner] Playwright reported an error for %s: %s", fetch_url, pw_err)
                if pw_html:
                    pw_text = _extract_visible_text(pw_html)
                    # Only switch to the Playwright result if it actually got
                    # us MORE content than the static pass — otherwise keep
                    # whatever static HTML/text we already had (e.g. a page
                    # that legitimately just has little text shouldn't be
                    # overwritten with a worse render).
                    if len(pw_text) > len(visible_text):
                        html_content = pw_html
                        status_code = pw_status or 200
                        result['error'] = None
                        extraction_method = "Playwright rendering"
                        js_rendering_used = True
                        visible_text = pw_text
                    logger.info(
                        "[URL Scanner] Playwright re-extraction complete: %d chars of visible text (used=%s)",
                        len(pw_text), js_rendering_used,
                    )
            except ImportError:
                logger.warning(
                    "[URL Scanner] Playwright is not installed — cannot render JS for %s", fetch_url
                )
                if js_required:
                    result['error'] = "This webpage requires JavaScript rendering. Static HTML contained insufficient content for analysis."
            except Exception as e:
                logger.error(
                    "[URL Scanner] Playwright rendering failed for %s: %s", fetch_url, e, exc_info=True
                )
                if js_required:
                    result['error'] = f"This webpage requires JavaScript rendering, but browser automation failed: {str(e)}"

    if visible_text and len(visible_text.strip()) >= 15:
        visible_lower = visible_text.lower()
        found = [p for p in SCAM_CONTENT_PHRASES if p in visible_lower]

        result['fetched']            = True
        result['suspicious_phrases'] = found
        result['content_snippet']    = visible_text[:500]
        # Fuller copy of the extracted text so the results page can show what
        # was actually scraped from the page (capped to keep the UI/response light).
        result['extracted_text']     = visible_text[:5000]
        result['extracted_text_len'] = len(visible_text)

        logger.info(
            "[URL Scanner] Step 3/5 — %d scam phrase(s) matched against curated phrase list: %s",
            len(found), found[:5],
        )

        # ── Step 4/5: keyword-based scoring, using the SAME score_keywords()
        # function the text scanner (analyse_text) uses, so URL page content
        # and pasted text are scored with identical keyword logic. ──────────
        try:
            kw_result = score_keywords(visible_text)
            kw_raw    = kw_result['score']
            kw_norm   = normalise_score(kw_raw, ceiling=20.0)

            result['keyword_score_raw']        = kw_raw
            result['keyword_score_normalised'] = kw_norm
            result['keyword_hits']             = kw_result['found']

            result['debug_logs']['keyword_score_raw']        = kw_raw
            result['debug_logs']['keyword_score_normalised'] = kw_norm
            result['debug_logs']['keyword_hits']              = kw_result['found']

            logger.info(
                "[URL Scanner] score_keywords() on page text — raw=%s normalised=%s hits=%s",
                kw_raw, kw_norm, kw_result['found'][:8],
            )
        except Exception as e:
            logger.error(
                "[URL Scanner] score_keywords() failed on extracted page text for %s: %s",
                fetch_url, e, exc_info=True,
            )

        # ── Step 5/5: run the extracted text through the text-scam ML model ──
        reached_text_model = False
        text_ml_prob = 0.0
        text_model_label = None
        try:
            text_ml = ml_predict(visible_text[:5000])
            text_model_label = text_ml.get('label')
            text_ml_prob = round(float(text_ml.get('probability', 0.0)), 4)
            result['text_model_label']       = text_model_label
            result['text_model_probability'] = text_ml_prob
            reached_text_model = True
            logger.info(
                "[URL Scanner] Text ML model scored page content — label=%s probability=%s",
                text_model_label, text_ml_prob,
            )
        except Exception as e:
            logger.error(
                "[URL Scanner] Text ML model failed on extracted page text for %s: %s",
                fetch_url, e, exc_info=True,
            )

        result['debug_logs']['reached_text_model'] = reached_text_model
        result['debug_logs']['text_ml_prob'] = text_ml_prob

        # Legacy heuristic rule score — kept alongside score_keywords() for
        # backward-compatible debug output (see 'rule_score' in the debug panel).
        try:
            from ml_model import rule_based_scam_score
            result['debug_logs']['rule_score'] = rule_based_scam_score(visible_text)
        except Exception as e:
            logger.warning(
                "[URL Scanner] rule_based_scam_score() failed for %s: %s", fetch_url, e, exc_info=True
            )
    else:
        logger.info(
            "[URL Scanner] Not enough visible text extracted (%d chars) — skipping keyword/ML content scoring",
            len(visible_text.strip()) if visible_text else 0,
        )

    result['debug_logs']['extracted_text_len'] = len(visible_text)
    result['debug_logs']['extraction_method'] = extraction_method if visible_text else "Failed"
    result['debug_logs']['js_rendering_used'] = js_rendering_used

    return result

def analyse_url_full(url: str) -> dict:
    """Wrap utils.analyse_url with a friendly result envelope."""
    if not url or not url.strip():
        return {'error': 'No URL provided'}

    logger.info("[URL Scanner] ==== New scan requested for: %s ====", url)

    base = analyse_url(url)
    rs   = base['risk_score']
    ri   = base['risk_level']
    logger.info("[URL Scanner] URL heuristic score (analyse_url): %s (%s)", rs, ri)

    indicators = []
    if not base['is_https']:        indicators.append('No HTTPS encryption')
    if base['has_ip']:              indicators.append('IP address as domain')
    if base['is_long']:             indicators.append('Abnormally long URL')
    if base['suspicious_kw']:       indicators.append(f"Phishing keywords: {', '.join(base['suspicious_kw'][:4])}")
    if base['tld_risk']:            indicators.append(f"High-risk TLD: {base['tld']}")
    if base['typosquat_risk']:      indicators.append('Possible typosquatting of known brand')
    if base['is_known_legit']:      indicators.append('Domain matches known legitimate site')

    if '@' in url:
        indicators.append('URL contains suspicious "@" character')
    if '%' in url:
        indicators.append('URL contains percent-encoded characters')
    if any('redirection' in f for f in base['flags']):
        indicators.append('URL contains suspicious redirection parameters')
    if any('entropy' in f for f in base['flags']):
        indicators.append('High string randomness/entropy')

    is_shortened_domain = any(sd in url.lower() for sd in SHORTENER_DOMAINS)
    if is_shortened_domain:
        indicators.append('Masked URL (using known link shortener)')

    content_result = analyse_webpage_content(url)
    scam_phrases    = content_result.get('suspicious_phrases', [])
    if scam_phrases:
        indicators.append(f"Scam phrases found on page: {', '.join(scam_phrases[:4])}")

    content_bonus = min(15 * len(scam_phrases), 45)

    text_ml_prob  = content_result.get('text_model_probability', 0.0) or 0.0
    text_ml_label = content_result.get('text_model_label')
    if content_result.get('fetched') and text_ml_label is not None:
        if text_ml_prob >= 0.5:
            indicators.append(
                f"Webpage text flagged as scam-like by text AI model ({round(text_ml_prob * 100)}% confidence)"
            )
        elif text_ml_prob < 0.35:
            indicators.append("Webpage text rated as likely legitimate by text AI model")
    
    text_ml_bonus = round(text_ml_prob * 35) if content_result.get('fetched') else 0

    url_ml_result = url_ml_predict(url)
    ml_prob       = url_ml_result.get('probability', 0.0)
    ml_fetched    = url_ml_result.get('fetched', False)
    ml_fetch_note = url_ml_result.get('fetch_note')

    try:
        url_ml_top_signals_raw = get_feature_importance_url(url, top_n=5)
        url_ml_top_signals = [name for name, _score in url_ml_top_signals_raw]
        logger.info(
            "[URL Scanner] get_feature_importance_url() top signals for %s: %s",
            url, url_ml_top_signals_raw,
        )
    except Exception as e:
        logger.warning(
            "[URL Scanner] get_feature_importance_url() failed for %s: %s", url, e, exc_info=True
        )
        url_ml_top_signals = []

    if url_ml_result.get('label') != 'unknown':
        if url_ml_result['label'] == 'phishing':
            indicators.append(
                f"AI model flags URL as phishing ({round(ml_prob * 100)}% confidence)"
            )
        else:
            indicators.append("AI model rates URL as likely legitimate")

        ml_bonus = round(ml_prob * (55 if ml_fetched else 40))
    else:
        ml_bonus = 0

    # Redirection check / Shortener suspension check
    shortener_warning_detected = False
    warning_phrases = [
        "created by a suspended account",
        "link has been suspended",
        "why was this link blocked",
        "link has been blocked",
        "flagged as spam, phishing",
        "no longer available because it was created by a suspended account",
        "violates our terms of service",
        "violates our acceptable use policy",
        "site has been suspended",
        "account suspended",
        "this link has been flagged"
    ]
    
    page_text_lower = content_result.get('content_snippet', '').lower()
    is_dest_shortened = any(sd in content_result.get('url_used', '').lower() for sd in SHORTENER_DOMAINS)
    
    if is_shortened_domain or is_dest_shortened:
        if any(p in page_text_lower for p in warning_phrases):
            shortener_warning_detected = True

    false_safe_floor = 0
    if url_ml_result.get('label') == 'phishing' and ml_prob >= 0.75:
        false_safe_floor = 65
    elif url_ml_result.get('label') == 'phishing' and ml_prob >= 0.60:
        false_safe_floor = 45

    if content_result.get('fetched') and text_ml_prob >= 0.80:
        false_safe_floor = max(false_safe_floor, 60)
    elif content_result.get('fetched') and text_ml_prob >= 0.65:
        false_safe_floor = max(false_safe_floor, 40)

    if base['typosquat_risk']:
        false_safe_floor = max(false_safe_floor, 65)
    if base['has_ip'] or '@' in url:
        false_safe_floor = max(false_safe_floor, 55)

    if shortener_warning_detected:
        indicators.append('URL officially suspended/blocked by provider for abuse/phishing')
        false_safe_floor = 90

    final_score = max(min(rs + content_bonus + ml_bonus + text_ml_bonus, 100), false_safe_floor)
    final_ri    = compute_risk_level(final_score)

    # ── Trusted-domain override / impersonation escalation ──────────────
    # Generic lexical/keyword models (suspicious words like "login",
    # "verify", "account", "security"; or a text-ML pass over a page that
    # legitimately talks about account security) will always fire on the
    # normal, expected content of major tech companies' own sites. Rather
    # than trying to hand-tune keyword weights per-domain, we check the
    # resolved domain against a small, curated allowlist of verified
    # official domains (trusted_companies.py) and correct the score:
    #   - exact/official domain (or subdomain of one)  -> cap the score low
    #   - contains a brand name but ISN'T that domain   -> push score high
    # A hard-suspension signal (shortener_warning_detected) still wins,
    # since even an official domain can be reported for abuse.
    website_domain = base.get('domain', '') or ''
    trusted_brand = None if shortener_warning_detected else match_trusted_domain(website_domain)
    impersonation_brand = None if trusted_brand else detect_brand_impersonation(website_domain)

    TRUST_CEILING = 12.0
    IMPERSONATION_FLOOR = 75.0

    if trusted_brand:
        if final_score > TRUST_CEILING:
            indicators.append(
                f"Domain verified as an official {trusted_brand.title()} domain (trusted-domain registry)"
            )
        final_score = min(final_score, TRUST_CEILING)
        final_ri = compute_risk_level(final_score)
    elif impersonation_brand:
        indicators.append(
            f"⚠ Domain contains the '{impersonation_brand.title()}' brand name but is NOT its official "
            f"domain — likely impersonation/lookalike site"
        )
        final_score = max(final_score, IMPERSONATION_FLOOR)
        final_ri = compute_risk_level(final_score)

    indicators = list(dict.fromkeys(indicators))

    # ── Explanation bullets ──────────────────────────────────────────────
    # Built only from signals that actually fed into the risk score above
    # (real keyword hits, real ML flags, real domain/TLD risk) — not a loose
    # re-scan of raw text — so the explanation can never claim "high-risk
    # indicators" when the computed score doesn't reflect that.
    explanation_bullets = []

    if trusted_brand:
        explanation_bullets.append(f"✓ Verified official {trusted_brand.title()} domain (trusted-domain registry)")
    if impersonation_brand:
        explanation_bullets.append(
            f"⚠ Mimics {impersonation_brand.title()} branding but is not an official {impersonation_brand.title()} domain"
        )
    if shortener_warning_detected:
        explanation_bullets.append("✓ URL officially suspended/blocked by the provider for abuse")
    if base['suspicious_kw'] or scam_phrases:
        kws_display = list(dict.fromkeys(list(base['suspicious_kw']) + list(scam_phrases)))[:4]
        explanation_bullets.append(f"✓ Suspicious keywords found: {', '.join(kws_display)}")
    if base['tld_risk'] > 0 or base['has_ip'] or base['typosquat_risk'] or '@' in url or is_shortened_domain or is_dest_shortened:
        explanation_bullets.append("✓ Suspicious domain, TLD, or shortened link structure")
    if not base['is_https']:
        explanation_bullets.append("✓ Connection is not secured with HTTPS")
    if (url_ml_result.get('label') == 'phishing' and ml_prob >= 0.5) or (text_ml_prob >= 0.5):
        explanation_bullets.append("✓ Flagged with high confidence by AI threat models")

    # The tone and content of the verdict always matches the FINAL risk
    # level, never the raw presence of a loosely-matched keyword.
    final_level = final_ri['level']
    if final_level == 'CRITICAL':
        if explanation_bullets:
            verdict = "🚨 This URL has been flagged with multiple high-risk indicators:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🚨 This URL shows strong phishing indicators and is likely malicious. Do not enter any personal information."
    elif final_level == 'HIGH':
        if explanation_bullets:
            verdict = "⚠️ This URL shows strong suspicious indicators:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "⚠️ This URL shows strong phishing indicators and is likely malicious."
    elif final_level == 'MEDIUM':
        if explanation_bullets:
            verdict = "🧐 This URL has some suspicious characteristics worth investigating:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🧐 This URL has some suspicious characteristics. Exercise caution before proceeding."
    elif final_level == 'LOW':
        if explanation_bullets:
            verdict = "🔵 Only minor risk factors were identified:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🔵 This URL appears mostly safe. Only minor risk factors were identified — basic verification is still recommended."
    else:  # SAFE
        verdict = "✅ No major suspicious indicators were detected. This URL appears to be safe."

    debug_logs = content_result.get('debug_logs', {})
    debug_logs['final_hybrid_score'] = final_score
    debug_logs['url_ml_prob'] = ml_prob
    debug_logs['url_heuristic_score'] = rs
    debug_logs['url_ml_top_signals'] = url_ml_top_signals
    debug_logs['url_ml_fetch_note'] = ml_fetch_note

    logger.info(
        "[URL Scanner] ==== Scan complete for %s — final_score=%s level=%s "
        "url_ml=%s(%.4f) text_ml=%s(%.4f) fetch_note=%s ====",
        url, final_score, final_ri['level'],
        url_ml_result.get('label', 'unknown'), ml_prob,
        content_result.get('text_model_label'), text_ml_prob,
        ml_fetch_note,
    )

    return {
        **base,
        'risk_score':      final_score,
        'risk_level':      final_ri['level'],
        'risk_color':      final_ri['color'],
        'risk_emoji':      final_ri['emoji'],
        'verdict':         verdict,
        'indicators':      indicators,
        'suspicious_kws':  base['suspicious_kw'],
        'recommendations': get_recommendations(final_ri['level']),
        'confidence':      min(95, max(50, int(max(ml_prob, text_ml_prob) * 100))),
        'scan_type':       'URL Scanner',
        'content_analysis':content_result,
        'open_url':        content_result.get('url_used', url),
        'url_ml_label':      url_ml_result.get('label', 'unknown'),
        'url_ml_probability':round(ml_prob * 100, 1),
        'url_ml_fetched':    ml_fetched,
        'url_ml_fetch_error':url_ml_result.get('fetch_error'),
        'url_ml_top_signals':url_ml_top_signals,
        'fetch_note':        ml_fetch_note,
        'text_model_label':       content_result.get('text_model_label'),
        'text_model_probability': round(text_ml_prob * 100, 1),
        'trusted_domain_check': {
            'verified_brand':      trusted_brand,
            'impersonation_brand': impersonation_brand,
        },
        'debug_logs':      debug_logs,
    }

# ─── QR content-type detection ──────────────────────────────────────────────
# Recognises the common QR payload shapes (URL, mailto:/bare email, tel:/bare
# phone number) so the QR scanner can route each type to the correct existing
# pipeline instead of guessing with a single loose check.
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
_PHONE_RE = re.compile(r'^\+?[0-9][0-9\s\-().]{6,18}[0-9]$')

def detect_qr_content_type(data: str) -> str:
    """
    Classify decoded QR payload as one of: URL, EMAIL, PHONE, TEXT.
    Mirrors the QR payload shapes commonly produced by generators:
      - URL:   'http://...', 'https://...', or a bare domain like 'example.com/x'
      - Email: 'mailto:user@domain.com' or a bare email address
      - Phone: 'tel:+1234567890' or a bare phone number
      - Text:  anything else (wifi configs, vCards, plain text, etc.)
    """
    if not data:
        return 'TEXT'

    payload = data.strip()

    # ── URL ──
    if payload.startswith(('http://', 'https://')):
        return 'URL'

    # ── Email ──
    if payload.lower().startswith('mailto:'):
        return 'EMAIL'
    if _EMAIL_RE.match(payload):
        return 'EMAIL'

    # ── Phone ──
    if payload.lower().startswith('tel:'):
        return 'PHONE'
    if _PHONE_RE.match(payload):
        return 'PHONE'

    # ── Bare domain heuristic (no scheme, e.g. "example.com/promo") ──
    first_segment = payload.split('/')[0].split('?')[0]
    if '.' in first_segment and ' ' not in first_segment and '@' not in first_segment:
        # crude but effective TLD-shape check: letters after the last dot
        tld_candidate = first_segment.rsplit('.', 1)[-1]
        if tld_candidate.isalpha() and 2 <= len(tld_candidate) <= 24:
            return 'URL'

    return 'TEXT'


# ─── Shared image / QR preprocessing helpers ───────────────────────────────
# Used by analyse_qr(), analyse_ocr_image(), and analyse_pdf() so all three
# extraction paths benefit from the same accuracy improvements.

def _deskew_image(gray):
    """
    Estimate and correct small page rotation using the minimum-area
    bounding rectangle of the foreground (text) pixels.

    Why this matters for the "words getting merged" symptom: even a
    2-5 degree skew makes ascenders/descenders from one text line lean
    into the line above or below, and makes the gaps between words on a
    slanted line inconsistent. Tesseract's line/word segmentation is very
    sensitive to this, so straightening the page BEFORE thresholding fixes
    a large share of merged-word and dropped-space errors for free.

    Returns the original array unchanged if there isn't enough foreground
    to estimate an angle safely, or if the estimated angle is negligible
    (already straight) or implausibly large (likely a bad estimate on a
    noisy image) — this keeps the correction conservative so it can't make
    a clean image worse.
    """
    import cv2
    import numpy as np

    inverted = cv2.bitwise_not(gray)
    _, bw = cv2.threshold(inverted, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    coords = np.column_stack(np.where(bw > 0))
    if coords.shape[0] < 50:
        return gray

    angle = cv2.minAreaRect(coords)[-1]
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle

    if abs(angle) < 0.3 or abs(angle) > 15:
        return gray  # already straight, or estimate is unreliable

    h, w = gray.shape[:2]
    center = (w // 2, h // 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    return cv2.warpAffine(
        gray, matrix, (w, h),
        flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE,
    )


def _enhance_image_for_ocr(pil_img):
    """
    Preprocess an image to improve OCR accuracy: grayscale -> deskew ->
    upscale (if small) -> contrast enhancement (CLAHE) -> denoise ->
    sharpen -> adaptive threshold. Returns a NEW PIL Image; never mutates
    the original, and callers should keep the raw image around as a
    fallback in case the enhanced version happens to OCR worse on a
    particular file.

    Tuning notes (these specific changes target merged words / missing
    spaces, which is the main accuracy complaint this pipeline had):
      - Deskew runs first (see _deskew_image) since skew is a common root
        cause of touching characters and inconsistent word gaps.
      - Upscaling now uses a higher floor (1600px) and interpolates on the
        already-deskewed image. Tesseract's LSTM engine generally does
        better with more pixels per character; too-small text is a classic
        cause of adjacent letters/words being read as one blob.
      - The adaptive-threshold block size was reduced (31 -> 25) and C
        raised slightly (11 -> 13). A large block size averages over a
        wider neighbourhood, which on tightly kerned or small fonts can
        bridge the gap between adjacent words into a single dark blob.
        A smaller, more local block size keeps inter-word gaps intact.
      - Denoising strength was reduced slightly (10 -> 7) since aggressive
        denoising can blur/close small gaps between characters, which is
        the opposite of what we want here.
    """
    import cv2
    import numpy as np
    from PIL import Image

    cv_img = cv2.cvtColor(np.array(pil_img.convert('RGB')), cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)

    # Straighten the page before anything else touches pixel spacing
    gray = _deskew_image(gray)

    # Upscale small images so OCR has more pixels per character to work with
    h, w = gray.shape[:2]
    if max(h, w) < 1600:
        scale = 1600 / max(h, w)
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Contrast enhancement
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    gray = clahe.apply(gray)

    # Denoise — median blur removes speckle noise at a small fraction of
    # the cost of fastNlMeansDenoising (which was the single biggest time
    # sink in this pipeline: it's near-quadratic in image size and was
    # running on every upscaled image/page, often taking several seconds
    # by itself). A 3x3 median blur is nearly as effective for the kind
    # of scan/photo noise we see here and is essentially instant.
    gray = cv2.medianBlur(gray, 3)

    # Sharpen (unsharp mask)
    blurred = cv2.GaussianBlur(gray, (0, 0), sigmaX=3)
    sharpened = cv2.addWeighted(gray, 1.5, blurred, -0.5, 0)

    # Adaptive threshold — helps OCR on uneven lighting / low contrast
    # scans. Smaller block size than before to avoid merging tightly
    # spaced words/characters into one dark region.
    thresh = cv2.adaptiveThreshold(
        sharpened, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 25, 13,
    )

    return Image.fromarray(thresh)


def _decode_qr_multi(cv_img):
    """
    Decode a QR code from a BGR OpenCV image using multiple decoders,
    scales, and rotations — handles rotated, blurry, or low-contrast codes
    that a single detectAndDecode() call would miss.

    Order: PyZbar (fast path) -> OpenCV QRCodeDetector (fast path) ->
    thorough multi-scale/multi-rotation retry with both decoders ->
    Otsu-thresholded retry -> WeChat QRCode detector (if the OpenCV build
    includes it). Returns (decoded_string_or_empty, decoder_name).
    """
    import cv2

    def _try_pyzbar(img):
        try:
            from pyzbar.pyzbar import decode as zbar_decode
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
            results = zbar_decode(gray)
            if results:
                return results[0].data.decode('utf-8', errors='ignore')
        except ImportError:
            pass
        except Exception:
            pass
        return ''

    def _try_opencv(img, detector):
        try:
            data, _, _ = detector.detectAndDecode(img)
            return data or ''
        except Exception:
            return ''

    def _rotate(img, angle):
        if angle == 90:
            return cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)
        if angle == 180:
            return cv2.rotate(img, cv2.ROTATE_180)
        if angle == 270:
            return cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)
        return img

    qr_detector = cv2.QRCodeDetector()

    # ── Fast path: try the image as-is (covers the vast majority of
    # clean, upright QR codes without any extra scanning cost) ──
    data = _try_pyzbar(cv_img)
    if data:
        return data, 'pyzbar'
    data = _try_opencv(cv_img, qr_detector)
    if data:
        return data, 'opencv'

    # ── Cheap pre-check before the expensive thorough fallback: does this
    # image even contain anything that looks like a QR finder pattern?
    # detect() just localises candidate squares — it's far cheaper than
    # the 24-attempt multi-scale/rotation decode loop below. If it finds
    # nothing, there's almost certainly no QR code on this page, so skip
    # straight to "not found" instead of burning time on every page of
    # every PDF (this was the main source of the slowdown).
    try:
        found, _ = qr_detector.detect(cv_img)
        if not found:
            return '', ''
    except Exception:
        pass  # if the cheap check itself fails, fall through to thorough scan

    # ── Thorough fallback: multi-scale + multi-rotation, for rotated,
    # blurry, or low-contrast QR codes ──
    for scale in (1.5, 2.0, 0.75):
        scaled = cv2.resize(cv_img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        for angle in (0, 90, 180, 270):
            rotated = _rotate(scaled, angle)
            data = _try_pyzbar(rotated)
            if data:
                return data, 'pyzbar'
            data = _try_opencv(rotated, qr_detector)
            if data:
                return data, 'opencv'

    # ── Otsu-thresholded (binarised) retry ──
    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    data = _try_pyzbar(thresh)
    if data:
        return data, 'pyzbar-threshold'
    gray_3ch = cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR)
    data = _try_opencv(gray_3ch, qr_detector)
    if data:
        return data, 'opencv-threshold'

    # ── WeChat QRCode detector, if the OpenCV build includes it ──
    try:
        wechat_detector = cv2.wechat_qrcode_WeChatQRCode()
        texts, _ = wechat_detector.detectAndDecode(cv_img)
        if texts:
            return texts[0], 'wechat'
    except Exception:
        pass

    return '', ''


def analyse_qr(image_bytes: bytes) -> dict:
    try:
        import cv2
        from PIL import Image
        import numpy as np

        pil_img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        cv_img  = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        qr_data, decoder_used = _decode_qr_multi(cv_img)

        if not qr_data:
            return {'error': 'No QR code detected in the image. Please ensure the QR code is clear, well-lit, and not blurry.'}

        # ── Step 1: identify content type (URL / EMAIL / PHONE / TEXT) ──────
        content_type = detect_qr_content_type(qr_data)
        is_url = content_type == 'URL'
        logger.info("[QR Scanner] Decoded (%s) payload classified as %s: %r", decoder_used, content_type, qr_data[:120])

        result = {
            'qr_data':      qr_data,
            'qr_type':      content_type,   # kept for backward-compat with existing UI key
            'content_type': content_type,
            'is_url':       is_url,
            'decoder_used': decoder_used,
        }

        # ── Step 2: route to the correct EXISTING pipeline — no duplicate
        # detection logic. URLs go through the full URL scanner pipeline
        # (feature extraction, ML prediction, webpage fetch, text scam
        # detection, combined risk score); everything else (plain text,
        # email address, phone number) goes through the same text-scam
        # detection module used by the Text Scanner. ─────────────────────
        if content_type == 'URL':
            # Normalise bare domains (e.g. "example.com/x") to a fetchable
            # URL before handing off, without altering analyse_url_full()
            # itself — this keeps the URL pipeline the single source of truth.
            target_url = qr_data if qr_data.startswith(('http://', 'https://')) else f'http://{qr_data}'
            url_result = analyse_url_full(target_url)
            result.update(url_result)
        else:
            # For EMAIL / PHONE / TEXT payloads, strip any URI scheme
            # (mailto:/tel:) before handing to the text scam detector so it
            # scores the actual address/number/content, not the scheme noise.
            text_payload = re.sub(r'^(mailto:|tel:)', '', qr_data, flags=re.IGNORECASE).strip()
            text_result = analyse_text(text_payload)
            result.update(text_result)

        result['scan_type'] = 'QR Scanner'
        return result

    except ImportError as e:
        return {'error': f'OpenCV not installed: {e}. Install with: pip install opencv-python-headless'}
    except Exception as e:
        return {'error': f'QR analysis failed: {str(e)}'}

# ─── Tesseract configuration + OCR quality scoring ──────────────────────────
# --oem 3 = default LSTM + legacy engine combined (most accurate, tried
#           first for everything in this pipeline)
# --psm 6 = "assume a single uniform block of text" — the best default for
#           screenshots, phone-camera photos of a message/document, and
#           single-column scans, which is the overwhelming majority of
#           CyberLens input. This is the #1 fix for the "words merged
#           together" symptom: the default PSM (3) does full page-layout
#           analysis and on a simple block of text it can mis-detect
#           column/paragraph boundaries and run words together, whereas
#           PSM 6 treats it as one block and preserves word gaps read
#           line-by-line.
# --psm 4 = single column of text of variable sizes — good for documents
#           with clear paragraph/heading structure
# --psm 3 = fully automatic page segmentation (no OSD) — safest generic
#           fallback for scanned pages with mixed layout (multi-column,
#           tables, embedded images)
# --psm 11 = sparse text, no particular order — last-resort fallback for
#           scattered/short text (banners, IDs, signage-style screenshots)
#
# `preserve_interword_spaces=1` is critical for requirement #2 (preserve
# spaces between words): without it, Tesseract's internal space-collapsing
# heuristic can drop legitimate spaces in some layouts.
_TESS_CONFIG_ATTEMPTS = [
    ('block',  6, 3),
    ('auto',   3, 3),
    ('sparse', 11, 3),
]


# Combined Tesseract language string so a single OCR pass can read mixed-
# script images/PDF pages (English + the Indic languages + Spanish already
# supported by language_utils.py) instead of only reading Latin script well.
#
# ⚠️ DEPLOYMENT REQUIREMENT: this requires the matching Tesseract
# traineddata files to be installed on the server. On Streamlit Community
# Cloud, add a packages.txt with:
#   tesseract-ocr-tam
#   tesseract-ocr-hin
#   tesseract-ocr-tel
#   tesseract-ocr-mal
#   tesseract-ocr-kan
#   tesseract-ocr-spa
# (tesseract-ocr-eng ships with the base tesseract-ocr package.)
#
# _get_tesseract_lang() uses whichever of these packs are ACTUALLY
# installed rather than an all-or-nothing check — with an all-or-nothing
# check, installing 5 of 6 packs still silently gives you English-only OCR
# (and if none of the requested extra languages are installed, Tesseract
# doesn't error, it silently returns an EMPTY result for the whole page —
# confirmed by testing directly against Tesseract 5.3.4). Using the
# intersection of "wanted" and "installed" means partial deployments still
# get partial multi-language support instead of none, and never sends a
# language string Tesseract will refuse to honour.
_TESSERACT_LANG_FULL = 'eng+tam+hin+tel+mal+kan+spa'
_TESSERACT_LANG_FAST = 'eng'   # cheap first-pass probe language
_tesseract_lang_cache = {'lang': None, 'missing': None}


def _get_tesseract_lang() -> str:
    """
    Return the Tesseract lang string built from the intersection of
    _TESSERACT_LANG_FULL and whatever traineddata is actually installed
    (checked once per process via pytesseract.get_languages(), then
    cached). Always includes 'eng'. Logs which requested languages are
    missing so a partial/incomplete packages.txt is diagnosable from
    server logs, and also exposes the missing set via
    _tesseract_lang_missing() so callers can surface it to the user
    instead of it only living in logs.
    """
    if _tesseract_lang_cache['lang'] is not None:
        return _tesseract_lang_cache['lang']

    import pytesseract
    wanted = set(_TESSERACT_LANG_FULL.split('+'))
    try:
        installed = set(pytesseract.get_languages(config=''))
    except Exception as e:
        logger.warning("[OCR] Could not query installed Tesseract languages (%s); "
                        "defaulting to English-only OCR.", e)
        installed = {'eng'}

    usable = wanted & installed
    usable.add('eng')  # always include English regardless of intersection result
    missing = sorted(wanted - installed)

    if missing:
        logger.warning(
            "[OCR] Missing Tesseract traineddata for: %s — those languages "
            "won't be OCR'd until packages.txt is deployed with them. "
            "Currently OCR-ready languages: %s",
            ', '.join(missing), '+'.join(sorted(usable))
        )

    _tesseract_lang_cache['lang'] = '+'.join(sorted(usable))
    _tesseract_lang_cache['missing'] = missing
    return _tesseract_lang_cache['lang']


def _tesseract_lang_missing() -> list:
    """Requested-but-not-installed language codes, populated by _get_tesseract_lang()."""
    if _tesseract_lang_cache['missing'] is None:
        _get_tesseract_lang()
    return _tesseract_lang_cache['missing'] or []


def _tesseract_config(psm: int, oem: int) -> str:
    return f'--oem {oem} --psm {psm} -c preserve_interword_spaces=1'


def _ocr_quality_score(text: str) -> float:
    """
    Heuristic score (higher = better) used to pick the best result among
    several preprocessing/--psm attempts, without needing ground truth.

    Rewards a healthy ratio of alphabetic content and typical English word
    lengths; penalises the two failure signatures we care about most:
      - merged words -> very few, abnormally long "words"
      - shredded/noisy output -> lots of 1-2 character fragments
    """
    words = text.split()
    if not words:
        return -1.0

    total_chars = max(len(text), 1)
    alpha_ratio = sum(c.isalpha() for c in text) / total_chars
    lengths = [len(w) for w in words]
    avg_len = sum(lengths) / len(lengths)
    long_word_ratio = sum(1 for l in lengths if l > 15) / len(words)
    tiny_word_ratio = sum(1 for l in lengths if l == 1) / len(words)

    score  = alpha_ratio * 10
    score -= long_word_ratio * 8      # signature of merged words
    score -= tiny_word_ratio * 3      # signature of shredded/garbled text
    score -= abs(avg_len - 5.0) * 0.3  # typical English avg word length ~4.7
    score += min(len(words), 200) * 0.01  # mild reward for recovering more text
    return score


def _mean_word_confidence(ocr_data: dict) -> float:
    """
    Mean Tesseract per-word confidence (0-100) over words with conf > 0,
    from image_to_data(output_type=Output.DICT). Returns -1.0 if there are
    no confident words at all (e.g. blank/unreadable image), so it always
    compares sensibly against other candidates.
    """
    confs = [float(c) for c in ocr_data.get('conf', []) if c not in (None, '', '-1') and float(c) > 0]
    if not confs:
        return -1.0
    return sum(confs) / len(confs)


def _ocr_with_data(pil_img, psm: int, oem: int, lang: str):
    """
    Run Tesseract once via image_to_data() (so we get per-word confidence
    for free) and reconstruct the plain text from the word list. Returns
    (text, mean_confidence, ocr_data_dict). ocr_data_dict is returned so
    callers can optionally do per-line language tagging
    (language_utils.tag_segments_from_ocr_data) without a second OCR call.
    """
    import pytesseract
    from pytesseract import Output

    config = _tesseract_config(psm, oem)
    data = pytesseract.image_to_data(pil_img, lang=lang, config=config, output_type=Output.DICT)

    # Rebuild text grouped by line so spacing/line breaks look like
    # image_to_string's output (image_to_data gives one row per word).
    lines = {}
    order = []
    n = len(data.get('text', []))
    for i in range(n):
        word = (data['text'][i] or '').strip()
        if not word:
            continue
        key = (data['block_num'][i], data['par_num'][i], data['line_num'][i])
        if key not in lines:
            lines[key] = []
            order.append(key)
        lines[key].append(word)
    text = '\n'.join(' '.join(lines[k]) for k in order).strip()

    return text, _mean_word_confidence(data), data


def _ocr_best_of(pil_img, quick: bool = False):
    """
    Run Tesseract and keep the best-scoring result, using a two-tier
    language strategy so most documents stay fast:

      Tier 1 (always): a single fast probe with English-only ('eng').
      Most images/pages are plain English/Latin-script documents, and
      multi-language Tesseract calls are measurably slower than
      single-language ones (~3x slower with 3 languages loaded,
      confirmed by direct timing) — so paying that cost on every image
      regardless of content was the main source of the slowdown.

      Tier 2 (only if Tier 1 looks weak): escalate to the combined
      multi-language string from _get_tesseract_lang() — this is where
      non-Latin script (Tamil/Hindi/Telugu/Malayalam/Kannada) or Spanish
      actually gets recognised. "Weak" means low confidence, a low
      heuristic score, or literally no text — the signature of either a
      hard image or non-English content, both of which justify the
      extra cost. If no extra language packs are installed, Tier 2 is
      skipped entirely (it would just repeat Tier 1's language for no
      gain).

    Selection within each tier blends two signals:
      - Tesseract's own mean per-word confidence from image_to_data()
        (more reliable than text-shape heuristics alone), and
      - the existing _ocr_quality_score() heuristic, as a tie-breaker
        since confidence alone can be fooled by a confidently-wrong
        low-PSM misread.

    quick=True (used for PDF pages that already look fine, or the 600 DPI
    escalation) only tries the single best-default config (`block`,
    psm 6) per tier, to bound the extra runtime. Full mode tries all 3
    per tier and stops early once a config already scores comfortably
    well on both signals, so easy images still only cost one Tesseract
    call in practice.

    Returns (text, mean_confidence) — mean_confidence is -1.0 if nothing
    was recognised.
    """
    attempts = _TESS_CONFIG_ATTEMPTS[:1] if quick else _TESS_CONFIG_ATTEMPTS

    def _run(lang, cfg_attempts):
        text, conf, combined = '', -1.0, float('-inf')
        for _, psm, oem in cfg_attempts:
            try:
                t, c, _data = _ocr_with_data(pil_img, psm, oem, lang)
            except Exception:
                continue
            if not t:
                continue
            score = _ocr_quality_score(t)
            # Normalise confidence (0-100) onto roughly the same scale as
            # the heuristic score (~ -8..+12) so neither signal dominates
            # by accident, then blend: confidence carries slightly more
            # weight since it reflects Tesseract's own certainty about
            # the specific characters recognised, not just output shape.
            comb = (c / 100.0) * 12.0 * 0.6 + score * 0.4
            if comb > combined:
                text, conf, combined = t, c, comb
            if c > 80.0 and score > 6.0:   # already good on both signals
                break
        return text, conf, combined

    # ── Tier 1: fast English-only probe ──
    fast_text, fast_conf, fast_combined = _run(_TESSERACT_LANG_FAST, attempts[:1])

    fast_is_weak = (
        not fast_text
        or fast_conf < 60.0
        or _ocr_quality_score(fast_text) < 4.0
    )

    full_lang = _get_tesseract_lang()
    other_langs_available = full_lang != _TESSERACT_LANG_FAST

    if fast_is_weak and other_langs_available:
        # ── Tier 2: escalate to the multi-language pass ──
        full_text, full_conf, full_combined = _run(full_lang, attempts)
        if full_combined > fast_combined:
            return full_text, full_conf
        return fast_text, fast_conf

    if not quick and fast_combined < 6.0 and len(attempts) > 1:
        # Fast pass wasn't great but doesn't look non-English either
        # (already checked above) and other language packs aren't the
        # answer — try the remaining psm configs in English before
        # giving up, preserving the old "try all 3 configs" behaviour
        # for genuinely hard-but-English images.
        rest_text, rest_conf, rest_combined = _run(_TESSERACT_LANG_FAST, attempts[1:])
        if rest_combined > fast_combined:
            return rest_text, rest_conf

    return fast_text, fast_conf


def _split_merged_words(text: str, min_len: int = 12) -> str:
    """
    Optional best-effort pass using the `wordninja` library (dictionary-
    based word segmentation) to break up runs like "thestudentwashappy"
    back into "the student was happy". This is the one step in the
    pipeline that can occasionally mis-split a genuine long word or proper
    noun, so it's applied ONLY to tokens that are purely alphabetic,
    lowercase, and longer than `min_len` characters — short/mixed-case
    tokens are left untouched to keep false positives rare.

    Silently no-ops if wordninja isn't installed (`pip install wordninja`);
    this is a nice-to-have layered on top of the config/preprocessing
    fixes above, not a hard dependency.
    """
    try:
        import wordninja
    except ImportError:
        return text

    def _fix(match):
        word = match.group(0)
        if len(word) <= min_len or not word.islower():
            return word
        pieces = wordninja.split(word)
        return ' '.join(pieces) if len(pieces) > 1 else word

    try:
        return re.sub(r'[a-z]+', _fix, text)
    except Exception:
        return text


def _clean_ocr_text(text: str) -> str:
    """
    Normalise raw Tesseract output into clean, readable text
    (requirement #5 — automatic OCR output cleanup):

      1. Normalise line endings and strip stray control characters.
      2. Rejoin words split by a line-wrap hyphen: "informa-\\ntion" ->
         "information".
      3. Rebuild paragraphs (requirement #3): split on blank lines, join
         the wrapped lines *within* each paragraph into one continuous
         line, then separate paragraphs from each other with a single
         blank line. This turns Tesseract's raw "one physical line per
         newline" output into actual paragraphs instead of either one
         giant blob or a choppy line-per-newline mess.
      4. Insert a space that Tesseract dropped at an obvious word boundary:
         a lowercase letter immediately followed by a capital letter
         ("...wordNextWord" -> "...word Next Word"), or a punctuation mark
         immediately followed by a letter with no space ("end.Start" ->
         "end. Start"). Deliberately conservative so it doesn't touch
         genuine camelCase-like OCR noise or acronyms.
      5. Collapse doubled/tripled spaces left over from the above.
    """
    if not text:
        return text

    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)

    # Rejoin hyphenated line-wraps
    text = re.sub(r'(\w)-\n(\w)', r'\1\2', text)

    # Rebuild paragraphs: join wrapped lines within a paragraph, keep
    # blank-line-separated paragraphs as separate blocks
    paragraphs = re.split(r'\n\s*\n', text)
    cleaned_paragraphs = []
    for para in paragraphs:
        lines = [ln.strip() for ln in para.split('\n') if ln.strip()]
        if lines:
            cleaned_paragraphs.append(' '.join(lines))
    text = '\n\n'.join(cleaned_paragraphs)

    # Insert obviously-missing spaces at word/sentence boundaries
    text = re.sub(r'([a-z])([A-Z][a-z])', r'\1 \2', text)
    text = re.sub(r'([.!?,;:])([A-Za-z])', r'\1 \2', text)

    # Collapse repeated horizontal whitespace (leave paragraph newlines alone)
    text = re.sub(r'[ \t]{2,}', ' ', text)
    text = re.sub(r'[ \t]*\n[ \t]*', '\n', text)

    return text.strip()


def analyse_ocr_image(image_bytes: bytes) -> dict:
    try:
        import pytesseract
        from PIL import Image

        pil_img = Image.open(io.BytesIO(image_bytes))

        # ── Preprocess for accuracy: deskew, grayscale, contrast
        # enhancement, sharpening, denoising, thresholding — then OCR the
        # cleaned-up image with several --psm/--oem configs and keep the
        # best-scoring one (see _ocr_best_of / requirement #6). Also try
        # the raw (unprocessed) image the same way and keep whichever of
        # the two — enhanced or raw — scores better overall, since on rare
        # images the enhancement can hurt more than it helps. ──
        candidates = []  # list of (text, mean_confidence)
        try:
            enhanced = _enhance_image_for_ocr(pil_img)
            enhanced_text, enhanced_conf = _ocr_best_of(enhanced)
            if enhanced_text:
                candidates.append((enhanced_text, enhanced_conf))
        except Exception as _enh_err:
            logger.warning("[OCR] Image preprocessing failed: %s", _enh_err)

        # Only pay for a second full OCR pass on the raw image if the
        # enhanced result looks weak or is missing. "Weak" is now judged
        # on Tesseract's own mean confidence first (more reliable,
        # especially across multiple languages at once), falling back to
        # the heuristic score if confidence is unavailable — on the large
        # majority of images the enhanced pass alone is already good, so
        # running a second (up to 3-config) OCR pass unconditionally here
        # was doubling OCR time for little benefit.
        if not candidates or candidates[0][1] < 55.0 or _ocr_quality_score(candidates[0][0]) < 6.0:
            try:
                raw_text, raw_conf = _ocr_best_of(pil_img)
                if raw_text:
                    candidates.append((raw_text, raw_conf))
            except Exception:
                pass

        if not candidates:
            return {'error': 'No text could be extracted from this image. Ensure the image is clear and contains readable text.'}

        # Pick the candidate with the best blended confidence+heuristic
        # score (same blend used inside _ocr_best_of, kept consistent).
        def _candidate_rank(c):
            text, conf = c
            return (conf / 100.0) * 12.0 * 0.6 + _ocr_quality_score(text) * 0.4

        extracted, extracted_conf = max(candidates, key=_candidate_rank)

        # ── Automatic cleanup (requirement #5) ──
        extracted = _clean_ocr_text(extracted)
        extracted = _split_merged_words(extracted)

        if not extracted:
            return {'error': 'No text could be extracted from this image. Ensure the image is clear and contains readable text.'}

        analysis = analyse_text(extracted)
        analysis['extracted_text']    = extracted
        analysis['char_count']        = len(extracted)
        analysis['word_count']        = len(extracted.split())
        analysis['scan_type']         = 'OCR Scanner'
        missing_langs = _tesseract_lang_missing()
        if missing_langs:
            analysis['ocr_languages_unavailable'] = missing_langs
        analysis['ocr_confidence']    = round(extracted_conf, 1)
        # Per-line language tags (additive) — mixed-script images now get a
        # language tag per line instead of one whole-document guess.
        try:
            analysis['language_segments'] = tag_segments(extracted)
        except Exception:
            analysis['language_segments'] = []
        return analysis

    except ImportError as e:
        return {'error': f'pytesseract not installed or Tesseract binary missing: {e}'}
    except Exception as e:
        return {'error': f'OCR failed: {str(e)}'}

_PDF_MAX_RENDER_PAGES = 20  # cap on pages rendered to images, to keep runtime bounded on huge PDFs

def _render_pdf_pages_high_res(pdf_bytes, dpi=300, max_pages=_PDF_MAX_RENDER_PAGES):
    """
    Render PDF pages to high-resolution PIL images (default 300 DPI, can go
    up to 600 DPI for hard-to-read scans) using PyMuPDF. Used to OCR
    scanned/image-only pages and to scan every page for QR codes. Returns
    a list of PIL.Image objects — empty if PyMuPDF isn't installed or
    rendering fails, so callers must tolerate an empty list and simply
    keep whatever text-layer extraction they already have.
    """
    try:
        import fitz  # PyMuPDF
        from PIL import Image
    except ImportError:
        return []

    images = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype='pdf')
        matrix = fitz.Matrix(dpi / 72.0, dpi / 72.0)
        for i, page in enumerate(doc):
            if i >= max_pages:
                break
            pix = page.get_pixmap(matrix=matrix)
            mode = 'RGB' if pix.n < 4 else 'RGBA'
            img = Image.frombytes(mode, (pix.width, pix.height), pix.samples)
            images.append(img.convert('RGB'))
        doc.close()
    except Exception as e:
        logger.warning("[PDF] High-res page rendering failed: %s", e)
    return images


def _render_pdf_page_at_dpi(pdf_bytes, page_index, dpi):
    """Re-render a single PDF page at a specific (higher) DPI. Returns a
    PIL.Image or None on failure."""
    try:
        import fitz
        from PIL import Image
    except ImportError:
        return None
    try:
        doc = fitz.open(stream=pdf_bytes, filetype='pdf')
        if page_index >= len(doc):
            doc.close()
            return None
        matrix = fitz.Matrix(dpi / 72.0, dpi / 72.0)
        pix = doc[page_index].get_pixmap(matrix=matrix)
        mode = 'RGB' if pix.n < 4 else 'RGBA'
        img = Image.frombytes(mode, (pix.width, pix.height), pix.samples).convert('RGB')
        doc.close()
        return img
    except Exception as e:
        logger.warning("[PDF] Page %d re-render at %d DPI failed: %s", page_index, dpi, e)
        return None


def _page_text_is_weak(text: str, min_chars: int = 25, min_words: int = 5) -> bool:
    """
    Decide whether a PDF page's embedded text layer counts as genuinely
    "searchable" (requirement #8: extract directly, skip OCR) or should be
    treated as scanned/image-only (requirement #7: OCR it).

    A page is "weak" (-> OCR it) if it has no text layer at all, or if the
    text layer is so sparse (a handful of characters/words) that it's
    almost certainly a stray watermark, page number, or extraction
    artifact rather than the page's real body text — the previous check
    (`pt and pt.strip()`) treated even a couple of stray characters as
    "this page is searchable," which under-triggered OCR on pages that
    were actually scanned images with a tiny bit of leaked text metadata.
    """
    if not text:
        return True
    stripped = text.strip()
    alnum_chars = sum(c.isalnum() for c in stripped)
    words = stripped.split()
    return alnum_chars < min_chars or len(words) < min_words


def _looks_column_jumbled(text: str) -> bool:
    """
    Cheap heuristic to flag pages where plain extract_text() likely
    scrambled reading order (common on multi-column layouts and tables):
    lots of very short, oddly-interleaved line fragments rather than
    normal sentence-length lines. Used only to decide whether the heavier
    layout-aware extract_text(layout=True) pass is worth trying — false
    positives just cost one extra (still cheap, text-layer-only) call, so
    this is intentionally biased toward "try it" over precision.
    """
    lines = [ln.strip() for ln in text.split('\n') if ln.strip()]
    if len(lines) < 6:
        return False  # too short a page for column-scrambling to matter

    word_counts = [len(ln.split()) for ln in lines]
    avg_words = sum(word_counts) / len(word_counts)
    short_line_ratio = sum(1 for w in word_counts if w <= 2) / len(word_counts)

    # Short-line-heavy AND low average words/line is the signature of
    # column text extracted as narrow horizontal slices instead of
    # reading order.
    return short_line_ratio > 0.45 and avg_words < 4.0


def analyse_pdf(pdf_bytes: bytes) -> dict:
    try:
        import pdfplumber

        text_pages  = []
        page_count  = 0
        weak_pages  = []   # indices of pages with little/no extractable text (likely scanned)

        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            page_count = len(pdf.pages)
            for idx, page in enumerate(pdf.pages):
                pt = page.extract_text()

                # Layout-aware fallback: plain extract_text() can scramble
                # reading order on multi-column pages/pages with tables.
                # Only pay for the heavier layout-aware pass when the fast
                # path looks jumbled, so normal single-column PDFs keep the
                # original (fast) behaviour.
                if pt and _looks_column_jumbled(pt):
                    try:
                        layout_pt = page.extract_text(layout=True)
                        if layout_pt and not _page_text_is_weak(layout_pt):
                            pt = layout_pt
                    except Exception:
                        pass

                if not _page_text_is_weak(pt):
                    # Searchable page — use the direct text layer as-is
                    # (requirement #8), no OCR needed for this page at all.
                    text_pages.append(pt)
                else:
                    weak_pages.append(idx)
                if sum(len(t) for t in text_pages) >= 3000:
                    break

        full_text = '\n'.join(text_pages)[:3000]

        # ── High-res OCR + QR pass (additive — never removes text already
        # extracted above) ───────────────────────────────────────────────
        # Renders pages at 300 DPI (600 DPI retry for pages that still OCR
        # poorly), then:
        #   1. OCRs any page pdfplumber found little/no text on, using the
        #      same preprocessing pipeline as analyse_ocr_image().
        #   2. Scans every rendered page for QR codes with the same
        #      multi-scale/multi-decoder logic as analyse_qr().
        # Degrades gracefully to the pre-existing text-only behaviour if
        # PyMuPDF isn't installed.
        qr_codes  = []
        ocr_added = False
        page_lang_segments = []
        try:
            page_images = _render_pdf_pages_high_res(pdf_bytes, dpi=300)

            if page_images:
                import cv2
                import numpy as np
                import pytesseract

                ocr_chunks = []
                for i, img in enumerate(page_images):
                    # ── OCR pages with weak/no text layer (requirement #7:
                    # scanned pages get OCR'd; searchable pages never reach
                    # here at all since they weren't added to weak_pages) ──
                    if (i in weak_pages or not full_text.strip()) and sum(len(c) for c in ocr_chunks) < 3000:
                        page_ocr_text, page_ocr_conf = '', -1.0
                        try:
                            enhanced = _enhance_image_for_ocr(img)
                            # quick=True: one well-chosen config (psm 6) per
                            # page keeps the per-page cost roughly the same
                            # as before, instead of trying all 3 configs on
                            # every page of a large PDF (requirement #9).
                            page_ocr_text, page_ocr_conf = _ocr_best_of(enhanced, quick=True)
                        except Exception:
                            pass

                        # Escalate to 600 DPI + the full auto-config search
                        # only if the 300 DPI pass barely got anything OR
                        # Tesseract itself wasn't confident in what it did
                        # get — confidence catches cases where a full page
                        # of low-quality text came back (length looks fine)
                        # but Tesseract is guessing at most of it. This is
                        # where the extra accuracy is worth the extra cost,
                        # since it only fires on genuinely hard pages.
                        if len(page_ocr_text) < 30 or page_ocr_conf < 45.0:
                            hi_res_img = _render_pdf_page_at_dpi(pdf_bytes, i, dpi=600)
                            if hi_res_img is not None:
                                try:
                                    enhanced_hi = _enhance_image_for_ocr(hi_res_img)
                                    hi_text, hi_conf = _ocr_best_of(enhanced_hi)
                                    # Prefer the 600 DPI pass if it's either
                                    # longer or Tesseract is more confident
                                    # in it, not just longer (a longer but
                                    # low-confidence result isn't actually
                                    # better).
                                    if hi_text and (len(hi_text) > len(page_ocr_text) or hi_conf > page_ocr_conf):
                                        page_ocr_text, page_ocr_conf = hi_text, hi_conf
                                except Exception:
                                    pass

                        if page_ocr_text:
                            cleaned_page_text = _clean_ocr_text(page_ocr_text)
                            ocr_chunks.append(cleaned_page_text)
                            ocr_added = True
                            try:
                                for seg in tag_segments(cleaned_page_text):
                                    seg['page'] = i + 1
                                    page_lang_segments.append(seg)
                            except Exception:
                                pass

                    # ── Scan this page for QR codes ──
                    try:
                        cv_img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                        data, decoder_used = _decode_qr_multi(cv_img)
                        if data:
                            qr_codes.append({
                                'page':         i + 1,
                                'data':         data,
                                'content_type': detect_qr_content_type(data),
                                'decoder_used': decoder_used,
                            })
                    except Exception:
                        pass

                if ocr_chunks:
                    full_text = (full_text + '\n\n' + '\n\n'.join(ocr_chunks)).strip()[:3000]
        except Exception as e:
            logger.warning("[PDF] High-res OCR/QR pass failed: %s", e)

        if not full_text.strip() and qr_codes:
            # Image-only PDF with no OCR-able text, but QR codes were found —
            # use their decoded payloads as the analysable text instead of
            # failing outright.
            full_text = ' '.join(q['data'] for q in qr_codes)[:3000]

        if not full_text.strip():
            return {'error': 'No readable text found in this PDF (it may be scanned or image-only).'}

        analysis = analyse_text(full_text)
        analysis['page_count']    = page_count
        analysis['word_count']    = len(full_text.split())
        analysis['char_count']    = len(full_text)
        analysis['preview_text']  = full_text[:500]
        analysis['scan_type']     = 'PDF Scanner'
        missing_langs = _tesseract_lang_missing()
        if missing_langs and ocr_added:
            analysis['ocr_languages_unavailable'] = missing_langs
        analysis['qr_codes']      = qr_codes
        analysis['ocr_applied']   = ocr_added
        analysis['language_segments'] = page_lang_segments if ocr_added else []
        return analysis

    except ImportError:
        try:
            import PyPDF2
            reader     = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
            page_count = len(reader.pages)
            texts      = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    texts.append(t)
            full_text = '\n'.join(texts)[:3000]
            if not full_text.strip():
                return {'error': 'No text extracted from PDF.'}
            analysis = analyse_text(full_text)
            analysis['page_count']   = page_count
            analysis['word_count']   = len(full_text.split())
            analysis['char_count']   = len(full_text)
            analysis['preview_text'] = full_text[:500]
            analysis['scan_type']    = 'PDF Scanner'
            return analysis
        except Exception as e2:
            return {'error': f'PDF extraction failed: {e2}'}
    except Exception as e:
        return {'error': f'PDF analysis failed: {str(e)}'}

def analyse_company(name: str, email: str, website: str) -> dict:
    """
    Full Company Verifier pipeline.

    Reuses the existing scanning pipelines rather than re-implementing them:
      - analyse_url_full()        → the same URL Scanner pipeline (heuristics +
                                      live page fetch + text ML + URL ML model)
                                      used on the URL Scanner page, run here
                                      against the company website.
      - analyse_email_full()      → recruiter-email pipeline (public/disposable
                                      provider checks, domain-vs-website match,
                                      scam keywords, entropy, digit ratio,
                                      typosquatting) from utils.py.
      - verify_company_identity() → cross-checks the claimed company name
                                      against the website domain, page title,
                                      and fetched page text.

    On top of those three pipelines, this function adds one more layer:
    cross-verification between all three inputs (name <-> email <-> website),
    then folds everything into a single 0-100 trust score with a level
    classification (Safe / Low / Medium / High / Critical) and a set of
    human-readable explanation bullets.
    """
    name    = (name or '').strip()
    email   = (email or '').strip()
    website = (website or '').strip()

    # 1. Run each existing pipeline
    url_result = analyse_url_full(website) if website else None
    website_domain = (url_result.get('domain', '') if url_result else '') or ''

    content = (url_result or {}).get('content_analysis', {}) or {}
    page_text = content.get('extracted_text', '') or content.get('content_snippet', '')

    identity_result = verify_company_identity(
        name, website_domain=website_domain,
        page_title=page_text, page_text=page_text,
    )
    email_result = analyse_email_full(
        email, website_domain=website_domain, company_name=name,
    ) if email else None

    # 2. Cross-verification between name / email / website
    cross_flags = []
    cross_penalty = 0

    email_domain = (email_result or {}).get('domain', '') if email_result else ''

    if name and email_result and email_domain:
        name_tokens = identity_result.get('tokens', [])
        significant = [t for t in name_tokens if len(t) >= 4] or name_tokens
        email_blob  = f"{email_result.get('local_part','')} {email_domain}".lower()
        name_in_email = any(t in email_blob for t in significant) if significant else False
        if significant and not name_in_email and not email_result.get('domain_matches_website'):
            cross_flags.append(
                f'Recruiter email ("{email}") appears unrelated to the company name ("{name}")'
            )
            cross_penalty += 20

    if email_result and email_result.get('domain_matches_website') is False and website_domain:
        cross_flags.append(
            f'Website ("{website_domain}") and recruiter email domain ("{email_domain}") do not match'
        )
        cross_penalty += 15

    if website_domain and identity_result.get('match_score', 0) == 0:
        cross_penalty += 20
    elif website_domain and not identity_result.get('name_matches_domain'):
        cross_penalty += 10

    fully_consistent = (
        bool(name and email_result and url_result)
        and identity_result.get('name_matches_domain')
        and bool(email_result.get('domain_matches_website'))
    )
    cross_bonus = 10 if fully_consistent else 0
    cross_score = max(0, min(100, cross_penalty - cross_bonus))

    # ── Trusted-company cross-check ──────────────────────────────────────
    # verify_company_identity() does pure name<->domain token matching,
    # which is brittle for real corporate names ("Amazon.com, Inc.",
    # "Alphabet Inc. (Google)", multi-word legal names, etc.) and has no
    # concept of "this domain is *actually, verifiably* that company".
    # Here we cross-check against the curated allowlist in
    # trusted_companies.py: if the domain IS a verified official domain
    # for a brand, AND the typed company name plausibly refers to that
    # same brand (or no name was given to contradict it), we trust the
    # match regardless of how the token-matching scored it. If the domain
    # instead merely *mimics* a known brand, we escalate instead.
    trusted_brand = match_trusted_domain(website_domain) if website_domain else None
    impersonation_brand = None if trusted_brand else (
        detect_brand_impersonation(website_domain) if website_domain else None
    )
    name_brand = company_name_matches_brand(name) if name else None
    brand_verified = bool(trusted_brand and (not name_brand or name_brand == trusted_brand))

    # 3. Individual risk scores (0-100, higher = riskier)
    company_name_risk = min(len(identity_result.get('suspicious_terms', [])) * 20, 80)
    identity_mismatch_risk = (100 - identity_result.get('match_score', 0)) if website_domain else 0
    email_risk = email_result.get('email_risk_score', 0) if email_result else 0
    url_risk   = url_result.get('risk_score', 0) if url_result else 0

    if brand_verified:
        # Domain is confirmed genuine for this brand — a token-matching
        # quirk (e.g. "Amazon.com, Inc." vs domain "amazon.com") shouldn't
        # still read as an identity mismatch.
        identity_mismatch_risk = 0
        cross_score = 0
    elif impersonation_brand:
        # Domain name-drops a real brand without being its official
        # domain — this is the impersonation case, so make sure identity
        # mismatch and cross-verification reflect maximum suspicion
        # rather than relying only on the URL pipeline to catch it.
        identity_mismatch_risk = max(identity_mismatch_risk, 90)
        cross_score = max(cross_score, 80)

    # 4. Weighted combination into a single risk score
    weighted_parts = []
    if website:
        weighted_parts.append((url_risk, 0.35))
        weighted_parts.append((identity_mismatch_risk, 0.15))
    if email:
        weighted_parts.append((email_risk, 0.30))
    weighted_parts.append((company_name_risk, 0.10))
    weighted_parts.append((cross_score, 0.10))

    total_weight = sum(w for _, w in weighted_parts) or 1.0
    risk_score = round(sum(s * w for s, w in weighted_parts) / total_weight, 1)
    risk_score = max(0.0, min(100.0, risk_score))

    TRUST_CEILING = 10.0
    IMPERSONATION_FLOOR = 80.0
    if brand_verified:
        risk_score = min(risk_score, TRUST_CEILING)
    elif impersonation_brand:
        risk_score = max(risk_score, IMPERSONATION_FLOOR)

    ri = compute_risk_level(risk_score)
    trust_score = max(0, round(100 - risk_score))

    # 5. Assemble flags / explanation bullets from every layer
    flags = []
    if brand_verified:
        flags.append(f"✓ Verified as the official {trusted_brand.title()} domain (trusted-domain registry)")
    if impersonation_brand:
        flags.append(
            f"⚠ Domain mimics {impersonation_brand.title()} branding but is NOT its official domain — likely impersonation"
        )
    if identity_result.get('suspicious_terms'):
        flags.append(
            f"Company name contains common fraud-recruitment phrasing: {', '.join(identity_result['suspicious_terms'][:3])}"
        )
    if website_domain and not identity_result.get('name_matches_domain') and not brand_verified:
        flags.append(
            f'Company name "{name}" does not clearly match the website domain ("{website_domain}")' if name else
            'No company name provided to compare against the website'
        )
    if email_result:
        flags.extend(email_result.get('flags', []))
    if url_result:
        flags.extend(url_result.get('flags', url_result.get('indicators', [])))
    flags.extend(cross_flags)
    flags = list(dict.fromkeys(flags))

    explanation_bullets = [f"- {f}" for f in flags[:8]] or ["- No significant red flags detected across name, email, or website."]

    level = ri['level']
    if level == 'CRITICAL':
        verdict = ("This company/recruiter profile shows multiple serious fraud indicators "
                   "across the name, email, and website:\n\n" + "\n".join(explanation_bullets))
    elif level == 'HIGH':
        verdict = ("Strong red flags detected - this profile is unlikely to be legitimate:\n\n"
                   + "\n".join(explanation_bullets))
    elif level == 'MEDIUM':
        verdict = ("Some suspicious or inconsistent elements were found. Verify independently "
                   "through official channels before proceeding:\n\n" + "\n".join(explanation_bullets))
    elif level == 'LOW':
        verdict = ("Only minor risk factors were identified. Still recommended to verify the "
                   "recruiter and offer through official channels:\n\n" + "\n".join(explanation_bullets))
    else:
        verdict = "Company name, recruiter email, and website appear consistent and largely legitimate."

    confidence = min(95, 45 + int(risk_score * 0.5) + (15 if (email and website) else 0))

    logger.info(
        "[Company Verifier] name=%r email=%r website=%r -> risk=%.1f level=%s "
        "(url=%.1f email=%.1f identity_mismatch=%.1f cross=%.1f)",
        name, email, website, risk_score, level, url_risk, email_risk,
        identity_mismatch_risk, cross_score,
    )

    return {
        'risk_score':         risk_score,
        'risk_level':         level,
        'risk_color':         ri['color'],
        'risk_emoji':         ri['emoji'],
        'confidence':         confidence,
        'trust_score':        trust_score,
        'company_analysis':   identity_result,
        'recruiter_analysis': email_result,
        'url_analysis':       url_result,
        'cross_verification': {
            'flags':      cross_flags,
            'penalty':    cross_penalty,
            'bonus':      cross_bonus,
            'consistent': fully_consistent,
        },
        'trusted_domain_check': {
            'verified_brand':      trusted_brand if brand_verified else None,
            'impersonation_brand': impersonation_brand,
            'brand_verified':      brand_verified,
        },
        'flags':            flags,
        'suspicious_kws':   flags[:8],
        'indicators':       flags,
        'recommendations':  get_recommendations(level),
        'verdict':          verdict,
        'scan_type':        'Company Verifier',
    }