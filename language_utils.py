# language_utils.py — UnifiedLens AI
# Multilingual support: auto-detect language + translate to English before analysis
#
# Supported languages:
#   Tamil (ta), English (en), Telugu (te), Malayalam (ml),
#   Kannada (kn), Hindi (hi), Spanish (es)
#
# Strategy (in priority order, zero-dependency first):
#   1. langdetect  — lightweight, offline, no API key needed
#   2. googletrans — free unofficial Google Translate API (no key)
#   3. deep-translator — fallback free translation library
#
# If ALL translation backends fail, the original text is returned unchanged
# so the rest of the UnifiedLens pipeline still works.

import re
import time
import asyncio
import inspect
import unicodedata
import streamlit as st

# ─── Language Metadata ──────────────────────────────────────────────────────────

SUPPORTED_LANGUAGES = {
    'ta': {'name': 'Tamil',     'native': 'தமிழ்',    'flag': '🇮🇳'},
    'en': {'name': 'English',   'native': 'English',   'flag': '🇬🇧'},
    'te': {'name': 'Telugu',    'native': 'తెలుగు',    'flag': '🇮🇳'},
    'ml': {'name': 'Malayalam', 'native': 'മലയാളം',   'flag': '🇮🇳'},
    'kn': {'name': 'Kannada',   'native': 'ಕನ್ನಡ',    'flag': '🇮🇳'},
    'hi': {'name': 'Hindi',     'native': 'हिन्दी',   'flag': '🇮🇳'},
    'es': {'name': 'Spanish',   'native': 'Español',   'flag': '🇪🇸'},
}

# Languages we can confidently handle
SUPPORTED_LANG_CODES = set(SUPPORTED_LANGUAGES.keys())

# Unicode block ranges for script-based heuristic detection
_SCRIPT_RANGES = {
    'hi': (0x0900, 0x097F),   # Devanagari → Hindi
    'ta': (0x0B80, 0x0BFF),   # Tamil
    'te': (0x0C00, 0x0C7F),   # Telugu
    'kn': (0x0C80, 0x0CFF),   # Kannada
    'ml': (0x0D00, 0x0D7F),   # Malayalam
}


# ─── Heuristic Script Detector (zero-dependency fallback) ─────────────────────

def _script_detect(text: str) -> str | None:
    """
    Count Unicode codepoints per Indic script block.
    Returns a language code if a script clearly dominates, else None.
    """
    counts = {lang: 0 for lang in _SCRIPT_RANGES}
    for ch in text:
        cp = ord(ch)
        for lang, (lo, hi) in _SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                counts[lang] += 1

    total_script = sum(counts.values())
    if total_script == 0:
        return None  # no Indic script found

    best_lang = max(counts, key=counts.get)
    # Only return if the dominant script accounts for ≥60% of script chars
    if counts[best_lang] / total_script >= 0.60:
        return best_lang
    return None


def _is_mostly_latin(text: str) -> bool:
    latin = sum(1 for ch in text if 'LATIN' in unicodedata.name(ch, ''))
    return latin / max(len(text.replace(' ', '')), 1) > 0.75


# ─── Language Detection ────────────────────────────────────────────────────────

def detect_language(text: str) -> dict:
    """
    Detect the language of the input text.

    Returns:
        {
          'lang_code':   str,    e.g. 'ta', 'hi', 'en'
          'lang_name':   str,    e.g. 'Tamil'
          'native_name': str,    e.g. 'தமிழ்'
          'flag':        str,    e.g. '🇮🇳'
          'confidence':  float,  0.0–1.0
          'is_supported':bool,
          'method':      str,    'script' | 'langdetect' | 'fallback'
        }
    """
    text = text.strip()

    # 1️⃣  Script heuristic (fast, no deps, very reliable for Indic scripts)
    script_lang = _script_detect(text)
    if script_lang:
        meta = SUPPORTED_LANGUAGES.get(script_lang, {})
        return {
            'lang_code':   script_lang,
            'lang_name':   meta.get('name', script_lang),
            'native_name': meta.get('native', ''),
            'flag':        meta.get('flag', '🏳️'),
            'confidence':  0.97,
            'is_supported':True,
            'method':      'script',
        }

    # 2️⃣  langdetect library
    try:
        from langdetect import DetectorFactory, detect_langs
        DetectorFactory.seed = 0          # deterministic: same text → same answer
        langs = detect_langs(text)
        if langs:
            top = langs[0]
            # Short English/Spanish messages are often mislabelled as fr/it/nl/
            # ro/tl/so… Translating those with a wrong source language mangles
            # the text. For Latin-script text, prefer the best-scoring *supported*
            # candidate (en/es); if none is plausible, fall through to the
            # English/Spanish heuristic below.
            if top.lang not in SUPPORTED_LANG_CODES and _is_mostly_latin(text):
                top = next((l for l in langs if l.lang in ('en', 'es')), None)
            if top is not None:
                code   = top.lang
                conf   = round(float(top.prob), 3)
                is_sup = code in SUPPORTED_LANG_CODES
                meta   = SUPPORTED_LANGUAGES.get(code, {})
                return {
                    'lang_code':   code,
                    'lang_name':   meta.get('name', code.upper()),
                    'native_name': meta.get('native', ''),
                    'flag':        meta.get('flag', '🏳️'),
                    'confidence':  conf,
                    'is_supported':is_sup,
                    'method':      'langdetect',
                }
    except Exception:
        pass

    # 3️⃣  Latin script → English fallback
    if _is_mostly_latin(text):
        # Could be Spanish — simple heuristic: common Spanish markers
        es_markers = ['de ', 'la ', 'el ', 'en ', 'que ', 'con ', 'para ', 'por ', 'los ', 'las ']
        es_hits = sum(1 for m in es_markers if m in text.lower())
        if es_hits >= 3:
            meta = SUPPORTED_LANGUAGES['es']
            return {
                'lang_code': 'es', 'lang_name': meta['name'],
                'native_name': meta['native'], 'flag': meta['flag'],
                'confidence': 0.65, 'is_supported': True, 'method': 'fallback',
            }
        meta = SUPPORTED_LANGUAGES['en']
        return {
            'lang_code': 'en', 'lang_name': meta['name'],
            'native_name': meta['native'], 'flag': meta['flag'],
            'confidence': 0.70, 'is_supported': True, 'method': 'fallback',
        }

    # 4️⃣  Unknown
    return {
        'lang_code': 'unknown', 'lang_name': 'Unknown', 'native_name': '',
        'flag': '🏳️', 'confidence': 0.0, 'is_supported': False, 'method': 'fallback',
    }


# ─── Translation ───────────────────────────────────────────────────────────────
# Root-cause notes (why non-English scams were scored as "safe"):
#   • Only the FIRST 500 chars could be sent to the MyMemory fallback (hard
#     limit) and googletrans 4.0.0-rc1 is unmaintained/broken, so for most real
#     messages BOTH backends failed.
#   • On failure the ORIGINAL (e.g. Tamil) text was silently handed to the
#     English-only ML model + keyword scorer → no keywords → "SAFE/LOW".
#   • @st.cache_data then cached that failed result, so retries kept failing.
# Fix: Google (deep-translator) as primary, text split into safe chunks,
# per-chunk fallbacks, output validation, and failures are never cached.

_GOOGLE_CHUNK   = 4500   # Google web limit is 5000 chars/request
_MYMEMORY_CHUNK = 450    # MyMemory hard limit is 500 chars/request

_MYMEMORY_CODES = {
    'ta': 'ta-IN', 'te': 'te-IN', 'ml': 'ml-IN',
    'kn': 'kn-IN', 'hi': 'hi-IN', 'es': 'es-ES',
}
_SEGMENT_RE = re.compile(r'[^\n.!?।॥]*[\n.!?।॥]+|[^\n.!?।॥]+')


def _split_chunks(text: str, limit: int) -> list[str]:
    """Split *text* into chunks <= limit chars at sentence/line boundaries."""
    pieces = []
    for seg in _SEGMENT_RE.findall(text):
        while len(seg) > limit:                     # one very long sentence
            cut = seg.rfind(' ', 0, limit)
            cut = cut if cut > limit // 2 else limit
            pieces.append(seg[:cut])
            seg = seg[cut:]
        if seg:
            pieces.append(seg)
    chunks, cur = [], ''
    for p in pieces:
        if cur and len(cur) + len(p) > limit:
            chunks.append(cur)
            cur = ''
        cur += p
    if cur:
        chunks.append(cur)
    return [c for c in chunks if c.strip()]


def _indic_ratio(s: str) -> float:
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    indic = sum(1 for c in letters
                if any(lo <= ord(c) <= hi for lo, hi in _SCRIPT_RANGES.values()))
    return indic / len(letters)


def _valid_translation(original: str, out: str, src_lang: str) -> bool:
    """Reject empty / untranslated output (some backends echo the input)."""
    if not out or not out.strip():
        return False
    if src_lang in _SCRIPT_RANGES:
        return _indic_ratio(out) < 0.5
    if src_lang == 'es' and len(original.split()) >= 3:
        return out.strip().lower() != original.strip().lower()
    return True


def _run_maybe_async(value):
    """googletrans >= 4.0.1 is async; rc1 is sync. Support both."""
    if not inspect.isawaitable(value):
        return value
    try:
        return asyncio.run(value)
    except RuntimeError:                           # a loop is already running
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(value)
        finally:
            loop.close()


def _tr_google(chunk: str, src: str) -> str:
    from deep_translator import GoogleTranslator
    return GoogleTranslator(source=src, target='en').translate(chunk)


def _tr_googletrans(chunk: str, src: str) -> str:
    from googletrans import Translator
    res = _run_maybe_async(Translator().translate(chunk, src=src, dest='en'))
    return res.text


def _tr_mymemory(chunk: str, src: str) -> str:
    from deep_translator import MyMemoryTranslator
    return MyMemoryTranslator(source=_MYMEMORY_CODES.get(src, src),
                              target='en-GB').translate(chunk)


# (name, function, chunk size) — tried in this order for every chunk
_BACKENDS = [
    ('deep_translator', _tr_google,      _GOOGLE_CHUNK),
    ('googletrans',     _tr_googletrans, _GOOGLE_CHUNK),
    ('mymemory',        _tr_mymemory,    _MYMEMORY_CHUNK),
]


def _translate_chunk(chunk: str, src: str, backend, dead: set, errors: list):
    name, fn, limit = backend
    pieces = [chunk] if len(chunk) <= limit else _split_chunks(chunk, limit)
    outs = []
    for piece in pieces:
        out = None
        for attempt in range(2):                   # one retry for flaky calls
            try:
                out = fn(piece, src)
                if _valid_translation(piece, out, src):
                    break
                out = None
            except Exception as e:                 # network / rate-limit / lib error
                errors.append(f"{name}: {e}")
                out = None
            time.sleep(0.4)
        if out is None:
            return None
        outs.append(out.strip())
    return ' '.join(outs)


def _translate_full(text: str, src_lang: str) -> tuple[str, str, list]:
    """Translate the COMPLETE text. Returns (english, method, errors).
    english is '' if any part could not be translated by any backend."""
    errors, dead, used = [], set(), []
    out_parts = []
    for chunk in _split_chunks(text, _GOOGLE_CHUNK):
        if not re.search(r'\w', chunk):           # punctuation/whitespace only
            out_parts.append((chunk.strip(), chunk))
            continue
        result = None
        for backend in _BACKENDS:
            if backend[0] in dead:
                continue
            result = _translate_chunk(chunk, src_lang, backend, dead, errors)
            if result:
                if backend[0] not in used:
                    used.append(backend[0])
                break
            if backend[0] not in used:             # never worked → skip it from now on
                dead.add(backend[0])
        if not result:
            return '', '', errors
        out_parts.append((result, chunk))

    joined = ''
    for out, chunk in out_parts:
        joined += out + ('\n' if chunk.endswith('\n') else ' ')
    return joined.strip(), '+'.join(used), errors


@st.cache_data(max_entries=256, show_spinner=False)
def _translate_cached(text: str, src_lang: str) -> tuple:
    """Cached ONLY on success — raising keeps failures out of the cache."""
    english, method, errors = _translate_full(text, src_lang)
    if not english:
        raise RuntimeError('; '.join(errors[-3:]) or 'no backend returned a translation')
    return english, method


def translate_to_english(text: str, src_lang: str) -> dict:
    """Translate supported non-English text to English (complete text)."""

    if src_lang == "en":
        return {
            "translated_text": text,
            "success": True,
            "method": "passthrough",
            "error": None,
        }

    try:
        english, method = _translate_cached(text, src_lang)
        return {
            "translated_text": english,
            "success": True,
            "method": method,
            "error": None,
        }
    except Exception as e:
        return {
            "translated_text": text,
            "success": False,
            "method": "passthrough",
            "error": f"Translation services are temporarily unavailable. ({e})",
        }

# ─── Combined: Detect + Translate ─────────────────────────────────────────────

def detect_and_translate(text: str) -> dict:
    """
    Full pipeline: detect language → translate to English if needed.

    Returns:
        {
          'original_text':    str,
          'translated_text':  str,   # English (same as original if already English)
          'was_translated':   bool,
          'lang_code':        str,
          'lang_name':        str,
          'native_name':      str,
          'flag':             str,
          'confidence':       float,
          'is_supported':     bool,
          'translation_method': str,
          'translation_success': bool,
          'translation_error': str | None,
          'detect_method':    str,
        }
    """
    detection = detect_language(text)
    lang_code = detection['lang_code']

    if lang_code == 'en' or lang_code == 'unknown':
        return {
            'original_text':      text,
            'translated_text':    text,
            'was_translated':     False,
            'translation_method': 'passthrough',
            'translation_success':True,
            'translation_error':  None,
            'detect_method':      detection['method'],
            **{k: detection[k] for k in
               ('lang_code', 'lang_name', 'native_name', 'flag', 'confidence', 'is_supported')},
        }

    translation = translate_to_english(text, lang_code)

    return {
        'original_text':      text,
        'translated_text':    translation['translated_text'],
        'was_translated':     translation['success'],
        'translation_method': translation['method'],
        'translation_success':translation['success'],
        'translation_error':  translation['error'],
        'detect_method':      detection['method'],
        **{k: detection[k] for k in
           ('lang_code', 'lang_name', 'native_name', 'flag', 'confidence', 'is_supported')},
    }


# ─── Per-line / per-segment language tagging ───────────────────────────────────
# Additive: does NOT change the shape of detect_and_translate(). This is for
# mixed-script pages/images where a single whole-document guess is wrong for
# some lines (e.g. an English heading over a Tamil paragraph).

def tag_segments(text: str) -> list[dict]:
    """
    Split *text* into lines and run the same _script_detect() heuristic on
    each line independently.

    Returns a list of:
        {
          'text':      str,   # the line, stripped
          'lang_code': str,   # e.g. 'ta', 'en', 'unknown'
          'lang_name': str,   # e.g. 'Tamil'
        }

    Blank lines are skipped. Lines with no dominant Indic script fall back
    to the same Latin-heuristic used in detect_language() (Spanish-marker
    check, else English, else 'unknown') so short lines still get a
    reasonable tag without paying for langdetect per line.
    """
    segments = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        code = _script_detect(line)
        if code is None:
            if _is_mostly_latin(line):
                es_markers = ['de ', 'la ', 'el ', 'en ', 'que ', 'con ', 'para ', 'por ', 'los ', 'las ']
                es_hits = sum(1 for m in es_markers if m in line.lower())
                code = 'es' if es_hits >= 2 else 'en'
            else:
                code = 'unknown'

        meta = SUPPORTED_LANGUAGES.get(code, {})
        segments.append({
            'text':      line,
            'lang_code': code,
            'lang_name': meta.get('name', 'Unknown' if code == 'unknown' else code.upper()),
        })

    return segments


def tag_segments_from_ocr_data(ocr_data: dict) -> list[dict]:
    """
    Same as tag_segments(), but groups pytesseract's image_to_data()
    output (Output.DICT) by (block_num, par_num, line_num) so segments
    align with actual visual lines/regions on the page instead of just
    splitting on '\\n' — more reliable when a line wraps oddly or when
    OCR merges/splits lines unexpectedly.

    *ocr_data* is the dict returned by:
        pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, ...)

    Returns the same shape as tag_segments(): [{'text','lang_code','lang_name'}, ...]
    Callers should pass whatever config/lang they used for OCR; this function
    only regroups + re-tags, it doesn't call Tesseract itself.
    """
    n = len(ocr_data.get('text', []))
    lines = {}
    order = []
    for i in range(n):
        word = (ocr_data['text'][i] or '').strip()
        if not word:
            continue
        key = (ocr_data.get('block_num', [0]*n)[i],
               ocr_data.get('par_num', [0]*n)[i],
               ocr_data.get('line_num', [0]*n)[i])
        if key not in lines:
            lines[key] = []
            order.append(key)
        lines[key].append(word)

    joined = '\n'.join(' '.join(lines[k]) for k in order)
    return tag_segments(joined)


# ─── Language Badge HTML ───────────────────────────────────────────────────────
# NOTE: Only uses div/span/strong — tags Streamlit's markdown renderer allows.
# <details>, <summary>, and most block-level tags are stripped by Streamlit.
# The original-text preview is handled via st.expander() in app.py, not here.

def language_badge_html(lang_result: dict) -> str:
    """
    Returns a safe HTML string (div/span only) for the language detection badge.
    Render with:  st.markdown(badge_html, unsafe_allow_html=True)
    """
    flag      = lang_result.get('flag', '🏳️')
    lang_name = lang_result.get('lang_name', 'Unknown')
    native    = lang_result.get('native_name', '')
    conf      = round(lang_result.get('confidence', 0) * 100)
    was_trans = lang_result.get('was_translated', False)
    method    = lang_result.get('translation_method', '')
    t_success = lang_result.get('translation_success', False)

    native_str = f' · {native}' if native and native != lang_name else ''
    t_color    = '#00ff9d' if t_success else '#ffb340'
    t_label    = f'✅ Translated via {method}' if (was_trans and t_success) else (
                 f'⚠️ Translation unavailable — original text analysed' if was_trans else '')

    trans_row = f'''
        <div style="margin-top:0.35rem;font-size:0.72rem;color:{t_color};
                    font-family:monospace;letter-spacing:0.03em">
            🌐 {t_label}
        </div>''' if was_trans else ''

    return f'''
    <div style="
        display:inline-flex;flex-direction:column;
        background:rgba(0,212,255,0.07);
        border:1px solid rgba(0,212,255,0.22);
        border-radius:12px;padding:0.5rem 1rem;
        margin-bottom:0.75rem;">
        <div style="display:flex;align-items:center;gap:0.5rem;
                    font-family:monospace;font-size:0.75rem;color:#00d4ff;">
            <span style="font-size:1.05rem">{flag}</span>
            <span>Language detected: <strong>{lang_name}</strong>{native_str}</span>
            <span style="color:rgba(0,212,255,0.4)">·</span>
            <span style="color:rgba(0,212,255,0.75)">{conf}% confidence</span>
        </div>{trans_row}
    </div>'''
