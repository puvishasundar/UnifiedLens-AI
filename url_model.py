# url_model.py — CyberLens AI
# Phishing URL detection pipeline (separate from the text scam model in ml_model.py)

import os
import re
import math
import logging
import joblib
import numpy as np
import pandas as pd
import streamlit as st

from collections import Counter
from urllib.parse import urlparse

from sklearn.ensemble         import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.impute           import SimpleImputer
from sklearn.pipeline         import Pipeline
from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics          import accuracy_score, classification_report, f1_score

# ─── Logging ────────────────────────────────────────────────────────────────────
# Uses the root logging config set up in app.py (logging.basicConfig). If this
# module is ever imported standalone, it still logs to the console at INFO level.
logger = logging.getLogger("cyberlens.url_model")

# ─── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_url_detector.pkl')
DATA_PATH  = os.path.join(BASE_DIR, 'url.csv')

_POSITIVE_LABELS = {
    'phishing', 'malicious', 'bad', 'scam', 'fraud', 'unsafe',
    '1', 1, True, 'yes', 'phish',
}

FEATURE_COLUMNS = [
    'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
    'num_params', 'suspicious_words', 'tld_risk', 'special_char_count',
    'digits_count', 'entropy',
]

_SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'secure', 'security',
    'confirm', 'banking', 'bank', 'webscr', 'password', 'suspend', 'suspended',
    'unlock', 'alert', 'billing', 'invoice', 'payment', 'paypal', 'wallet',
    'crypto', 'gift', 'bonus', 'free', 'win', 'winner', 'prize', 'urgent',
    'click', 'limited', 'expire', 'reset', 'authenticate', 'validate',
    'recover', 'support', 'helpdesk', 'lucky', 'money', 'share', 'invitation'
]

_DEFAULT_TLD_PRIOR = 0.5

# IPv4: 1-3 digit octets x4. IPv6: bracketed "[...]" (URL form) or bare hex-colon form.
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_IPV6_RE = re.compile(r'^\[?[0-9a-fA-F:]+:[0-9a-fA-F:]*\]?$')

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)

def _is_ip_address(domain: str) -> bool:
    """True for IPv4 (e.g. 192.168.0.1) or IPv6 (e.g. [::1], 2001:db8::1) host strings."""
    if not domain:
        return False
    d = domain.strip('[]')
    if _IPV4_RE.match(d):
        return True
    # IPv6 needs at least two colons and only hex/colon characters
    if d.count(':') >= 2 and _IPV6_RE.match(domain):
        return True
    return False

def _extract_domain_and_tld(u: str):
    try:
        parsed = urlparse(u)
    except Exception as e:
        logger.warning("[url_model] Failed to urlparse '%s': %s", u, e)
        parsed = None

    domain = (parsed.netloc if parsed else '').lower()
    domain = domain.split('@')[-1]

    # Strip a trailing :port, but don't break bracketed IPv6 hosts like [::1]:443
    if domain.startswith('['):
        host_end = domain.find(']')
        domain = domain[:host_end + 1] if host_end != -1 else domain
    else:
        domain = domain.split(':')[0]

    domain_no_www = domain[4:] if domain.startswith('www.') else domain

    tld_match = re.search(r'\.([a-z0-9]{2,})$', domain_no_www) if not _is_ip_address(domain_no_www) else None
    tld = tld_match.group(1) if tld_match else ''

    return parsed, domain_no_www, tld

def extract_url_only_features(url: str) -> dict:
    u = (url or '').strip()
    if not u.startswith(('http://', 'https://')):
        u = 'http://' + u

    parsed, domain, tld = _extract_domain_and_tld(u)
    path = (parsed.path if parsed else '') or ''
    query = (parsed.query if parsed else '') or ''
    scheme = (parsed.scheme if parsed else 'http')

    is_ip = 1 if _is_ip_address(domain) else 0

    num_subdirs = len([p for p in path.split('/') if p])
    num_params = (len(query.split('&')) if query else 0)

    url_lower = u.lower()
    suspicious_words = sum(1 for w in _SUSPICIOUS_WORDS if w in url_lower)

    specials = sum(1 for ch in u if not ch.isalnum() and ch not in ('.', '/', ':'))
    digits = sum(ch.isdigit() for ch in u)

    feats = {
        'url_length':          len(u),
        'num_dots':            u.count('.'),
        'has_https':           1 if scheme == 'https' else 0,
        'has_ip':              is_ip,
        'num_subdirs':         num_subdirs,
        'num_params':          num_params,
        'suspicious_words':    suspicious_words,
        'special_char_count':  specials,
        'digits_count':        digits,
        'entropy':             _shannon_entropy(u),
        '_tld':                tld,
        '_domain':             domain,
        '_clean_url':          u,
    }
    return feats

@st.cache_data(max_entries=256, show_spinner=False)
def extract_features_for_url(url: str) -> dict:
    try:
        return extract_url_only_features(url)
    except Exception as e:
        logger.warning("[url_model] Feature extraction failed for '%s': %s", url, e, exc_info=True)
        return {
            'url_length': 0, 'num_dots': 0, 'has_https': 0, 'has_ip': 0,
            'num_subdirs': 0, 'num_params': 0, 'suspicious_words': 0,
            'special_char_count': 0, 'digits_count': 0, 'entropy': 0.0,
            '_tld': '', '_domain': '', '_clean_url': url or '',
            '_error': str(e),
        }

def _tld_risk(tld: str, tld_risk_map: dict, tld_prior: float) -> float:
    return float(tld_risk_map.get((tld or '').lower(), tld_prior))

def _row_to_feature_vector(feat_dict: dict, tld_risk_map: dict, tld_prior: float) -> list:
    vec = []
    for col in FEATURE_COLUMNS:
        if col == 'tld_risk':
            vec.append(_tld_risk(feat_dict.get('_tld', ''), tld_risk_map, tld_prior))
        else:
            vec.append(feat_dict.get(col, 0))
    return vec

def _coerce_binary(v) -> int:
    if pd.isna(v):
        return 0
    s = str(v).strip().lower()
    if s in ('1', 'true', 'yes', 'y'):
        return 1
    if s in ('0', 'false', 'no', 'n', ''):
        return 0
    try:
        return 1 if float(s) != 0 else 0
    except ValueError:
        return 0

def build_tld_risk_map(df: pd.DataFrame, y: pd.Series) -> tuple:
    tld_prior = float(y.mean()) if len(y) else _DEFAULT_TLD_PRIOR

    if 'tld' not in df.columns:
        return {}, tld_prior

    tmp = pd.DataFrame({'tld': df['tld'].fillna('').astype(str).str.lower().str.strip(), 'y': y.values})
    grouped = tmp.groupby('tld')['y'].mean()
    return grouped.to_dict(), tld_prior

def train_url_model(data_path: str = DATA_PATH) -> dict:
    logger.info("[url_model] Training URL phishing model from %s", data_path)
    df = pd.read_csv(data_path)

    if 'label' not in df.columns:
        raise ValueError("url.csv must contain a 'label' column")

    y = df['label'].apply(
        lambda v: 1 if str(v).strip().lower() in {str(x).lower() for x in _POSITIVE_LABELS} else 0
    )

    tld_risk_map, tld_prior = build_tld_risk_map(df, y)
    binary_like_cols = {'has_https', 'has_ip'}

    X = pd.DataFrame(index=df.index)
    for col in FEATURE_COLUMNS:
        if col == 'tld_risk':
            X[col] = df['tld'].fillna('').astype(str).str.lower().str.strip().map(tld_risk_map).fillna(tld_prior) \
                if 'tld' in df.columns else tld_prior
        elif col in df.columns:
            if col in binary_like_cols:
                X[col] = df[col].apply(_coerce_binary)
            else:
                X[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        else:
            X[col] = 0

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight='balanced', n_jobs=-1, random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.08, random_state=42,
    )

    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft',
        weights=[1, 1],
    )

    pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('clf', ensemble),
    ])

    pipeline.fit(X_train, y_train)

    probas      = pipeline.predict_proba(X_test)[:, 1]
    best_thresh = 0.5
    best_f1     = 0.0
    for t in np.arange(0.30, 0.71, 0.01):
        preds = (probas >= t).astype(int)
        f = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, round(float(t), 2)

    y_pred = (probas >= best_thresh).astype(int)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring='f1', n_jobs=-1)

    logger.info(
        "[url_model] Training complete — accuracy=%.4f threshold=%.2f cv_f1_mean=%.4f cv_f1_std=%.4f",
        acc, best_thresh, float(cv_scores.mean()), float(cv_scores.std()),
    )

    artifact = {
        'pipeline':        pipeline,
        'threshold':       best_thresh,
        'feature_columns': FEATURE_COLUMNS,
        'tld_risk_map':    tld_risk_map,
        'tld_prior':       tld_prior,
    }
    joblib.dump(artifact, MODEL_PATH)
    logger.info("[url_model] Saved trained artifact to %s", MODEL_PATH)

    return {
        'accuracy':   acc,
        'threshold':  best_thresh,
        'cv_f1_mean': round(float(cv_scores.mean()), 4),
        'cv_f1_std':  round(float(cv_scores.std()),  4),
        'report':     report,
        'pipeline':   pipeline,
        'tld_risk_map': tld_risk_map,
        'tld_prior':  tld_prior,
    }

@st.cache_resource
def load_url_artifact():
    if os.path.exists(MODEL_PATH):
        try:
            artifact = joblib.load(MODEL_PATH)
            if not isinstance(artifact, dict):
                artifact = {
                    'pipeline': artifact,
                    'threshold': 0.5,
                    'feature_columns': FEATURE_COLUMNS,
                    'tld_risk_map': {},
                    'tld_prior': _DEFAULT_TLD_PRIOR,
                }
            artifact.setdefault('feature_columns', FEATURE_COLUMNS)
            artifact.setdefault('tld_risk_map', {})
            artifact.setdefault('tld_prior', _DEFAULT_TLD_PRIOR)

            if artifact['feature_columns'] != FEATURE_COLUMNS:
                raise ValueError('Stale model artifact — retraining')

            logger.info("[url_model] Loaded existing artifact from %s", MODEL_PATH)
            return artifact
        except Exception as e:
            logger.warning(
                "[url_model] Failed to load artifact at %s (%s) — will attempt to retrain",
                MODEL_PATH, e, exc_info=True,
            )

    if os.path.exists(DATA_PATH):
        try:
            result = train_url_model()
            return {
                'pipeline':        result['pipeline'],
                'threshold':       result['threshold'],
                'feature_columns': FEATURE_COLUMNS,
                'tld_risk_map':    result['tld_risk_map'],
                'tld_prior':       result['tld_prior'],
            }
        except Exception as e:
            logger.error("[url_model] Retraining failed: %s", e, exc_info=True)

    logger.warning("[url_model] No artifact and no training data found at %s — URL ML predictions disabled", DATA_PATH)
    return None

def predict_url(url: str, fetch_webpage: bool = False) -> dict:
    """
    Predict whether a URL is phishing based on lexical/structural URL features.

    Note on `fetch_webpage`: this model intentionally does NOT fetch the live
    webpage itself. Live content fetching (HTML retrieval, JS rendering,
    scam-phrase scanning, text-model scoring) is handled upstream by
    analyzer.analyse_webpage_content(), which is reused by analyse_url_full()
    to avoid issuing a second, redundant HTTP request per scan. If you pass
    fetch_webpage=True, this is logged and reflected in 'fetch_note', but the
    returned 'fetched' flag stays False since no fetch happens *in this model*.
    """
    if fetch_webpage:
        logger.info(
            "[url_model] fetch_webpage=True requested for '%s' — no-op here by design; "
            "webpage fetching/content scoring is done upstream in analyzer.analyse_webpage_content().",
            url,
        )

    artifact = load_url_artifact()

    if artifact is None:
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     False,
            'fetch_error': None,
            'fetch_note':  'Webpage fetching is handled upstream in analyzer.py, not in url_model.' if fetch_webpage else None,
            'features':    {},
        }

    pipeline      = artifact['pipeline']
    threshold     = artifact['threshold']
    tld_risk_map  = artifact.get('tld_risk_map', {})
    tld_prior     = artifact.get('tld_prior', _DEFAULT_TLD_PRIOR)

    try:
        feat_dict = extract_features_for_url(url)
    except Exception as e:
        logger.warning("[url_model] extract_features_for_url raised for '%s': %s", url, e, exc_info=True)
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     False,
            'fetch_error': str(e),
            'fetch_note':  'Webpage fetching is handled upstream in analyzer.py, not in url_model.' if fetch_webpage else None,
            'features':    {},
        }

    vector = _row_to_feature_vector(feat_dict, tld_risk_map, tld_prior)
    X_row  = pd.DataFrame([vector], columns=FEATURE_COLUMNS)

    try:
        proba   = pipeline.predict_proba(X_row)[0]
        ml_prob = float(proba[1])
    except Exception as e:
        logger.error("[url_model] predict_proba failed for '%s': %s", url, e, exc_info=True)
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     False,
            'fetch_error': str(e),
            'fetch_note':  'Webpage fetching is handled upstream in analyzer.py, not in url_model.' if fetch_webpage else None,
            'features':    feat_dict,
        }

    label      = 'phishing' if ml_prob >= threshold else 'legitimate'
    confidence = round(abs(ml_prob - 0.5) * 2.0, 4)

    display_features = {k: v for k, v in feat_dict.items() if not k.startswith('_')}
    display_features['tld'] = feat_dict.get('_tld', '')

    logger.info(
        "[url_model] Prediction for '%s': label=%s probability=%.4f confidence=%.4f",
        url, label, ml_prob, confidence,
    )

    return {
        'label':       label,
        'probability': round(ml_prob, 4),
        'confidence':  confidence,
        'fetched':     False,
        'fetch_error': None,
        'fetch_note':  'Webpage fetching is handled upstream in analyzer.py, not in url_model.' if fetch_webpage else None,
        'features':    display_features,
    }

def get_feature_importance_url(url: str, top_n: int = 5) -> list:
    """
    Return the top contributing FEATURE_COLUMNS for a given URL's prediction,
    ranked by (model feature importance x this URL's normalised feature value).
    Mirrors ml_model.get_feature_importance() so app.py can show *why* a URL
    was flagged, not just the final score.

    Returns a list of (feature_name, contribution_score) tuples, e.g.:
        [('suspicious_words', 0.41), ('entropy', 0.22), ...]
    """
    artifact = load_url_artifact()
    if artifact is None:
        return []

    pipeline     = artifact['pipeline']
    tld_risk_map = artifact.get('tld_risk_map', {})
    tld_prior    = artifact.get('tld_prior', _DEFAULT_TLD_PRIOR)

    try:
        feat_dict = extract_features_for_url(url)
        vector    = _row_to_feature_vector(feat_dict, tld_risk_map, tld_prior)

        # Average feature_importances_ across the RF + GB ensemble members.
        clf = pipeline.named_steps['clf']
        importances = np.mean(
            [est.feature_importances_ for _, est in clf.estimators_ if hasattr(est, 'feature_importances_')]
            or [np.zeros(len(FEATURE_COLUMNS))],
            axis=0,
        )

        # Normalise this URL's raw feature values to 0-1 so a large url_length
        # doesn't dominate purely due to scale, then weight by model importance.
        raw_vals = np.array(vector, dtype=float)
        max_vals = np.maximum(raw_vals.max(), 1e-9)
        norm_vals = raw_vals / max_vals

        contributions = importances * norm_vals
        pairs = sorted(
            zip(FEATURE_COLUMNS, contributions),
            key=lambda p: p[1], reverse=True,
        )
        return [(name, round(float(score), 4)) for name, score in pairs[:top_n] if score > 0]
    except Exception as e:
        logger.warning("[url_model] get_feature_importance_url failed for '%s': %s", url, e, exc_info=True)
        return []

def batch_predict_url(urls: list) -> list:
    """Run predict_url() over a list of URLs."""
    return [predict_url(u) for u in urls]

if not os.path.exists(MODEL_PATH):
    try:
        if os.path.exists(DATA_PATH):
            train_url_model()
    except Exception as e:
        logger.error("[url_model] Could not pre-train URL model on startup: %s", e, exc_info=True)
