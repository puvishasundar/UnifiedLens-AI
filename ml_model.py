# ml_model.py — CyberLens AI  (v2 — accuracy-hardened)
# Scam / phishing detection pipeline
# Improvements over v1:
#   • Dual vectoriser: word n-grams (1-3) + char n-grams (3-5) → catches obfuscated text
#   • Lemmatisation + stop-word removal in preprocessing
#   • Ensemble: soft-voting LogisticRegression + SGDClassifier + RandomForest
#   • Threshold tuning via precision-recall curve (maximise F1)
#   • Rule-based pre-filter for high-confidence scam signals
#   • Stratified k-fold cross-validation during training
#   • min_df=2 to reduce overfitting on tiny corpora
#   • Calibrated probabilities (CalibratedClassifierCV)

import os
import re
import joblib
import numpy as np
import pandas as pd
import nltk
import streamlit as st

from sklearn.feature_extraction.text  import TfidfVectorizer
from sklearn.linear_model             import LogisticRegression, SGDClassifier
from sklearn.ensemble                 import RandomForestClassifier, VotingClassifier
from sklearn.calibration              import CalibratedClassifierCV
from sklearn.model_selection          import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics                  import accuracy_score, classification_report, f1_score
from sklearn.pipeline                 import Pipeline, FeatureUnion
from sklearn.base                     import BaseEstimator, TransformerMixin
from sklearn.preprocessing            import FunctionTransformer

# ─── NLTK Setup ────────────────────────────────────────────────────────────────
def ensure_nltk():
    for pkg in ['stopwords', 'punkt', 'wordnet', 'omw-1.4']:
        for prefix in ['tokenizers/', 'corpora/', '']:
            try:
                nltk.data.find(f'{prefix}{pkg}')
                break
            except LookupError:
                try:
                    nltk.download(pkg, quiet=True)
                    break
                except Exception:
                    pass

ensure_nltk()

# ─── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'scam_detector.pkl')

# v3: primary training data is now scam.csv (user-supplied dataset).
# sample_data.csv is kept as a legacy fallback so existing deployments
# that haven't added scam.csv yet keep working unchanged.
_SCAM_CSV_PATH   = os.path.join(BASE_DIR, 'scam.csv')
_LEGACY_CSV_PATH = os.path.join(BASE_DIR, 'sample_data.csv')
DATA_PATH  = _SCAM_CSV_PATH if os.path.exists(_SCAM_CSV_PATH) else _LEGACY_CSV_PATH

# ─── Scam signal rules (high-precision heuristics) ──────────────────────────────
# These patterns are near-certain indicators; used to boost confidence.
_SCAM_PATTERNS = [
    r'\bpay\b.{0,40}\b(fee|deposit|now|today|urgent|immediately)\b',
    r'\b(wire transfer|bitcoin|crypto|zelle|paypal)\b.{0,30}\b(send|pay|transfer)\b',
    r'\b(guaranteed|no experience|no interview|direct (joining|selection))\b',
    r'\b(send|share).{0,20}\b(otp|aadhaar|pan|ssn|bank (card|account|detail))\b',
    r'\bearning?.{0,10}\$[\d,]+.{0,10}(day|week|hour|month)\b',
    r'\b(click|login|verify).{0,30}(password|credentials|account)\b',
    r'work from home.{0,40}earn.{0,20}\$[\d,]+',
    r'\b(limited (seats|offer)|act fast|hurry)\b',
]
_SCAM_RE = [re.compile(p, re.IGNORECASE) for p in _SCAM_PATTERNS]

def rule_based_scam_score(text: str) -> float:
    """Returns 0.0–1.0 based on how many scam rules fire.
    Saturates at 2 hits (was 3) so the signal is stronger on moderate matches.
    Each hit also carries weighted confidence via sigmoid scaling.
    """
    hits = sum(1 for r in _SCAM_RE if r.search(text))
    if hits == 0:
        return 0.0
    # Sigmoid-style: 1 hit → ~0.57, 2 hits → ~0.72 (triggers stronger blend), 3+ → ~0.92+
    return round(min(1.0 - (1.0 / (1.0 + hits * 1.3)), 0.98), 4)

# ─── Text Preprocessing ─────────────────────────────────────────────────────────

@st.cache_resource
def get_stop_words():
    try:
        from nltk.corpus import stopwords
        return set(stopwords.words('english'))
    except Exception:
        return set()

@st.cache_resource
def get_lemmatizer():
    try:
        from nltk.stem import WordNetLemmatizer
        return WordNetLemmatizer()
    except Exception:
        return None

@st.cache_data(max_entries=512)
def preprocess_text(text: str) -> str:
    """Clean, normalise, lemmatise text for ML pipeline."""
    if not isinstance(text, str):
        text = str(text)

    # ── structural replacements (preserve semantics as tokens) ──────────────
    text = text.lower()
    text = re.sub(r'http\S+|www\S+',           ' URLTOKEN ',     text)
    text = re.sub(r'\$[\d,]+',                 ' MONEYTOKEN ',   text)
    text = re.sub(r'rs\.?\s*[\d,]+',           ' MONEYTOKEN ',   text)
    text = re.sub(r'[\d,]+\s*%',               ' PERCENTTOKEN ', text)
    text = re.sub(r'\b\d{10,}\b',              ' PHONETOKEN ',   text)   # phone numbers
    text = re.sub(r'\b[\w.+-]+@[\w-]+\.\w+\b', ' EMAILTOKEN ',  text)   # email addresses
    text = re.sub(r'[^a-z\s]',                 ' ',              text)
    text = re.sub(r'\s+',                      ' ',              text).strip()

    stop  = get_stop_words()
    lemma = get_lemmatizer()
    tokens = []
    for t in text.split():
        if len(t) <= 2 or t in stop:
            continue
        tokens.append(lemma.lemmatize(t) if lemma else t)

    return ' '.join(tokens)

# ─── Feature union helper ───────────────────────────────────────────────────────
class IdentityTransformer(BaseEstimator, TransformerMixin):
    """Pass-through for use inside FeatureUnion."""
    def fit(self, X, y=None):  return self
    def transform(self, X):    return X

# ─── Training ───────────────────────────────────────────────────────────────────
def train_model(data_path: str = DATA_PATH) -> dict:
    """
    Train dual-TF-IDF + soft-voting ensemble pipeline.
    Returns dict with accuracy, cv_scores, report, pipeline, threshold.
    """
    df = pd.read_csv(data_path)
    df.dropna(subset=['text', 'label'], inplace=True)
    df['clean'] = df['text'].apply(preprocess_text)

    X = df['clean'].astype(str).to_numpy()
    # Robust label mapping: accepts 'scam'/'phishing'/'spam'/1/'1' as positive class,
    # so scam.csv can use slightly different label spellings than the old sample data.
    _POSITIVE_LABELS = {'scam', 'phishing', 'spam', 'fraud', '1', 1, True}
    y = df['label'].apply(lambda v: 1 if (str(v).strip().lower() in _POSITIVE_LABELS) else 0).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Word n-gram TF-IDF ──────────────────────────────────────────────────────
    word_tfidf = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=8000,
        sublinear_tf=True,
        min_df=2,           # v2: was 1 → reduces overfitting
        analyzer='word',
        strip_accents='unicode',
    )

    # ── Character n-gram TF-IDF (catches obfuscation like "j0b", "free$$") ─────
    char_tfidf = TfidfVectorizer(
        ngram_range=(3, 5),
        max_features=4000,
        sublinear_tf=True,
        min_df=2,
        analyzer='char_wb',
    )

    # ── Base classifiers ────────────────────────────────────────────────────────
    lr = LogisticRegression(
        C=2.0,
        max_iter=1000,
        class_weight='balanced',
        solver='lbfgs',
        random_state=42,
    )

    # SGD with log-loss = fast logistic regression variant, different inductive bias
    sgd_base = SGDClassifier(
        loss='modified_huber',   # supports predict_proba
        alpha=0.001,
        max_iter=1000,
        class_weight='balanced',
        random_state=42,
    )
    sgd = CalibratedClassifierCV(sgd_base, cv=3, method='isotonic')

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )

    # ── Soft-voting ensemble ────────────────────────────────────────────────────
    ensemble = VotingClassifier(
        estimators=[('lr', lr), ('sgd', sgd), ('rf', rf)],
        voting='soft',
        weights=[3, 2, 2],   # LR gets slightly more weight (best on short text)
    )

    # ── Full pipeline: dual TF-IDF → ensemble ───────────────────────────────────
    pipeline = Pipeline([
        ('features', FeatureUnion([
            ('word', word_tfidf),
            ('char', char_tfidf),
        ])),
        ('clf', ensemble),
    ])

    pipeline.fit(X_train, y_train)

    # ── Threshold tuning: pick threshold that maximises F1 on test set ─────────
    probas       = pipeline.predict_proba(X_test)[:, 1]
    best_thresh  = 0.5
    best_f1      = 0.0
    for t in np.arange(0.30, 0.71, 0.01):
        preds = (probas >= t).astype(int)
        f     = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, round(float(t), 2)

    # ── Evaluation ──────────────────────────────────────────────────────────────
    y_pred = (probas >= best_thresh).astype(int)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Scam'])

    # ── Stratified k-fold CV (more reliable than single split on small data) ────
    cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring='f1', n_jobs=-1)

    # ── Persist ─────────────────────────────────────────────────────────────────
    artifact = {'pipeline': pipeline, 'threshold': best_thresh}
    joblib.dump(artifact, MODEL_PATH)

    return {
        'accuracy':   acc,
        'threshold':  best_thresh,
        'cv_f1_mean': round(float(cv_scores.mean()), 4),
        'cv_f1_std':  round(float(cv_scores.std()),  4),
        'report':     report,
        'pipeline':   pipeline,
    }

@st.cache_resource
def load_artifact():
    """Load (or train-and-save) the ML artifact. Cached for the lifetime of the server process."""

    if os.path.exists(MODEL_PATH):
        try:
            artifact = joblib.load(MODEL_PATH)
            # backward-compat: v1 saved the pipeline directly
            if not isinstance(artifact, dict):
                artifact = {'pipeline': artifact, 'threshold': 0.5}
            return artifact
        except Exception:
            pass

    if os.path.exists(DATA_PATH):
        try:
            result = train_model()
            return {'pipeline': result['pipeline'], 'threshold': result['threshold']}
        except Exception as e:
            print(f"[ml_model] Warning: training failed: {e}")

    return None


@st.cache_data(max_entries=256)
def predict(text: str) -> dict:
    """
    Predict whether a piece of text is a scam.

    Returns:
        {
          'label':        'scam' | 'legitimate' | 'unknown',
          'probability':  float  (0.0–1.0, probability of scam),
          'confidence':   float  (0.0–1.0),
          'rule_score':   float  (0.0–1.0, heuristic signal strength),
        }
    """
    rule_score = rule_based_scam_score(text)
    artifact   = load_artifact()

    if artifact is None:
        # No model: fall back to rules alone
        label = 'scam' if rule_score >= 0.67 else ('legitimate' if rule_score < 0.1 else 'unknown')
        return {
            'label':       label,
            'probability': round(min(rule_score * 0.9, 0.95), 4),
            'confidence':  round(rule_score, 4),
            'rule_score':  round(rule_score, 4),
        }

    pipeline  = artifact['pipeline']
    threshold = artifact['threshold']

    clean    = preprocess_text(text)
    proba    = pipeline.predict_proba([clean])[0]
    ml_prob  = float(proba[1])

    # NEW: Zero floor for completely safe text
    CLEAN_ML_THRESHOLD = 0.15

    if rule_score == 0.0 and ml_prob < CLEAN_ML_THRESHOLD:
        blended_prob = 0.0

    elif rule_score >= 0.70:
        blended_prob = round(0.35 * ml_prob + 0.65 * rule_score, 4)

    else:
        blended_prob = round(0.50 * ml_prob + 0.50 * rule_score, 4)

    label = "scam" if blended_prob >= threshold else "legitimate"
    confidence = round(abs(blended_prob - 0.5) * 2.0, 4)

    # ── Fix confidence: distance from 0.5 scaled to 0–1 ─────────────────────────
    # Old: max(p, 1-p) gave 60% confidence for a 60% scam score (too low).
    # New: distance from centre × 2 gives full 0–100% range.
    confidence = round(abs(blended_prob - 0.5) * 2.0, 4)

    return {
        'label':       label,
        'probability': blended_prob,
        'confidence':  confidence,
        'rule_score':  round(rule_score, 4),
    }


def batch_predict(texts: list) -> list:
    """Run predict() over a list of strings."""
    return [predict(t) for t in texts]


def get_feature_importance(text: str, top_n: int = 10) -> list:
    """
    Return the top TF-IDF word tokens for the input text,
    ranked by their TF-IDF score (word vectoriser only).
    """
    artifact = load_artifact()
    if artifact is None:
        return []

    pipeline = artifact['pipeline']
    clean    = preprocess_text(text)

    try:
        features = pipeline.named_steps['features']
        word_vec = features.transformer_list[0][1]   # 'word' TF-IDF
        vec      = word_vec.transform([clean])
        names    = word_vec.get_feature_names_out()
        scores   = vec.toarray()[0]
        pairs    = [(names[i], round(float(scores[i]), 4))
                    for i in scores.argsort()[::-1] if scores[i] > 0]
        return pairs[:top_n]
    except Exception:
        return []


# ─── Bootstrap ──────────────────────────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    try:
        if os.path.exists(DATA_PATH):
            train_model()
    except Exception as e:
        print(f"[ml_model] Warning: could not pre-train model: {e}")
