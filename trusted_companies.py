# trusted_companies.py — CyberLens AI
#
# Curated allowlist of verified official domains for well-known
# organisations, plus logic to:
#
#   1. Recognise a genuine visit/reference to one of them, so the rest of
#      the pipeline can stop penalising completely normal brand behaviour
#      (login pages, "verify your account" copy, security pages, etc.)
#      that generic lexical/keyword models mistake for phishing.
#
#   2. Flag lookalike / impersonation domains that use a well-known brand
#      name WITHOUT being the official domain — these should be treated
#      as MORE suspicious, not less.
#
# Design intent: this list is intentionally small and hand-verified rather
# than auto-generated. A wrong or overly broad entry here creates a blind
# spot attackers can exploit, so only add domains you can verify
# independently (company's own "official site" statement, WHOIS, etc.).
# This module answers a narrow question and is meant to sit ALONGSIDE the
# existing ML/keyword risk scoring, not replace it.

from typing import Optional

from utils import _domain_core

# brand key -> set of *official*, verified registrable domains.
# Subdomains of these (e.g. accounts.google.com, aws.amazon.com) are
# automatically covered by match_trusted_domain()'s suffix check below.
#
# NOTE ON MATCHING: entries here are literal, hand-verified registrable
# domains (not TLD patterns). match_trusted_domain() only accepts an exact
# match or a subdomain of one of these exact strings, so a country-code
# entry like 'amazon.in' is a completely separate, equally "official"
# domain from 'amazon.com' — one is never substituted for the other. This
# same exact/suffix check is also what makes multi-part suffixes
# (.co.in, .gov.in, .com.au, ...) work correctly without a public-suffix
# -list dependency: we're checking "is this a subdomain of a known-good
# domain", not trying to compute an arbitrary domain's eTLD+1.
TRUSTED_COMPANIES = {
    # ── Search engines ───────────────────────────────────────────────
    'google':     {'google.com', 'google.co.in', 'google.co.uk', 'gmail.com',
                   'youtube.com', 'goog.co', 'gstatic.com'},
    'bing':       {'bing.com'},                                        # NEW
    'duckduckgo': {'duckduckgo.com'},                                  # NEW
    'yahoo':      {'yahoo.com', 'yahoo.co.in'},                        # NEW

    # ── E-commerce ────────────────────────────────────────────────────
    'amazon':     {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in',
                   'amazon.ca', 'amazon.co.jp', 'a2z.com'},
    'flipkart':   {'flipkart.com'},                                    # NEW
    'myntra':     {'myntra.com'},                                      # NEW
    'meesho':     {'meesho.com'},                                      # NEW
    'ajio':       {'ajio.com'},                                        # NEW
    'snapdeal':   {'snapdeal.com'},                                    # NEW
    'ebay':       {'ebay.com', 'ebay.in'},                             # NEW
    'walmart':    {'walmart.com'},                                     # NEW
    'alibaba':    {'alibaba.com', 'aliexpress.com'},                   # NEW
    'shopify':    {'shopify.com'},                                     # NEW

    # ── Banking & finance (India + international) ───────────────────
    'sbi':        {'onlinesbi.sbi', 'sbi.co.in'},                      # NEW
    'hdfcbank':   {'hdfcbank.com'},                                    # NEW
    'icicibank':  {'icicibank.com'},                                   # NEW
    'axisbank':   {'axisbank.com'},                                    # NEW
    'kotak':      {'kotak.com'},                                       # NEW
    'rbi':        {'rbi.org.in'},                                      # NEW
    'chase':      {'chase.com'},                                       # NEW
    'wellsfargo': {'wellsfargo.com'},                                  # NEW
    'citibank':   {'citibank.com', 'citi.com'},                        # NEW
    'hsbc':       {'hsbc.com', 'hsbc.co.in'},                          # NEW
    'paypal':     {'paypal.com'},
    'visa':       {'visa.com'},                                        # NEW
    'mastercard': {'mastercard.com'},                                  # NEW

    # ── Payment services (India-heavy) ────────────────────────────────
    'paytm':      {'paytm.com'},                                       # NEW
    'phonepe':    {'phonepe.com'},                                     # NEW
    'razorpay':   {'razorpay.com'},                                    # NEW
    'stripe':     {'stripe.com'},                                      # NEW

    # ── Government (India) ─────────────────────────────────────────────
    'incometax':  {'incometax.gov.in'},                                # NEW
    'uidai':      {'uidai.gov.in'},                                    # NEW
    'digilocker': {'digilocker.gov.in'},                               # NEW
    'india_gov':  {'india.gov.in'},                                    # NEW
    'cybercrime': {'cybercrime.gov.in'},                               # NEW
    'passportindia': {'passportindia.gov.in'},                         # NEW

    # ── Education / universities ─────────────────────────────────────
    'iit':        {'iitb.ac.in', 'iitd.ac.in', 'iitm.ac.in'},          # NEW
    'ugc':        {'ugc.ac.in'},                                       # NEW
    'coursera':   {'coursera.org'},                                    # NEW
    'udemy':      {'udemy.com'},                                       # NEW
    'edx':        {'edx.org'},                                         # NEW

    # ── Social media ──────────────────────────────────────────────────
    'meta':       {'meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com'},
    'twitter':    {'twitter.com', 'x.com'},                            # NEW
    'linkedin':   {'linkedin.com'},
    'reddit':     {'reddit.com'},                                      # NEW
    'pinterest':  {'pinterest.com'},                                   # NEW
    'snapchat':   {'snapchat.com'},                                    # NEW
    'tiktok':     {'tiktok.com'},                                      # NEW

    # ── Email providers ────────────────────────────────────────────────
    'microsoft':  {'microsoft.com', 'live.com', 'outlook.com', 'office.com',
                   'microsoftonline.com', 'msn.com', 'azure.com', 'msft.net'},
    'zoho':       {'zoho.com', 'zoho.in'},                             # NEW
    'protonmail': {'proton.me', 'protonmail.com'},                     # NEW
    'rediffmail': {'rediffmail.com'},                                  # NEW

    # ── Cloud / developer platforms ──────────────────────────────────
    'aws':        {'aws.amazon.com', 'amazonaws.com'},                 # NEW
    'github':     {'github.com'},                                      # NEW
    'gitlab':     {'gitlab.com'},                                      # NEW
    'digitalocean': {'digitalocean.com'},                              # NEW
    'cloudflare': {'cloudflare.com'},                                  # NEW
    'heroku':     {'heroku.com'},                                      # NEW

    # ── Job / recruitment ──────────────────────────────────────────────
    'naukri':     {'naukri.com'},                                      # NEW
    'indeed':     {'indeed.com'},                                      # NEW
    'glassdoor':  {'glassdoor.com'},                                   # NEW
    'shine':      {'shine.com'},                                       # NEW
    'internshala':{'internshala.com'},                                 # NEW

    # ── Technology companies ─────────────────────────────────────────
    'openai':     {'openai.com', 'chatgpt.com'},
    'wikipedia':  {'wikipedia.org', 'wikimedia.org', 'wiktionary.org'},
    'apple':      {'apple.com', 'icloud.com'},
    'netflix':    {'netflix.com'},
    'anthropic':  {'anthropic.com', 'claude.ai', 'claude.com'},
    'adobe':      {'adobe.com'},                                       # NEW
    'oracle':     {'oracle.com'},                                      # NEW
    'ibm':        {'ibm.com'},                                         # NEW
    'samsung':    {'samsung.com'},                                     # NEW
    'infosys':    {'infosys.com'},                                     # NEW
    'wipro':      {'wipro.com'},                                       # NEW
    'tcs':        {'tcs.com'},                                         # NEW
    'accenture':  {'accenture.com'},                                   # NEW

    # ── Productivity tools ────────────────────────────────────────────
    'zoom':       {'zoom.us'},                                         # NEW
    'slack':      {'slack.com'},                                       # NEW
    'notion':     {'notion.so'},                                       # NEW
    'dropbox':    {'dropbox.com'},                                     # NEW
    'trello':     {'trello.com'},                                      # NEW
    'canva':      {'canva.com'},                                       # NEW

    # ── News & media ──────────────────────────────────────────────────
    'timesofindia': {'timesofindia.indiatimes.com'},                   # NEW
    'thehindu':   {'thehindu.com'},                                    # NEW
    'ndtv':       {'ndtv.com'},                                        # NEW
    'bbc':        {'bbc.com', 'bbc.co.uk'},                            # NEW
    'reuters':    {'reuters.com'},                                     # NEW

    # ── Travel ────────────────────────────────────────────────────────
    'makemytrip': {'makemytrip.com'},                                  # NEW
    'irctc':      {'irctc.co.in'},                                     # NEW
    'goibibo':    {'goibibo.com'},                                     # NEW
    'booking':    {'booking.com'},                                     # NEW
    'airbnb':     {'airbnb.com'},                                      # NEW

    # ── Food delivery ─────────────────────────────────────────────────
    'zomato':     {'zomato.com'},                                      # NEW
    'swiggy':     {'swiggy.com'},                                      # NEW
    'ubereats':   {'ubereats.com'},                                    # NEW
    'dominos':    {'dominos.co.in'},                                   # NEW

    # ── Streaming services ────────────────────────────────────────────
    'hotstar':    {'hotstar.com'},                                     # NEW
    'primevideo': {'primevideo.com'},                                  # NEW
    'spotify':    {'spotify.com'},                                     # NEW
}

# brand token (as it might appear inside a domain string) -> canonical key.
# Used only to spot "brand name present but domain isn't the real one".
# Kept intentionally specific to brand-identifying tokens so this doesn't
# fire on ordinary generic words (no 'mail', 'pay', 'bank', etc. alone).
_BRAND_TOKENS = {
    'amazon': 'amazon', 'google': 'google', 'microsoft': 'microsoft',
    'openai': 'openai', 'chatgpt': 'openai', 'wikipedia': 'wikipedia',
    'apple': 'apple', 'facebook': 'meta', 'instagram': 'meta',
    'whatsapp': 'meta', 'linkedin': 'linkedin', 'paypal': 'paypal',
    'netflix': 'netflix', 'anthropic': 'anthropic', 'claude': 'anthropic',
    'flipkart': 'flipkart', 'myntra': 'myntra', 'meesho': 'meesho',        # NEW
    'ajio': 'ajio', 'snapdeal': 'snapdeal', 'ebay': 'ebay',                # NEW
    'walmart': 'walmart', 'alibaba': 'alibaba', 'aliexpress': 'alibaba',   # NEW
    'hdfcbank': 'hdfcbank', 'icicibank': 'icicibank',                     # NEW
    'axisbank': 'axisbank', 'kotak': 'kotak',                             # NEW
    'wellsfargo': 'wellsfargo', 'citibank': 'citibank', 'hsbc': 'hsbc',   # NEW
    'paytm': 'paytm', 'phonepe': 'phonepe',                                # NEW
    'razorpay': 'razorpay', 'stripe': 'stripe',                           # NEW
    'uidai': 'uidai', 'digilocker': 'digilocker',                         # NEW
    'coursera': 'coursera', 'udemy': 'udemy',                             # NEW
    'twitter': 'twitter', 'reddit': 'reddit', 'pinterest': 'pinterest',   # NEW
    'snapchat': 'snapchat', 'tiktok': 'tiktok', 'zoho': 'zoho',           # NEW
    'protonmail': 'protonmail', 'rediffmail': 'rediffmail',               # NEW
    'github': 'github', 'gitlab': 'gitlab', 'cloudflare': 'cloudflare',   # NEW
    'digitalocean': 'digitalocean', 'heroku': 'heroku',                   # NEW
    'naukri': 'naukri', 'indeed': 'indeed', 'glassdoor': 'glassdoor',     # NEW
    'shine': 'shine', 'internshala': 'internshala',                       # NEW
    'adobe': 'adobe', 'oracle': 'oracle', 'samsung': 'samsung',           # NEW
    'infosys': 'infosys', 'wipro': 'wipro', 'accenture': 'accenture',     # NEW
    'zoom': 'zoom', 'slack': 'slack', 'notion': 'notion',                 # NEW
    'dropbox': 'dropbox', 'trello': 'trello', 'canva': 'canva',           # NEW
    'makemytrip': 'makemytrip', 'irctc': 'irctc', 'goibibo': 'goibibo',   # NEW
    'booking': 'booking', 'airbnb': 'airbnb',                             # NEW
    'zomato': 'zomato', 'swiggy': 'swiggy', 'dominos': 'dominos',         # NEW
    'hotstar': 'hotstar', 'spotify': 'spotify',                          # NEW
}


def _normalise(domain: str) -> str:
    d = (domain or '').lower().strip()
    if d.startswith('www.'):
        d = d[4:]
    return d


def match_trusted_domain(domain: str) -> Optional[str]:
    """
    Return the canonical brand key if `domain` IS (or is a subdomain of)
    an official domain for a known brand, else None.

    Subdomains are allowed (accounts.google.com -> 'google') but this is a
    strict suffix match on the *registrable* domain, so it correctly
    REJECTS lookalikes such as 'google.com.verify-account.net' (the
    official-looking prefix doesn't make 'verify-account.net' safe) and
    'amazon-security.com' (not a subdomain of amazon.com at all).
    """
    d = _normalise(domain)
    if not d:
        return None
    for brand, official_domains in TRUSTED_COMPANIES.items():
        for off in official_domains:
            if d == off or d.endswith('.' + off):
                return brand
    return None


def detect_brand_impersonation(domain: str) -> Optional[str]:
    """
    Return the brand being impersonated if `domain` contains a well-known
    brand token but is NOT that brand's official domain.

        'amazon-security-verify.com'  -> 'amazon'   (impersonation)
        'micros0ft-support.net'       -> None       (token doesn't match;
                                                       typosquat detection
                                                       for character-level
                                                       tricks is handled
                                                       separately by the
                                                       existing typosquat
                                                       heuristic in utils)
        'amazon.com'                  -> None       (it's the real thing)
    """
    d = _normalise(domain)
    if not d or match_trusted_domain(d):
        return None
    core = _domain_core(d) if d else ''
    haystack = f"{d} {core}"
    for token, brand in _BRAND_TOKENS.items():
        if token in haystack:
            return brand
    return None


def company_name_matches_brand(company_name: str) -> Optional[str]:
    """
    Fuzzy-map free-text company name (as typed into the Company Verifier
    form) to one of our canonical brand keys, so the caller can cross-check
    'the name the user typed' against 'the domain they gave us'.
    """
    name = (company_name or '').lower()
    if not name:
        return None
    for token, brand in _BRAND_TOKENS.items():
        if token in name:
            return brand
    return None
