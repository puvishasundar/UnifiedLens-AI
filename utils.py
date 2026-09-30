# utils.py — CyberLens AI
# Shared helpers: keyword lists, heuristics, risk scoring, URL tools

import re
import math
from collections import Counter
from urllib.parse import urlparse

def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — used to flag randomly-generated strings
    (e.g. auto-generated phishing subdomains, or random-looking email local
    parts). Shared by analyse_url() and the email analysis pipeline so both
    use identical randomness scoring instead of duplicating the formula."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

# ─── Suspicious Keyword Lexicon ─────────────────────────────────────────────────
NEGATION_WORDS = {
    "no", "not", "never", "without", "don't", "doesn't", "isn't", "aren't", "won't",
    "free", "no registration fee", "no processing fee", "no joining fee",
    "no payment required", "we never ask for otp", "official website",
    "official email", "verified company", "free of cost", "no advance payment",
    "no security deposit", "no hidden charges", "never ask for otp",
    "never share your otp", "official company website"
}

SCAM_KEYWORDS = {
    # Urgency / pressure
    'urgent': 3, 'immediate': 3, 'immediately': 3, 'limited offer': 3,
    'act now': 3, 'expiring': 2, 'deadline': 2, 'last chance': 3,
    'hurry': 2, 'asap': 2, 'today only': 3,
    # Money / payment
    'payment required': 4, 'pay fee': 4, 'registration fee': 4,
    'processing fee': 4, 'security deposit': 4, 'wire transfer': 4,
    'bitcoin': 3, 'crypto payment': 4, 'zelle': 3, 'paypal': 2,
    'advance payment': 4, 'deposit': 2, 'invest': 1, 'guaranteed income': 4,
    'earn guaranteed': 4, 'guaranteed': 3, 'guaranteed placement': 4,
    # Unrealistic promises
    'earn $5000': 4, 'earn $3000': 4, 'earn $2000': 3,
    'earn rs 50000': 4, 'earn rs 30000': 3, 'no experience': 3,
    'no interview': 4, 'direct selection': 4, 'no skills': 3,
    'work from home': 1, 'get rich': 4, 'easy money': 4,
    # Credential harvesting
    'send bank details': 5, 'provide ssn': 5, 'share otp': 5,
    'bank account details': 4, 'personal documents': 3,
    'mother maiden name': 5, 'share documents': 3,
    # Phishing
    'click here': 2, 'verify your account': 3, 'confirm your account': 3,
    'your account is': 2, 'login to verify': 3, 'enter your password': 4,
    'reset your password': 2, 'suspicious activity': 1,
    # OTP / KYC / Indian cyber fraud patterns
    'otp': 3, 'one time password': 4, 'share your otp': 5,
    'kyc update': 4, 'kyc verification': 4, 'complete your kyc': 4,
    'kyc expired': 4, 'aadhaar': 1, 'pan card': 1,
    'send aadhaar': 5, 'send pan': 5,
    # Lottery / prize scams
    'you have won': 4, 'you won': 3, 'lucky winner': 4,
    'claim your prize': 4, 'lottery': 3, 'sweepstakes': 3,
    'congratulations you': 3, 'selected winner': 4,
    # Job / placement scams
    'placement fee': 5, 'joining fee': 5, 'training fee': 4,
    'offer letter fee': 5, 'hr team': 1, 'salary upto': 2,
    'ctc upto': 2, 'package upto': 2, 'dream job': 2,
    # Tech support / impersonation scams
    'your computer': 2, 'virus detected': 4, 'call microsoft': 4,
    'call our toll free': 3, 'your device is': 3,
    'technical support': 2, 'refund processing': 3,
    # Generic pressure / social engineering
    'do not share': 2, 'confidential': 1, 'act immediately': 4,
    'your account will be': 3, 'account suspended': 4,
    'account blocked': 4, 'reactivate': 3,
    # Courier / Customs / Delivery scams
    'customs fee': 5, 'customs charge': 5, 'customs duty': 5,
    'clearance charges': 5, 'clearance fee': 5, 'customs clearance': 5,
    'package held': 5, 'parcel held': 5, 'parcel on hold': 5,
    'package on hold': 5, 'shipment held': 5, 'shipment on hold': 5,
    'delivery failed': 4, 'delivery attempt failed': 5,
    'delivery on hold': 4, 'unable to deliver': 4,
    'package destruction': 5, 'parcel destruction': 5,
    'package will be destroyed': 5, 'shipment destroyed': 5,
    'pay to release': 5, 'pay to collect': 5, 'pay to receive': 5,
    'release fee': 5, 'release charges': 5,
    'refundable fee': 5, 'refundable customs': 5, 'refundable deposit': 4,
    'mandatory fee': 5, 'mandatory customs': 5, 'mandatory charge': 5,
    'courier scam': 5, 'courier fee': 4, 'courier charges': 4,
    'international parcel': 3, 'international package': 3,
    'dhl': 1, 'fedex': 1, 'bluedart': 1, 'ekart': 1, 'india post': 1,
    'track your parcel': 3, 'track your package': 3, 'track your shipment': 3,
    're-delivery': 3, 'reschedule delivery': 3,
    'within 15 minutes': 5, 'within 30 minutes': 5, 'within 10 minutes': 5,
    'within 24 hours': 4, 'within 48 hours': 3,
    'cancel delivery': 5, 'delivery cancelled': 5, 'delivery will be cancelled': 5,
    'return to sender': 3, 'returned to origin': 4,
    'pending customs': 5, 'pending clearance': 5, 'awaiting customs': 4,
    'storage charges': 4, 'warehouse fee': 4, 'holding fee': 4,
    # Banking / financial impersonation scams
    'your card is blocked': 5, 'card blocked': 4, 'debit card blocked': 5,
    'credit card blocked': 5, 'card suspended': 4,
    'net banking blocked': 5, 'net banking suspended': 4,
    'upi blocked': 5, 'upi suspended': 4, 'upi limit': 3,
    'bank account frozen': 5, 'account frozen': 5, 'account deactivated': 5,
    'sbi': 1, 'hdfc': 1, 'icici': 1, 'axis bank': 1, 'kotak': 1,
    'rbi': 3, 'rbi notice': 5, 'reserve bank': 3,
    'your loan is approved': 4, 'pre-approved loan': 4, 'instant loan': 4,
    'loan approved': 4, 'loan offer': 3, 'no collateral': 4,
    'low interest loan': 4, 'personal loan approved': 4,
    'credit score': 1, 'cibil score': 2, 'improve cibil': 4,
    'cashback offer': 3, 'reward points expiring': 4, 'redeem points': 3,
    # Investment / trading / crypto scams
    'guaranteed returns': 5, 'guaranteed profit': 5, 'guaranteed 10x': 5,
    'double your money': 5, 'triple your money': 5,
    'risk free investment': 5, 'risk-free investment': 5,
    'high returns': 4, 'high profit': 4, 'daily returns': 4,
    'weekly returns': 4, 'monthly returns': 4,
    'stock tip': 4, 'insider tip': 5, 'sure shot': 5,
    'multibagger': 4, '100x returns': 5, '10x returns': 5,
    'crypto trading': 3, 'crypto investment': 3, 'forex trading': 3,
    'trading signal': 4, 'trading group': 3, 'trading telegram': 4,
    'nft investment': 3, 'defi investment': 3, 'passive income': 3,
    'referral bonus': 3, 'refer and earn': 3, 'join our group': 3,
    'whatsapp group': 1, 'telegram group': 1,
    'sebi registered': 4, 'rbi approved': 5, 'government approved scheme': 5,
    # Romance / social engineering scams
    'gift card': 4, 'itunes gift card': 5, 'google play gift card': 5,
    'amazon gift card': 4, 'steam gift card': 4,
    'send gift card': 5, 'buy gift card': 4, 'gift card code': 5,
    'i love you': 1, 'lonely': 1, 'dating': 1,
    'military officer': 4, 'deployed overseas': 4, 'stranded abroad': 4,
    'emergency money': 4, 'hospital emergency': 4, 'stuck abroad': 4,
    'send money urgently': 5, 'money transfer urgently': 5,
    'western union': 4, 'moneygram': 4, 'hawala': 4,
    # Government / authority impersonation scams
    'income tax notice': 5, 'income tax department': 4, 'it department': 3,
    'tax refund': 4, 'tds refund': 5, 'gst refund': 4,
    'cybercrime department': 5, 'cyber crime notice': 5,
    'police notice': 5, 'cbi notice': 5, 'enforcement directorate': 5,
    'arrest warrant': 5, 'fir filed': 5, 'legal action': 4,
    'court notice': 5, 'summons': 4, 'legal notice': 4,
    'aadhaar blocked': 5, 'aadhaar suspended': 5, 'aadhaar linked': 3,
    'pan blocked': 5, 'pan suspended': 5, 'pan deactivated': 5,
    'trai': 3, 'trai notice': 5, 'mobile number blocked': 5,
    'sim blocked': 5, 'sim suspended': 4,
    'epfo': 3, 'pf withdrawal': 3, 'pf account': 2,
    'pm yojana': 3, 'government scheme': 2, 'subsidy approved': 4,
    'digital arrest': 5,
    # Extended urgency / time-pressure patterns
    'last opportunity': 4, 'final notice': 4, 'final warning': 5,
    'do not ignore': 4, 'respond immediately': 4, 'reply immediately': 4,
    'do not delay': 4, 'time sensitive': 3, 'time-sensitive': 3,
    'expires in': 3, 'valid for': 2, 'offer expires': 3,
    'non-payment': 5, 'failure to pay': 5, 'if not paid': 5,
    'penalty': 2, 'fine': 1, 'legal consequences': 5,
    # Social media / OTT / subscription scams
    'your netflix': 3, 'netflix account': 3, 'netflix suspended': 4,
    'amazon prime': 2, 'prime account': 2, 'hotstar': 2,
    'instagram account': 2, 'facebook account': 2, 'account hacked': 4,
    'your instagram': 3, 'your facebook': 3,
    'free subscription': 4, 'free premium': 4, 'upgrade free': 4,
    # Health / insurance scams
    'insurance claim': 3, 'claim approved': 4, 'claim settlement': 4,
    'policy expired': 4, 'policy lapsed': 4, 'renew immediately': 4,
    'free health checkup': 3, 'free insurance': 4,
    'cashless treatment': 3, 'hospital cashless': 3,
    'covid relief': 4, 'relief fund': 4, 'compensation fund': 4,
    # Additional scam/suspicious keywords
    'verify now': 4, 'click below': 3, 'limited time': 3,
    'claim reward': 4, 'claim prize': 4, 'lottery winner': 5,
    'jackpot': 4, 'selected randomly': 4, 'free iphone': 5,
    'crypto reward': 5, 'bitcoin giveaway': 5,
    'investment opportunity': 3, 'work from home earning': 4,
    'captcha typing job': 5, 'release payment': 5,
    'security alert': 3, 'unauthorized login': 4,
    'bank blocked': 5, 'kyc expired': 5,
    'identity suspension': 5, 'verification failed': 4, 'account disabled': 5,
    'government notice': 4, 'cyber cell': 4, 'national security': 4,
    'confidential investigation': 5, 'passport blocked': 5,
    'court order': 5, 'case id': 4, 'criminal activity detected': 5,
    'suspicious activity detected': 4, 'click to verify': 4,
    'login immediately': 4, 'verify identity': 4, 'update banking details': 5,
    'reward expires today': 5, 'gift voucher': 3, 'international lottery': 5,
    'whatsapp hr': 5, 'telegram manager': 5, 'contact payout officer': 5,
    'activation fee': 5, 'registration charge': 4, 'remote salary': 4,
    'overseas placement': 4, 'free visa': 4, 'free laptop': 4,
    '100% guaranteed': 5, 'risk free investment': 5, 'instant payout': 5,
    'otp sharing': 5, 'remote access': 4, 'screen sharing': 4,
    'download apk': 5, 'install app': 3, 'tinyurl': 3, 'bit.ly': 3,
    'rebrand.ly': 3, 'free recharge': 4, 'casino bonus': 4, 'betting reward': 4,
    'adult verification': 5, 'confirm password': 4, 'wallet unlocked': 4,
    'nft reward': 4, 'airdrop bonus': 4, 'mining income': 4,
    'crypto wallet verification': 5, 'limited seats': 3, 'emergency alert': 4,
    'red notice': 5, 'high priority warning': 4, 'user verification pending': 4,
    'identity mismatch': 5, 'kyc mismatch': 5, 'banking restriction': 5,
    'login expired': 4, 'session timeout': 3, 'reactivate now': 5,
    'social media recovery': 4, 'instagram blue tick': 4,
    'youtube monetization reward': 4, 'copyright strike removal': 4,
    'exclusive access': 3, 'vip membership': 3, 'premium unlocked': 4,
    'earn daily': 4, 'fast cash': 4, 'guaranteed selection': 5,
    'document mismatch': 5, 'suspicious transaction': 5,
    'wire transfer pending': 4, 'wire transfer failed': 4,
    'charity donation request': 4, 'humanitarian fund release': 5,
    'un compensation fund': 5, 'foreign inheritance': 5, 'lucky draw': 4,
    'bonus credited': 3, 'exclusive reward': 3, 'fear': 1, 'panic': 1,
    'last attempt': 5, 'important notice': 3, 'immediate response required': 5,
    'avoid suspension': 4, 'avoid arrest': 5, 'secret reward': 4,
    'special opportunity': 3, 'limited access': 3, 'do not ignore': 4,
    'sensitive information': 3, 'strict action': 4, 'legal escalation': 5,
    'final attempt': 5, 'login-auth': 5, 'secure-update': 5,
    'account-verify': 5, 'wallet-bonus': 5, 'reward-center': 5, 'gift-claim': 5,
    'kyc-update': 4, 'banking-alert': 5, 'security-check': 4, 'identity-confirm': 5,
    # Legal threat / cybercrime impersonation language
    'money laundering': 5, 'money laundering investigation': 5,
    'illegal transaction': 5, 'illegal transactions': 5,
    'illegal international': 5, 'fraudulent transaction': 5,
    'section 66': 5, 'section 66c': 5, 'section 66d': 5,
    'it act': 4, 'information technology act': 4, 'legal complaint': 5,
    'complaint filed': 5, 'complaint initiated': 5, 'case status': 4,
    'case active': 5, 'case registered': 5, 'arrest approval': 5,
    'arrest pending': 5, 'immediate arrest': 5, 'police action': 5,
    'police will': 5, 'avoid police': 5, 'immediate escalation': 5,
    'stop escalation': 5, 'biometric verification': 5,
    'identity verification required': 4, 'account freeze': 5,
    'bank account freeze': 5, 'freeze account': 5, 'passport blacklist': 5,
    'blacklisted': 4, 'blacklist': 4, 'pan card suspension': 5,
    'financial monitoring': 5, 'monitoring enabled': 4, 'fir registration': 5,
    'fir will be': 5, 'fir filed against': 5, 'new delhi': 2,
    'cyber crime investigation': 5, 'national cyber': 5, 'cyber emergency': 5,
    'respond within': 4, 'failure to respond': 5, 'within 20 minutes': 5,
    'within 1 hour': 4,
    # Fake job / overseas employment scam language
    'approved without interview': 5, 'selected without interview': 5,
    'no interview required': 5, 'direct approval': 4, 'overseas job': 4,
    'overseas remote': 4, 'overseas opportunity': 4, 'international hiring': 5,
    'international hiring database': 5, 'employee activation': 5,
    'activate now': 4, 'activate immediately': 5, 'receive offer letter': 4,
    'laptop shipment': 4, 'laptop will be sent': 4, 'contact hr on whatsapp': 5,
    'hr manager whatsapp': 5, 'whatsapp number': 2, 'digital operations': 2,
    'remote selection': 4, 'name will be removed': 5, 'permanently remove': 5,
    'removed from database': 5, 'salary package': 2, 'monthly salary': 1,
    'ctc': 1, 'shortlisted': 2, 'resume shortlisted': 3, 'profile shortlisted': 3,
    'hiring database': 5, 'global hiring': 3, 'activate today': 4,
    'activate your account today': 4, 'overseas salary': 4, 'foreign salary': 4,
    # UPI-specific scam patterns
    'upi pin': 5, 'enter upi pin': 5, 'enter your upi pin': 5,
    'upi pin to receive': 5, 'share upi pin': 5, 'collect request': 4,
    'payment request': 4, 'approve request': 4, 'accept collect request': 5,
    'scan to receive': 5, 'scan qr to receive': 5, 'scan this qr': 4,
    'scan the qr code': 4, 'qr code payment': 3, 'qr to receive money': 5,
    'qr for refund': 5, 'refund qr': 5, 'upi id blocked': 5,
    'upi transaction failed': 4, 'upi deactivated': 5, 'gpay support': 4,
    'phonepe support': 4, 'paytm support': 4, 'bhim upi': 3, 'upi mandate': 4,
    'auto debit mandate': 4, 'money will be credited': 4, 'receive payment scan': 5,
    # QR code scam patterns
    'qr code expired': 4, 'update qr code': 4, 'new qr code': 3,
    'scan and win': 5, 'scan to claim': 5, 'scan to unlock': 4,
    'malicious qr': 3, 'qr code scam': 5,
    # Electricity / utility bill scams
    'electricity bill': 3, 'electricity bill due': 4, 'power bill overdue': 4,
    'electricity disconnected': 5, 'power disconnection': 5,
    'electricity disconnection tonight': 5, 'meter disconnected': 5,
    'pay electricity bill immediately': 5, 'discom': 3, 'eb office': 3,
    'update meter details': 4, 'smart meter update': 4, 'electricity board': 2,
    'bill overdue': 3, 'last date to pay bill': 4, 'gas connection blocked': 4,
    'water bill overdue': 3,
    # Scholarship / education fee scams
    'scholarship approved': 5, 'scholarship selected': 4, 'scholarship offer': 4,
    'scholarship fee': 5, 'processing fee for scholarship': 5,
    'scholarship amount credited': 4, 'education loan approved': 4,
    'fee waiver': 3, 'admission confirmed': 3, 'seat confirmed fee': 4,
    'management quota': 3, 'nsp scholarship': 3, 'national scholarship portal': 2,
    'university grant': 3, 'grant disbursement': 4, 'scholarship disbursement': 4,
    # Online shopping / e-commerce scams
    'order cancelled refund': 4, 'order refund pending': 4,
    'cash on delivery fraud': 4, 'fake order confirmation': 4,
    'order not delivered': 3, 'wrong product refund': 3, 'return pickup fee': 4,
    'exchange fee': 4, 'flipkart order': 2, 'amazon order': 2, 'myntra order': 2,
    'meesho order': 2, 'huge discount today only': 4, 'flash sale': 2,
    'mega sale 90% off': 4, 'fake online store': 5, 'suspicious checkout page': 4,
    'pay to confirm order': 5, 'advance payment for delivery': 5,
    # AI voice / deepfake scams
    'ai voice clone': 5, 'voice cloning': 5, 'cloned voice': 5,
    'deepfake video': 5, 'deepfake call': 5, 'ai generated video': 4,
    'fake video call': 5, 'video call from unknown officer': 5,
    'this is your son': 4, 'this is your daughter': 4,
    'emergency call from relative': 4, 'kidnapped': 4, 'accident emergency money': 5,
    'voice message urgent': 4, 'synthetic voice': 4, 'ai impersonation': 5,
    # Gaming and reward app scams
    'gaming reward': 4, 'game winning amount': 4, 'withdraw winnings': 4,
    'rummy bonus': 4, 'ludo cash bonus': 4, 'betting app bonus': 4,
    'fantasy app winnings': 4, 'app download bonus': 3, 'refer app earn cash': 4,
    'task completion reward': 4, 'survey reward': 3, 'click and earn': 4,
    'watch ad and earn': 3, 'spin and win': 4, 'daily check in reward': 3,
    'redeem cash reward': 4,
    # Fake customer care / helpline scams
    'customer care number': 3, 'toll free helpline': 3, 'fake customer care': 5,
    'call this number for refund': 5, 'call this number to resolve': 4,
    'complaint number': 3, 'escalation number': 3, 'talk to our agent': 3,
    'connect with agent': 3,
    # Referral / MLM scams
    'mlm scheme': 4, 'multi level marketing': 3, 'network marketing income': 4,
    'refer 5 friends': 4, 'invite and earn': 4, 'downline income': 4,
    'binary income plan': 5, 'join with small investment': 4,
}

SAFE_KEYWORDS = {
    'meeting', 'schedule', 'rescheduled', 'project', 'assignment', 'submission',
    'report', 'presentation', 'seminar', 'internship', 'interview',
    'google meet', 'zoom', 'official portal', 'documentation', 'receipt',
    'invoice', 'attached', 'reference', 'confirmation', 'registration',
    'support ticket', 'help desk', 'customer care', 'feedback',
    'guidelines', 'instructions', 'syllabus', 'department', 'university',
    'classroom', 'faculty', 'staff', 'candidate', 'resume', 'application',
    'review process', 'verification completed', 'payment received',
    'tracking number', 'shipment update', 'delivery update',
    'thank you', 'please review', 'attached file', 'agenda', 'discussion',
    'conference', 'deadline reminder', 'orientation', 'offer discussion',
    'training session', 'account statement', 'billing cycle',
    'subscription renewal', 'maintenance notice', 'service update',
    'employee id', 'attendance', 'timesheet', 'workspace', 'portal access',
    'secure login', 'multi-factor authentication', 'official communication',
    'student portal', 'exam hall', 'library', 'lab session',
    'internal marks', 'event registration', 'hackathon', 'technical symposium',
    'job application', 'career portal', 'placement cell', 'team meeting',
    'mentor', 'coordinator', 'faculty advisor', 'hr department',
    'salary credited', 'bank statement', 'otp for login', 'account secured',
    'privacy policy', 'community guidelines', 'customer satisfaction',
    'invoice copy', 'shipment tracking', 'courier update',
    'successful transaction', 'payment confirmation', 'document uploaded',
    'application accepted', 'technical support', 'software update',
    'version release', 'maintenance scheduled', 'ticket resolved',
    'support request', 'video call', 'call scheduled', 'appointment confirmed',
    'delivery expected', 'system generated mail', 'authentication successful',
    'welcome aboard', 'employee onboarding', 'coding round',
    'assessment test', 'interview slot', 'review pending', 'workshop',
    'certificate', 'congratulations on selection', 'campus drive',
    'team collaboration', 'google', 'microsoft', 'amazon', 'apple',
    'official app', 'verified account', 'customer support team',
    'order confirmation', 'delivery partner', 'terms of service',
    'privacy notice', 'unsubscribe', 'newsletter'
}

SAFE_PHRASES = [
    "no registration fee", "no processing fee", "no joining fee",
    "no payment required", "no advance payment", "no security deposit",
    "no hidden charges", "we never ask for otp", "never ask for otp",
    "never share your otp", "official website", "official email",
    "official company website", "free of cost"
]

PHISHING_URL_PATTERNS = [
    r'login', r'signin', r'verify', r'secure', r'account', r'update',
    r'confirm', r'banking', r'support', r'help', r'alert', r'notification',
    r'reset', r'lucky', r'money', r'win', r'share', r'invitation', r'bonus',
    r'gift', r'prize', r'reward', r'claim', r'pay', r'crypto', r'wallet',
    r'refund', r'card', r'loan', r'free', r'earn', r'cash', r'deposit',
    r'giving',
]
# NOTE: bare brand names (google, amazon, microsoft, apple, paypal, etc.)
# are intentionally NOT included here — matching them against the raw URL
# string flags the legitimate brand domains themselves (e.g. "google.com"
# contains "google"). Brand *impersonation* is already handled below via
# `typosquat_risk` (brand name present but domain isn't the real one) and
# `is_known_legit` (exact/subdomain match against LEGIT_DOMAINS), which are
# far more accurate signals than a plain substring match.

LEGIT_DOMAINS = {
    'google.com', 'microsoft.com', 'amazon.com', 'linkedin.com',
    'apple.com', 'facebook.com', 'twitter.com', 'github.com',
    'paypal.com', 'naukri.com', 'indeed.com', 'glassdoor.com',
    'infosys.com', 'wipro.com', 'tcs.com', 'hcltech.com',
    'accenture.com', 'ibm.com', 'deloitte.com', 'amazon.in',
    'flipkart.com', 'zoho.com', 'freshworks.com'
}

SCAM_TLD_RISK = {
    '.xyz': 4, '.top': 4, '.click': 4, '.loan': 4, '.work': 3,
    '.pw': 4, '.gq': 4, '.cf': 4, '.tk': 4, '.ml': 3, '.ga': 3,
    '.win': 3, '.bid': 3, '.review': 3, '.country': 3
}

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rebrand.ly', 'is.gd',
    'buff.ly', 'ow.ly', 'v.gd', 'shorturl.at', 'tiny.cc', 'git.io',
    't.ly', 'rb.gy', 'dub.sh', 'urlqr.me'
}

def score_keywords(text: str) -> dict:
    text_lower = text.lower()

    for phrase in SAFE_PHRASES:
        text_lower = text_lower.replace(phrase, "")

    found = {}
    total = 0

    for kw, weight in SCAM_KEYWORDS.items():
        match = re.search(re.escape(kw), text_lower)
        if not match:
            continue
        before = text_lower[max(0, match.start()-35):match.start()]
        words = before.split()
        if any(word in NEGATION_WORDS for word in words):
            continue
        # Count each distinct keyword once — a single benign word repeated
        # several times (e.g. in a long legitimate document) should not
        # inflate the score the way it would if every occurrence counted.
        found[kw] = weight
        total += weight

    # ── Combination bonuses ──────────────────────────────────────────────
    # A single generic word is weak evidence on its own; genuine scams are
    # far more reliably identified by *combinations* of suspicious signals
    # (e.g. an urgent payment demand, or a fake job offer with a fee).
    combos = [
        (["registration fee", "urgent"], 5),
        (["registration fee", "immediately"], 5),
        (["otp", "bank"], 6),
        (["lottery", "claim"], 6),
        (["kyc", "account blocked"], 7),
        (["offer letter", "fee"], 7),
        (["click here", "verify"], 6),
        (["bitcoin", "investment"], 6),
        (["work from home", "guaranteed"], 6),
        (["gift card", "send"], 7),
        # Payment request + urgency
        (["payment required", "urgent"], 6),
        (["payment required", "act now"], 6),
        (["pay fee", "immediately"], 6),
        # Fake/unrealistic job offers
        (["salary upto", "no interview"], 7),
        (["ctc upto", "no experience"], 6),
        (["guaranteed placement", "fee"], 7),
        (["direct selection", "fee"], 7),
        # Registration / processing fee combos
        (["processing fee", "guaranteed"], 6),
        (["registration fee", "guaranteed"], 6),
        (["joining fee", "no interview"], 7),
        # Account verification / phishing pressure
        (["verify your account", "urgent"], 6),
        (["confirm your account", "immediately"], 6),
        (["kyc update", "account blocked"], 7),
        (["click here", "account suspended"], 7),
        (["enter your password", "verify your account"], 7),
    ]

    for keywords, bonus in combos:
        if all(k in text_lower for k in keywords):
            total += bonus

    # ── Safe-context damping ─────────────────────────────────────────────
    # Legitimate/institutional language present alongside only weak,
    # low-severity keyword hits (the previously unused SAFE_KEYWORDS list)
    # should not, on its own, push everyday content into a false-positive
    # scam classification.
    safe_hits = [w for w in SAFE_KEYWORDS if w in text_lower]
    if safe_hits and found:
        weak_only = all(w <= 2 for w in found.values())
        if weak_only:
            total = max(0, total - (2 * min(len(safe_hits), 4)))

    return {
        "score": total,
        "found": list(found.keys()),
        "details": found,
        "safe_context": safe_hits[:6],
    }

def compute_risk_level(score: float) -> dict:
    if score >= 81:
        return {'level': 'CRITICAL', 'color': '#ef4444', 'emoji': '🔴'}
    elif score >= 61:
        return {'level': 'HIGH',     'color': '#f97316', 'emoji': '🟠'}
    elif score >= 41:
        return {'level': 'MEDIUM',   'color': '#ffb340', 'emoji': '🟡'}
    elif score >= 21:
        return {'level': 'LOW',      'color': '#3b82f6', 'emoji': '🔵'}
    else:
        return {'level': 'SAFE',     'color': '#00ff9d', 'emoji': '🟢'}

def normalise_score(raw: float, ceiling: float = 20.0) -> float:
    return round(min(raw / ceiling, 1.0) * 100, 1)

def analyse_url(url: str) -> dict:
    """
    Heuristic phishing / suspicious URL analysis.
    """
    result = {
        'url':           url,
        'is_https':      False,
        'domain':        '',
        'tld':           '',
        'has_ip':        False,
        'is_long':       False,
        'suspicious_kw': [],
        'tld_risk':      0,
        'is_known_legit':False,
        'typosquat_risk':False,
        'risk_score':    0,
        'risk_level':    {},
        'trust_score':   0,
        'flags':         [],
    }

    url_clean = url.strip()
    if not url_clean.startswith(('http://', 'https://')):
        url_clean = 'http://' + url_clean

    try:
        parsed = urlparse(url_clean)
    except Exception:
        result['flags'].append('Could not parse URL')
        result['risk_score'] = 75
        result['risk_level'] = compute_risk_level(75)
        return result

    result['is_https'] = parsed.scheme == 'https'
    domain             = parsed.netloc.lower().replace('www.', '')
    result['domain']   = domain

    tld_match = re.search(r'\.[a-z0-9]{2,}$', domain)
    tld = tld_match.group(0) if tld_match else ''
    result['tld'] = tld
    result['tld_risk'] = SCAM_TLD_RISK.get(tld, 0)

    # 1. IP address as domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]):
        result['has_ip'] = True
        result['flags'].append('IP address used as domain (high risk)')

    # 2. URL length
    if len(url) > 75:
        result['is_long'] = True
        result['flags'].append(f'Unusually long URL ({len(url)} chars)')

    # 3. Suspicious keywords in URL
    url_lower = url.lower()
    found_kw = [p for p in PHISHING_URL_PATTERNS if re.search(p, url_lower)]
    result['suspicious_kw'] = found_kw

    # 4. Known legit domain
    result['is_known_legit'] = any(domain == ld or domain.endswith('.' + ld) for ld in LEGIT_DOMAINS)

    # 5. Typosquatting
    for legit in LEGIT_DOMAINS:
        core = legit.split('.')[0]
        if core in domain and not (domain == legit or domain.endswith('.' + legit)):
            result['typosquat_risk'] = True
            result['flags'].append(f'Possible typosquatting of {legit}')
            break

    # 6. Check @ symbol
    if '@' in url_clean:
        result['flags'].append('URL contains "@" character (highly suspicious)')

    # 7. Check percent encoding
    if '%' in url_clean:
        result['flags'].append('URL contains percent-encoded characters')

    # 8. Check redirect parameters
    redirect_params = ['redirect', 'url', 'link', 'next', 'destination', 'return', 'to']
    query_lower = parsed.query.lower()
    for param in redirect_params:
        if f'{param}=' in query_lower:
            result['flags'].append(f'URL contains redirection parameter: "{param}"')
            break

    # 9. Digits ratio check
    digit_count = sum(c.isdigit() for c in url_clean)
    digit_ratio = digit_count / len(url_clean) if len(url_clean) > 0 else 0
    if digit_ratio > 0.15:
        result['flags'].append(f'High ratio of digits in URL ({round(digit_ratio*100)}%)')

    # 10. Special character count check
    special_chars = sum(1 for c in url_clean if c in ['-', '_', '=', '?', '&', '%', '$', '@', '+'])
    if special_chars > 8:
        result['flags'].append(f'Unusually high number of special characters ({special_chars})')

    # 11. Entropy check (shared shannon_entropy() helper — see top of file)
    ent = shannon_entropy(url_clean)
    if ent > 4.5:
        result['flags'].append(f'High URL entropy ({round(ent, 2)})')

    # 12. Shortener checking
    is_shortened = any(domain == sd or domain.endswith('.' + sd) for sd in SHORTENER_DOMAINS)
    if is_shortened:
        result['flags'].append('Shortened URL used (frequently used to mask the final destination)')

    # Compute heuristic risk score
    score = 0
    if not result['is_https']:
        score += 25
    if result['has_ip']:
        score += 35
    if result['is_long']:
        score += 12
    if result['suspicious_kw']:
        score += len(result['suspicious_kw']) * 12
    if result['tld_risk']:
        score += result['tld_risk'] * 10
    if result['typosquat_risk']:
        score += 40
    if '@' in url_clean:
        score += 30
    if '%' in url_clean:
        score += 8
    if any('redirection parameter' in f for f in result['flags']):
        score += 15
    if digit_ratio > 0.15:
        score += 10
    if special_chars > 8:
        score += 12
    if ent > 4.5:
        score += 10
    if is_shortened:
        score += 15

    if result['is_known_legit']:
        score = max(0, score - 60)

    score = min(score, 100)
    result['risk_score']  = score
    result['risk_level']  = compute_risk_level(score)
    result['trust_score'] = max(0, 100 - score)

    return result

FAKE_RECRUITER_SIGNALS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'rediffmail.com', 'ymail.com', 'mail.com',
]

SUSPICIOUS_COMPANY_WORDS = [
    'overseas', 'international jobs', 'global placement', 'abroad job',
    'guaranteed job', 'visa sponsor', 'no fees', 'direct joining',
    '100% placement', 'assured job',
]

# ─── Company Verifier — Email Analysis Lexicons ─────────────────────────────
# Public/free webmail providers. Not inherently malicious, but a recruiter
# claiming to represent a real company while emailing from one of these is a
# well-known red flag in job-scam / recruiter-impersonation cases.
PUBLIC_EMAIL_PROVIDERS = {
    'gmail.com': 'Gmail', 'googlemail.com': 'Gmail',
    'yahoo.com': 'Yahoo Mail', 'ymail.com': 'Yahoo Mail', 'yahoo.co.in': 'Yahoo Mail',
    'outlook.com': 'Outlook', 'hotmail.com': 'Outlook/Hotmail',
    'live.com': 'Outlook/Live', 'msn.com': 'Outlook/MSN',
    'aol.com': 'AOL Mail', 'icloud.com': 'iCloud Mail', 'me.com': 'iCloud Mail',
    'protonmail.com': 'ProtonMail', 'proton.me': 'ProtonMail',
    'mail.com': 'Mail.com', 'gmx.com': 'GMX', 'zoho.com': 'Zoho Mail',
    'yandex.com': 'Yandex Mail', 'rediffmail.com': 'Rediffmail',
    'inbox.com': 'Inbox.com',
}

# Known temporary / disposable email domains, commonly used to receive scam
# replies without any trace back to a real identity.
DISPOSABLE_EMAIL_DOMAINS = {
    'mailinator.com', 'tempmail.com', 'temp-mail.org', '10minutemail.com',
    'guerrillamail.com', 'guerrillamail.info', 'throwawaymail.com',
    'yopmail.com', 'trashmail.com', 'getnada.com', 'fakeinbox.com',
    'dispostable.com', 'sharklasers.com', 'maildrop.cc', 'mintemail.com',
    'moakt.com', 'discard.email', 'mailnesia.com', 'spamgourmet.com',
    'tempinbox.com', 'emailondeck.com', '33mail.com', 'mohmal.com',
}

# Well-known brand names used to detect typosquatting of the brand itself
# inside an email or website domain (e.g. "amaz0n", "micros0ft"). Kept
# separate from LEGIT_DOMAINS (which is full domains) since here we only
# need the bare brand word.
TYPOSQUAT_BRANDS = [
    'google', 'microsoft', 'amazon', 'apple', 'facebook', 'paypal',
    'linkedin', 'netflix', 'twitter', 'instagram', 'flipkart', 'infosys',
    'wipro', 'accenture', 'deloitte', 'ibm', 'tcs', 'hcl', 'naukri',
    'indeed', 'glassdoor', 'walmart', 'adobe', 'oracle', 'salesforce',
]

# Leetspeak / homoglyph substitution map used to normalise a domain or email
# before comparing it against TYPOSQUAT_BRANDS, so "amaz0n" / "micr0soft" /
# "g00gle" normalise back to their real-word form before comparison.
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '$': 's', '@': 'a',
})

def _leet_normalise(s: str) -> str:
    return s.lower().translate(_LEET_MAP)

def _levenshtein(a: str, b: str) -> int:
    """Small dependency-free edit-distance implementation used to catch
    near-miss typosquats (one inserted/deleted/substituted character) that
    leetspeak normalisation alone wouldn't catch."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + cost)
        prev = cur
    return prev[-1]

def _domain_core(domain: str) -> str:
    """Best-effort registrable-name extraction: 'jobs.amazon.co.in' -> 'amazon',
    'amazon.com' -> 'amazon'. Good enough for brand/typosquat comparison
    without needing a full public-suffix-list dependency."""
    domain = (domain or '').lower().strip().replace('www.', '')
    parts = [p for p in domain.split('.') if p]
    if not parts:
        return ''
    # Strip a trailing country-style TLD pair like co.in / com.au if present
    generic_second_level = {'co', 'com', 'net', 'org', 'gov', 'edu'}
    if len(parts) >= 3 and parts[-2] in generic_second_level:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]

def detect_domain_typosquat(domain: str) -> dict:
    """Detect brand impersonation in a bare domain (email domain or website
    domain) via leetspeak-normalisation + small edit-distance matching
    against TYPOSQUAT_BRANDS. Returns {'detected': bool, 'target': str|None}.
    """
    core = _domain_core(domain)
    if not core:
        return {'detected': False, 'target': None}
    normalised = _leet_normalise(core)
    for brand in TYPOSQUAT_BRANDS:
        if normalised == brand:
            continue  # exact match IS the brand itself, not an impersonation
        if brand in normalised or normalised in brand:
            return {'detected': True, 'target': brand}
        if abs(len(normalised) - len(brand)) <= 2 and _levenshtein(normalised, brand) <= 1:
            return {'detected': True, 'target': brand}
    return {'detected': False, 'target': None}

def analyse_recruiter_email(email: str) -> dict:
    email  = email.lower().strip()
    domain = email.split('@')[-1] if '@' in email else ''
    risky  = domain in FAKE_RECRUITER_SIGNALS
    return {
        'email':      email,
        'domain':     domain,
        'is_free_mail': risky,
        'risk':       'HIGH' if risky else 'LOW',
        'note': 'Legitimate companies use corporate email domains, not free providers.' if risky else 'Domain looks professional.'
    }

def analyse_company_name(name: str) -> dict:
    name_lower = name.lower()
    matches    = [w for w in SUSPICIOUS_COMPANY_WORDS if w in name_lower]
    score      = min(len(matches) * 20, 80)
    return {
        'name':             name,
        'suspicious_terms': matches,
        'risk_score':       score,
        'risk_level':       compute_risk_level(score),
    }

EMAIL_LOCAL_PART_FLAG_WORDS = [
    'hr', 'recruiter', 'recruitment', 'hiring', 'jobs', 'job', 'career',
    'placement', 'noreply', 'no-reply', 'admin', 'official', 'support',
    'manager', 'urgent', 'payment', 'fee', 'money',
]

def analyse_email_full(email: str, website_domain: str = '', company_name: str = '') -> dict:
    """
    Full recruiter-email analysis pipeline for the Company Verifier.

    Reuses existing shared logic rather than re-implementing it:
      - score_keywords()      → same scam-phrase lexicon/negation-handling
                                 used by the Text Scanner and URL page-text
                                 analysis, run here against the email string.
      - shannon_entropy()     → same randomness measure used by analyse_url().
      - detect_domain_typosquat() → same leetspeak/edit-distance typosquat
                                 logic used for the website domain, applied
                                 here to the email domain.
      - compute_risk_level()  → same 5-tier thresholds as every other module.
    """
    result = {
        'email': '', 'local_part': '', 'domain': '',
        'is_public_provider': False, 'public_provider_name': None,
        'is_disposable': False,
        'domain_matches_website': None,   # None = no website provided to compare
        'suspicious_keyword_hits': [],
        'has_random_chars': False, 'entropy': 0.0,
        'has_excessive_numbers': False, 'digit_ratio': 0.0,
        'typosquat_detected': False, 'typosquat_target': None,
        'flags': [],
        'email_risk_score': 0,
        'email_trust_score': 100,
        'risk_level': compute_risk_level(0),
    }

    if not email or not email.strip() or '@' not in email:
        result['flags'].append('No valid recruiter email provided')
        return result

    email = email.strip().lower()
    local_part, _, domain = email.partition('@')
    result['email']       = email
    result['local_part']  = local_part
    result['domain']      = domain

    score = 0

    # 1. Public/free email provider check
    provider_name = PUBLIC_EMAIL_PROVIDERS.get(domain)
    if provider_name:
        result['is_public_provider']   = True
        result['public_provider_name'] = provider_name
        result['flags'].append(f'Recruiter uses a free/public email provider ({provider_name})')
        score += 30

    # 2. Disposable / temporary email domain check
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        result['is_disposable'] = True
        result['flags'].append(f'Disposable/temporary email domain detected ({domain})')
        score += 45

    # 3. Domain-vs-website comparison
    if website_domain:
        website_clean = website_domain.lower().strip().replace('www.', '')
        if domain == website_clean or _domain_core(domain) == _domain_core(website_clean):
            result['domain_matches_website'] = True
        else:
            result['domain_matches_website'] = False
            if not result['is_public_provider']:
                result['flags'].append(
                    f'Recruiter email domain ("{domain}") does not match the company website domain ("{website_clean}")'
                )
                score += 35

    # 4. Suspicious keyword detection — reuse the shared scam-keyword scorer
    kw_result = score_keywords(f'{local_part} {domain}')
    if kw_result['found']:
        result['suspicious_keyword_hits'] = kw_result['found']
        result['flags'].append(f"Suspicious keyword(s) in email: {', '.join(kw_result['found'][:4])}")
        score += min(normalise_score(kw_result['score'], ceiling=15.0) * 0.25, 25)

    # Softer local-part word flags (informational — not scored on their own,
    # only meaningful combined with a free/public provider above)
    local_flag_hits = [w for w in EMAIL_LOCAL_PART_FLAG_WORDS if w in local_part]
    if local_flag_hits and result['is_public_provider']:
        result['flags'].append(
            f"Generic recruiting term(s) used on a free-mail address: {', '.join(local_flag_hits[:3])}"
        )
        score += 8

    # 5. Random-character detection via shared shannon_entropy()
    ent = shannon_entropy(local_part)
    result['entropy'] = round(ent, 2)
    if len(local_part) >= 6 and ent > 3.4:
        result['has_random_chars'] = True
        result['flags'].append(f'Recruiter email local-part looks randomly generated (entropy {round(ent,2)})')
        score += 20

    # 6. Excessive digits in the local part
    digit_count = sum(c.isdigit() for c in local_part)
    digit_ratio = digit_count / len(local_part) if local_part else 0
    result['digit_ratio'] = round(digit_ratio, 2)
    if digit_ratio > 0.35:
        result['has_excessive_numbers'] = True
        result['flags'].append(f'Unusually high proportion of digits in email address ({round(digit_ratio*100)}%)')
        score += 15

    # 7. Typosquatting of a known brand in the email domain
    typo = detect_domain_typosquat(domain)
    if typo['detected']:
        result['typosquat_detected'] = True
        result['typosquat_target']   = typo['target']
        result['flags'].append(f"Email domain appears to impersonate \"{typo['target']}\" (typosquatting)")
        score += 50

    score = min(round(score), 100)
    result['email_risk_score']  = score
    result['email_trust_score'] = max(0, 100 - score)
    result['risk_level']        = compute_risk_level(score)
    result['flags'] = list(dict.fromkeys(result['flags']))
    return result

_COMPANY_SUFFIX_WORDS = {
    'pvt', 'private', 'ltd', 'limited', 'llc', 'inc', 'incorporated',
    'corp', 'corporation', 'co', 'company', 'group', 'holdings',
    'technologies', 'technology', 'solutions', 'services', 'enterprises',
    'international', 'global', 'industries',
}

def _company_name_tokens(name: str) -> list:
    """Lowercase, strip punctuation, and drop generic corporate-suffix
    words, leaving the distinctive tokens of a company name for matching
    against a domain / page title / page text."""
    cleaned = re.sub(r'[^a-z0-9\s]', ' ', name.lower())
    tokens  = [t for t in cleaned.split() if t and t not in _COMPANY_SUFFIX_WORDS]
    return tokens

def verify_company_identity(name: str, website_domain: str = '',
                             page_title: str = '', page_text: str = '') -> dict:
    """
    Cross-checks a claimed company name against:
      - the website's domain name,
      - the webpage's <title>,
      - the webpage's extracted visible text.
    (page_title/page_text are expected to come from analyse_url_full()'s
    existing content_analysis output — no separate fetch is performed here.)
    """
    result = {
        'name': name, 'tokens': [],
        'name_matches_domain': False,
        'name_in_title':       False,
        'name_in_content':     False,
        'match_score':         0,
        'suspicious_terms':    [],
        'flags':               [],
    }
    if not name or not name.strip():
        result['flags'].append('No company name provided')
        return result

    tokens = _company_name_tokens(name)
    result['tokens'] = tokens

    # Reuse the legacy suspicious-company-word heuristic (no duplication)
    legacy = analyse_company_name(name)
    result['suspicious_terms'] = legacy['suspicious_terms']
    if legacy['suspicious_terms']:
        result['flags'].append(
            f"Company name contains common fraud-recruitment phrasing: {', '.join(legacy['suspicious_terms'][:3])}"
        )

    domain_core = _domain_core(website_domain) if website_domain else ''
    title_lower = (page_title or '').lower()
    text_lower  = (page_text or '').lower()

    significant = [t for t in tokens if len(t) >= 4] or tokens

    if domain_core and significant:
        if any(t in domain_core or domain_core in t for t in significant):
            result['name_matches_domain'] = True

    if title_lower and significant:
        if any(t in title_lower for t in significant):
            result['name_in_title'] = True

    if text_lower and significant:
        if any(t in text_lower for t in significant):
            result['name_in_content'] = True

    score = 0
    if result['name_matches_domain']:
        score += 50
    if result['name_in_title']:
        score += 25
    if result['name_in_content']:
        score += 25
    result['match_score'] = score

    if website_domain and score == 0:
        result['flags'].append(
            f'Company name "{name}" was not found in the website domain, title, or page content'
        )
    elif website_domain and not result['name_matches_domain']:
        result['flags'].append(
            f'Company name "{name}" does not resemble the website domain ("{website_domain}")'
        )

    return result

def make_empty_stats() -> dict:
    return {
        'total_scans':    0,
        'threats_found':  0,
        'safe_scans':     0,
        'critical':       0,
        'risk_scores':    [],
        'scan_history':   [],
    }

def update_stats(stats: dict, verdict: str, risk_score: float, scan_type: str) -> dict:
    import datetime
    stats['total_scans'] += 1
    stats['risk_scores'].append(risk_score)

    lvl = compute_risk_level(risk_score)['level']
    if lvl in ('CRITICAL', 'HIGH', 'MEDIUM'):
        stats['threats_found'] += 1
    else:
        stats['safe_scans'] += 1

    if lvl == 'CRITICAL':
        stats['critical'] += 1

    stats['scan_history'].append({
        'type':    scan_type,
        'verdict': verdict,
        'score':   risk_score,
        'level':   lvl,
        'ts':      datetime.datetime.now().strftime('%H:%M:%S'),
    })
    return stats

def avg_risk(stats: dict) -> float:
    scores = stats.get('risk_scores', [])
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 1)