# UnifiedLens AI 

**Project by:** Puvisha S, Vidhya Priya P, Hemanthika M
**Stack:** Python · Streamlit · scikit-learn · NLTK · Plotly · OpenCV · Tesseract OCR
website link: https://unifiedlens-ai-lanr2sgx37vt4ib5iw9vfj.streamlit.app/
---

## 🛡️ What Is UnifiedLens AI?

UnifiedLens AI is a **real-time AI-powered cybersecurity intelligence platform** built to protect everyday users — especially job seekers and students — from online scams, phishing attacks, and digital fraud. It combines machine learning, natural language processing (NLP), heuristic rule engines, and computer vision into a single web-based security dashboard.

The core mission is simple: **detect digital threats before victims are harmed.** Whether the threat arrives as a suspicious WhatsApp message, a fake job offer email, a malicious URL, a fraudulent QR code, or a scam-laced PDF — UnifiedLens AI can scan and score it in seconds.

---

## 🎨 Visual Design & UI System

The UI has a premium **dark cyberpunk / threat-intelligence aesthetic**, inspired by real-world security dashboards and SIEM tools.

### Design Identity

* **Color palette:** Deep space navy background (`#020409`), electric cyan primary (`#00d4ff`), neon green safe (`#00ff9d`), threat red (`#ff3366`), warning amber (`#ffb340`), purple accent (`#7c3aed`)
* **Typography:** Three distinct font roles — `Orbitron` for display and scores, `Rajdhani` for headings and labels, `JetBrains Mono` for data and monospace content, plus `Inter` for body text
* **Background Effect:** An animated Matrix-style canvas (`<canvas id="cl-matrix">`) renders scrolling columns of cyan characters — Latin digits, Japanese katakana, and cybersecurity symbols — at low opacity, creating a live "active system" atmosphere without distracting from the content
* **Glass morphism cards:** Result cards use translucent backgrounds with subtle borders and glowing effects
* **Animations:** Result cards fade in on appearance, badges slide in from the left, and metric cells appear with staggered delays. Threat levels also use pulse animations for urgent results

### Top Bar

A fixed header renders through an embedded HTML component with:

* **Brand logo:** Animated pulsing shield icon with gradient border
* **Live ticker:** A scrolling marquee showing real-time session statistics, ML engine status, and security alerts
* **Status pill:** A green **"SYSTEMS ONLINE"** badge with a pulsing status indicator

### Navigation

Seven navigation tabs are provided through custom HTML buttons with SVG icons:

* Dashboard
* Analyzer
* URL Scanner
* QR Scanner
* Company Verifier
* Analytics
* About

The active tab is visually highlighted, and navigation is connected to Streamlit's interface through JavaScript bridging.

---

# 📄 Pages & Features

## 1. Dashboard

The landing page provides an overview of the current security scanning session.

### Main Components

* **Animated radar scanner** — three pulsing concentric rings with a sweeping radar beam around a central shield, establishing the threat-monitoring theme
* **4 live stat cards:**
  * Total Scans
  * Threats Detected
  * Safe Scans
  * Critical Threats
* **Quick Action Grid:** Four clickable cards for:
  * AI Analyzer
  * URL Scanner
  * QR Scanner
  * Company Verifier
* **Recent Threat History:** A reverse-chronological feed displaying recent scans with threat level, scan type, risk score, and timestamp

The statistics are maintained in the application session and updated as scans are performed.

---

## 2. AI Analyzer — Text / Image OCR / PDF

The AI Analyzer is the core analysis feature and provides three major input methods.

---

### 📝 Text / Message Analysis

Users can paste suspicious messages, job offers, emails, recruiter messages, or other text content.

The interface provides:

* Multilingual support
* Language detection
* Translation where required
* Character counter
* Quick example messages
* Animated analysis progress
* AI-based threat detection
* Rule-based analysis
* Risk scoring
* Explainable suspicious indicators

When the user selects **Analyze Threat**, the system processes the input through stages including:

1. Language detection
2. Translation
3. NLP analysis
4. Pattern detection
5. Risk scoring
6. Threat report generation

The result includes:

* Language detection badge
* Detected language
* Native language name/script
* Detection confidence
* Translation status
* Neural Risk Ring
* Verdict badge
* Threat level
* Risk score
* AI verdict
* Suspicious indicators
* Recommendations

---

### 🖼️ Image / OCR Analysis

Users can upload image files such as:

* PNG
* JPG
* BMP
* TIFF

The image is processed using **Tesseract OCR**.

The OCR pipeline performs image enhancement before text extraction. This can include:

* Upscaling
* Contrast enhancement
* Denoising
* Sharpening
* Deskewing
* Adaptive thresholding

The extracted text is then passed through the same text-analysis pipeline used for normal messages.

The result displays:

* Extracted text information
* Word count
* Character count
* Threat level
* Risk score
* Suspicious indicators
* Final analysis

This allows screenshots of scam messages, advertisements, job offers, or other suspicious content to be analyzed instead of requiring users to manually type the text.

---

### 📄 PDF Document Analysis

Users can upload PDF documents for threat analysis.

The system:

1. Opens the PDF
2. Extracts the available text layer
3. Checks whether the extracted text is sufficient
4. Uses OCR when the page appears to be scanned or contains weak text extraction
5. Detects QR codes contained within PDF pages
6. Combines the extracted information
7. Sends the resulting content to the AI analysis pipeline

The PDF pipeline uses `pdfplumber` and supporting PDF/OCR tools.

For scanned pages, the system can render pages at high resolution and apply OCR. Difficult pages can receive an additional higher-resolution OCR pass.

The result includes:

* Filename
* File size
* Page count
* Word count
* Character count
* Text preview
* OCR status
* Detected QR codes where applicable
* Threat analysis

This allows UnifiedLens AI to detect scam content even when the malicious information is embedded inside a scanned document rather than a normal text-based PDF.

---

# 3. URL Scanner

The URL Scanner is a dedicated phishing-detection component designed specifically for suspicious links.

Users can enter any URL and receive a structural and threat-based analysis.

### Scanning Process

The URL scanner performs stages such as:

1. URL parsing
2. Domain analysis
3. Reputation and structural checks
4. Phishing pattern detection
5. Machine-learning prediction
6. Risk scoring

The result can include:

* HTTPS status
* Domain
* TLD
* IP-as-domain detection
* URL length
* Suspicious words
* Typosquatting detection
* Known-legitimate-domain check
* Trust score
* ML prediction
* Risk level

The system combines independent URL analysis techniques rather than relying on a single indicator.

---

# 4. QR Scanner

The QR Scanner allows users to upload QR-code images and inspect their decoded content.

Supported image formats include:

* PNG
* JPG
* BMP
* GIF

The system uses **OpenCV's QRCodeDetector** along with additional decoding strategies to improve detection reliability.

The QR pipeline can:

1. Detect the QR code
2. Decode its payload
3. Identify the payload type
4. Route the content to the appropriate analysis engine

If the decoded content is a:

* **URL** → it is passed to the URL Scanner
* **Text message** → it is passed to the AI Text Analyzer

This creates a connection between QR scanning and the existing threat-detection pipelines.

The decoded payload is displayed to the user together with the resulting security analysis.

---

# 5. Company Verifier

The Company Verifier is designed particularly for evaluating suspicious recruitment offers and recruiter information.

The user can provide:

* Company Name
* Recruiter Email
* Company Website

The system combines multiple independent checks.

### Company Name Analysis

The system examines the company name and related information for suspicious recruitment indicators such as:

* Guaranteed jobs
* 100% placement claims
* Overseas job promises
* Suspicious employment language
* Other scam-related phrases

### Recruiter Email Analysis

The recruiter email is checked for indicators including:

* Free/public email providers
* Disposable email services
* Website-domain mismatch
* Suspicious email keywords
* Random-looking email local parts
* Excessive digits
* Brand typosquatting

### Website Analysis

The company website is passed through the URL analysis pipeline.

The system checks:

* URL structure
* Domain characteristics
* HTTPS
* Suspicious patterns
* Typosquatting
* TLD risk
* Domain reputation indicators

### Cross-Verification

The Company Verifier also checks whether the provided:

**Company Name ↔ Recruiter Email ↔ Website**

are mutually consistent.

The system compares company-name tokens against the website domain, website title, fetched page content, and recruiter email information.

A trusted-company/domain check can provide an additional identity confirmation, while detected brand impersonation can significantly increase the risk.

The final result provides:

* Company risk
* Email risk
* Website risk
* Identity mismatch information
* Cross-verification information
* Overall risk score
* Trust score
* Verdict
* Recommendations

---

# 6. Analytics Dashboard

The Analytics section provides a visual summary of scanning activity.

It includes:

### Summary Statistics

* Total Scans
* Threats Detected
* Safe Scans
* Critical Threats

### Threat Distribution

A Plotly donut chart displays the distribution of:

* SAFE
* LOW
* MEDIUM
* HIGH
* CRITICAL

The chart provides both count and percentage information.

### Scan Category Analysis

A bar chart displays the number of scans performed through different tools, such as:

* AI Analyzer
* URL Scanner
* QR Scanner
* OCR Scanner
* Other supported analysis categories

### Scan History

The scan history table displays recent scans with:

* Scan index
* Scan type
* Threat level
* Risk score
* Timestamp

The application stores scan-history information within browser/session storage so that dashboard statistics can be updated as the user performs scans.

---

# 7. About

The About section explains the purpose and capabilities of UnifiedLens AI.

It includes:

### What UnifiedLens Protects Against

Five major threat categories are highlighted:

1. Fake Jobs
2. Phishing Links
3. QR Scams
4. Fake Recruiters
5. Fraudulent PDFs

### How It Works

The basic workflow is:

**Upload → AI Analysis → Risk Scoring → Threat Report**

### Why This Project Matters

UnifiedLens AI focuses on the growing problem of online scams affecting students, job seekers, and everyday internet users.

The platform aims to make cybersecurity analysis easier to access by allowing users to check multiple forms of suspicious digital content through a single interface.

### Future Vision

The planned future improvements include:

* Mobile-responsive application
* AI chatbot for user guidance
* Complete multilingual website interface
* Voice scam detection from uploaded audio
* User login and saved scan history

The footer provides the project team information and technology stack.

---

# 🧠 AI / ML Engine — Text Scam Detection

The text-analysis engine is built using a combination of **dual TF-IDF feature extraction, machine-learning ensemble classification, rule-based detection, and threshold-based decision making**.

## Architecture: Dual TF-IDF + Soft-Voting Ensemble

### Feature Extraction

The text model uses two complementary TF-IDF representations.

### Word N-Gram TF-IDF

The word-level vectorizer uses n-grams from 1 to 3 words.

It captures meaningful phrases such as:

* "pay registration fee"
* "guaranteed income"
* "no interview"
* "verify your account"

This allows the model to learn relationships between individual words and short phrases.

### Character N-Gram TF-IDF

Character-level n-grams from 3 to 5 characters are also used.

This helps detect intentionally modified or obfuscated scam words such as:

* `j0b`
* `fr33`
* character-level spelling variations

Both feature sets are combined using `FeatureUnion`.

This gives the model both **semantic word-level information and character-level patterns**.

---

# 🤖 Text Classification Ensemble

The text model uses three classifiers through soft voting.

### Logistic Regression

Logistic Regression is the primary classifier and receives the highest ensemble weight.

It is effective for high-dimensional sparse text representations such as TF-IDF features.

### SGDClassifier

An SGD-based classifier with modified Huber loss provides a different learning approach and increases ensemble diversity.

Its probability output is calibrated using `CalibratedClassifierCV`.

### Random Forest

Random Forest introduces non-linear decision-making and helps the ensemble capture patterns that may not be represented by the linear classifiers.

### Soft Voting

The three models do not simply vote on their final labels.

Instead, their predicted probabilities are combined using weighted soft voting.

The Logistic Regression model has weight **3**, while the SGD and Random Forest models have weight **2** each.

---

# ⚙️ Text Model Training Pipeline

The training process follows these major stages:

1. Load the training data
2. Map the scam/legitimate labels
3. Preprocess the text
4. Convert the text into TF-IDF features
5. Train the ensemble
6. Split the data using an 80/20 stratified train/test split
7. Tune the classification threshold
8. Evaluate the model using F1 score
9. Perform stratified cross-validation
10. Save the trained model and threshold

The model uses a **F1-maximizing threshold strategy** rather than automatically assuming that `0.5` is the best decision boundary.

---

# 🎯 Text Model Threshold & F1 Score

The model first produces a probability representing how strongly the input appears to belong to the scam class.

The **threshold acts as the decision cut-off**.

For the current fine-tuned Text Model:

* **Threshold: 0.67**
* **F1 Score: 97%**

The decision process is:

**Probability ≥ 0.67 → Scam**

**Probability < 0.67 → Legitimate**

The threshold was selected through threshold tuning to improve the balance between identifying actual scams and avoiding incorrect scam classifications.

### Easy explanation

**"The Text Model uses a 0.67 threshold, and its F1 score is 97%."**

---

# 🔍 Text Model Inference

During prediction:

1. The input text is preprocessed
2. Word and character TF-IDF features are generated
3. The ensemble produces an ML probability
4. The rule-based scam detector independently calculates a rule score
5. The ML probability and rule score are blended
6. The resulting probability is compared with the tuned threshold
7. The final result is classified as Scam or Legitimate
8. A confidence value is calculated

When strong rule-based scam signals are detected, the rule engine receives greater influence in the final probability.

This hybrid approach allows the system to combine **learned statistical patterns with explicit high-confidence scam patterns**.

---

# 🧩 Rule-Based Pre-Filter

The text model also contains a rule-based pre-filter for high-confidence scam constructions.

Examples include patterns related to:

* Payment or registration fees
* Wire transfers
* Cryptocurrency payments
* OTP or bank-detail requests
* Guaranteed jobs
* No-interview selection
* Unrealistic earning claims
* Password or credential requests
* Urgency and limited-seat pressure

Multiple rule matches are converted into a saturating rule score between 0 and 1.

This prevents the system from relying entirely on the machine-learning classifier when an input contains extremely strong scam patterns.

---

# 🔎 Explainability

UnifiedLens AI provides interpretability through feature extraction.

The system can identify important TF-IDF tokens associated with a particular input.

This allows the result to show suspicious indicators that contributed to the prediction instead of presenting only a final label.

The user can therefore understand **why the system considered the message suspicious**.

---

# 🔗 URL Phishing ML Model

UnifiedLens AI contains a **separate machine-learning model specifically designed for URL phishing detection**.

The URL model is independent from the text-message model because URLs have a fundamentally different structure from natural-language messages.

The model analyzes the URL itself rather than depending on the textual content of the webpage.

---

# 📊 URL Features

The URL model extracts **11 structural features**:

1. `url_length`
2. `num_dots`
3. `has_https`
4. `has_ip`
5. `num_subdirs`
6. `num_params`
7. `suspicious_words`
8. `tld_risk`
9. `special_char_count`
10. `digits_count`
11. `entropy`

These features describe the structural characteristics of a URL.

For example:

* Very long URLs can indicate suspicious construction
* Multiple subdirectories can indicate unusual URL structure
* Raw IP addresses can be suspicious
* Large numbers of parameters can indicate redirection or tracking
* Suspicious words can indicate phishing intent
* High entropy can indicate randomly generated URL components
* Excessive digits or special characters can provide additional signals

---

# 🧠 URL ML Architecture

The URL model uses a soft-voting ensemble containing:

### Random Forest

Random Forest uses multiple decision trees to learn complex relationships between URL features.

### Gradient Boosting

Gradient Boosting builds models sequentially and focuses on improving previous errors.

### Soft Voting

The two models combine their predicted probabilities to produce the final ML probability.

The model is wrapped in a pipeline with median imputation so that missing numeric values can be handled safely.

---

# 🎯 URL Model Threshold & F1 Score

Like the Text Model, the URL model does not simply rely on a default probability cut-off.

The final threshold was tuned for the phishing classification task.

For the current fine-tuned URL Model:

* **Threshold: 0.65**
* **F1 Score: 100%**

The decision process is:

**Probability ≥ 0.65 → Phishing**

**Probability < 0.65 → Legitimate**

### Easy explanation

**"The URL Model uses a 0.65 threshold, and its F1 score is 100% for phishing detection."**

The threshold therefore acts as the final decision boundary between phishing and legitimate URLs.

---

# 🔍 URL Model Inference

During URL prediction:

1. The URL is parsed
2. The 11 structural features are extracted
3. The features are passed into the trained ensemble
4. The ensemble produces a phishing probability
5. The probability is compared with the tuned threshold
6. The final result is classified as phishing or legitimate
7. Confidence and supporting feature information are returned

The URL model itself does not need to fetch the webpage.

Live webpage fetching and webpage-content analysis are handled separately by the higher-level analyzer.

This avoids performing duplicate network requests during a single URL scan.

---

# 🌐 URL Heuristic Risk Analysis

In addition to the URL ML model, UnifiedLens AI uses an independent rule-based URL analysis engine.

The heuristic system checks multiple signals, including:

| Signal                       |      Risk Contribution |
| ---------------------------- | ---------------------: |
| Non-HTTPS URL                |                    +25 |
| IP address as domain         |                    +35 |
| Long URL                     |                    +12 |
| Suspicious URL keywords      | +12 per distinct match |
| Risky TLD                    |         Weighted score |
| Typosquatting                |                    +40 |
| `@` character                |                    +30 |
| Percent encoding             |                     +8 |
| Redirect parameters          |                    +15 |
| High digit ratio             |                    +10 |
| High special-character count |                    +12 |
| High entropy                 |                    +10 |
| Known link shortener         |                    +15 |
| Known legitimate domain      | Strong trust reduction |

The final heuristic score is capped between 0 and 100.

The system then combines the independent URL signals with the machine-learning results and, where applicable, webpage-content analysis.

This provides a layered approach instead of relying on a single detection method.

---

# 🌍 Multilingual Engine

UnifiedLens AI supports analysis across **7 languages**:

| Code | Language  | Script  |
| ---- | --------- | ------- |
| `ta` | Tamil     | தமிழ்   |
| `en` | English   | Latin   |
| `te` | Telugu    | తెలుగు  |
| `ml` | Malayalam | മലയാളം  |
| `kn` | Kannada   | ಕನ್ನಡ   |
| `hi` | Hindi     | हिन्दी  |
| `es` | Spanish   | Español |

The system is designed to support regional-language scam detection, which is particularly important for users receiving suspicious messages in local languages.

---

# 🔤 Language Detection

The language-detection system uses multiple strategies.

### 1. Unicode Script Detection

The system checks Unicode character ranges to identify Indic scripts.

This allows languages such as Tamil, Telugu, Malayalam, Kannada, and Hindi to be identified based on their writing systems.

### 2. Language Detection Library

For Latin-script languages, an offline language-detection mechanism is used to distinguish languages such as English and Spanish.

### 3. Fallback Detection

Additional language markers can be checked when required to improve identification.

---

# 🔄 Translation

When the detected language requires translation for the English-based analysis pipeline, UnifiedLens AI attempts translation using:

1. `googletrans`
2. `deep-translator`

If translation is unavailable, the original text is still passed through the analysis pipeline so that the scan does not fail completely.

The interface can show:

* Original language
* Native language name
* Detection confidence
* Translation status
* Original text
* English translation used for analysis

---

# 🧮 Risk Scoring System

UnifiedLens AI uses a unified **0–100 risk score**.

The score is mapped into five threat levels:

|  Score | Level    |
| -----: | -------- |
|   0–20 | SAFE     |
|  21–40 | LOW      |
|  41–60 | MEDIUM   |
|  61–80 | HIGH     |
| 81–100 | CRITICAL |

This allows different scanning modules to communicate their results using the same risk-level terminology.

---

# 🔑 Scam Keyword Engine

The system uses a large manually curated scam-keyword lexicon containing weighted threat phrases.

The keyword categories cover a broad range of scams, including:

* Urgency and pressure tactics
* Payment demands
* Job and placement scams
* OTP and credential theft
* KYC fraud
* Aadhaar and PAN scams
* Lottery and prize scams
* Banking impersonation
* Investment and cryptocurrency scams
* Romance scams
* Government impersonation
* Digital arrest scams
* Courier and customs scams
* UPI and QR-payment scams
* Electricity and utility scams
* Scholarship scams
* E-commerce refund scams
* Fake customer-care scams
* AI voice/deepfake scams
* MLM and referral scams

Each keyword or phrase has a weighted importance depending on how strongly it indicates fraudulent activity.

---

# 🛡️ False-Positive Reduction

UnifiedLens AI also includes mechanisms designed to reduce unnecessary false positives.

### Negation Awareness

The system checks for phrases such as:

* "no"
* "not"
* "never"
* "official website"
* "no registration fee"
* "never ask for OTP"

This prevents a legitimate warning statement such as **"we never ask for your OTP"** from being incorrectly interpreted as an OTP request.

### Safe Context

Common legitimate words and phrases can reduce the effect of weak scam keywords when they appear in normal institutional or everyday contexts.

### Combination Bonuses

Certain suspicious keyword combinations receive additional scoring because multiple related indicators together are stronger evidence than an individual generic word.

For example:

**"registration fee" + "urgent"**

is more suspicious than either phrase independently.

---

# 📧 Recruiter Email Analysis

The recruiter-email analyzer provides multiple independent checks.

It can identify:

* Public/free email providers
* Disposable email domains
* Website-domain mismatch
* Scam-related keywords
* Random-looking email addresses
* Excessive digits
* Brand typosquatting

The system uses a shared Shannon entropy implementation to identify email local parts that appear randomly generated.

---

# 🔤 Typosquatting Detection

UnifiedLens AI includes typosquatting detection for domains and email addresses.

The system uses:

* Leetspeak normalization
* Levenshtein edit distance
* Domain-core extraction
* Known-brand comparison

For example, intentional substitutions such as:

`amaz0n`

can be normalized toward:

`amazon`

and compared with known legitimate brands.

This helps detect domains that attempt to imitate well-known companies.

---

# 🏢 Company Identity Verification

The Company Verifier removes generic company suffixes such as:

* Pvt
* Ltd
* Inc
* Technologies
* Solutions
* Global

and focuses on distinctive company-name tokens.

These tokens can then be compared with:

* Website domain
* Website title
* Website visible text

This creates a company identity match score.

The system also performs cross-verification between the company name, recruiter email, and website.

A genuine and mutually consistent combination receives stronger trust, while mismatches can increase the risk.

---

# 📄 PDF & OCR Processing

The PDF pipeline uses multiple extraction strategies.

For normal PDFs, native text extraction is attempted first.

If the extracted content is weak — for example, because the PDF is essentially a scanned document — the system invokes OCR.

Pages can be rendered at high resolution before OCR processing.

The OCR pipeline includes:

* Image enhancement
* Tesseract OCR
* Multiple page-segmentation configurations
* OCR quality scoring
* Post-processing
* Merged-word correction

For difficult pages, the system can escalate to a higher-resolution OCR pass.

QR codes embedded inside PDF pages can also be detected independently.

This means a PDF containing only an image or QR code can still be analyzed rather than automatically failing because it has no conventional text layer.

---

# 📊 Analytics & Statistics

UnifiedLens AI maintains scan statistics including:

* Total scans
* Threats found
* Safe scans
* Critical threats
* Risk scores
* Scan history

Each scan can be recorded with:

* Scan type
* Verdict
* Risk score
* Threat level
* Timestamp

These records are used to populate the Dashboard and Analytics sections.

---

# 💾 Model Persistence

The trained models are saved as serialized artifacts using `joblib`.

The text model artifact contains the trained:

* TF-IDF pipeline
* Ensemble classifier
* Tuned threshold

The URL model artifact contains the trained:

* URL feature pipeline
* Random Forest + Gradient Boosting ensemble
* Tuned threshold
* Learned TLD-risk information

This allows the application to load the trained models without retraining them for every scan.

---

# 🗂️ File Architecture

| File                           | Role                                                                              |
| ------------------------------ | --------------------------------------------------------------------------------- |
| `app.py`                       | Streamlit frontend, UI, navigation and result rendering                           |
| `analyzer.py`                  | High-level analysis wrappers for text, URL, QR, OCR, PDF and company verification |
| `ml_model.py`                  | Text scam classifier, preprocessing, training, inference and rule engine          |
| `url_model.py`                 | URL phishing classifier, feature extraction, training and inference               |
| `utils.py`                     | Keyword lexicon, risk scoring, URL heuristics and company/email analysis          |
| `language_utils.py`            | Language detection, translation and language-related UI                           |
| `styles.css`                   | Custom styling, animations and visual components                                  |
| `scam_detector.pkl`            | Trained text-model artifact                                                       |
| `phishing_url_detector.pkl`    | Trained URL-model artifact                                                        |
| `scam.csv` / `sample_data.csv` | Text-model training data                                                          |
| `url.csv`                      | URL-model training data                                                           |
| `requirements.txt`             | Python dependencies                                                               |
| `packages.txt`                 | System dependencies required for OCR                                              |

---

# ⚙️ Tech Stack Summary

### Framework

**Streamlit**

Used to build the interactive cybersecurity dashboard and web interface.

### Machine Learning / NLP

* scikit-learn
* TF-IDF
* Logistic Regression
* SGDClassifier
* Random Forest
* Gradient Boosting
* VotingClassifier
* CalibratedClassifierCV
* NLTK

### Computer Vision

* OpenCV
* Pillow
* pytesseract
* Tesseract OCR

### PDF Processing

* pdfplumber
* PyPDF2
* PyMuPDF

### Visualization

* Plotly

### Language Processing

* langdetect
* googletrans
* deep-translator

### Persistence

* joblib

### URL Analysis

* Python `urllib.parse`
* Custom regular expressions
* Structural URL features
* Heuristic risk analysis

---

# 🎯 What Makes UnifiedLens AI Stand Out

## 1. Multilingual-First Design

UnifiedLens AI supports **Tamil, Hindi, Telugu, Kannada, Malayalam, Spanish, and English**, allowing suspicious content to be analyzed across multiple languages.

The focus on regional languages is particularly useful for detecting scams that may not appear in English.

---

## 2. Multi-Modal Threat Detection

Instead of focusing on only one input type, UnifiedLens AI can analyze:

* Text
* Messages
* Images
* PDFs
* URLs
* QR codes
* Recruiter emails
* Company websites

These different input types are connected to appropriate analysis pipelines.

---

## 3. Two Dedicated ML Models

UnifiedLens AI uses two independently designed machine-learning systems:

### Text Model

A **dual TF-IDF + soft-voting ensemble** designed for scam-message detection.

### URL Model

An **11-feature structural ensemble** using Random Forest and Gradient Boosting for phishing URL detection.

Each model has its own tuned decision threshold.

Current fine-tuned values:

* **Text Model → Threshold 0.67 → F1 Score 97%**
* **URL Model → Threshold 0.65 → F1 Score 100%**

---

## 4. Interpretable AI

The system does not simply return a label.

It can provide:

* Suspicious keywords
* Rule-based indicators
* Important text features
* URL structural features
* Typosquatting information
* Identity mismatches
* Recommendations

This helps users understand the reasoning behind a threat result.

---

## 5. Ensemble + Rule Hybrid

UnifiedLens AI combines statistical machine learning with explicit cybersecurity rules.

The ML models learn patterns from training data, while rule-based detection provides strong signals for known scam constructions.

This combination helps the system detect both **learned patterns and explicit high-confidence threat signals**.

---

## 6. India-Specific Threat Intelligence

The scam lexicon includes threat categories particularly relevant to Indian users, including:

* OTP fraud
* Aadhaar scams
* PAN phishing
* UPI scams
* KYC fraud
* Fake placement fees
* Digital arrest scams
* Fake government notices
* Courier/customs scams
* Electricity disconnection scams
* Scholarship scams

This makes the platform more relevant to regional scam scenarios.

---

## 7. Production-Style Security Interface

The platform uses a dedicated cybersecurity visual identity with:

* Dark threat-intelligence interface
* Animated Matrix background
* Radar visualization
* Neural Risk Ring
* Threat-level badges
* Glass-style result cards
* Live scan statistics
* Analytics dashboard
* Explainable threat reports

The goal is to provide the experience of a professional security-analysis platform while keeping the interface accessible to ordinary users.

---

# 🚀 Overall System Workflow

The complete UnifiedLens AI workflow can be summarized as:

**User Input**

↓

**Input Identification**

Text / URL / QR / Image / PDF / Company Details

↓

**Specialized Processing**

NLP / URL Feature Extraction / QR Decoding / OCR / PDF Extraction / Email & Website Verification

↓

**AI + Rule-Based Analysis**

Machine Learning + Heuristics + Threat Keywords + Structural Checks

↓

**Risk Calculation**

Unified 0–100 Risk Score

↓

**Threat Classification**

SAFE / LOW / MEDIUM / HIGH / CRITICAL

↓

**Explainable Threat Report**

Verdict + Risk Score + Indicators + Recommendations

↓

**Analytics**

Scan History + Threat Distribution + Statistics

---

## 🛡️ Final Summary

UnifiedLens AI is designed as a **unified, multimodal cybersecurity intelligence platform** that combines machine learning, NLP, computer vision, OCR, URL analysis, QR decoding, multilingual processing, heuristic rules, and company verification.

Its architecture separates text and URL intelligence into dedicated machine-learning models while connecting them through a common risk-scoring and threat-reporting framework.

The current fine-tuned ML configuration uses:

**Text Model → Threshold 0.67 → F1 Score 97%**

**URL Model → Threshold 0.65 → F1 Score 100%**

By combining these models with rule-based threat intelligence and multiple input-analysis pipelines, UnifiedLens AI aims to provide an accessible way for students, job seekers, and everyday users to identify suspicious digital content before it causes harm.

**UnifiedLens AI — Detect the threat. Understand the risk. Stay safe.**
