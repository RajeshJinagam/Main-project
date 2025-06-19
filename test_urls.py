import pandas as pd
import joblib
import os
from urllib.parse import urlparse
import re

# ✅ Feature extraction
def extract_features_from_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return [
        1 if '@' in url else 0,
        len(url),
        url.count('.'),
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        1 if url.lower().startswith('https') else 0,
        1 if '-' in parsed.netloc else 0,
        len(parsed.path.split('/')) - 1,
        sum([url.count(c) for c in ['?', '=', '&', '%']]),
        len(parsed.netloc),
        1 if re.search(r'(login|secure|bank|account|verify|signin)', url.lower()) else 0,
        1 if any(t in domain for t in [
            "google.com", "microsoft.com", "amazon.com", "paypal.com",
            "accounts.google.com", "github.com", "wikipedia.org", "linkedin.com"
        ]) else 0
    ]

# ✅ Feature column names
feature_columns = [
    'has_at_symbol', 'url_length', 'dot_count', 'has_ip', 'uses_https',
    'has_hyphen', 'subdirectory_count', 'special_char_count', 'domain_length',
    'has_login_keyword', 'is_trusted_domain'
]

# ✅ Load model using correct path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'Phishing_project', 'phishing_project', 'model', 'phishing_model.pkl')
model = joblib.load(MODEL_PATH)

# ✅ Test URLs
test_urls = [
    "https://www.google.com",
    "http://192.168.0.1/login",
    "http://malicious.com@phishingsite.com/login",
    "https://secure-login.paypal.com",
    "http://example.com/secure/verify?banklogin=true",
    "https://www.amazon.com",
    "http://free-gift-card.win/$1000",
    "https://www.microsoft.com/en-us",
    "http://login-update.confirmation.net",
    "https://accounts.google.com/ServiceLogin"
]

# ✅ Predict and print results
print("\n🔍 Test Results:")
for url in test_urls:
    features = extract_features_from_url(url)
    df = pd.DataFrame([features], columns=feature_columns)
    proba = model.predict_proba(df)[0][1]
    label = "Phishing" if proba > 0.995 else "Legitimate"
    print(f"{url} → {label} (Confidence: {proba:.2f})")
