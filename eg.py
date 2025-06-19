import pandas as pd

df = pd.read_csv('phishing.csv')
print(df.columns)



import pandas as pd
import joblib
from urllib.parse import urlparse
import re

# ✅ Feature extractor with all features used during training
def extract_features_from_url(url):
    parsed = urlparse(url)
    return [
        1 if '@' in url else 0,                            # has_at_symbol
        len(url),                                          # url_length
        url.count('.'),                                    # dot_count
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0, # has_ip
        1 if url.lower().startswith('https') else 0,       # uses_https
        1 if '-' in parsed.netloc else 0,                  # has_hyphen
        len(parsed.path.split('/')) - 1,                   # subdirectory_count
        sum([url.count(c) for c in ['?', '=', '&', '%']]),# special_char_count
        len(parsed.netloc),                                # domain_length
        1 if re.search(r'(login|secure|bank|account|verify|signin)', url.lower()) else 0, # has_login_keyword
        sum(c.isdigit() for c in url),                     # digit_count
        1 if 'http' in parsed.path.lower() else 0,         # double_http
        1 if '//' in urlparse(url).path else 0,            # has_redirect
        len(parsed.query)                                  # query_length
    ]

# ✅ Full feature list used in model training (order matters)
feature_columns = [
    'has_at_symbol', 'url_length', 'dot_count', 'has_ip', 'uses_https',
    'has_hyphen', 'subdirectory_count', 'special_char_count', 'domain_length',
    'has_login_keyword', 'digit_count', 'double_http', 'has_redirect', 'query_length'
]

# ✅ Load the model (adjust path if needed)
model = joblib.load('phishing_project/model/phishing_model.pkl')# or 'phishing_project/model/phishing_model.pkl'

# ✅ Test URLs
test_urls = [
    "https://www.google.com",
    "http://192.168.0.1/login",
    "http://malicious.com@phishingsite.com/login",
    "https://secure-login.paypal.com",
    "http://example.com/secure/verify?banklogin=true",
    "http://free-gift-card.win/$1000",
    "https://www.microsoft.com/en-us",
    "http://login-update.confirmation.net",
    "https://accounts.google.com/ServiceLogin"
]

# ✅ Prediction loop
threshold = 0.7
print("\n🔍 Test Results:")
for url in test_urls:
    features = extract_features_from_url(url)
    df = pd.DataFrame([features], columns=feature_columns)
    proba = model.predict_proba(df)[0]
    confidence = proba[1]
    label = "Phishing" if confidence > threshold else "Legitimate"
    print(f"{url} → {label} (Confidence: {confidence:.2f})")
