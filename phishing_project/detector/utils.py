import re
from urllib.parse import urlparse

trusted_domains = [
    "google.com", "microsoft.com", "amazon.com", "paypal.com",
    "accounts.google.com", "github.com", "wikipedia.org", "linkedin.com"
]

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
        1 if any(t in domain for t in trusted_domains) else 0
    ]
