import pandas as pd
import re
import time
from urllib.parse import urlparse
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

start = time.time()

# 🔐 Trusted domains
trusted_domains = [
    "google.com", "microsoft.com", "amazon.com", "paypal.com",
    "accounts.google.com", "github.com", "wikipedia.org", "linkedin.com"
]

# 🧠 Feature extraction
def extract_features_from_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return [
        1 if '@' in url else 0,
        len(url),
        url.count('.'),
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        1 if url.lower().startswith('https') else 0,
        1 if '-' in domain else 0,
        len(parsed.path.split('/')) - 1,
        sum(url.count(c) for c in ['?', '=', '&', '%']),
        len(domain),
        1 if re.search(r'(login|secure|bank|account|verify|signin)', url.lower()) else 0,
        1 if any(t in domain for t in trusted_domains) else 0
    ]

# 🔠 Feature names
feature_columns = [
    'has_at_symbol', 'url_length', 'dot_count', 'has_ip', 'uses_https',
    'has_hyphen', 'subdirectory_count', 'special_char_count', 'domain_length',
    'has_login_keyword', 'is_trusted_domain'
]

# 📄 Load dataset
df = pd.read_csv('phishing.csv')
df.rename(columns={'Label': 'Result'}, inplace=True)
df['Result'] = df['Result'].map({'bad': 1, 'good': 0})
df['URL'] = df['URL'].astype(str)
df.dropna(subset=['URL', 'Result'], inplace=True)

# 🔽 Optional: Reduce dataset for faster training (remove if not needed)
df = df.sample(n=2000, random_state=42)

# 🛠 Feature extraction
X = pd.DataFrame(df['URL'].apply(extract_features_from_url).tolist(), columns=feature_columns)
y = df['Result']

# 🔀 Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=42
)

# ⚙️ Define scaled models
lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))
svc = make_pipeline(StandardScaler(), SVC(probability=True))
dt = DecisionTreeClassifier(max_depth=5)

# 🤖 LSD hybrid model
lsd_model = VotingClassifier(estimators=[
    ('lr', lr),
    ('svc', svc),
    ('dt', dt)
], voting='soft')

# 🚀 Train model
lsd_model.fit(X_train, y_train)

# 💾 Save model
joblib.dump(lsd_model, 'lsd_model.pkl')
print("✅ LSD hybrid model saved as lsd_model.pkl")

# 📊 Evaluate
y_pred = lsd_model.predict(X_test)
accuracy = round(accuracy_score(y_test, y_pred) * 100)

print(f"\n✅ Accuracy: {accuracy}%")
print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred))
print("\n📉 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

end = time.time()
print(f"\n⏱️ Training and evaluation completed in {round(end - start, 2)} seconds.")
