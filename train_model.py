import pandas as pd
import joblib
import re
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Trusted domain list
trusted_domains = [
    "google.com", "microsoft.com", "amazon.com", "paypal.com",
    "accounts.google.com", "github.com", "wikipedia.org", "linkedin.com"
]

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
        1 if '-' in domain else 0,
        len(parsed.path.split('/')) - 1,
        sum(url.count(c) for c in ['?', '=', '&', '%']),
        len(domain),
        1 if re.search(r'(login|secure|bank|account|verify|signin)', url.lower()) else 0,
        1 if any(t in domain for t in trusted_domains) else 0
    ]

# ✅ Feature names (same order as above)
feature_columns = [
    'has_at_symbol', 'url_length', 'dot_count', 'has_ip', 'uses_https',
    'has_hyphen', 'subdirectory_count', 'special_char_count', 'domain_length',
    'has_login_keyword', 'is_trusted_domain'
]

# ✅ Load dataset
df = pd.read_csv('phishing.csv')
df.rename(columns={'Label': 'Result'}, inplace=True)
df['Result'] = df['Result'].map({'bad': 1, 'good': 0})
df['URL'] = df['URL'].astype(str)
df.dropna(subset=['URL', 'Result'], inplace=True)

# ✅ Extract features
X = pd.DataFrame(df['URL'].apply(extract_features_from_url).tolist(), columns=feature_columns)
y = df['Result']

# ✅ Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)

# ✅ Train XGBoost model
model = XGBClassifier(
    n_estimators=300,
    max_depth=10,
    learning_rate=0.1,
    scale_pos_weight=2,
    use_label_encoder=False,
    eval_metric='logloss'
)
model.fit(X_train, y_train)
joblib.dump(model, 'phishing_model.pkl')
print("✅ XGBoost model trained and saved as phishing_model.pkl")

# ✅ Evaluation
accuracy = accuracy_score(y_test, model.predict(X_test))
print("\n📊 Accuracy:", accuracy)
print("\n📉 Confusion Matrix:\n", confusion_matrix(y_test, model.predict(X_test)))
print("\n📝 Classification Report:\n", classification_report(y_test, model.predict(X_test)))

# ✅ Feature Importance Plot
plt.figure(figsize=(10, 6))
sns.barplot(x=model.feature_importances_, y=feature_columns)
plt.title("🔍 Feature Importance for Phishing Detection")
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.tight_layout()
plt.savefig("feature_importance.png")
plt.show()
print("📊 Feature importance saved to feature_importance.png")
