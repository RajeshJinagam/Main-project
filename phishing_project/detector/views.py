import os
import joblib
import pandas as pd
from django.shortcuts import render
from .utils import extract_features_from_url

# Correct model path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_project', 'model', 'phishing_model.pkl')
print("📂 Model path:", MODEL_PATH)
print("📂 Exists?", os.path.exists(MODEL_PATH))

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    model = None
    print(f"❌ Error loading model: {e}")


# Feature names (must match training)
feature_columns = [
    'has_at_symbol', 'url_length', 'dot_count', 'has_ip', 'uses_https',
    'has_hyphen', 'subdirectory_count', 'special_char_count',
    'domain_length', 'has_login_keyword', 'is_trusted_domain'
]

def home(request):
    result = None
    error = None

    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            features = extract_features_from_url(url)

            if model is None:
                raise Exception("Model not loaded!")

            df = pd.DataFrame([features], columns=feature_columns)
            prediction = model.predict(df)[0]
            prob = model.predict_proba(df)[0][1]
            result = f"{'Phishing' if prediction == 1 else 'Legitimate'} (Confidence: {prob:.2f})"

        except Exception as e:
            error = f"Error: {str(e)}"

    return render(request, 'home.html', {'result': result, 'error': error})
