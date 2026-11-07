
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Load dataset
data = pd.read_csv("../dataset/urls.csv")

# Create ML pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5)
    )),
    ("classifier", LogisticRegression())
])

# Train the model
model.fit(data["url"], data["label"])

# Save trained model
joblib.dump(model, "phishing_model.pkl")

print("PhishGuard AI ML model trained successfully!")
