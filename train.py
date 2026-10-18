import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from src.features import extract_features
from src.allowlist import KNOWN_DOMAINS

# 1. Load data and collapse 4 classes into benign (0) vs malicious (1)
df = pd.read_csv("data/malicious_phish.csv")
df["label"] = (df["type"] != "benign").astype(int)

# 2. Balanced sample so the model stays small and fair
n = 40000
df = pd.concat([
    df[df.label == 0].sample(n, random_state=42),
    df[df.label == 1].sample(n, random_state=42),
])

# 3. Add benign examples for well-known domains (fixes the bare-domain bias)
paths = ["", "/", "/about", "/help", "/login", "/search?q=test"]
extra = [d + p for d in KNOWN_DOMAINS for p in paths]
extra_df = pd.DataFrame({"url": extra, "type": "benign", "label": 0})
df = pd.concat([df, extra_df], ignore_index=True)

# 4. Extract features
print("Extracting features...")
X = pd.DataFrame([extract_features(u) for u in df["url"]])
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

# 5. Two models: baseline vs random forest
models = {
    "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    "random_forest": RandomForestClassifier(
        n_estimators=100, max_depth=20, min_samples_leaf=5, random_state=42, n_jobs=-1),
}

best_name, best_f1, best_model = None, 0, None
for name, model in models.items():
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print(f"\n=== {name} ===")
    print(classification_report(y_test, pred, target_names=["benign", "malicious"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, pred))
    report = classification_report(y_test, pred, output_dict=True)
    f1 = report["macro avg"]["f1-score"]
    if f1 > best_f1:
        best_name, best_f1, best_model = name, f1, model

# 6. Save the best one
joblib.dump({"model": best_model, "columns": list(X.columns)},
            "models/model.pkl", compress=3)
print(f"\nSaved best model: {best_name} (macro F1 = {best_f1:.3f})")