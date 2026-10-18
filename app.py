import joblib
import pandas as pd
import streamlit as st
from src.features import extract_features

st.set_page_config(page_title="URL Detector", page_icon="🔍")

@st.cache_resource
def load():
    return joblib.load("models/model.pkl")

bundle = load()
model, columns = bundle["model"], bundle["columns"]

st.title("🔍 Malicious URL Detector")
st.write("Paste a link to get a risk score based on the structure of the URL.")

url = st.text_input("URL", placeholder="paypa1-secure-login.com/verify?id=1")

if st.button("Check") and url.strip():
    feats = extract_features(url)
    X = pd.DataFrame([feats])[columns]
    risk = model.predict_proba(X)[0][1]

    if risk >= 0.7:
        st.error(f"🚨 Likely malicious. Risk score: {risk:.0%}")
    elif risk >= 0.4:
        st.warning(f"⚠️ Suspicious. Risk score: {risk:.0%}")
    else:
        st.success(f"✅ Looks safe. Risk score: {risk:.0%}")
    st.progress(float(risk))

    reasons = []
    if feats["suspicious_words"]:
        reasons.append(f"Contains {feats['suspicious_words']} suspicious keyword(s) like login/verify")
    if feats["has_ip"]:
        reasons.append("Uses a raw IP address instead of a domain name")
    if feats["has_at"]:
        reasons.append("Contains an '@' symbol")
    if feats["num_hyphens"] >= 2:
        reasons.append("Has several hyphens in the URL")
    if feats["url_length"] > 75:
        reasons.append("Unusually long URL")
    if feats["num_subdomains"] >= 3:
        reasons.append("Many subdomains")
    if feats["entropy"] > 4.5:
        reasons.append("Looks random or obfuscated")

    st.subheader("Why?")
    if reasons:
        for r in reasons:
            st.write("•", r)
    else:
        st.write("No obvious red flags in the URL structure.")

st.caption("Trained on a 2021 public dataset using URL text only. "
           "It can make mistakes, so don't rely on it as your only protection.")