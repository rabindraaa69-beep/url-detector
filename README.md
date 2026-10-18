# \# 🔍 Malicious URL Detector

# 

# A machine learning app that scores how likely a URL is to be malicious, using only the structure of the link, and explains why.

# 

# Live demo: https://url-detector-7cnb9ivo4mjjzszgxymfq7.streamlit.app/

# 

# \## How it works

# 1\. \*\*Data:\*\* Malicious URLs Dataset (Kaggle, \~651K URLs). Phishing, malware and defacement are merged into one "malicious" class, and a balanced sample is used.

# 2\. \*\*Features:\*\* 15 hand-built features such as URL length, dots, hyphens, digits, IP address use, subdomain count, suspicious keywords, entropy and a known-domain flag.

# 3\. \*\*Models:\*\* Logistic regression (baseline) vs random forest.

# 4\. \*\*App:\*\* Streamlit page showing a risk score and the reasons behind it.

# 

# \## Results

# | Model | Accuracy | Macro F1 |

# |---|---|---|

# | Logistic regression | 65% | 0.65 |

# | Random forest | 82% | 0.82 |







# \## Design choices

# \- `http://`, `https://` and `www.` are stripped before feature extraction, so the model can't cheat by learning protocol presence.

# \- The dataset has few bare domains labeled benign, so a model trained on it flags sites like `google.com`. I added an allowlist of well-known domains and benign training examples to reduce this.

# 

# \## Limitations

# \- Trained on 2021 data using URL text only (no page content, WHOIS or reputation lookups).

# \- The allowlist is a patch, not a full solution, and lookalike domains can still fool the model.

# \- It is a learning project, not a replacement for real security tools.

# 

# \## Run locally

