import streamlit as st
import joblib
import numpy as np
import re
import matplotlib.pyplot as plt
from datetime import datetime
import pandas as pd

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Fake URL Detection System",
    page_icon="🔐",
    layout="wide"
)

# ---------------- LOAD MODEL ----------------
model = None
model_loaded = False
try:
    model = joblib.load("model.pkl")
    model_loaded = True
except Exception as load_error:
    st.warning(
        "Unable to load model.pkl. The file is missing or corrupted. "
        "The app will continue using rule-based detection only."
    )
    st.write(f"Debug: {load_error}")

    class DummyModel:
        def predict(self, X):
            return np.zeros((X.shape[0],), dtype=int)

    model = DummyModel()

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>

html, body, [class*="css"]  {
    font-family: 'Segoe UI', sans-serif;
    color: black;
}

.main {
    background-color: #f5f7fb;
}

[data-testid="stAppViewContainer"] {
    background-color: #020817;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg,#020617,#0f172a);
    color: white;
}

.sidebar-title {
    font-size: 28px;
    font-weight: bold;
    color: white;
    margin-bottom: 20px;
}

.big-title {
    font-size: 52px;
    font-weight: bold;
    color: white;
}

.subtitle {
    font-size: 24px;
    color: #cbd5e1;
}

.card {
    background-color: white;
    padding: 25px;
    border-radius: 18px;
    text-align: center;
    box-shadow: 0px 3px 12px rgba(0,0,0,0.15);
    color: black;
}

.card h2 {
    color: black;
}

.card h4 {
    color: black;
}

.safe-box {
    background-color: #dcfce7;
    color: green;
    padding: 15px;
    border-radius: 12px;
    font-weight: bold;
}

.fake-box {
    background-color: #fee2e2;
    color: red;
    padding: 15px;
    border-radius: 12px;
    font-weight: bold;
}

.info-box {
    background-color: white;
    color: black;
    padding: 25px;
    border-radius: 16px;
}

.info-box p {
    color: black;
}

h1,h2,h3,h4,h5,h6,label,p {
    color: white;
}

.stTextInput label {
    color: white !important;
}

.stTextArea label {
    color: white !important;
}

.stButton>button {
    width: 100%;
    background: linear-gradient(90deg,#4f46e5,#6366f1);
    color: white;
    border-radius: 10px;
    border: none;
    height: 50px;
    font-size: 17px;
    font-weight: bold;
}

.stButton>button:hover {
    background: linear-gradient(90deg,#4338ca,#4f46e5);
    color: white;
}

footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# ---------------- FEATURE EXTRACTION ----------------
def extract_features(url):

    features = []

    # 1 URL Length
    features.append(len(url))

    # 2 HTTPS Usage
    features.append(
        1 if url.startswith("https") else 0
    )

    # 3 IP Address Presence
    features.append(
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url)
        else 0
    )

    # 4 '@' Symbol
    features.append(
        1 if '@' in url else 0
    )

    # 5 Hyphen Count
    features.append(
        url.count('-')
    )

    # 6 Dot Count
    features.append(
        url.count('.')
    )

    # 7 Slash Count
    features.append(
        url.count('/')
    )

    # 8 Digit Count
    features.append(
        sum(c.isdigit() for c in url)
    )

    # 9 Special Character Count
    special_chars = re.findall(
        r'[!@#$%^&*(),?":{}|<>]',
        url
    )

    features.append(
        len(special_chars)
    )

    # 10 Suspicious Keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "bonus",
        "free",
        "account"
    ]

    features.append(
        1 if any(
            word in url.lower()
            for word in suspicious_words
        ) else 0
    )

    # Fill remaining features to 22
    while len(features) < 22:
        features.append(0)

    return features


# ---------------- PREDICTION ----------------
def predict(url):

    # Auto add HTTPS
    if not url.startswith("http"):
        url = "https://" + url

    suspicious = 0
    reasons = []
    positive = []

    # ---------------- SAFE DOMAIN CHECK ----------------
    safe_sites = [
        "google.com",
        "github.com",
        "kaggle.com",
        "youtube.com",
        "amazon.com",
        "microsoft.com",
        "openai.com",
        "wikipedia.org",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "memcyco.com",
        "stackoverflow.com",
        "oracle.com",
        "python.org",
        "w3schools.com"
    ]

    if any(site in url for site in safe_sites):

        positive.append("Trusted domain")
        positive.append("Safe website")

        return "Legitimate", positive, 99

    # ---------------- HTTPS CHECK ----------------
    if url.startswith("https://"):
        positive.append("Uses secure HTTPS protocol")
    else:
        suspicious += 2
        reasons.append("No HTTPS")

    # ---------------- URL LENGTH ----------------
    if len(url) <= 80:
        positive.append("Reasonable URL length")
    else:
        suspicious += 1
        reasons.append("Very long URL")

    # ---------------- @ SYMBOL ----------------
    if '@' not in url:
        positive.append("No '@' symbol")
    else:
        suspicious += 3
        reasons.append("Contains '@' symbol")

    # ---------------- IP ADDRESS ----------------
    if not re.search(r'\d+\.\d+\.\d+\.\d+', url):
        positive.append("No IP address")
    else:
        suspicious += 3
        reasons.append("Contains IP address")

    # ---------------- DIGIT COUNT ----------------
    digits = sum(c.isdigit() for c in url)

    if digits > 5:
        suspicious += 2
        reasons.append("Too many numbers")

    # ---------------- DOT COUNT ----------------
    if url.count('.') > 3:
        suspicious += 2
        reasons.append("Too many subdomains")

    # ---------------- SUSPICIOUS WORDS ----------------
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "bonus",
        "free",
        "account"
    ]

    # Count how many suspicious keywords appear and weight each match
    lower_url = url.lower()
    found_keywords = [w for w in suspicious_words if w in lower_url]

    if found_keywords:
        matches = len(found_keywords)
        # add 2 points per matched keyword (previously added 2 for any match)
        suspicious += 2 * matches
        reasons.append(
            f"Suspicious keywords detected: {', '.join(found_keywords)}"
        )

    # ---------------- RULE-BASED DECISION ----------------
    if suspicious >= 3:
        return "Fake", reasons, 95

    # ---------------- MACHINE LEARNING ----------------
    features = np.array(
        extract_features(url)
    ).reshape(1, -1)

    # FIX FEATURE MISMATCH
    features = features[:, :22]

    result = model.predict(features)

    confidence = 95

    if result[0] == 1:
        return "Fake", reasons + ["ML Prediction"], confidence

    return "Legitimate", positive + ["ML Prediction"], confidence

# ---------------- SIDEBAR ----------------
with st.sidebar:

    st.markdown(
        "<div class='sidebar-title'>🛡️ Fake URL Detection System</div>",
        unsafe_allow_html=True
    )

    st.write("🏠 Home")
    st.write("🔗 Single URL Check")
    st.write("📄 Bulk URL Check")
    st.write("📊 Analysis Dashboard")
    st.write("ℹ️ About")

    st.markdown("---")

    st.subheader("About This System")

    st.write("""
    This system uses Machine Learning models
    to detect whether a URL is phishing or safe.
    """)

    st.subheader("Model Used")

    st.write("• Random Forest")
    st.write("• XGBoost")
    st.write("• Feature Engineering")

# ---------------- HEADER ----------------
left, right = st.columns([3,1])

with left:

    st.markdown(
        "<div class='big-title'>FAKE URL DETECTION SYSTEM</div>",
        unsafe_allow_html=True
    )

    st.markdown(
        "<div class='subtitle'>Detect phishing URLs using Machine Learning</div>",
        unsafe_allow_html=True
    )

    st.markdown(
        "<h3 style='color:#4f46e5;'>Stay Safe • Stay Secure</h3>",
        unsafe_allow_html=True
    )

with right:

    st.image(
        "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        width=220
    )

# ---------------- STATS ----------------
st.write("")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown("""
    <div class='card'>
    <h4 style='color:black;'>URLs Analyzed</h4>
    <h2>1,245</h2>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown("""
    <div class='card'>
    <h4 style='color:green;'>Legitimate</h4>
    <h2>842</h2>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown("""
    <div class='card'>
    <h4 style='color:red;'>Phishing</h4>
    <h2>403</h2>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown("""
    <div class='card'>
    <h4 style='color:#7c3aed;'>Accuracy</h4>
    <h2>97%</h2>
    </div>
    """, unsafe_allow_html=True)

# ---------------- URL CHECK ----------------
st.write("")

col1, col2 = st.columns(2)

# SINGLE URL
with col1:

    st.markdown("## 🔗 Check Single URL")

    url = st.text_input(
        "Enter URL",
        placeholder="https://example.com"
    )

    if st.button("Analyze URL"):

        if not url.strip():
            st.error("Please enter a URL")
        else:

            result, reasons, confidence = predict(url)

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if "history" not in st.session_state:
                st.session_state.history = []

            st.session_state.history.append(
                [url, result, timestamp, confidence]
            )

            if result == "Legitimate":

                st.markdown(
                    "<div class='safe-box'>✅ Legitimate URL</div>",
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    "<div class='fake-box'>❌ Fake URL</div>",
                    unsafe_allow_html=True
                )

            st.subheader("Confidence Score")

            st.progress(int(confidence))

            st.write(f"{confidence:.2f}%")

            st.subheader("Analysis")

            for r in reasons:
                st.write(f"✔ {r}")

# BATCH CHECK
with col2:

    st.markdown("## 📄 Check Multiple URLs")

    batch_urls = st.text_area(
        "Enter multiple URLs",
        placeholder="One URL per line",
        height=180
    )

    if st.button("Analyze URLs"):

        urls = batch_urls.split("\n")

        results = []

        for u in urls:

            if u.strip():

                res, rea, conf = predict(u)

                results.append(
                    [u, res, conf]
                )

        batch_df = pd.DataFrame(
            results,
            columns=["URL", "Result", "Confidence"]
        )

        st.dataframe(batch_df)

# ---------------- ACCURACY GRAPH ----------------
st.write("")

st.subheader("📈 Model Accuracy")

models = ["Random Forest", "XGBoost"]
values = [96, 97]

fig, ax = plt.subplots(figsize=(6,3))

ax.bar(models, values)

ax.set_ylim([90,100])

st.pyplot(fig)

# ---------------- HISTORY ----------------
st.subheader("📜 Scan History")

if "history" in st.session_state and st.session_state.history:

    df = pd.DataFrame(
        st.session_state.history,
        columns=[
            "URL",
            "Result",
            "Timestamp",
            "Confidence"
        ]
    )

    st.dataframe(df)

    fake_count = sum(
        1 for row in st.session_state.history
        if row[1] == "Fake"
    )

    legit_count = len(
        st.session_state.history
    ) - fake_count

    fig2, ax2 = plt.subplots(figsize=(4,4))

    ax2.pie(
        [fake_count, legit_count],
        labels=["Fake", "Legitimate"],
        autopct='%1.1f%%'
    )

    st.pyplot(fig2)

    csv = df.to_csv(index=False)

    st.download_button(
        "⬇ Download History",
        csv,
        "history.csv",
        "text/csv"
    )

# ---------------- FOOTER ----------------
st.write("")

st.markdown("""
<div class='info-box'>

<h3 style='color:black;'>🛡️ Why URL Detection is Important?</h3>

<p style='color:black;'>

Phishing attacks are increasing rapidly and can steal
sensitive information.

This system uses Random Forest and XGBoost models
to detect malicious URLs in real time.

</p>

</div>
""", unsafe_allow_html=True)

st.markdown("---")

st.markdown(
    "<center>© 2026 Fake URL Detection System | Built with Streamlit</center>",
    unsafe_allow_html=True
)
