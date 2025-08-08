import streamlit as st
import pandas as pd
import joblib
from utils import parse_log_file
from streamlit_lottie import st_lottie
import json

#css
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Lexend:wght@400;600;800&display=swap');
* {
        font-family: 'Lexend', sans-serif !important;
}

h1, h2, h3, h4, h5, h6 {
        font-weight: 600 !important;
}

.stMarkdown h1 {
        font-size: 60px;
        text-align: center;
}
            
body {
    background-color: #000000;
    color: white;
    font-family: 'Lexend', sans-serif;
}

h1 {
            font-size: 100px;
            font-weight: 800;
            text-align: center;
            margin-bottom: 20px;
            color: white;
            letter-spacing: 2px;
            -webkit-background-clip: text;
}
            
.stButton>button {
    background-color: #ff4b4b;
    color: white;
    font-weight: bold;
    font-size: 16px;
    border-radius: 25px;
    padding: 10px 25px;
    border: none;
}

</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
/* Fade In */
.fade-in {
    animation: fadeIn 2s ease-in-out forwards;
    opacity: 0;
    text-align: center;
}
@keyframes fadeIn {
    to { opacity: 1; }
}

.glow {
    text-align: center;
    font-size: 60px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 10px;
    text-shadow:
        0 0 5px #ff69b4,
        0 0 10px #ff69b4,
        0 0 20px #ff69b4,
        0 0 40px #ff1493,
        0 0 80px #ff1493;
}
</style>
""", unsafe_allow_html=True)
#hero sec

st.markdown('<h1 class=" glow fade-in">SentinelAI</h1>', unsafe_allow_html=True)
st.markdown('<p class="fade-in">Protect your systems with real-time AI-powered threat detection.</p>', unsafe_allow_html=True)

# Load Lottie animation

def load_lottie(filepath):
    with open(filepath, "r") as f:
        return json.load(f)
    
blob_animation = load_lottie("app/blob.json")
st_lottie(blob_animation, height=300)

#file upload, model load, prediction

# Load trained model
model = joblib.load('models/best_model.pkl')

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")
# Upload log file
col1, col2 = st.columns([2,1]) #wider left, smaller right

with col1:
    st.subheader("Upload Log File")
    st.write("Upload your system's `auth.log` file. This will be parsed and analyzed for potential threats.")
    uploaded_file = st.file_uploader("Choose an auth.log file", type=["log", "txt"])

    if uploaded_file:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_file:
            temp_file.write(uploaded_file.read())
            temp_file_path = temp_file.name
        st.success("File uploaded successfully!")

        # Parse the log file
        df = parse_log_file(temp_file_path)
        st.markdown("### 📊 Parsed Log Data")
        st.write("This table shows the extracted details from your log file including timestamps, users, IPs, and ports.")
        df_preview = df.head().copy()
        df_preview.index = range(1, len(df_preview) + 1)
        st.dataframe(df_preview)

        if df.empty:
            st.warning("No valid log entries found in the uploaded file.")
        else:
            df['user'] = pd.factorize(df['user'])[0]
            df['ip'] = pd.factorize(df['ip'])[0]
            df['port'] = pd.to_numeric(df['port'])
            
            X = df[['user', 'ip', 'port']]
            predictions = model.predict(X)
            df['prediction'] = predictions
            df['Threat'] = df['prediction'].map({0:"✅ Safe", 1: "🚨 Threat"})

            st.markdown("### 🤖 AI Threat Predictions")
            st.write("This model analyzes the parsed data and classifies each login attempt as either Safe or a Threat.")
            result_df = df[['timestamp', 'user', 'ip', 'port', 'status', 'prediction', 'Threat']].copy()
            result_df.index = range(1, len(result_df) + 1)
            st.dataframe(result_df)

with col2:
    if uploaded_file and not df.empty:
        # Stats
        threat_count = df['prediction'].sum()
        safe_count = len(df) - threat_count

        st.markdown("### 📊 Summary")
        st.write("This chart gives you a visual snapshot of the number of safe vs. threat entries.")
        st.metric("🚨 Total Threats", threat_count)
        st.metric("✅ Safe Logins", safe_count)

        st.markdown("### 📈 Threat Overview")
        st.write("Key statistics based on the predictions. Quickly assess your system’s current threat level.")
        st.bar_chart(df['Threat'].value_counts())
    else:
        st.info("Awaiting file upload to display metrics.")
# ========== 5. Footer / Company Logos (Optional) ========== #
st.markdown("""
<div style="text-align: center;">
    <p style="font-size:14px;">Powered by Streamlit & AI | Created by Nashita Kausar 🧠</p>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["Threat Dashboard", "IP Reputation", "About"])

import requests
with tab2:
    st.markdown("## 🔐 IP Reputation Checker")
    st.write("Check the reputation of an IP address to see if it has been associated with malicious activity.")

    ip = st.text_input("Enter an IP address", placeholder="e.g., 192.152.1.1")

    if ip:
        with st.spinner("Checking IP reputation..."):
            headers = {
                'Key': st.secrets["ABUSEIPDB_API_KEY"],
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
            }

            response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
            if response.status_code == 200:
                result = response.json()['data']
                st.success(f"IP {ip} Reputation:")
                st.metric("Abuse Score", result['abuseConfidenceScore'])
                st.write(f"Country: {result.get('countryCode', 'N/A')}")
                st.write(f"ISP: {result.get('isp', 'N/A')}")
                st.write(f"Domain: {result.get('domain', 'N/A')}")
                st.write(f"Total Reports: {result.get('totalReports', 0)}")
                st.write(f"Last Reported: {result.get('lastReportedAt', 'N/A')}")
                st.write(f"Usage Type: {result.get('usageType', 'N/A')}")

                if result['abuseConfidenceScore'] > 0:
                    st.warning("⚠️ This IP has been reported for abusive behavior.")

            else:
                st.error("Error fetching IP reputation. Please try again later.")
import os
from PIL import Image
import base64
with tab3:
    st.markdown("## About the Creator!")
    st.markdown("""
    <div style="text-align: center; font-size: 28px; font-weight: bold; margin-bottom: 15px;">
                Hi, I'm Nashita!
    </div>
    """, unsafe_allow_html=True)

    # Load and display profile image
    image_path = os.path.join(os.path.dirname(__file__), 'assets', 'nashitaimg.png')
    profile_image = Image.open(image_path)

    #center and sizing image
    st.markdown(f"""
                <div style="display: flex; justify-content: center; margin-bottom: 20px;">
                <img src="data:image/png;base64,{base64.b64encode(open(image_path, "rb").read()).decode()}"
                style="width: 200px; height: 200px; border-radius: 50%; object-fit: cover;" />
                </div>
                """, unsafe_allow_html=True)
    st.markdown("""
    **IT - Software Development + Data Technologies** Student @ the University of Cincinnati
    
    I'm super passionate about machine learning, cybersecurity, and building innovative solutions to real-world problems!
    """)

    st.markdown("## About SentinelAI!")
    st.markdown("""
    **SentinelAI** is a real-time threat detection system that leverages machine learning to analyze system logs and identify potential security threats. 
    It provides an intuitive dashboard for users to upload their log files, view parsed data, and receive AI-powered predictions on login attempts.
    The project aims to enhance cybersecurity awareness and empower users with actionable insights into their system's security posture.
    
    The app offers:
    - 📊 **Log File Parsing** and Feature Extraction
    - 🤖 **ML-Powered Threat Detection** (built with scikit-learn)
    - 🌐 **IP Reputation Scanning** using live data from [AbuseIPDB](https://abuseipdb.com)
    - 🎯 A **fully functional Streamlit dashboard** with metrics, charts, and beautiful UI
    - 🧪 Built-in support for uploading `.log` files and generating threat reports

    This project combines AI, security, and usability, which makes it ideal for SOC teams, sysadmins, and security enthusiasts!
    """)

    st.markdown("## ⚙️ Tech Stack")
    st.markdown("""
    - **Frontend:** Streamlit + HTML/CSS (custom styled)
    - **Backend:** Python
    - **ML Model:** Random Forest Classifier (trained on parsed `auth.log` features)
    - **APIs Used:** AbuseIPDB (IP reputation lookup)
    - **Libraries:** pandas, scikit-learn, joblib, requests, streamlit-lottie
    """) 

    st.markdown("## 🔍 Real-World Application")
    st.markdown("""
    - Simulates how SIEM (Security Information & Event Management) tools identify and flag threats
    - Gives cybersecurity analysts a user-friendly interface to visualize system access logs
    - Easily extendable to handle multiple log formats, geolocation, and even alert systems
    """)
