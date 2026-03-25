import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="Custom Standalone SIEM", page_icon="🛡️", layout="wide")
st.markdown("<h1 style='text-align: center; color: #00FF00;'>🛡️ Standalone Cyber Sentinel</h1>", unsafe_allow_html=True)

placeholder = st.empty()

while True:
    try:
        df = pd.read_csv("standalone_siem.csv")
        with placeholder.container():
            col1, col2 = st.columns(2)
            col1.metric("Status", "UNDER ATTACK" if "CRITICAL" in df.values else "MONITORING")
            col2.metric("Target IP", "192.168.56.20")
            
            st.write("### Incident Logs")
            st.dataframe(df.iloc[::-1], use_container_width=True)
            
            if "CRITICAL" in df.values:
                st.error("🚨 MAJOR INCIDENT: Java RMI Remote Code Execution Detected!")
            elif "RISK" in df.values:
                st.warning("⚠️ PROACTIVE ALERT: Vulnerable Java Version Identified on Target.")
    except:
        st.info("Waiting for data...")
    time.sleep(1)
