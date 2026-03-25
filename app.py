import streamlit as st
import pandas as pd
import time
import os

# Streamlit config
st.set_page_config(page_title="Cyber-Sentinel IDS Dashboard", page_icon="🛡️", layout="wide")

# Custom CSS for the High-End UI
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .metric-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #30363d;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .metric-card h3 { color: #8b949e; margin-bottom: 10px; font-size: 1.2rem; }
    .status-safe { color: #39ff14; font-weight: bold; font-size: 1.8rem; text-shadow: 0 0 5px #39ff14; } 
    .status-risk { color: #ffbf00; font-weight: bold; font-size: 1.8rem; text-shadow: 0 0 5px #ffbf00; }
    .status-critical { color: #ff0000; font-weight: bold; font-size: 1.8rem; text-shadow: 0 0 10px #ff0000; animation: pulse 1s infinite alternate; } 
    
    @keyframes pulse {
        from { opacity: 1; transform: scale(1); }
        to { opacity: 0.8; transform: scale(1.05); }
    }
    
    .live-terminal {
        background-color: #000000;
        color: #39ff14;
        font-family: 'Courier New', Courier, monospace;
        padding: 15px;
        border-radius: 8px;
        height: 350px;
        overflow-y: auto;
        border: 1px solid #30363d;
        box-shadow: inset 0 0 10px rgba(57, 255, 20, 0.1);
        display: flex;
        flex-direction: column-reverse;
    }
    .term-line { margin: 2px 0; font-size: 0.95rem; }
    .term-critical { color: #ff0000; font-weight: bold; }
    .term-risk { color: #ffbf00; font-weight: bold; }
    .term-safe { color: #39ff14; }
    .payload-text { color: #00ffff; font-size: 0.85rem; font-style: italic; }
</style>
""", unsafe_allow_html=True)

CSV_DB = "standalone_siem.csv"
st.title("🛡️ Sentinel IDS: Java RMI (CVE-2013-4040)")
st.markdown("Real-time Threat Detection, Payload Extraction, and Live Logging")

# Download button in the top right
colA, colB = st.columns([0.8, 0.2])
with colA:
    pass
with colB:
    if os.path.exists(CSV_DB):
        with open(CSV_DB, "rb") as f:
            st.download_button(label="📥 Download CSV Logs", data=f.read(), file_name="standalone_siem_export.csv", mime="text/csv", use_container_width=True)

placeholder = st.empty()

while True:
    with placeholder.container():
        if os.path.exists(CSV_DB):
            try:
                df = pd.read_csv(CSV_DB)
                
                # Check column existence to support older CSV format natively
                if "Extracted Payload" not in df.columns:
                    df["Extracted Payload"] = "N/A"
                    
                # Default States
                sys_status_html = "<span class='status-safe'>MONITORING (SAFE)</span>"
                threat_count = 0
                unique_attackers = 0
                
                if not df.empty:
                    statuses = df["Status"].tolist()
                    critical_df = df[df["Status"] == "CRITICAL"]
                    threat_count = critical_df.shape[0]
                    unique_attackers = critical_df["Source IP"].nunique()
                    
                    if "CRITICAL" in statuses:
                        sys_status_html = "<span class='status-critical'>CRITICAL (UNDER ATTACK)</span>"
                    elif "RISK" in statuses:
                        sys_status_html = "<span class='status-risk'>RISK (VULNERABLE)</span>"

                # Render Metric Cards
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.markdown(f"<div class='metric-card'><h3>System Status</h3>{sys_status_html}</div>", unsafe_allow_html=True)
                with col2:
                    st.markdown(f"<div class='metric-card'><h3>Target IP</h3><div style='font-size:1.8rem; color:#c9d1d9; font-weight:bold;'>192.168.56.20</div></div>", unsafe_allow_html=True)
                with col3:
                    count_color = "#ff0000" if threat_count > 0 else "#39ff14"
                    st.markdown(f"<div class='metric-card'><h3>Threat Count</h3><div style='font-size:1.8rem; color:{count_color}; font-weight:bold;'>{threat_count}</div></div>", unsafe_allow_html=True)
                with col4:
                    atk_color = "#ff0000" if unique_attackers > 0 else "#39ff14"
                    st.markdown(f"<div class='metric-card'><h3>Unique Attackers</h3><div style='font-size:1.8rem; color:{atk_color}; font-weight:bold;'>{unique_attackers}</div></div>", unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Build Live Terminal Logs
                st.subheader("💻 Live IDS Terminal")
                terminal_logs = ""
                for _, row in df.iterrows():
                    css_class = "term-safe"
                    if row["Status"] == "CRITICAL": css_class = "term-critical"
                    elif row["Status"] == "RISK": css_class = "term-risk"
                    
                    cmd_info = ""
                    if "Extracted Payload" in df.columns and pd.notna(row["Extracted Payload"]) and row["Extracted Payload"] != "N/A":
                        cmd_info = f"<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;↳ <span class='payload-text'>Payload Snippet: {row['Extracted Payload']}</span>"
                    
                    terminal_logs += f"<div class='term-line {css_class}'>root@sentinel:~# [{row['Timestamp']}] [{row['Source IP']}] [{row['Status']}] - {row['Message']} {cmd_info}</div>"
                
                st.markdown(f"<div class='live-terminal'><div>{terminal_logs}</div></div>", unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # Structured DataFrame
                st.subheader("📊 Structured Logs Table")
                st.dataframe(df.iloc[::-1].reset_index(drop=True), use_container_width=True)
                
            except pd.errors.EmptyDataError:
                st.info("Scanner initialized. Waiting for data...")
            except Exception as e:
                st.error(f"Error reading DB: {e}")
        else:
            st.info("Waiting for scanner (sentinel_logic.py) to start...")
            
    time.sleep(1)
