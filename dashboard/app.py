import streamlit as st
import sqlite3
import pandas as pd
import os
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "../database/dns_logs.db")

st.set_page_config(
    page_title="DNS Exfil Detector",
    page_icon="🔍",
    layout="wide"
)

def get_alerts():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def get_stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        total    = conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
        alerts   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
        conn.close()
        return total, alerts, critical
    except:
        return 0, 0, 0

st.title("🔍 DNS Exfiltration Detection System")
st.markdown("Real-time DNS traffic monitoring and threat detection")
st.divider()

total, alerts, critical = get_stats()
col1, col2, col3 = st.columns(3)
col1.metric("Total DNS Queries", total)
col2.metric("Total Alerts", alerts)
col3.metric("Critical Alerts", critical)

st.divider()

st.subheader("🚨 Alert Feed")
df = get_alerts()

if df.empty:
    st.info("No alerts yet — run main.py and simulator to generate alerts")
else:
    def color_severity(val):
        colors = {
            'CRITICAL': 'background-color: #ff4444; color: white',
            'MEDIUM':   'background-color: #ffaa00; color: black',
            'LOW':      'background-color: #ffff00; color: black'
        }
        return colors.get(val, '')

    styled = df.style.map(color_severity, subset=['severity'])
    st.dataframe(styled, width='stretch')

    st.subheader("📊 Risk Score Distribution")
    st.bar_chart(df.set_index('timestamp')['score'])

st.divider()
st.caption("Auto-refreshes every 5 seconds")
time.sleep(5)
st.rerun()
