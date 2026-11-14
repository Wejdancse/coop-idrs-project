import streamlit as st
import sqlite3
import pandas as pd
import joblib
import subprocess
import os
from datetime import datetime

DB_PATH = "/home/wejdan/idrs/db/idrs.db"
MODEL_PATH = "/home/wejdan/idrs/isolation_forest_model.pkl"
LOG_PATH = "/home/wejdan/idrs/logs/incidents.log"

st.set_page_config(page_title="IDRS Dashboard", layout="wide")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("<h1 style='text-align:center;'>IDRS Login</h1>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1,1,1])
    with col2:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login", use_container_width=True):
           if username == os.getenv("IDRS_USER", "admin") and password == os.getenv("IDRS_PASS", "changeme"):
                st.session_state.authenticated = True
                st.rerun()
        else:
                st.error("Invalid credentials")
    st.stop()


st.markdown("""
<style>
    .stApp { background-color: #0D0A10; }
    .stMetric {
        background-color: #2B3242;
        border: 3px solid #4EA3BA;
        border-radius: 10px;
        padding: 14px;
    }
    div[data-testid="stMetricValue"] { color: #48F2FB; font-size: 24px !important; font-weight: 700; }
    div[data-testid="stMetricLabel"] { color: #FAFAFA; }
    h1 {
        color: #E967EA; border: 3px solid #E967EA; border-radius: 8px;
        padding: 8px 12px !important; font-size: 26px !important; font-weight: 800;
    }
    h2, h3 {
        color: #48F2FB !important; background-color: #1a1a1a;
        border: 2px solid #48F2FB; border-radius: 8px;
        padding: 5px 10px !important; font-size: 15px !important; display: inline-block;
    }
    [data-testid="stDataFrame"] { border: 2px solid #2B3242; border-radius: 10px; }
    .stTabs [data-baseweb="tab"] { color: #FAFAFA; font-size: 14px; }
    p, span, label { color: #FAFAFA; }

    header[data-testid="stHeader"] {
        height: 0px;
        background: transparent;
    }
    div[data-testid="stToolbar"] {
        display: none;
    }
    .block-container {
        padding-top: 1rem !important;
    }
</style>
""", unsafe_allow_html=True)

SID_NAMES = {
    "1:1000001:1": "ICMP Ping", "1:1000002:1": "SSH Brute-Force (Hydra)",
    "1:1000003:1": "Port Scan (Nmap)", "1:1000004:1": "Baseline Traffic",
    "1:1000005:1": "SQL Injection - UNION SELECT", "1:1000006:1": "SQL Injection - OR 1=1",
    "1:1000007:1": "SQL Injection - DROP TABLE", "1:1000008:1": "XSS - Script Tag",
    "1:1000009:1": "XSS - onerror", "1:1000010:1": "Directory Traversal",
    "1:1000011:1": "Directory Traversal (Encoded)", "1:1000012:1": "Command Injection - Semicolon",
    "1:1000013:1": "Command Injection - Pipe", "1:1000014:1": "WordPress wp-login Probe",
    "1:1000015:1": "WordPress xmlrpc Probe", "1:1000016:1": "Admin Panel Probe",
    "1:1000017:1": "phpMyAdmin Probe", "1:1000018:1": "Bash Shellshock Injection",
    "1:1000019:1": "OpenSSL Heartbleed Probe", "1:1000020:1": "Web Shell Connection",
    "1:1000021:1": "Log4Shell JNDI Lookup", "1:1000022:1": "sqlmap Scanner",
    "1:1000023:1": "Nikto Scanner", "1:1000024:1": "Nmap NSE Scripting",
    "1:1000025:1": "curl Automated Tool", "1:1000026:1": "python-requests Tool",
    "1:1000027:1": "SSH Version Scan Probe", "1:1000028:1": "Anonymous FTP Login",
    "1:1000029:1": "SMB NULL Session",
}

SEVERITY_MAP = {
    "1000002": "Critical", "1000005": "Critical", "1000006": "Critical", "1000007": "Critical",
    "1000008": "Critical", "1000009": "Critical", "1000010": "Critical", "1000011": "Critical",
    "1000012": "Critical", "1000013": "Critical", "1000018": "Critical", "1000019": "Critical",
    "1000020": "Critical", "1000021": "Critical", "1000028": "Critical", "1000029": "Critical",
    "1000001": "Low", "1000003": "Medium", "1000014": "Medium", "1000015": "Medium",
    "1000016": "Medium", "1000017": "Medium", "1000022": "Low", "1000023": "Low",
    "1000024": "Low", "1000025": "Low", "1000026": "Low", "1000027": "Low",
}

@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)

def load_raw_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM alerts WHERE label IS NOT NULL", conn)
    conn.close()
    return df

def engineer_features(df):
    df = df[df['src_ip'] != '192.168.56.10'].copy()
    df['parsed_time'] = pd.to_datetime(df['timestamp'], format='%m/%d-%H:%M:%S.%f', errors='coerce')
    df = df.dropna(subset=['parsed_time'])
    df['time_window'] = df['parsed_time'].dt.floor('3s')
    features = df.groupby(['src_ip', 'time_window']).agg(
        packet_count=('id', 'count'), distinct_ports=('dst_port', 'nunique'),
        distinct_protocols=('protocol', 'nunique'),
        hour_of_day=('parsed_time', lambda x: x.dt.hour.iloc[0]),
        label=('label', lambda x: x.mode()[0]),
        signature=('signature', lambda x: x.mode()[0] if not x.mode().empty else None),
        action_taken=('action_taken', lambda x: x.mode()[0] if not x.mode().empty else None)
    ).reset_index()
    return features, df

def run_ml_predictions(features, model):
    feature_cols = ['packet_count', 'distinct_ports', 'distinct_protocols', 'hour_of_day']
    predictions = model.predict(features[feature_cols])
    features['ml_flagged'] = pd.Series(predictions).map({1: False, -1: True})
    return features

def add_detection_method(features):
    features['snort_flagged'] = features['label'] == 'attack'
    def method(row):
        if row['snort_flagged'] and row['ml_flagged']: return 'Signature + ML'
        elif row['snort_flagged']: return 'Signature Only'
        elif row['ml_flagged']: return 'ML Only'
        else: return 'Normal'
    features['detection_method'] = features.apply(method, axis=1)
    return features

def check_service(name):
    result = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    return result.stdout.strip() == "active"

with st.spinner("Loading live data and running ML predictions..."):
    model = load_model()
    raw_df = load_raw_data()
    features, raw_clean = engineer_features(raw_df)
    features = run_ml_predictions(features, model)
    features = add_detection_method(features)
    features['attack_name'] = features['signature'].map(SID_NAMES).fillna(features['signature'])

def extract_sid(sig):
    if sig and ":" in str(sig):
        return str(sig).split(":")[1]
    return None
features['sid'] = features['signature'].apply(extract_sid)
features['severity'] = features['sid'].map(SEVERITY_MAP).fillna('Low')

st.markdown("<h1 style='text-align:center;'>IDRS \u2014 Intrusion Detection & Response Dashboard</h1>", unsafe_allow_html=True)
st.caption(f"Two-Layer Detection: Snort Signatures + Isolation Forest ML  \u2022  Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

tab1, tab2 = st.tabs(["\U0001F4CA Overview", "\U0001F6E1\uFE0F Operations"])

# ============ TAB 1: OVERVIEW ============
with tab1:
    total_windows = len(features)
    attack_windows = len(features[features['label'] == 'attack'])
    normal_windows = len(features[features['label'] == 'normal'])
    blocked_count = len(features[features['action_taken'].isin(['blocked', 'blocked_temp'])])
    critical_count = len(features[features["severity"] == "Critical"])
    if critical_count >= 20:
        threat = "\U0001F534 Critical"
    elif critical_count >= 10:
        threat = "\U0001F7E0 High"
    elif critical_count >= 3:
        threat = "\U0001F7E1 Medium"
    else:
        threat = "\U0001F7E2 Low"

    events_per_min = len(features[features["time_window"] > features["time_window"].max() - pd.Timedelta(minutes=1)]) if not features.empty else 0

    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    c1.metric("Traffic Windows", f"{total_windows:,}")
    c2.metric("Attacks Detected", f"{attack_windows:,}")
    c3.metric("Normal Traffic", f"{normal_windows:,}")
    c4.metric("Blocked", f"{blocked_count:,}")
    c5.metric("Threat Level", threat)
    c6.metric("Events / Min", events_per_min)
    c7.metric("System Status", "\U0001F7E2 Running" if check_service("idrs-snort") else "\U0001F534 Offline")

    st.divider()
    if attack_windows > 0:
        latest = features[features['label']=='attack'].sort_values('time_window', ascending=False).iloc[0]
        st.error(f"""
### Active Incident
**Attack:** {latest.attack_name}  |  **Source:** {latest.src_ip}  |  **Severity:** {latest.severity}  |  **Detection:** {latest.detection_method}  |  **Action:** {latest.action_taken}
""")

    st.divider()
    import altair as alt

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Alerts Over Time")
        timeline = features.copy()
        timeline['minute'] = timeline['time_window'].astype(str).str[:16]
        timeline_counts = timeline[timeline['label']=='attack'].groupby('minute').size().reset_index(name='count')
        if not timeline_counts.empty:
            chart = alt.Chart(timeline_counts).mark_line(color="#E967EA", point=True).encode(
                x=alt.X('minute:N', title='Time'), y=alt.Y('count:Q', title='Attacks')
            ).properties(height=260).configure_axis(labelColor='#FAFAFA', titleColor='#FAFAFA', gridColor='#2B3242').configure_view(strokeWidth=0)
            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No attack data yet.")

    with col2:
        st.subheader("Attack Type Distribution")
        comp = features[features['label']=='attack']['attack_name'].value_counts().reset_index()
        comp.columns = ['type', 'count']
        if len(comp) > 5:
            top5 = comp.nlargest(5, 'count')
            other_sum = comp['count'][5:].sum()
            other_row = pd.DataFrame({'type': ['Other'], 'count': [other_sum]})
            comp = pd.concat([top5, other_row], ignore_index=True)
        if not comp.empty:
            donut = alt.Chart(comp).mark_arc(innerRadius=50, stroke='#0D0A10', strokeWidth=2).encode(
                theta='count:Q', color=alt.Color('type:N', scale=alt.Scale(scheme='turbo')),
                tooltip=['type', 'count']
            ).properties(height=260).configure_legend(labelColor='#FAFAFA', titleColor='#FAFAFA', labelFontSize=13, titleFontSize=15)
            st.altair_chart(donut, use_container_width=True)

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Detection Method Breakdown")
        method_counts = features['detection_method'].value_counts().reset_index()
        method_counts.columns = ['method', 'count']
        chart2 = alt.Chart(method_counts).mark_bar(color="#48F2FB", cornerRadiusEnd=6).encode(
            x=alt.X('count:Q'), y=alt.Y('method:N', sort='-x', title=None)
        ).properties(height=220).configure_axis(labelColor='#FAFAFA', titleColor='#FAFAFA', gridColor='#2B3242').configure_view(strokeWidth=0)
        st.altair_chart(chart2, use_container_width=True)

    with col4:
        st.subheader("Top Attacking IPs")
        top_ips = features[features['label']=='attack']['src_ip'].value_counts().reset_index()
        top_ips.columns = ['Source IP', 'Alerts']
        blocked_ips_set = set(features[features['action_taken'].astype(str).str.contains('blocked', na=False)]['src_ip'].values)
        top_ips['Blocked'] = top_ips['Source IP'].apply(lambda ip: "\u2714" if ip in blocked_ips_set else "\u2716")
        st.dataframe(top_ips, use_container_width=True, height=220, hide_index=True)

# ============ TAB 2: OPERATIONS ============
with tab2:
    st.subheader("System Health")
    services = ["idrs-snort", "idrs-watch-alerts", "wazuh-manager", "idrs-dashboard"]
    cols = st.columns(len(services))
    for i, svc in enumerate(services):
        status = "\U0001F7E2 Active" if check_service(svc) else "\U0001F534 Down"
        cols[i].metric(svc.replace("idrs-", "").replace("-", " ").title(), status)

    st.divider()
    st.subheader("Detection Accuracy (Isolation Forest)")
    attack_rows = features[features['label'] == 'attack']
    normal_rows = features[features['label'] == 'normal']
    tp = (attack_rows['ml_flagged'] == True).sum()
    fn = (attack_rows['ml_flagged'] == False).sum()
    fp = (normal_rows['ml_flagged'] == True).sum()
    tn = (normal_rows['ml_flagged'] == False).sum()
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp+tn+fp+fn) else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Accuracy", f"{accuracy*100:.1f}%")
    m2.metric("Precision", f"{precision*100:.1f}%")
    m3.metric("Recall", f"{recall*100:.1f}%")
    m4.metric("F1 Score", f"{f1*100:.1f}%")

    st.divider()
    st.subheader("Automated Response Log")
    try:
        with open(LOG_PATH, "r") as f:
            lines = f.readlines()[-15:]
        log_text = "".join(reversed(lines))
        st.code(log_text, language=None)
    except FileNotFoundError:
        st.info("No incidents logged yet.")

    st.divider()
    st.subheader("Recent Alerts (Detailed)")
    display_cols = ['time_window', 'src_ip', 'attack_name', 'severity', 'detection_method', 'action_taken']
    recent = features[features['label']=='attack'].sort_values('time_window', ascending=False)[display_cols].head(50)
    recent.columns = ['Time', 'Source', 'Attack Type', 'Severity', 'Detection', 'Action']

    def color_severity(val):
        colors = {
            "Critical": "background-color:#8B0000;color:white;",
            "High": "background-color:#C75B12;color:white;",
            "Medium": "background-color:#B8860B;color:white;",
            "Low": "background-color:#1E6F3D;color:white;"
        }
        return colors.get(val, "")

    st.dataframe(recent.style.map(color_severity, subset=["Severity"]), use_container_width=True, height=400, hide_index=True)

    if not recent.empty:
        st.divider()
        st.subheader("Investigation Panel")
        selected = recent.iloc[0]
        st.info(f"""
**Attack:** {selected['Attack Type']}  |  **Source IP:** {selected['Source']}  |  **Severity:** {selected['Severity']}  |  **Detection:** {selected['Detection']}  |  **Response:** {selected['Action']}  |  **Timestamp:** {selected['Time']}
""")

st.divider()
st.markdown("<p style='text-align:center;font-size:12px;color:#4EA3BA;'>Co-op Project by: Wejdan Ahmad Alrefai</p>", unsafe_allow_html=True)
