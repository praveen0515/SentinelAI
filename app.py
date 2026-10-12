"""
SentinelAI - Real-Time Threat Detection & SIEM Analytics Dashboard
Standalone demo with simulated data. No backend required.
Author: Praveen Patil | github.com/praveen0515
"""

import random
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentinelAI – Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  section[data-testid="stSidebar"] { background-color: #0d1117; }
  .block-container { padding-top: 1rem; }
  .kpi-box {
    background: linear-gradient(135deg,#131b2e,#1a253f);
    border: 1px solid #233554;
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 10px;
  }
  .kpi-val  { font-size: 26px; font-weight: 700; font-family: monospace; }
  .kpi-lbl  { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #8892b0; }
  .kpi-sub  { font-size: 11px; color: #64ffda; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.image(
    "https://img.shields.io/badge/SentinelAI-v1.0-00d4aa?style=for-the-badge&logo=shield",
    use_column_width=True,
)
st.sidebar.markdown("### 🛡️ SentinelAI Controls")
st.sidebar.success("🟢 Standalone Demo Mode")
st.sidebar.markdown("---")

time_filter = st.sidebar.selectbox(
    "Analysis Window",
    ["Last 6 Hours", "Last 12 Hours", "Last 24 Hours", "Last 7 Days"],
    index=2,
)
hours_map = {"Last 6 Hours": 6, "Last 12 Hours": 12, "Last 24 Hours": 24, "Last 7 Days": 168}
n_hours = hours_map[time_filter]

severity_filter = st.sidebar.selectbox(
    "Minimum Severity",
    ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
)

if st.sidebar.button("⚡ Inject 25 Attack Logs (Demo)"):
    st.sidebar.success("✅ 25 attack vectors simulated! Dashboard refreshed.")

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**Praveen Patil**  \n"
    "[GitHub](https://github.com/praveen0515) · "
    "[LinkedIn](https://linkedin.com/in/praveen0515)  \n"
    "MIT License © 2026"
)

# ── Deterministic seed for consistent demo data ───────────────────────────────
random.seed(42)

# ── Demo data generators ─────────────────────────────────────────────────────

SEVERITIES   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLORS   = {"CRITICAL": "#e63946", "HIGH": "#f77f00", "MEDIUM": "#fcbf49", "LOW": "#457b9d"}
CATEGORIES   = [
    "SQL Injection", "Automated Scanner", "Cross-Site Scripting (XSS)",
    "Path Traversal", "Credential Stuffing", "Command Injection", "DDoS Spike",
]
COUNTRIES    = [
    ("Russia",      "Moscow",    55.75, 37.62, "CRITICAL"),
    ("China",       "Beijing",   39.90, 116.41, "HIGH"),
    ("USA",         "Ashburn",   39.04, -77.49, "HIGH"),
    ("Ukraine",     "Kyiv",      50.45, 30.52, "CRITICAL"),
    ("Germany",     "Frankfurt", 50.11, 8.68, "HIGH"),
    ("Netherlands", "Amsterdam", 52.37, 4.90, "MEDIUM"),
    ("Brazil",      "São Paulo", -23.55, -46.63, "CRITICAL"),
    ("Iran",        "Tehran",    35.69, 51.39, "CRITICAL"),
    ("India",       "Bengaluru", 12.97, 77.59, "MEDIUM"),
]


def make_kpi():
    total = 8_450 + random.randint(0, 300)
    threats = 420 + random.randint(0, 40)
    return {
        "total":    total,
        "threats":  threats,
        "rate":     round(threats / total * 100, 2),
        "crit_hi":  185 + random.randint(0, 20),
        "latency":  round(1.2 + random.uniform(0, 0.3), 2),
        "f1":       0.928,
        "precision":0.942,
        "recall":   0.915,
    }


def make_timeline(n):
    rows = []
    base = datetime.utcnow() - timedelta(hours=n)
    step = n if n <= 24 else n // 24
    ticks = n // step
    for i in range(ticks):
        t = base + timedelta(hours=i * step)
        rows.append({
            "time":     t.strftime("%H:%M" if n <= 24 else "%b %d"),
            "Critical": random.randint(2, 8),
            "High":     random.randint(3, 12),
            "Medium":   random.randint(2, 9),
            "Low":      random.randint(1, 5),
        })
    return pd.DataFrame(rows)


def make_geo():
    rows = []
    for country, city, lat, lon, sev in COUNTRIES:
        rows.append({
            "country":      country,
            "city":         city,
            "lat":          lat,
            "lon":          lon,
            "threat_count": random.randint(15, 120),
            "category":     random.choice(CATEGORIES),
            "severity":     sev,
        })
    return pd.DataFrame(rows)


def make_alerts(n_hours):
    alerts = []
    for i in range(12):
        sev = random.choices(SEVERITIES, weights=[3, 4, 3, 2])[0]
        c = random.choice(COUNTRIES)
        ts = datetime.utcnow() - timedelta(
            hours=random.uniform(0, min(n_hours, 24))
        )
        alerts.append({
            "ID":        f"ALT-{1000+i}",
            "Time (UTC)": ts.strftime("%Y-%m-%d %H:%M"),
            "Client IP":  f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "Severity":   sev,
            "Category":   random.choice(CATEGORIES),
            "Score":      round(random.uniform(-0.48, -0.06), 3),
            "Country":    c[0],
            "Status":     random.choice(["⚠️ Pending", "✅ ACK"]),
        })
    return pd.DataFrame(alerts)


def make_categories():
    return pd.DataFrame({
        "Category": CATEGORIES,
        "Count":    [142, 115, 78, 45, 32, 21, 15],
    })


# ── Generate data ─────────────────────────────────────────────────────────────
kpi       = make_kpi()
df_time   = make_timeline(n_hours)
df_geo    = make_geo()
df_alerts = make_alerts(n_hours)
df_cat    = make_categories()

if severity_filter != "ALL":
    df_alerts = df_alerts[df_alerts["Severity"] == severity_filter]

# ── Header ───────────────────────────────────────────────────────────────────
st.title("🛡️ SentinelAI: Real-Time Threat Intelligence")
st.caption(
    "AI-Powered Anomaly Detection • Isolation Forest ML Engine • "
    "30-Dimensional Behavioural Telemetry  |  "
    f"Last refresh: **{datetime.utcnow().strftime('%H:%M:%S UTC')}**"
)

# ── KPI Row ──────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
for col, val, label, sub, color in [
    (c1, f"{kpi['total']:,}",      "Ingested Logs",     "Active stream",                 "#00f2fe"),
    (c2, f"{kpi['threats']:,}",    "Threats Detected",  f"{kpi['crit_hi']} Critical/High","#ff5c77"),
    (c3, f"{kpi['rate']}%",        "Anomaly Rate",      "Contamination: 5%",             "#ffd166"),
    (c4, f"{kpi['f1']:.3f}",       "ML F1-Score",       f"P={kpi['precision']} R={kpi['recall']}","#06d6a0"),
    (c5, f"{kpi['latency']} ms",   "Inference Latency", "Sub-millisecond scoring",       "#118ab2"),
]:
    col.markdown(
        f'<div class="kpi-box">'
        f'<div class="kpi-lbl">{label}</div>'
        f'<div class="kpi-val" style="color:{color}">{val}</div>'
        f'<div class="kpi-sub">{sub}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "🌍 Live Threat Map",
    "📈 Threat Timeline",
    "🚨 SOC Alerts Feed",
    "🔬 ML Diagnostics",
])

# ── Tab 1 – Geo Map ───────────────────────────────────────────────────────────
with tab1:
    st.subheader("Global Threat Origin Distribution")
    fig_map = px.scatter_geo(
        df_geo,
        lat="lat", lon="lon",
        hover_name="city",
        hover_data={"country": True, "threat_count": True, "category": True,
                    "severity": True, "lat": False, "lon": False},
        size="threat_count",
        color="severity",
        color_discrete_map=SEV_COLORS,
        projection="natural earth",
        title="Malicious Inbound Traffic — Geographic Origin",
    )
    fig_map.update_geos(
        showcountries=True, countrycolor="#233554",
        showocean=True,     oceancolor="#0b0f19",
        showland=True,      landcolor="#131b2e",
        bgcolor="#0b0f19",
    )
    fig_map.update_layout(
        template="plotly_dark", height=500,
        paper_bgcolor="#0b0f19",
        margin=dict(l=0, r=0, t=40, b=0),
    )
    st.plotly_chart(fig_map, use_container_width=True)

# ── Tab 2 – Timeline ──────────────────────────────────────────────────────────
with tab2:
    col_t, col_d = st.columns([7, 3])
    with col_t:
        st.subheader("Threat Detections by Severity (Stacked)")
        fig_bar = go.Figure()
        for sev, color in SEV_COLORS.items():
            fig_bar.add_trace(go.Bar(x=df_time["time"], y=df_time[sev],
                                     name=sev, marker_color=color))
        fig_bar.update_layout(
            barmode="stack", template="plotly_dark",
            paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19",
            margin=dict(l=10, r=10, t=30, b=10),
            legend=dict(orientation="h", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_d:
        st.subheader("Attack Vectors")
        fig_pie = px.pie(
            df_cat, names="Category", values="Count", hole=0.55,
            color_discrete_sequence=px.colors.sequential.Plasma_r,
        )
        fig_pie.update_layout(
            template="plotly_dark", paper_bgcolor="#0b0f19",
            margin=dict(l=10, r=10, t=30, b=10), showlegend=False,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

# ── Tab 3 – Alerts ────────────────────────────────────────────────────────────
with tab3:
    st.subheader("Security Operations Center — Live Alerts Feed")
    if df_alerts.empty:
        st.success("No alerts matching the selected severity filter.")
    else:
        st.dataframe(
            df_alerts.style.applymap(
                lambda v: f"color: {SEV_COLORS.get(v, '#fff')}" if v in SEV_COLORS else "",
                subset=["Severity"],
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.markdown("---")
        st.subheader("🔍 Forensic Inspector")
        sel = st.selectbox("Select Alert ID to drill down:", df_alerts["ID"].tolist())
        row = df_alerts[df_alerts["ID"] == sel].iloc[0]
        dc1, dc2 = st.columns(2)
        with dc1:
            st.markdown(f"**Severity:** `{row['Severity']}`")
            st.markdown(f"**Client IP:** `{row['Client IP']}`  ({row['Country']})")
            st.markdown(f"**Attack Category:** `{row['Category']}`")
            st.markdown(f"**Anomaly Score:** `{row['Score']}`")
            st.markdown(f"**Timestamp (UTC):** `{row['Time (UTC)']}`")
            st.markdown(f"**Status:** {row['Status']}")
        with dc2:
            features = pd.DataFrame({
                "Feature":       ["sqli_signature", "payload_entropy", "ip_req_freq_1m",
                                  "special_char_ratio", "path_traversal"],
                "Value":         [1.0, 4.35, 24.0, 0.28, 0.0],
                "Z-Score":       [4.5, 2.2, 2.9, 3.4, 0.1],
            })
            st.markdown("**Top Anomalous Features:**")
            st.table(features)

# ── Tab 4 – ML Diagnostics ────────────────────────────────────────────────────
with tab4:
    col_m1, col_m2 = st.columns(2)

    with col_m1:
        st.subheader("Model Performance Metrics")
        metrics_df = pd.DataFrame({
            "Metric":    ["Precision", "Recall", "F1-Score", "Avg Latency"],
            "Value":     [f"{kpi['precision']:.3f}", f"{kpi['recall']:.3f}",
                          f"{kpi['f1']:.3f}", f"{kpi['latency']} ms"],
            "Benchmark": ["≥ 0.90", "≥ 0.90", "≥ 0.90", "< 2 ms"],
            "Status":    ["✅", "✅", "✅", "✅"],
        })
        st.table(metrics_df)

        st.subheader("Feature Engineering — 30 Dimensions")
        st.markdown("""
| Group | Features |
|---|---|
| **Structural** | Request length, query params, special-char ratio, digit ratio |
| **Entropy** | Shannon entropy of URI, payload body |
| **Velocity** | IP req freq 1-min/5-min, error rate, unique endpoint count |
| **Client** | User-Agent length/entropy, scanner UA flag, empty UA flag |
| **Signatures** | SQLi, XSS, Path Traversal, Command Injection heuristics |
| **Temporal** | Hour of day, weekend flag, off-hours flag |
        """)

    with col_m2:
        st.subheader("Anomaly Score Gauge")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=-0.28,
            title={"text": "Example Decision Score"},
            gauge={
                "axis": {"range": [-0.5, 0.2]},
                "bar":  {"color": "#f77f00"},
                "steps": [
                    {"range": [-0.5,  -0.35], "color": "#e63946"},
                    {"range": [-0.35, -0.25], "color": "#f77f00"},
                    {"range": [-0.25, -0.15], "color": "#fcbf49"},
                    {"range": [-0.15, -0.05], "color": "#457b9d"},
                    {"range": [-0.05,  0.20], "color": "#2a9d8f"},
                ],
                "threshold": {"line": {"color": "white", "width": 4},
                              "thickness": 0.75, "value": -0.28},
            },
        ))
        fig_gauge.update_layout(
            template="plotly_dark", paper_bgcolor="#0b0f19",
            height=280, margin=dict(l=10, r=10, t=40, b=10),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        st.subheader("Severity Threshold Table")
        st.markdown("""
| Severity | Score Range | Action |
|---|---|---|
| 🔴 CRITICAL | < -0.35 | Immediate WAF Block |
| 🟠 HIGH | -0.35 to -0.25 | Incident Ticket |
| 🟡 MEDIUM | -0.25 to -0.15 | CAPTCHA Challenge |
| 🔵 LOW | -0.15 to -0.05 | Flag & Monitor |
| 🟢 NORMAL | ≥ -0.05 | Allow |
        """)

# ── Footer ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#8892b0;font-size:12px'>"
    "SentinelAI SIEM Dashboard · Built by "
    "<a href='https://github.com/praveen0515' style='color:#64ffda'>Praveen Patil</a>"
    " · MIT 2026"
    "</div>",
    unsafe_allow_html=True,
)
