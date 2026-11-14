# IDRS — Intrusion Detection and Response System

A two-layer hybrid network intrusion detection and automated response system built as a graduation project for a B.Sc. in Computer Engineering (Network & Security track).

The system combines **Snort 3 signature-based detection** with an **Isolation Forest machine learning model** for anomaly detection, feeds alerts through **Wazuh SIEM**, stores them in **SQLite**, triggers **automated UFW firewall responses**, and displays everything on a live **Streamlit dashboard**.

---

## Architecture
```
Network Traffic
      │
      ▼
┌─────────────┐
│   Snort 3   │  ← Signature-based detection (29 custom rules)
└──────┬──────┘
       │ JSON alerts
       ▼
┌─────────────┐
│    Wazuh    │  ← Log collection, decoding, alert management
└──────┬──────┘
       │ alerts.json
       ▼
┌─────────────┐
│   Python    │  ← watch_alerts.py parses and labels every alert
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   SQLite    │  ← Persistent structured storage
└──────┬──────┘
       │
  ┌────┴────┐
  ▼         ▼
┌──────┐  ┌───────────────────┐
│ UFW  │  │ Isolation Forest  │
│Auto  │  │ Anomaly Detection │
│Block │  └───────────────────┘
└──────┘          │
       │          │
       └────┬─────┘
            ▼
   ┌─────────────────┐
   │ Streamlit       │
   │ Dashboard       │
   └─────────────────┘
```



---

## How It Works

**Layer 1 — Signature Detection (Snort 3)**
Snort monitors live network traffic and matches packets against 29 custom rules covering reconnaissance (ICMP ping, port scan), credential attacks (SSH brute-force), and application-layer attacks (SQL injection, XSS, Shellshock, Log4Shell, directory traversal, web shells).

**Layer 2 — Anomaly Detection (Isolation Forest)**
Raw alerts are grouped into time-window feature vectors (packet count, distinct ports, distinct protocols, hour of day) per source IP. An Isolation Forest model trained exclusively on normal baseline traffic flags windows that deviate from learned normal behavior — catching attacks that have no matching signature.

**Log Pipeline (Wazuh → Python → SQLite)**
A custom Wazuh decoder parses Snort 3's JSON output (which differs from Snort 2 field names) and a custom rule (ID 100002) forwards matching alerts. `watch_alerts.py` tails `alerts.json` continuously, labels each alert as `attack` or `normal` by source IP, and inserts it into SQLite within ~2 seconds of detection.

**Automated Response (UFW)**
`auto_response.py` processes unactioned attack alerts from the database. High-severity detections (brute-force, injection attacks, exploits) trigger a temporary 20-second UFW block on the source IP, then auto-unblock. Reconnaissance-level activity (port scans, probes) is logged only. A safety exclusion list prevents the defender and management IPs from ever being blocked.

**Dashboard (Streamlit)**
A live dashboard with two tabs:
- **Overview** — total traffic windows, attacks detected, blocked count, threat level, alerts-over-time chart, attack type breakdown, top attacking IPs
- **Operations** — system health (Snort/Wazuh/dashboard status), Isolation Forest accuracy metrics, automated response log, detailed alerts table with investigation panel

---

## Results

| Metric | Value |
|---|---|
| Isolation Forest detection rate | 78.7% (148/188 attack windows) |
| Isolation Forest false-positive rate | 6.9% (87/1,268 normal windows) |
| Combined detection (Snort + ML) | 100% — no attack window missed by both layers |
| Snort-only catches | 40 windows (low-and-slow brute-force ML missed) |
| ML-only catches | 87 windows (behavioral anomalies with no matching signature) |
| Both layers | 148 windows |
| Total alerts stored | 53,000+ |

**Key insight:** Neither layer alone achieves full coverage. Snort catches quiet low-volume attacks that look statistically normal to the ML model. Isolation Forest catches high-volume anomalous behavior that may not match any predefined signature. Together they cover the full attack surface tested.

---

## Lab Environment

| VM | OS | IP | Role |
|---|---|---|---|
| Defender | Ubuntu Server 22.04 | 192.168.56.10 | Runs Snort 3, Wazuh, Python pipeline, dashboard |
| Attacker | Kali Linux | 192.168.56.104 | Generates controlled attack traffic |
| IDRS-Normal | Ubuntu Server | 192.168.56.105 | Generates continuous normal baseline traffic |

All three VMs run on VirtualBox with a Host-Only network (`192.168.56.0/24`). No internet exposure.

---

## Attack Test Cases

| # | Attack | Tool | Snort Rule | Response |
|---|---|---|---|---|
| 1 | SYN port scan | `nmap -sS` | sid:1000003 | Logged only |
| 2 | Aggressive scan | `nmap -A` | sid:1000003 | Logged only |
| 3 | SSH brute-force | `hydra` | sid:1000002 | Temp blocked (20s) |
| 4 | ICMP flood | `ping -f` | sid:1000001 | Logged only |
| 5 | UDP port scan | `nmap -sU` | sid:1000003 | Logged only |

---

## Project Structure

```
idrs-intrusion-detection-response/
├── README.md
├── requirements.txt
├── .gitignore
│
├── snort/
│   └── idrs.rules
│
├── wazuh/
│   ├── local_decoder.xml
│   └── local_rules.xml
│
├── scripts/
│   ├── init_db.py
│   ├── watch_alerts.py
│   ├── process_alerts.py
│   ├── auto_response.py
│   ├── train_model.py
│   ├── view_alerts.py
│   └── unblock_ip.sh
│
├── dashboard/
│   ├── dashboard.py
│   └── .streamlit/
│       └── config.toml
│
└── systemd/
    ├── idrs-snort.service
    ├── idrs-watch-alerts.service
    └── idrs-dashboard.service
```


---

## Setup and Installation

> This project runs on Ubuntu Server 22.04 in a VirtualBox lab environment.

### 1. Install Snort 3
Snort 3 must be compiled from source. Follow the [official Snort 3 build guide](https://docs.snort.org/start/installation), then copy `snort/idrs.rules` to `/usr/local/etc/snort/` and add it to `snort.lua`:

```lua
ips = {
    include = RULE_PATH .. "/idrs.rules",
    variables = default_variables
}
```

Set `HOME_NET` to your lab subnet:
```lua
HOME_NET = '192.168.56.0/24'
```

### 2. Install Wazuh
Follow the [Wazuh single-node installation guide](https://documentation.wazuh.com/current/installation-guide/index.html), then:

```bash
sudo cp wazuh/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
sudo cp wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Add this block to `/var/ossec/etc/ossec.conf` to watch Snort's JSON alert file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/snort/alert_json.txt</location>
</localfile>
```

### 3. Set up Python environment

```bash
cd ~/idrs
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Initialize the database

```bash
python3 scripts/init_db.py
```

### 5. Train the Isolation Forest model

```bash
python3 scripts/train_model.py
```

### 6. Install systemd services

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now idrs-snort idrs-watch-alerts idrs-dashboard
```

### 7. Access the dashboard

Open a browser and go to `http://192.168.56.10:8501`

---

## Challenges and Solutions

**Snort 3 / Wazuh decoder mismatch**
Most available Wazuh decoders target Snort 2, which uses field names like `src_ip` and `dst_ip`. Snort 3 uses `src_ap` and `dst_ap`. Copying a Snort 2 decoder causes silent failures — Wazuh loads it without error but extracts no fields. Solution: wrote a custom decoder from scratch targeting Snort 3's actual JSON output.

**Alert offset bug**
Restarting `watch_alerts.py` without offset tracking re-inserted the entire alert history on every restart. Solution: the script tracks a byte offset in `.alerts_offset` and always resumes from where it stopped.

**UFW rule ordering**
Inserting a block rule at the wrong position in the UFW chain caused it to be evaluated after the existing ALLOW rules, so blocks had no effect. Solution: `ufw insert 1 deny from <ip>` places the deny rule at position 1, before any allow rules.

**VirtualBox promiscuous mode**
Snort running on the defender VM couldn't see traffic between other VMs until VirtualBox's Host-Only adapter was set to "Allow All" for promiscuous mode.

---

## Limitations

- Lab environment only — not tested on real network hardware
- Isolation Forest misses low-and-slow attacks (single brute-force attempts) that look statistically similar to normal traffic with only 4 features
- No UDP detection rules beyond basic port scanning
- Normal traffic baseline is synthetic (generated script), not real organizational traffic
- Dashboard login uses a hardcoded credential (demo only)

---

## Future Work

- Add more ML features (packets per second, connection duration, payload entropy)
- Replace Isolation Forest with a supervised model once labeled data grows
- Add email or webhook alerting on high-severity detections
- Extend rules to cover more attack categories (DNS tunneling, ARP spoofing)
- Deploy on physical hardware with real network traffic

---
