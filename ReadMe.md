# SOC Threat Intelligence Platform

A Security Operations Center (SOC) Threat Intelligence project built using **Splunk Enterprise** to detect, analyze, and monitor cyber threats using real-world datasets, threat intelligence lookups, behavioral analytics, and AI-inspired detection models.

This project integrates:
- Threat Intelligence (TI) feeds
- Splunk lookup tables
- Correlation searches
- Behavioral detection rules
- Risk scoring
- AI-based anomaly detection
- Dashboards and alerts

---

# 📌 Project Overview

The goal of this project is to simulate a real SOC environment capable of:

- Detecting malicious IPs, domains, URLs, and User-Agents
- Identifying brute-force and port scan attacks
- Performing threat enrichment using external intelligence
- Creating risk-based prioritization
- Generating alerts and dashboards for analysts
- Applying AI-inspired detection models for anomaly detection

The project was implemented entirely in **Splunk Enterprise** using custom SPL queries, lookup tables, and saved alerts.

---

# 🛠 Technologies Used

- Splunk Enterprise
- SPL (Search Processing Language)
- CSV Datasets
- Threat Intelligence Feeds
- Lookup Tables
- Behavioral Analytics
- Risk Scoring
- AI-inspired Detection Models

---

# 📂 Project Structure

```bash
SOC-project-Threat-Intelligence/
│
├── datasets/
│   ├── train_test_network.csv
│   ├── linux_auth_logs_full(balanced).csv
│
├── lookups/
│   ├── threat_intel_ips.csv
│   ├── threat_intel_domains.csv
│   ├── threat_intel_urls.csv
│   ├── threat_intel_useragents.csv
│
├── spl_queries/
│   ├── rule_1.spl
│   ├── rule_2.spl
│   ├── ...
│
├── README.md
```

---

# 📊 Data Sources

The project uses two primary datasets:

## 1. Network Traffic Dataset

Contains:
- Source IPs
- Destination IPs
- DNS queries
- URLs
- HTTP User-Agents
- Labels for attacks

Dataset:
```bash
train_test_network.csv
```

---

## 2. Linux Authentication Logs

Contains:
- Login attempts
- Source IPs
- Usernames
- Login status
- Ports
- Servers
- Attack anomalies

Dataset:
```bash
linux_auth_logs_full(balanced).csv
```

---

# 🧠 Threat Intelligence Lookups

Several threat intelligence lookup tables were created and integrated into Splunk.

## Lookup Tables

| Lookup | Description |
|---|---|
| `threat_intel_ips.csv` | Malicious IP addresses |
| `threat_intel_domains.csv` | Malicious domains |
| `threat_intel_urls.csv` | Malicious URLs |
| `threat_intel_useragents.csv` | Suspicious User-Agents |

---
# 🔍 Detection Rules

The SOC Threat Intelligence platform contains 9 advanced detection and correlation rules designed to identify malicious activity, enrich indicators of compromise (IOCs), detect behavioral anomalies, and prioritize threats based on risk severity.

These rules combine:
- Threat Intelligence enrichment
- Behavioral analytics
- Correlation searches
- Risk scoring
- AI-inspired anomaly detection

---

# Rule 1 — Malicious IP in Authentication Logs

Detects malicious source IP addresses attempting authentication against Linux systems by correlating authentication logs with external threat intelligence feeds.

### Features
- Threat intelligence enrichment
- Login activity monitoring
- Severity classification
- User targeting visibility

```spl
index=soc_project source="linux_auth_logs_full(balanced).csv"
| lookup threat_intel_ips ioc_value AS source_ip
OUTPUT severity, source AS ti_source, description
| where isnotnull(severity)
| stats count AS hit_count,
values(username) AS targeted_users,
values(status) AS login_status
by source_ip, severity, description
| sort -hit_count
```

---

# Rule 2 — Malicious IP in Network Traffic

Detects malicious source or destination IP addresses inside network traffic logs using threat intelligence lookups.

### Features
- Source and destination IP inspection
- IOC correlation
- Attack type visibility
- Threat severity identification

```spl
index=soc_project source="train_test_network.csv"
| eval check_ip=mvappend(src_ip, dst_ip)
| mvexpand check_ip
| lookup threat_intel_ips ioc_value AS check_ip
OUTPUT severity, source AS ti_source, description
| where isnotnull(severity)
| stats count AS hits,
values(label) AS attack_label,
values(type) AS attack_type
by check_ip, severity, description
| sort -hits
```

---

# Rule 3 — Malicious Domain Detection

Detects suspicious and malicious domains queried through DNS traffic.

### Features
- DNS query inspection
- Domain IOC enrichment
- Threat severity mapping
- Host visibility

```spl
index=soc_project source="train_test_network.csv"
dns_query!="-"
dns_query!=""
| lookup threat_intel_domains ioc_value AS dns_query
OUTPUT severity, source AS ti_source, description
| where isnotnull(severity)
| stats count AS hits,
values(src_ip) AS requesting_hosts
by dns_query, severity, description
| sort -hits
```

---

# Rule 4 — Malicious URL Detection

Detects malicious URLs accessed within network communications.

### Features
- URL inspection
- IOC enrichment
- Source and destination tracking
- Threat classification

```spl
index=soc_project source="train_test_network.csv"
http_uri!="-"
http_uri!=""
| lookup threat_intel_urls ioc_value AS http_uri
OUTPUT severity, source AS ti_source, description
| where isnotnull(severity)
| stats count AS hits,
values(src_ip) AS source_hosts,
values(dst_ip) AS dest_hosts
by http_uri, severity, description
| sort -hits
```

---

# Rule 5 — Suspicious User-Agent Detection

Detects suspicious or malicious HTTP User-Agent strings frequently associated with malware, scanners, bots, or automated attack tools.

### Features
- User-Agent inspection
- Behavioral detection
- Threat intelligence correlation
- Target URL visibility

```spl
index=soc_project source="train_test_network.csv"
http_user_agent!="-"
http_user_agent!=""
| lookup threat_intel_useragents ioc_value AS http_user_agent
OUTPUT severity, source AS ti_source, description
| where isnotnull(severity)
| stats count AS hits,
values(src_ip) AS source_hosts,
values(http_uri) AS target_urls
by http_user_agent, severity, description
| sort -hits
```

---

# Rule 6 — Brute Force Detection

Detects brute-force login attempts by identifying excessive failed authentication attempts from the same source IP address.

### Features
- Failed login monitoring
- User targeting analysis
- Risk classification
- Authentication anomaly detection

```spl
index=soc_project source="linux_auth_logs_full(balanced).csv"
status="Failed"
| stats count AS failed_attempts,
dc(username) AS unique_users_targeted,
values(username) AS usernames,
latest(_time) AS last_attempt
by source_ip
| where failed_attempts > 10
| sort -failed_attempts
| eval risk_level=case(
failed_attempts>100, "Critical",
failed_attempts>50, "High",
failed_attempts>20, "Medium",
1==1, "Low")
```

---

# Rule 7 — Port Scan Detection

Detects port scanning activity by analyzing anomalous connection behavior across multiple ports and servers.

### Features
- Port scanning detection
- Multi-server targeting analysis
- Scan intensity monitoring
- Behavioral threat analysis

```spl
index=soc_project source="linux_auth_logs_full(balanced).csv"
anomaly_label="port_scan"
| stats count AS scan_events,
dc(port) AS ports_scanned,
dc(server) AS servers_targeted,
values(server) AS server_list
by source_ip
| sort -scan_events
| eval risk_level=case(
scan_events>100, "Critical",
scan_events>50, "High",
1==1, "Medium")
```

---

# Rule 8 — Multi-IOC Risk Scoring

Combines multiple indicators of compromise into a unified risk score to improve threat prioritization and incident response.

### Features
- Multi-source IOC enrichment
- IP severity scoring
- Domain severity scoring
- URL severity scoring
- User-Agent severity scoring
- Risk tier classification

```spl
index=soc_project source="train_test_network.csv"
| lookup threat_intel_ips ioc_value AS src_ip OUTPUT severity AS ip_severity
| lookup threat_intel_ips ioc_value AS dst_ip OUTPUT severity AS dst_ip_severity
| lookup threat_intel_domains ioc_value AS dns_query OUTPUT severity AS domain_severity
| lookup threat_intel_urls ioc_value AS http_uri OUTPUT severity AS url_severity
| lookup threat_intel_useragents ioc_value AS http_user_agent OUTPUT severity AS ua_severity
| eval ip_score=case(ip_severity=="critical",5, ip_severity=="high",3, ip_severity=="medium",1, isnotnull(dst_ip_severity),2, 1==1,0)
| eval domain_score=case(domain_severity=="critical",5, domain_severity=="high",3, domain_severity=="medium",1, 1==1,0)
| eval url_score=case(url_severity=="critical",5, url_severity=="high",3, url_severity=="medium",1, 1==1,0)
| eval ua_score=case(ua_severity=="critical",5, ua_severity=="high",3, ua_severity=="medium",1, 1==1,0)
| eval total_threat_score=ip_score+domain_score+url_score+ua_score
| where total_threat_score > 0
```

---

# Rule 9 — AI-Based Threat Prioritization

Uses weighted attack scoring and threat intelligence enrichment to prioritize high-risk malicious activity automatically.

### Features
- Weighted attack scoring
- Threat intelligence enrichment
- Automated prioritization
- Risk-based classification
- AI-inspired analytics

```spl
index=soc_project source="train_test_network.csv" label=1
| eval attack_risk=case(
type=="backdoor",10,
type=="ransomware",10,
type=="mitm",9,
type=="injection",8,
type=="xss",7,
type=="password",7,
type=="ddos",6,
type=="dos",5,
type=="scanning",4,
1==1,1)
| lookup threat_intel_ips ioc_value AS src_ip OUTPUT severity AS ti_severity
| eval ti_bonus=case(
ti_severity=="critical",5,
ti_severity=="high",3,
ti_severity=="medium",1,
1==1,0)
| eval final_risk=attack_risk + ti_bonus
| stats avg(final_risk) AS avg_risk,
max(final_risk) AS max_risk,
count AS events
by src_ip, type
| sort -max_risk
```

# 🤖 AI Detection Models

The project includes three AI-inspired security analytics models.

---

# AI Model 1 — Weighted Risk Score

Calculates weighted risk based on attack type and TI enrichment.

Risk levels:
- IMMEDIATE
- HIGH
- MEDIUM
- LOW

```spl
index=soc_project source="train_test_network.csv" label=1
| eval attack_risk=case(
type=="backdoor",10,
type=="ransomware",10,
type=="mitm",9,
type=="injection",8,
type=="xss",7,
type=="password",7,
type=="ddos",6,
type=="dos",5,
type=="scanning",4,
1==1,1)
| lookup threat_intel_ips ioc_value AS src_ip OUTPUT severity AS ti_severity
| eval ti_bonus=case(
ti_severity=="critical",5,
ti_severity=="high",3,
ti_severity=="medium",1,
1==1,0)
| eval final_risk=attack_risk + ti_bonus
| stats avg(final_risk) AS avg_risk,
max(final_risk) AS max_risk,
count AS events
by src_ip, type
| sort -max_risk
```

---

# AI Model 2 — Authentication Anomaly Detection

Uses statistical anomaly detection with:
- Hourly aggregation
- Average calculations
- Standard deviation
- Z-score analysis

```spl
index=soc_project source="linux_auth_logs_full(balanced).csv"
| bin _time span=1h
| stats count AS total_attempts,
sum(eval(if(status=="Failed",1,0))) AS failures,
dc(username) AS unique_users
by source_ip, _time
| eventstats avg(total_attempts) AS avg_attempts,
stdev(total_attempts) AS stdev_attempts
| eval z_score=round((total_attempts-avg_attempts)/stdev_attempts, 2)
| where z_score > 2
| sort -z_score
```

---

# AI Model 3 — IP Enrichment

Enriches suspicious authentication activity by:
- Failed login thresholds
- Unique targeted users
- Risk categorization

```spl
index=soc_project source="linux_auth_logs_full(balanced).csv"
status="Failed"
| stats count AS failed_attempts,
dc(username) AS unique_users_targeted,
values(username) AS usernames
by source_ip
| where failed_attempts > 10
| sort -failed_attempts
| eval risk_level=case(
failed_attempts>40, "CRITICAL",
failed_attempts>30, "HIGH",
failed_attempts>20, "MEDIUM",
1==1, "LOW")
```

---

# 📈 Dashboards

The project includes custom SOC dashboards for monitoring:

- Threat severity distribution
- Top malicious IPs
- IOC statistics
- Alert trends
- Risk scoring
- Triggered alerts

---

# 🚨 Alerts

Configured saved alerts include:

- Malicious IP Detection
- Brute Force Detection
- Port Scan Detection
- Multi-IOC Risk Alerts
- Suspicious User-Agent Alerts

---

# 📌 Key Features

✅ Threat Intelligence Integration  
✅ Behavioral Analytics  
✅ IOC Correlation  
✅ Risk-Based Prioritization  
✅ AI-Inspired Detection  
✅ Real-Time Alerting  
✅ SOC Dashboards  
✅ Splunk Lookups  
✅ Threat Enrichment  
✅ Authentication Monitoring  

---

# 📷 Screenshots

The repository includes screenshots demonstrating:
- Loaded datasets
- Lookup tables
- Detection rule execution
- Threat intelligence enrichment
- AI model results
- Triggered alerts
- SOC dashboards

---

# 🚀 Future Improvements

Potential future enhancements:
- Integration with VirusTotal API
- MITRE ATT&CK Mapping
- SOAR Automation
- Machine Learning Models
- GeoIP Visualization
- Email Alerting
- Real-time Streaming Data
- UEBA (User and Entity Behavior Analytics)

---

# 👩‍💻 Authors

- Farah Alzoubi
- Marah Alkilani

GitHub Repository:
https://github.com/MarahAlkilani/SOC-project-Threat-Intelligence-

---

# 📜 License

This project is for educational and academic purposes only.

---

# ⭐ Acknowledgments

Special thanks to:
- Splunk Enterprise
- Open-source Threat Intelligence feeds
- SOC and Cybersecurity research communities
- University instructors and project supervisors
