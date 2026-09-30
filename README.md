# 🛡️ ScamShield

## AI-Powered Scam Message & URL Detection System

ScamShield is a cybersecurity application designed to detect suspicious messages, phishing attempts, fraudulent offers, and potentially malicious URLs.

It combines rule-based detection, NLP/ML analysis, URL intelligence, risk scoring, and explainable results to help users understand why a message may be suspicious.

---

## 🚨 Problem

Online scams are becoming increasingly sophisticated. Attackers use urgency, fake rewards, impersonation, financial requests, malicious links, and social engineering techniques to trick users into sharing sensitive information or making unauthorized payments.

Traditional keyword-based detection may fail when attackers change their wording or use more sophisticated techniques.

ScamShield aims to provide a smarter and more explainable approach to scam detection.

---

## 💡 Solution

ScamShield analyzes suspicious messages and URLs and provides:

- Risk Level
- Risk Score
- Scam Category
- Detection Confidence
- Likely Attacker Intent
- Detection Reasons
- URL Security Indicators
- Safety Recommendations

The goal is not only to identify suspicious content, but also to explain **why it may be dangerous** and **what the attacker may be trying to achieve**.

---

## 🔍 Key Features

### 📩 Message Analysis
Detects suspicious patterns in messages, including phishing attempts, fake offers, financial scams, and social engineering.

### 🧠 AI + Rule-Based Detection
Combines NLP/ML analysis with security rules for more comprehensive detection.

### 🔗 URL Intelligence
Analyzes URLs for suspicious characteristics such as:

- IP-based URLs
- Missing HTTPS
- Link shorteners
- Suspicious domains
- Other URL risk indicators

### 🎯 Attacker Intent Analysis
Identifies possible attacker objectives such as:

- Credential theft
- Financial fraud
- OTP/PIN theft
- Personal information harvesting
- Malicious link interaction
- Social engineering

### 📊 Risk Scoring
Produces a risk score to communicate the severity of detected content.

### 📝 Explainable Detection
Shows the reasons and indicators behind the detection instead of providing only a final result.

### 📚 Scan History
Stores previous scans so users can review their previous security checks.

---

## 🏗️ System Architecture

```text
User
  │
  ▼
ScamShield Web Interface
  │
  ▼
Input Preprocessing
  │
  ├──────────────┬──────────────┐
  ▼              ▼              ▼
NLP / ML      Security       URL
Analysis       Rules       Intelligence
  │              │              │
  └──────────────┼──────────────┘
                 ▼
          Risk Scoring Engine
                 │
                 ▼
       Category & Intent Analysis
                 │
                 ▼
        Explainable Result
                 │
                 ▼
           Scan History
           🧰 Technology Stack
- Frontend: HTML, CSS, JavaScript
- Backend: Python, Flask
- Machine Learning: Python / NLP
- Database: SQLite
- URL Analysis: Python
- Model: Scikit-learn / NLP model
- Version Control: Git & GitHub
- Development: Visual Studio Code
ScamShield/
│
├── app.py
├── detector.py
├── detector_backup.py
├── d.py
├── database.py
├── train_model.py
├── url.py
├── scamshield.db
│
├── models/
│   └── scamshield_nlp.pkl
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   └── history.html
│
├── static/
│   └── style.css
│
├── .gitignore
└── README.md