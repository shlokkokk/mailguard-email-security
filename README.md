# MailGuard – Email Security Dashboard

MailGuard is a modern email security dashboard designed to analyze and flag **phishing, scam, spam, and social engineering emails** using **rule-based heuristics**, with an architecture that is **AI-ready** for future ML/NLP integration.

This project focuses on **clarity, explainability, and UI-driven threat intelligence**, not black-box magic.

---

## ✨ Features

### 🔍 Email Security Analyzer
- Paste raw email content and analyze it instantly
- Calculates a **Threat Score (0–100)**
- Classifies risk levels:
  - Safe
  - Low
  - Medium
  - High
  - Critical

### 🎣 Threat Categories
Each email is evaluated across multiple dimensions:
- **Phishing** – credential theft & impersonation
- **Scam** – financial manipulation attempts
- **Spam** – unwanted or bulk messaging
- **Social Engineering** – urgency, pressure, manipulation cues

### 📊 Visual Dashboard
- Clean cyber-themed UI
- Threat score visualization
- Category-wise risk percentages
- Recent analysis activity feed
- Monthly stats (emails analyzed, threats blocked, accuracy)

### 🌍 Threat Intelligence (WIP)
- Timeline of detected threats
- Threat type distribution
- Geographic threat origins
- Threat database with severity & status  
⚠️ *This section is currently under active development.*

### ⚙️ Settings Panel
- Detection sensitivity control
- AI feature toggles (future-ready)
- Performance metrics display
- Privacy & notification options

---

## 🧠 Detection Logic (Current)

MailGuard currently uses **rule-based heuristics**, including:
- Sender & domain mismatches
- Suspicious URLs and URL obfuscation
- Urgency and pressure language
- Credential request patterns
- Attachment indicators
- Behavioral red flags

> The system is intentionally **explainable**.  
> Every score can be traced back to a rule.

---

## 🤖 AI-Ready Architecture

While the current engine is rule-based, the project is structured to support:
- NLP-based content analysis
- ML threat scoring models
- Reputation-based sender intelligence
- External threat feeds & classifiers

No fake “AI buzzwords” - only real extensibility.

---

## 📂 Project Structure
```
mailguard-email-security/
├── index.html # Main dashboard
├── threat-intelligence.html # Threat intel (WIP)
├── settings.html # Settings panel
├── main.js # Detection & UI logic
├── app.py # Backend API (optional)
├── README.md
├── LICENSE
└── .gitignore
```

---

## 🚧 Current Status

- Core dashboard: ✅ stable
- Email analyzer: ✅ working
- Threat scoring: ✅ functional
- Threat Intelligence: 🚧 under construction
- AI integration: 🧠 for explaination

---

## ⚠️ Disclaimer

This project is for **educational and research purposes**.  
It does **not** replace enterprise-grade email security solutions.

---

## 📜 License

MIT License — use it, modify it, learn from it.
