# 🛡️ PREVENT-PROMPT-INJECTION: Advanced AI Security Firewall

![AI Security Banner](https://img.shields.io/badge/Security-Advanced-red?style=for-the-badge&logo=shield)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-React%20%7C%20FastAPI%20%7C%20Gemma-green?style=for-the-badge)

## 🚀 Overview
**PREVENT-PROMPT-INJECTION** is a state-of-the-art, real-time security layer designed to protect Large Language Models (LLMs) from malicious exploitation. It acts as an intelligent proxy between users and AI models, intercepting and neutralising threats before they reach the core intelligence.

Built for the **Saptagiri Hackathon**, this project demonstrates a multi-layered defense-in-depth strategy, combining deterministic regex rules, semantic analysis, and "LLM-as-a-Judge" self-reflection.

---

## 🔥 Key Features

### 1. 🛡️ Multi-Layered Input Defense
- **Regex Guardrails:** High-speed pattern matching for 15+ attack categories (Jailbreaks, DAN modes, Prompt Leaking).
- **Semantic Similarity:** Detects variants of known attacks using vector embeddings (Full Mode).
- **Gemma Judge:** Uses a local `Gemma:2b` instance to perform real-time binary classification of user intent.
- **JSON Injection Scan:** Sanitises and validates complex nested payloads for prototype pollution and key-based attacks.

### 2. 🌐 Network & Infrastructure Security
- **Geo-IP Blocking:** Restricted access from sanctioned or high-risk regions.
- **TOR/Proxy Detection:** Automatically intercepts requests from anonymity networks.
- **Bot Rate Limiting:** Advanced protection against high-frequency automated attacks.
- **Token Budgeting:** Prevents "Prompt Flood" attacks by enforcing strict character-to-token ratios.

### 3. 🔍 Live Observability
- **Real-time Threat Dashboard:** Visualise risk scores, matched patterns, and security decisions instantly.
- **Integrated Logging:** Every interaction is logged to a secure Supabase backend for forensic analysis.
- **Hybrid Intelligence:** Seamlessly switches between Google Gemini (Cloud) and Local Gemma (Ollama) for fault-tolerant resilience.

---

## 🛠️ Tech Stack
- **Frontend:** React + Vite + TailwindCSS + Shadcn/UI (Modern Glassmorphism UI)
- **Backend:** FastAPI (Python 3.11+)
- **LLMs:** Google Gemini 2.0 (Primary API) / Ollama Gemma:2b (Local Fallback)
- **Database:** Supabase (Real-time Request Logs)
- **Security:** custom multi-turn conversation tracker & threat escalation engine.

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Hariprajwal/PREVENT-PROPMT-INEJECTION.git
cd PREVENT-PROPMT-INEJECTION
```

### ⚡ Quick Start (1-Click Windows Launcher)
Double-click `launch.bat` (or `run.bat`) in the root folder, or run:
```cmd
launch.bat
```
This automatically launches both the **FastAPI Backend** and **React Frontend**, verifies dependencies, and opens `http://localhost:5173` in your browser.

---

### Manual Setup

#### Setup Backend
```bash
cd CyberSecurity_For_ai_backend
pip install -r requirements.txt
# Create a .env file and add your credentials:
# LLM_MODE=hybrid
# API_KEY=your_gemini_api_key
# SUPABASE_URL=...
# SUPABASE_KEY=...
python api_server.py
```

#### Setup Frontend
```bash
cd CyberSecurity_For_ai_frontend
npm install
npm run dev
```

---

## 📊 Security Policy
We take AI security seriously. If you discover a vulnerability or a prompt that bypasses our firewall, please report it via the Security tab.

## ⚖️ License
Distributed under the **MIT License**. See `LICENSE` for more information.

---

**Built with ❤️ for the Saptagiri Hackathon 2026 TEAM : TRIAL AND ERROR **
