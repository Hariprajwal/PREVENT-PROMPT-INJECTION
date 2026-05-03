# CyberSecurity for AI Backend & Monitoring Dashboard

This repository contains the backend and monitoring infrastructure for the **AI Firewall Chatbot**, designed to provide real-time protection against prompt injection, jailbreaks, and unsafe outputs when interacting with Large Language Models (LLMs).

## Project Structure

- **`api_server.py`**: The main FastAPI entry point for the chatbot UI to connect to. It handles chat requests, routes them through the security layer, and communicates with the configured LLM.
- **`main.py`**: Contains the core logic for the Smart Agent, intent classification (chat vs web search), and interactions with local/external APIs.
- **`security_layer.py`**: The multi-layered rule-based risk engine that analyzes inputs and outputs for vulnerabilities (e.g., prompt overrides, sensitive data extraction).
- **`monitoring/`**: A Django-based backend application responsible for logging all API interactions, user sessions, and calculating ML-based composite risk scores.
- **`monitoring_ui/`**: A React/Vite dashboard that provides a clean, institutional minimalist interface to visualize real-time attacks, blocked requests, and system health.
- **`.env`**: Configuration file to switch between local execution (Ollama/Gemma:2B) and cloud APIs (Google Gemini, OpenAI).

## Features

- **Multi-layered Intent Classification**: Automatically decides whether a user query requires casual chat, a localized answer, or an active web search using DuckDuckGo.
- **Local & Cloud LLM Support**: Seamlessly switch between local models (Ollama) for privacy or cloud APIs (Gemini/OpenAI) for performance.
- **Continuous Monitoring**: Every interaction is logged to the Django database and visible in the React dashboard with calculated risk metrics.
- **Dynamic Threat Scoring**: Combines rule-based pattern matching with ML-based anomaly detection (Isolation Forest) to determine request safety.

## Getting Started

### 1. Prerequisites
- Python 3.11+
- Node.js & npm (for the React dashboards)
- [Ollama](https://ollama.com/) installed with the `gemma:2b` model (if using local mode).

### 2. Setup the Environment
```bash
python3 -m venv venv311
source venv311/bin/activate
pip install -r requirements.txt
```

### 3. Configure `.env`
Create or edit the `.env` file to select your LLM provider:
```ini
LLM_MODE=gemma      # Choose 'gemma' or 'api'
# API_PROVIDER=gemini # If using 'api', specify 'gemini' or 'openai'
# API_KEY=your_key_here
```

### 4. Running the Services
You need to run three separate services for the full stack:

**AI Firewall API (Port 8000)**
```bash
python api_server.py
```

**Monitoring Backend (Django, Port 5654)**
```bash
cd monitoring
python manage.py runserver 5654
```

**Monitoring Dashboard (React, Port 5174)**
```bash
cd monitoring_ui
npm install
npm run dev
```
