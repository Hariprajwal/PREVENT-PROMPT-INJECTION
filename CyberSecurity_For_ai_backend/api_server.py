# ─── FastAPI Server for AI Firewall Chatbot ───────────────────────────
# Supports two LLM backends (configured via .env):
#   LLM_MODE=gemma  → Local Ollama Gemma:2B  (default)
#   LLM_MODE=api    → External API (Google Gemini or OpenAI)
#
# Usage:
#   cd ~/python_folder
#   source venv311/bin/activate
#   python api_server.py
#
# Endpoints:
#   POST /api/chat   — Send a message (with optional security toggle)
#   POST /api/reset  — Reset conversation & threat history
#   GET  /api/health — Health check

import os
from dotenv import load_dotenv

load_dotenv()  # read .env file

from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import requests
import time

# ─── Configuration from .env ──────────────────────────────────────────
LLM_MODE = os.getenv("LLM_MODE", "gemma").strip().lower()
API_PROVIDER = os.getenv("API_PROVIDER", "gemini").strip().lower()
API_KEY = os.getenv("API_KEY", "").strip()
API_MODEL = os.getenv("API_MODEL", "gemini-2.0-flash").strip()
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))

from main import smart_agent_api, conversation, OLLAMA_URL, MODEL_NAME
from security_layer import SECURITY_LEVEL
from file_extractor import extract_text, is_supported, IMAGE_EXTENSIONS

# ─── External API Client ─────────────────────────────────────────────
_api_client = None

def _get_api_client():
    """Lazy-init the external API client."""
    global _api_client
    if _api_client is not None:
        return _api_client

    if API_PROVIDER == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=API_KEY)
        _api_client = genai.GenerativeModel(API_MODEL)
    elif API_PROVIDER == "openai":
        from openai import OpenAI
        _api_client = OpenAI(api_key=API_KEY)
    else:
        raise ValueError(f"Unknown API_PROVIDER: {API_PROVIDER}")
    return _api_client


def call_api_llm(prompt: str) -> str:
    """Send a prompt to the configured external API and return the response."""
    client = _get_api_client()

    if API_PROVIDER == "gemini":
        response = client.generate_content(prompt)
        return response.text
    elif API_PROVIDER == "openai":
        response = client.chat.completions.create(
            model=API_MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content
    else:
        return "Unknown API provider."


# ─── Monkey-patch ask_gemma when in API mode ──────────────────────────
if LLM_MODE == "api":
    import main as _main_module

    _original_ask_gemma = _main_module.ask_gemma

    def _api_ask_gemma(prompt, safe_mode=False):
        """Replacement for ask_gemma that routes to external API."""
        from security_layer import build_safe_system_prompt
        if safe_mode:
            prompt = build_safe_system_prompt(prompt)
        try:
            return call_api_llm(prompt)
        except Exception as e:
            return f"API request failed: {e}"

    # Patch the function in the main module so all internal callers use it
    _main_module.ask_gemma = _api_ask_gemma


# ─── Resolve display name ────────────────────────────────────────────
def _display_model():
    if LLM_MODE == "api":
        return f"{API_PROVIDER}/{API_MODEL}"
    return MODEL_NAME


# ─── App setup ────────────────────────────────────────────────────────
app = FastAPI(title="AI Firewall API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response models ────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    security_enabled: bool = True
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    risk_score: float
    attack_type: Optional[str]
    decision: str
    confidence: str
    matched_patterns: list
    normalized_input: str
    final_prompt: str
    output_filter_action: str
    latency_ms: int
    model: str
    security_level: str


# ─── Endpoints ────────────────────────────────────────────────────────

@app.post("/api/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest):
    """Process a chat message through the security layer and the active LLM."""
    if not req.message or not req.message.strip() or len(req.message) > 4000:
        return ChatResponse(
            response="⚠️ Invalid message. Please enter a message (max 4000 characters).",
            risk_score=0.0,
            attack_type=None,
            decision="allow",
            confidence="low",
            matched_patterns=[],
            normalized_input=req.message or "",
            final_prompt="",
            output_filter_action="none",
            latency_ms=0,
            model=_display_model(),
            security_level=SECURITY_LEVEL,
        )

    result = smart_agent_api(req.message.strip(), security_enabled=req.security_enabled)

    # Map confidence from matched_patterns count
    patterns = result.get("matched_patterns", [])
    if len(patterns) >= 2:
        confidence = "high"
    elif len(patterns) == 1:
        confidence = "medium"
    else:
        confidence = "low"

    return ChatResponse(
        response=result["response"],
        risk_score=result["risk_score"],
        attack_type=result.get("attack_type"),
        decision=result["decision"],
        confidence=confidence,
        matched_patterns=patterns,
        normalized_input=result.get("normalized_input", req.message),
        final_prompt=result.get("normalized_input", req.message),
        output_filter_action=result.get("output_filter_action", "none"),
        latency_ms=result["latency_ms"],
        model=_display_model(),
        security_level=SECURITY_LEVEL,
    )


@app.post("/api/chat/upload", response_model=ChatResponse)
async def upload_endpoint(
    file: UploadFile = File(...),
    message: str = Form(""),
    security_enabled: bool = Form(True),
):
    """Process an uploaded file/image through the security layer.
    Extracts text via OCR or document parsing, then scans it."""
    start = time.time()
    filename = file.filename or "unknown"

    # Validate extension
    if not is_supported(filename):
        return ChatResponse(
            response=f"⚠️ Unsupported file type: {filename}. Supported: txt, pdf, docx, csv, md, eml, msg, png, jpg, jpeg, gif, bmp, webp",
            risk_score=0.0, attack_type=None, decision="allow", confidence="low",
            matched_patterns=[], normalized_input=filename, final_prompt="",
            output_filter_action="none", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Read file bytes
    file_bytes = await file.read()
    if len(file_bytes) > 10 * 1024 * 1024:  # 10 MB limit
        return ChatResponse(
            response="⚠️ File too large. Maximum file size is 10 MB.",
            risk_score=0.0, attack_type=None, decision="allow", confidence="low",
            matched_patterns=[], normalized_input=filename, final_prompt="",
            output_filter_action="none", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Extract text
    try:
        extracted_text = extract_text(file_bytes, filename)
    except Exception as e:
        return ChatResponse(
            response=f"⚠️ Could not extract text from {filename}: {e}",
            risk_score=0.0, attack_type=None, decision="allow", confidence="low",
            matched_patterns=[], normalized_input=filename, final_prompt="",
            output_filter_action="none", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    if not extracted_text.strip():
        ext = os.path.splitext(filename)[1].lower()
        is_image = ext in IMAGE_EXTENSIONS
        return ChatResponse(
            response=f"⚠️ No text could be extracted from {filename}." + (
                " The image may not contain readable text." if is_image else ""),
            risk_score=0.0, attack_type=None, decision="allow", confidence="low",
            matched_patterns=[], normalized_input=filename, final_prompt="",
            output_filter_action="none", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Combine user message with extracted text for security scan
    combined_input = extracted_text
    if message.strip():
        combined_input = f"{message.strip()}\n\n[Extracted from {filename}]:\n{extracted_text}"
    else:
        combined_input = f"[Extracted from {filename}]:\n{extracted_text}"

    # Run through the same security pipeline
    result = smart_agent_api(combined_input, security_enabled=security_enabled)

    patterns = result.get("matched_patterns", [])
    if len(patterns) >= 2:
        confidence = "high"
    elif len(patterns) == 1:
        confidence = "medium"
    else:
        confidence = "low"

    latency = int((time.time() - start) * 1000)

    return ChatResponse(
        response=result["response"],
        risk_score=result["risk_score"],
        attack_type=result.get("attack_type"),
        decision=result["decision"],
        confidence=confidence,
        matched_patterns=patterns,
        normalized_input=f"[File: {filename}] {extracted_text[:200]}",
        final_prompt=combined_input[:500],
        output_filter_action=result.get("output_filter_action", "none"),
        latency_ms=latency,
        model=_display_model(),
        security_level=SECURITY_LEVEL,
    )

@app.post("/api/reset")
async def reset_endpoint():
    """Reset conversation history and threat scores."""
    conversation.reset()
    return {"status": "ok", "message": "Conversation and threat history cleared."}


@app.get("/api/health")
async def health_endpoint():
    """Health check — verifies the active LLM backend is available."""
    if LLM_MODE == "api":
        # Quick validation: try a tiny call to the API
        try:
            test = call_api_llm("ping")
            return {
                "status": "healthy",
                "llm_mode": "api",
                "provider": API_PROVIDER,
                "model": API_MODEL,
                "security_level": SECURITY_LEVEL,
            }
        except Exception as e:
            return {"status": "unhealthy", "llm_mode": "api", "provider": API_PROVIDER, "detail": str(e)}
    else:
        # Gemma / Ollama health check
        try:
            res = requests.get(f"{OLLAMA_URL.replace('/api/generate', '')}/api/tags", timeout=5)
            if res.status_code == 200:
                models = [m["name"] for m in res.json().get("models", [])]
                has_model = any(MODEL_NAME in m for m in models)
                return {
                    "status": "healthy",
                    "llm_mode": "gemma",
                    "ollama": "running",
                    "model": MODEL_NAME,
                    "model_available": has_model,
                    "security_level": SECURITY_LEVEL,
                    "available_models": models,
                }
            else:
                return {"status": "degraded", "ollama": "error", "detail": f"HTTP {res.status_code}"}
        except requests.exceptions.ConnectionError:
            return {"status": "unhealthy", "ollama": "not running", "detail": "Cannot connect to Ollama at " + OLLAMA_URL}
        except Exception as e:
            return {"status": "unhealthy", "ollama": "error", "detail": str(e)}


# ─── Run server ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  AI Firewall API Server")
    print(f"  LLM Mode: {LLM_MODE.upper()}")
    if LLM_MODE == "api":
        print(f"  Provider: {API_PROVIDER}")
        print(f"  Model: {API_MODEL}")
    else:
        print(f"  Model: {MODEL_NAME}")
        print(f"  Ollama URL: {OLLAMA_URL}")
    print(f"  Security Level: {SECURITY_LEVEL}")
    print(f"  Server: http://localhost:{SERVER_PORT}")
    print("=" * 60)
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT)
