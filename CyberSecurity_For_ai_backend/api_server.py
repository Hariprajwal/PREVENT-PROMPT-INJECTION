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

import sys
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import os
from dotenv import load_dotenv

load_dotenv()  # read .env file

from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import requests
import time
import threading

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()

def log_to_supabase(log_data):
    try:
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }
        requests.post(f"{SUPABASE_URL}/rest/v1/firewall_logs", json=log_data, headers=headers, timeout=3)
    except Exception as e:
        pass

# ─── Networking Check ───────────────────────────────────────────────────
from networking import check_network_security

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


# ─── Monkey-patch ask_gemma when in API or Hybrid mode ────────────────
if LLM_MODE in ("api", "hybrid"):
    import main as _main_module

    _original_ask_gemma = _main_module.ask_gemma

    def _api_ask_gemma(prompt, safe_mode=False):
        """Replacement for ask_gemma that routes to external API with local fallback."""
        from security_layer import build_safe_system_prompt
        
        # If hybrid but no API key is set, immediately fallback
        if LLM_MODE == "hybrid" and not API_KEY:
            return _original_ask_gemma(prompt, safe_mode=safe_mode)

        try:
            _prompt_to_send = build_safe_system_prompt(prompt) if safe_mode else prompt
            return call_api_llm(_prompt_to_send)
        except Exception as e:
            if LLM_MODE == "hybrid":
                print(f"  [⚠️ API Failed: {e}. Falling back to local Gemma...]")
                return _original_ask_gemma(prompt, safe_mode=safe_mode)
            else:
                return f"API request failed: {e}"

    # Patch the function in the main module so all internal callers use it
    _main_module.ask_gemma = _api_ask_gemma


# ─── Resolve display name ────────────────────────────────────────────
def _display_model():
    if LLM_MODE == "hybrid":
        return f"Hybrid ({API_PROVIDER} → {MODEL_NAME})"
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

from fastapi import FastAPI, File, UploadFile, Form, Request

@app.post("/api/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest, request: Request):
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

    # Extract client IP (Support simulated header for testing)
    client_ip = request.headers.get("X-Simulate-IP", request.client.host)
    auth_header = request.headers.get("Authorization", "")

    # ── Network Security Check (Rate Limit / TOR / Geo / JWT) ─────
    is_allowed, block_decision, attack_type = check_network_security(client_ip, auth_header)
    
    if not is_allowed:
        # Create block response
        response_obj = ChatResponse(
            response=f"⛔ Request Blocked by Network Defense: {attack_type}",
            risk_score=100.0,
            attack_type=attack_type,
            decision=block_decision,
            confidence="high",
            matched_patterns=[],
            normalized_input=req.message or "",
            final_prompt="",
            output_filter_action="block",
            latency_ms=0,
            model=_display_model(),
            security_level=SECURITY_LEVEL,
        )
        
        # Log attack directly to Supabase
        log_data = {
            "session_id": req.session_id or "anonymous",
            "user_input": req.message,
            "security_enabled": req.security_enabled,
            "attack_type": attack_type,
            "risk_score": 1.0,
            "decision": block_decision,
            "matched_patterns": [],
            "normalized_input": req.message or "",
            "final_prompt": "[BLOCKED]",
            "llm_response": f"[Intercepted] {attack_type}",
            "output_filter_action": "block",
            "latency_ms": 0,
        }
        threading.Thread(target=log_to_supabase, args=(log_data,)).start()
        return response_obj

    result = smart_agent_api(req.message.strip(), security_enabled=req.security_enabled)

    # Log standard interaction to Supabase
    log_data = {
        "session_id": req.session_id or "anonymous",
        "user_input": req.message,
        "security_enabled": req.security_enabled,
        "attack_type": result.get("attack_type"),
        "risk_score": result.get("risk_score", 0.0),
        "decision": result.get("decision", "allow"),
        "matched_patterns": result.get("matched_patterns", []),
        "normalized_input": result.get("normalized_input", req.message),
        "final_prompt": result.get("normalized_input", req.message),
        "llm_response": result.get("response", ""),
        "output_filter_action": result.get("output_filter_action", "none"),
        "latency_ms": result.get("latency_ms", 0),
    }
    threading.Thread(target=log_to_supabase, args=(log_data,)).start()

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
    request: Request,
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

    # Extract client IP
    client_ip = request.headers.get("X-Simulate-IP", request.client.host)
    auth_header = request.headers.get("Authorization", "")

    # ── Network Security Check (Rate Limit / TOR / Geo / JWT) ─────
    is_allowed, block_decision, attack_type = check_network_security(client_ip, auth_header)
    
    if not is_allowed:
        response_obj = ChatResponse(
            response=f"⛔ Request Blocked by Network Defense: {attack_type}",
            risk_score=100.0,
            attack_type=attack_type,
            decision=block_decision,
            confidence="high",
            matched_patterns=[],
            normalized_input=f"[File: {filename}]",
            final_prompt="",
            output_filter_action="block",
            latency_ms=0,
            model=_display_model(),
            security_level=SECURITY_LEVEL,
        )
        log_data = {
            "session_id": session_id or "anonymous",
            "user_input": f"[File: {filename}]",
            "security_enabled": security_enabled,
            "attack_type": attack_type,
            "risk_score": 1.0,
            "decision": block_decision,
            "matched_patterns": [],
            "normalized_input": f"[File: {filename}]",
            "final_prompt": "[BLOCKED]",
            "llm_response": f"[Intercepted] {attack_type}",
            "output_filter_action": "block",
            "latency_ms": 0,
        }
        threading.Thread(target=log_to_supabase, args=(log_data,)).start()
        return response_obj

    result = smart_agent_api(combined_input, security_enabled=security_enabled)

    # Log interaction to Supabase
    latency = int((time.time() - start) * 1000)
    log_data = {
        "session_id": session_id or "anonymous",
        "user_input": f"[File: {filename}]",
        "security_enabled": security_enabled,
        "attack_type": result.get("attack_type"),
        "risk_score": result.get("risk_score", 0.0),
        "decision": result.get("decision", "allow"),
        "matched_patterns": result.get("matched_patterns", []),
        "normalized_input": result.get("normalized_input", ""),
        "final_prompt": result.get("normalized_input", ""),
        "llm_response": result.get("response", ""),
        "output_filter_action": result.get("output_filter_action", "none"),
        "latency_ms": result.get("latency_ms", 0),
    }
    threading.Thread(target=log_to_supabase, args=(log_data,)).start()

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


@app.post("/api/chat/json", response_model=ChatResponse)
async def json_chat_endpoint(request: Request):
    """
    Accepts ANY JSON body, recursively scans every field for injection,
    then forwards only safe content to the LLM.
    
    This endpoint handles real-world JSON API abuse scenarios:
    - Prototype pollution (__proto__, constructor)
    - Prompt injection buried in nested fields
    - Oversized payloads (token budget)
    """
    from security_layer import scan_json_payload, check_token_budget
    start = time.time()
    client_ip = request.headers.get("X-Simulate-IP", request.client.host)
    auth_header = request.headers.get("Authorization", "")

    # Network check
    is_allowed, block_decision, attack_type = check_network_security(client_ip, auth_header)
    if not is_allowed:
        return ChatResponse(
            response=f"⛔ Request Blocked by Network Defense: {attack_type}",
            risk_score=1.0, attack_type=attack_type, decision=block_decision,
            confidence="high", matched_patterns=[],
            normalized_input="[blocked before JSON parse]", final_prompt="",
            output_filter_action="block", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Read raw body
    try:
        body_bytes = await request.body()
        raw_body = body_bytes.decode("utf-8")
    except Exception as e:
        return ChatResponse(
            response=f"⚠️ Could not read request body: {e}",
            risk_score=0.0, attack_type=None, decision="allow", confidence="low",
            matched_patterns=[], normalized_input="", final_prompt="",
            output_filter_action="none", latency_ms=0,
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Token budget on raw body
    budget = check_token_budget(raw_body)
    if not budget["safe"]:
        return ChatResponse(
            response=f"⛔ {budget['reason']}",
            risk_score=0.96, attack_type="Prompt Flood / Token Exhaustion", decision="block",
            confidence="high", matched_patterns=[{"label": budget["reason"], "type": "flood", "weight": 0.96}],
            normalized_input=raw_body[:200], final_prompt="[BLOCKED — token budget]",
            output_filter_action="block", latency_ms=int((time.time()-start)*1000),
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # JSON injection scan
    json_result = scan_json_payload(raw_body)
    if not json_result["safe"]:
        flagged = json_result.get("flagged_fields", [])
        patterns = [{"label": f["reason"], "type": f["category"], "weight": 0.97} for f in flagged]
        return ChatResponse(
            response=f"⛔ **JSON Injection Blocked**\n\n{json_result['reason']}\n\nMalicious keys/values were stripped. Request not forwarded to LLM.",
            risk_score=0.99, attack_type="JSON Injection / Prototype Pollution", decision="block",
            confidence="high", matched_patterns=patterns,
            normalized_input=raw_body[:500], final_prompt="[BLOCKED — JSON sanitized]",
            output_filter_action="block", latency_ms=int((time.time()-start)*1000),
            model=_display_model(), security_level=SECURITY_LEVEL,
        )

    # Safe — extract a user message and process normally
    try:
        obj = __import__("json").loads(raw_body)
        # Find first string value to use as message
        def _find_message(o):
            if isinstance(o, dict):
                for k in ("message", "query", "prompt", "text", "content", "input"):
                    if k in o and isinstance(o[k], str):
                        return o[k]
                for v in o.values():
                    r = _find_message(v)
                    if r: return r
            elif isinstance(o, str):
                return o
            return None
        message = _find_message(obj) or str(obj)[:500]
    except Exception:
        message = raw_body[:500]

    result = smart_agent_api(message.strip(), security_enabled=True)
    latency = int((time.time() - start) * 1000)
    patterns = result.get("matched_patterns", [])
    confidence = "high" if len(patterns) >= 2 else "medium" if len(patterns) == 1 else "low"
    return ChatResponse(
        response=result["response"],
        risk_score=result["risk_score"],
        attack_type=result.get("attack_type"),
        decision=result["decision"],
        confidence=confidence,
        matched_patterns=patterns,
        normalized_input=result.get("normalized_input", message),
        final_prompt=result.get("normalized_input", message),
        output_filter_action=result.get("output_filter_action", "none"),
        latency_ms=latency,
        model=_display_model(),
        security_level=SECURITY_LEVEL,
    )


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
