from ddgs import DDGS
import requests
from bs4 import BeautifulSoup
import json
import re
import base64
from security_layer import (
    security_check_input, security_check_output,
    scan_web_content, preprocess_input,
    build_safe_system_prompt, SECURITY_LEVEL
)
from conversation_tracker import ConversationTracker

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "gemma:2b"

# ─── Global conversation tracker ─────────────────────────────────────
conversation = ConversationTracker(max_history=20, threat_threshold=3)

# ─── Helper: Call Gemma ───────────────────────────────────────────────
def ask_gemma(prompt, safe_mode=False):
    """Send a prompt to the local Gemma model and return the response.
    If safe_mode=True, wraps prompt with hardened system instructions."""
    if safe_mode:
        prompt = build_safe_system_prompt(prompt)
    try:
        res = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            }
        )
        data = res.json()
        if "error" in data:
            return f"Ollama Error: {data['error']}"
        return data.get("response", "No response received.")
    except Exception as e:
        return f"Request failed: {e}"


# ─── Helper: Extract confidence score from Gemma response ────────────
def extract_confidence(response):
    """Extract CONFIDENCE: <number> from Gemma's response."""
    match = re.search(r'CONFIDENCE:\s*(\d+)', response, re.IGNORECASE)
    return int(match.group(1)) if match else 5  # default to 5 if not found


# ─── 3-Layer Intent Classifier ────────────────────────────────────────
def classify_intent(user_input):
    """
    Layer 0: Casual chat triggers (instant)
    Layer 0.5: Conversational/subjective guard (no web search for personal/opinion questions)
    Layer 1: Real-time keyword check (instant, no LLM call)
    Layer 2: Gemma self-assessment — does it know the answer?
    Layer 3: Confidence score fallback
    """
    query_lower = user_input.lower()

    # ── Layer 0: Casual chat (no LLM call needed) ────────────────
    casual_triggers = [
        "hey", "hello", "hi", "how are you", "what's up",
        "good morning", "good night", "thanks", "thank you",
        "bye", "ok", "okay", "cool", "nice", "great", "lol",
        "who are you", "what are you", "your name",
        "are you", "do you", "can you", "will you", "are u"
    ]
    if any(trigger in query_lower for trigger in casual_triggers):
        print("  [Layer 0: Casual chat detected → chat]")
        return "chat"

    # ── Layer 0.5: Conversational/opinion guard ────────────────────
    # Questions about the AI itself or subjective opinions should
    # never trigger a web search — always handle in chat mode.
    conversational_patterns = [
        r'\bare\s+you\b',
        r'\bdo\s+you\b',
        r'\bcan\s+you\b',
        r'\bwill\s+you\b',
        r'\byou\s+(a|an|really|just|smart|dumb|good|bad)\b',
        r'\bam\s+i\b',
        r'\bwhat\s+(do|can|will|should|would)\s+you\b',
        r'\bsmart\s+or\s+dumb\b',
        r'\bdumb\s+(programme|program|ai|bot)\b',
        r'\bwhy\s+(is|are|does|did)\b',
        r'\b(what|how)\s+(is|are|does|did|happened)\b',
        r'\b(not\s+working|broken|failing|latency|slow|bad)\b',
    ]
    if any(re.search(p, query_lower) for p in conversational_patterns):
        print("  [Layer 0.5: Conversational/opinion question → chat]")
        return "chat"

    # ── Layer 1: Real-time keywords (instant, no LLM needed) ─────
    realtime_keywords = [
        "weather", "stock price", "live score", "right now",
        "breaking news", "current price", "latest news", "this hour",
        "score today", "price today", "happening now"
    ]
    news_keywords = [
        "today's news", "todays news", "headlines", "news today",
        "what happened today", "current events", "recent news"
    ]

    search_keywords = [
        "search", "research", "look up", "find info", "google", "duckduckgo"
    ]

    if any(kw in query_lower for kw in realtime_keywords) or any(kw in query_lower for kw in search_keywords):
        print("  [Layer 1: Search/Real-time keyword detected → web_search]")
        return "web_search"
        
    if any(kw in query_lower for kw in news_keywords):
        print("  [Layer 1: News keyword detected → news]")
        return "news"

    # Default fallback: always return chat unless explicitly asked to search
    print("  [Default: No search keywords found → chat]")
    return "chat"


# ─── Web Search ───────────────────────────────────────────────────────
def web_search(query):
    """Search DuckDuckGo and return a list of URLs."""
    results = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, max_results=5):
            results.append(r["href"])
    return results


# ─── Fetch Page Content ──────────────────────────────────────────────
# Sites that use JavaScript to render content — requests+BS4 cannot
# handle these. They return an empty or near-empty HTML shell.
JS_HEAVY_DOMAINS = {
    "reddit.com", "linkedin.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "tiktok.com",
    "app.github.com",  # github.com/owner/repo handled separately
}

def fetch_page(url):
    """
    Fetch a web page and extract its main text content.
    - Uses realistic browser headers to reduce bot-blocking.
    - Prioritizes <article>, <main>, <section> over nav/footer noise.
    - Detects JS-heavy pages and warns the user.
    """
    try:
        # Realistic browser headers to avoid bot detection
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

        # Check for known JS-heavy domains
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().replace("www.", "")
        if any(d in domain for d in JS_HEAVY_DOMAINS):
            print(f"  [⚠️ {domain} uses JavaScript rendering — content may be empty]")

        res = requests.get(url, headers=headers, timeout=8)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        # Remove noise: scripts, styles, nav, header, footer, ads
        for tag in soup(["script", "style", "nav", "header", "footer",
                          "aside", "form", "noscript", "iframe"]):
            tag.extract()

        # Try to find the main content area first (better quality)
        content_tags = soup.find_all(
            ["article", "main", "section"],
            limit=3
        )
        if content_tags:
            text = " ".join(tag.get_text(separator=" ", strip=True) for tag in content_tags)
        else:
            # Fallback: extract all remaining body text
            text = soup.get_text(separator=" ", strip=True)

        # Collapse multiple spaces/newlines
        text = re.sub(r"\s{2,}", " ", text).strip()
        text = text[:4000]  # increased limit for better context

        # Warn if page seems empty (likely JS-rendered) but still return what we found
        if len(text) < 100:
            print(f"  [⚠️ Very little text extracted from {url} — page may require JavaScript or is just short]")


        # Security: Scan web content for indirect injection
        scan = scan_web_content(text)
        if not scan["safe"]:
            print(f"  [⚠️ Security: Flagged {url} - {scan['reason']}]")
            return "__INJECTION_DETECTED__"
        return text

    except requests.exceptions.HTTPError as e:
        print(f"  [Fetch error for {url}: HTTP {e.response.status_code}]")
        return ""
    except requests.exceptions.Timeout:
        print(f"  [Fetch error for {url}: Request timed out]")
        return ""
    except Exception as e:
        print(f"  [Fetch error for {url}: {e}]")
        return ""


# ─── Web Search Agent ────────────────────────────────────────────────
def web_agent(query):
    """Search the web and answer based on fetched content."""
    print("[Agent: Searching the web...]")
    urls = web_search(query)
    if not urls:
        print("  [No search results found, falling back to chat]")
        return ask_gemma(query, safe_mode=True)

    print(f"  [Found {len(urls)} URLs: {', '.join(urls[:3])}]")

    combined_text = ""
    for url in urls[:3]:
        print(f"  [Fetching content from: {url}]")
        fetched = fetch_page(url)
        # Security: Abort entire search if injection detected
        if fetched == "__INJECTION_DETECTED__":
            return "🛡️ Search aborted: Indirect injection detected in web content. Your query is safe, but the web results contained manipulation attempts."
        if fetched:
            combined_text += fetched + "\n\n"
        else:
            print(f"  [Warning: Could not extract text from {url}]")

    if not combined_text.strip():
        print("  [No content extracted, falling back to chat]")
        return ask_gemma(query, safe_mode=True)

    prompt = f"""Answer the question based on the following web data.
Be concise and informative.

Web data:
{combined_text}

Question: {query}
Answer:"""

    return ask_gemma(prompt, safe_mode=True)


# ─── News Agent ──────────────────────────────────────────────────────
def news_agent(query):
    """Fetch latest news articles and summarize them."""
    print("[Agent: Fetching latest news...]")
    urls = web_search(f"{query} latest news today")
    if not urls:
        print("  [No news results found]")
        return ask_gemma(f"What do you know about: {query}", safe_mode=True)

    print(f"  [Found {len(urls)} news sources]")

    combined_text = ""
    for url in urls[:3]:
        print(f"  [Fetching news from: {url}]")
        fetched = fetch_page(url)
        # Security: Abort entire search if injection detected
        if fetched == "__INJECTION_DETECTED__":
            return "🛡️ News fetch aborted: Indirect injection detected in web content."
        if fetched:
            combined_text += fetched + "\n\n"
        else:
            print(f"  [Warning: Could not extract news from {url}]")

    if not combined_text.strip():
        return ask_gemma(f"What do you know about recent news on: {query}", safe_mode=True)

    prompt = f"""Based on the following news articles, provide a summary of the latest news.
Be concise, list the key headlines and details.

News articles:
{combined_text}

Question: {query}
Summary:"""

    return ask_gemma(prompt, safe_mode=True)



# ─── GitHub-aware Fetcher ─────────────────────────────────────────────
GITHUB_REPO_RE = re.compile(
    r'https?://github\.com/([\w\-\.]+)/([\w\-\.]+)/?$', re.IGNORECASE
)

def fetch_github_readme(url):
    """
    Fetch README content from a GitHub repo URL using:
    1. GitHub API (returns rendered markdown as plain text)
    2. raw.githubusercontent.com fallback (main / master branch)
    Returns plain text content or None.
    """
    match = GITHUB_REPO_RE.match(url.rstrip('/'))
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    print(f"  [GitHub: Detected repo {owner}/{repo}, fetching README via API...]")

    # ── Try GitHub API (no auth needed for public repos) ─────────
    api_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
    try:
        resp = requests.get(
            api_url,
            headers={"Accept": "application/vnd.github.v3.raw"},
            timeout=10
        )
        if resp.status_code == 200:
            print("  [GitHub: README fetched via API ✓]")
            return resp.text[:5000]
        elif resp.status_code == 404:
            print("  [GitHub: No README found via API]")
    except Exception as e:
        print(f"  [GitHub API error: {e}]")

    # ── Fallback: raw.githubusercontent.com ───────────────────────
    for branch in ["main", "master"]:
        for filename in ["README.md", "readme.md", "README.rst", "README.txt"]:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
            try:
                resp = requests.get(raw_url, timeout=8)
                if resp.status_code == 200:
                    print(f"  [GitHub: README fetched from raw ({branch}/{filename}) ✓]")
                    return resp.text[:5000]
            except Exception:
                continue

    print("  [GitHub: Could not fetch README from any source]")
    return None


def url_agent(url, query):
    """Fetch a specific URL and answer questions about it.
    Automatically uses the GitHub API for GitHub repo URLs.
    Stores fetched content in conversation context for follow-up questions."""
    print(f"[Agent: Reading URL directly...]")

    content = None
    label = "web page"

    # ── Special handler: GitHub repo URLs ────────────────────────
    if GITHUB_REPO_RE.match(url.rstrip('/')):
        content = fetch_github_readme(url)
        label = "GitHub README"
        if content:
            scan = scan_web_content(content)
            if not scan["safe"]:
                return "🛡️ URL blocked: Indirect injection detected in GitHub README content."
        else:
            return f"Could not fetch the README from {url}. The repository may be private or have no README."
    else:
        # ── Standard URL fetch ────────────────────────────────────────
        print(f"  [Fetching content from: {url}]")
        fetched = fetch_page(url)
        if fetched == "__INJECTION_DETECTED__":
            return "🛡️ URL blocked: Indirect injection detected in the page content."
        if not fetched:
            return f"Could not extract any content from {url}. The page may require JavaScript or block scrapers."
        content = fetched

    # ── Store content in conversation context for follow-up questions ───
    conversation.set_context("last_url", {"url": url, "content": content, "label": label})
    print(f"  [Context stored: {label} from {url[:60]}...]")

    # Strip all URLs and internet-related trigger words from the user's question 
    # so Gemma doesn't hallucinate "I can't access the internet"
    clean_query = re.sub(r'https?://\S+', '', query).strip()
    clean_query = re.sub(r'\b(url|link|website|webpage|site)\b', 'document', clean_query, flags=re.IGNORECASE)
    
    # If the user just typed a URL or a vague command like "read this", give Gemma a clear goal
    if len(clean_query.split()) < 4 or "read" in clean_query.lower() or "what" in clean_query.lower():
        clean_query = "Summarize this text in 2-3 sentences."

    # Gemma 2B gets overwhelmed with long content + complex instructions.
    # Trim to 2000 chars and use a minimal prompt format.
    trimmed = content[:2000]

    # NOTE: safe_mode=False because the content was already scanned for injection
    # by scan_web_content / fetch_page. Using safe_mode triggers Gemma's trained
    # refusal about "untrusted web data".
    prompt = f"""Read the following text and follow the instruction.

{trimmed}

Instruction: {clean_query}
Answer:"""

    return ask_gemma(prompt, safe_mode=False)


# ─── Context Follow-Up Agent ────────────────────────────────────────────
def context_followup_agent(query):
    """Answer a follow-up question using the previously fetched URL content."""
    ctx = conversation.get_url_context()
    print(f"[Agent: Answering follow-up using stored {ctx['label']} context...]")

    # Strip URLs and internet trigger words from query
    clean_query = re.sub(r'https?://\S+', '', query).strip()
    clean_query = re.sub(r'\b(url|link|website|webpage|site)\b', 'document', clean_query, flags=re.IGNORECASE)
    
    if len(clean_query.split()) < 4 or "read" in clean_query.lower() or "what" in clean_query.lower():
        clean_query = "Summarize this text in 2-3 sentences."

    trimmed = ctx['content'][:2000]

    prompt = f"""Read the following text and follow the instruction.

{trimmed}

Previous conversation:
{conversation.get_history_text(max_turns=4)}

Instruction: {clean_query}
Answer:"""
    return ask_gemma(prompt, safe_mode=False)



# ─── Chat Agent (no web) ───────────────────────────────────────────────
def chat(query):
    """Direct conversation with Gemma, including recent conversation history."""
    print("[Agent: Thinking...]")
    history_text = conversation.get_history_text(max_turns=6)
    if history_text:
        prompt = f"""Here is the recent conversation history:
{history_text}

Now answer the following: {query}"""
    else:
        prompt = query
    return ask_gemma(prompt)


# ─── Smart Agent (auto-routing) ──────────────────────────────────────
def smart_agent(user_input):
    """
    Automatically routes the user's prompt to the right agent:
      1. Security: Pre-process and validate input
      2. If the input contains a URL → fetch that URL directly
      3. Otherwise, ask Gemma to classify the intent → web_search / news / chat
      4. Security: Validate output
    """
    # ── Security: Pre-process input ──────────────────────────────
    user_input = preprocess_input(user_input)

    # ── Security: Check input against all layers ─────────────────
    print("[🛡️ Security: Checking input...]")
    check = security_check_input(user_input, conversation.get_history(), ask_gemma)
    threat_score = check.get("threat_score", 0)
    conversation.add_turn("user", user_input, threat_score)

    if not check["safe"]:
        blocked_msg = f"🛡️ Request blocked: {check['reason']}"
        print(f"  [🛡️ BLOCKED: {check['reason']} (category: {check.get('category', 'unknown')})")
        conversation.add_turn("assistant", blocked_msg, 0)
        return blocked_msg

    # ── Security: Check multi-turn escalation ────────────────────
    if conversation.is_escalating():
        blocked_msg = "🛡️ Conversation blocked: Repeated suspicious activity detected. Type 'reset' to start fresh."
        conversation.add_turn("assistant", blocked_msg, 0)
        return blocked_msg

    print("  [🛡️ Security: Input passed ✓]")

    # Check for direct URLs first
    words = user_input.split()
    urls_in_input = [w for w in words if w.startswith("http://") or w.startswith("https://")]

    if urls_in_input:
        response = url_agent(urls_in_input[0], user_input)
    else:
        # Use Gemma to classify intent automatically
        print("[Agent: Classifying your query...]")
        intent = classify_intent(user_input)
        print(f"  [Detected intent: {intent}]")

        if intent == "news":
            response = news_agent(user_input)
        elif intent == "web_search":
            response = web_agent(user_input)
        else:
            response = chat(user_input)

    # ── Security: Validate output (full mode only) ───────────────
    out_check = security_check_output(response, user_input, ask_gemma)
    if not out_check["safe"]:
        print(f"  [🛡️ Output blocked: {out_check['reason']}]")
        response = "🛡️ Response filtered: The generated response was flagged by safety review."

    conversation.add_turn("assistant", response, 0)
    return response


# ─── API-friendly wrapper ────────────────────────────────────────────
def smart_agent_api(user_input, security_enabled=True):
    """
    Same as smart_agent() but returns structured data for the FastAPI server.
    Returns: {
        "response": str,
        "risk_score": float,
        "attack_type": str | None,
        "decision": "allow" | "sanitize" | "block",
        "category": str,
        "matched_patterns": list,
        "normalized_input": str,
        "latency_ms": int,
    }
    """
    import time
    start = time.time()

    if not security_enabled:
        # Direct mode — no security layer
        response = chat(user_input)
        conversation.add_turn("user", user_input, 0)
        conversation.add_turn("assistant", response, 0)
        latency = int((time.time() - start) * 1000)
        return {
            "response": response,
            "risk_score": 0.0,
            "attack_type": None,
            "decision": "allow",
            "category": "",
            "matched_patterns": [],
            "normalized_input": user_input,
            "latency_ms": latency,
        }

    # ── Security: Pre-process input ──────────────────────────────
    processed_input = preprocess_input(user_input)

    # ── Security: Check input against all layers ─────────────────
    print("[🛡️ Security: Checking input...]")
    check = security_check_input(processed_input, conversation.get_history(), ask_gemma)
    threat_score = check.get("threat_score", 0)
    conversation.add_turn("user", processed_input, threat_score)

    if not check["safe"]:
        blocked_msg = f"🛡️ Request blocked: {check['reason']}"
        print(f"  [🛡️ BLOCKED: {check['reason']} (category: {check.get('category', 'unknown')})")
        conversation.add_turn("assistant", blocked_msg, 0)
        latency = int((time.time() - start) * 1000)
        return {
            "response": blocked_msg,
            "risk_score": 1.0,
            "attack_type": check.get("category", "unknown"),
            "decision": "block",
            "category": check.get("category", "unknown"),
            "matched_patterns": [{"label": check["reason"], "type": check.get("category", "unknown"), "weight": 1.0}],
            "normalized_input": processed_input,
            "latency_ms": latency,
        }

    # ── Security: Check multi-turn escalation ────────────────────
    if conversation.is_escalating():
        blocked_msg = "🛡️ Conversation blocked: Repeated suspicious activity detected. Type 'reset' to start fresh."
        conversation.add_turn("assistant", blocked_msg, 0)
        latency = int((time.time() - start) * 1000)
        return {
            "response": blocked_msg,
            "risk_score": 1.0,
            "attack_type": "multi_turn_escalation",
            "decision": "block",
            "category": "multi_turn_escalation",
            "matched_patterns": [{"label": "Repeated suspicious activity", "type": "multi_turn_escalation", "weight": 1.0}],
            "normalized_input": processed_input,
            "latency_ms": latency,
        }

    print("  [🛡️ Security: Input passed ✓]")

    # Determine risk level for decision label
    risk_score = check.get("threat_score", 0) / 2.0  # normalize 0-2 to 0-1
    if risk_score >= 0.7:
        decision = "block"
    elif risk_score >= 0.3:
        decision = "sanitize"
    else:
        decision = "allow"

    # Route to appropriate agent
    words = processed_input.split()
    urls_in_input = [w for w in words if w.startswith("http://") or w.startswith("https://")]

    if urls_in_input:
        response = url_agent(urls_in_input[0], processed_input)
    else:
        print("[Agent: Classifying your query...]")
        intent = classify_intent(processed_input)
        print(f"  [Detected intent: {intent}]")

        if intent == "news":
            response = news_agent(processed_input)
        elif intent == "web_search":
            response = web_agent(processed_input)
        else:
            response = chat(processed_input)

    # ── Security: Validate output ────────────────────────────────
    out_check = security_check_output(response, processed_input, ask_gemma)
    output_filtered = False
    if not out_check["safe"]:
        print(f"  [🛡️ Output blocked: {out_check['reason']}]")
        response = "🛡️ Response filtered: The generated response was flagged by safety review."
        output_filtered = True

    conversation.add_turn("assistant", response, 0)
    latency = int((time.time() - start) * 1000)

    return {
        "response": response,
        "risk_score": risk_score,
        "attack_type": check.get("category") if check.get("category") else None,
        "decision": decision,
        "category": check.get("category", ""),
        "matched_patterns": [{"label": check.get("reason", ""), "type": check.get("category", ""), "weight": risk_score}] if check.get("category") else [],
        "normalized_input": processed_input,
        "output_filter_action": "filtered" if output_filtered else "none",
        "latency_ms": latency,
    }


# ─── Main Loop ───────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Gemma:2b Smart Web Search Agent")
    print(f"  🛡️ Security Layer: {SECURITY_LEVEL} mode")
    print("  The agent auto-detects when to search the web!")
    print("  Type 'quit' or 'exit' to stop.")
    print("  Type 'reset' to clear conversation & threat history.")
    print("=" * 60)

    while True:
        try:
            user_input = input("\nYou: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["quit", "exit"]:
                print("Goodbye!")
                break
            if user_input.lower() == "reset":
                conversation.reset()
                print("🔄 Conversation and threat history cleared.")
                continue

            response = smart_agent(user_input)
            print(f"\nGemma: {response}")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")
