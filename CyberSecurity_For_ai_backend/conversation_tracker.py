# ─── Multi-Turn Conversation Tracker ─────────────────────────────────
# Tracks conversation history, cumulative threat scores, and
# fetched URL/page context for follow-up question continuity.


class ConversationTracker:
    """
    Tracks conversation history and cumulative threat scoring.

    Each turn is assigned a threat_score:
      0 = safe
      1 = suspicious (matched a soft rule or borderline)
      2 = malicious (blocked by classifier)

    If cumulative threat exceeds the threshold, the conversation
    is flagged as escalating (multi-turn attack pattern).
    """

    def __init__(self, max_history=20, threat_threshold=3):
        self.history = []  # list of {"role", "content", "threat_score"}
        self.max_history = max_history
        self.threat_threshold = threat_threshold
        self.cumulative_threat = 0
        self._context = {}  # stores fetched URL/page content for continuity

    # ── History management ─────────────────────────────────────────────

    def add_turn(self, role, content, threat_score=0):
        """Add a conversation turn with its threat score."""
        self.history.append({
            "role": role,
            "content": content,
            "threat_score": threat_score
        })
        self.cumulative_threat += threat_score

        # Keep history bounded
        if len(self.history) > self.max_history:
            removed = self.history.pop(0)
            self.cumulative_threat = max(0, self.cumulative_threat - removed["threat_score"])

    def get_history(self):
        """Return the conversation history list."""
        return self.history

    def get_history_text(self, max_turns=6):
        """Return recent conversation history as formatted text for context injection."""
        lines = []
        for turn in self.history[-max_turns:]:
            prefix = "User" if turn["role"] == "user" else "Assistant"
            lines.append(f"{prefix}: {turn['content'][:300]}")
        return "\n".join(lines)

    # ── Context storage (for URL/page fetched content) ─────────────────

    def set_context(self, key, value):
        """Store a named context value (e.g., fetched URL content)."""
        self._context[key] = value

    def get_context(self, key, default=None):
        """Retrieve a stored context value."""
        return self._context.get(key, default)

    def has_url_context(self):
        """Check if there is a recently fetched URL context stored."""
        return "last_url" in self._context

    def get_url_context(self):
        """Return the last fetched URL context dict: {url, content, label}."""
        return self._context.get("last_url", None)

    def clear_url_context(self):
        """Clear the stored URL context."""
        self._context.pop("last_url", None)

    # ── Threat scoring ─────────────────────────────────────────────────

    def get_cumulative_threat(self):
        """Return the current cumulative threat score."""
        return self.cumulative_threat

    def is_escalating(self):
        """
        Detect multi-turn escalation patterns.
        Only triggers if the cumulative threat is high AND the current prompt is suspicious.
        """
        if not self.history or self.history[-1].get("threat_score", 0) == 0:
            return False
        return self.cumulative_threat >= self.threat_threshold

    def get_recent_threat_count(self, window=5):
        """Count how many of the last N turns were suspicious/malicious."""
        recent = self.history[-window:]
        return sum(1 for t in recent if t.get("threat_score", 0) > 0)

    def reset(self):
        """Reset conversation history, context, and threat scores."""
        self.history = []
        self.cumulative_threat = 0
        self._context = {}
