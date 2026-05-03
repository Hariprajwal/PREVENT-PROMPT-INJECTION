from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from core.models import RequestLog, ChatbotUser, UserProfile

# ─── AI_firewall user ID (set after first migration) ─────────────────
_AI_USER_ID = None


def _get_ai_user_id():
    """Lazily fetch the AI_firewall user_id."""
    global _AI_USER_ID
    if _AI_USER_ID is None:
        user = ChatbotUser.objects.filter(username="AI_firewall").first()
        if user:
            _AI_USER_ID = str(user.user_id)
        else:
            _AI_USER_ID = "AI_firewall"
    return _AI_USER_ID


# ─── POST /api/chatbot/log/ ──────────────────────────────────────────
class ChatbotLogView(APIView):
    """
    Receives a chatbot interaction log from api_server.py,
    runs ML risk scoring, and stores it in RequestLog.
    """

    def post(self, request):
        data = request.data
        user_input = (data.get("user_input") or "")[:500]
        chatbot_risk = float(data.get("risk_score", 0))
        attack_type = data.get("attack_type")
        decision = data.get("decision", "allow")
        ip = data.get("ip", "127.0.0.1")
        device = data.get("device", "AI Firewall Chatbot")
        endpoint = data.get("endpoint", "/api/chat")
        latency_ms = data.get("latency_ms", 0)

        user_id = _get_ai_user_id()

        # ── ML Risk Scoring ──────────────────────────────────
        ml_risk = 0
        try:
            from core.ml_service import build_ml_features, get_ml_risk_score
            from core.services.profile_service import get_or_create_profile

            profile = get_or_create_profile(user_id)

            context = {"ip": ip, "device": device, "endpoint": endpoint}
            features = build_ml_features(context, profile, flag=None)
            ml_result = get_ml_risk_score(features)
            ml_risk = ml_result.get("risk", 0)

            # Update profile with new IP data
            prefix = ".".join(ip.split(".")[:2])
            ip_data = profile.usual_ip_prefixes or {}
            ip_data[prefix] = ip_data.get(prefix, 0) + 1
            profile.usual_ip_prefixes = ip_data
            if device:
                profile.usual_device = device
            profile.save()
        except Exception as e:
            print(f"[ML Scoring] Error: {e}")

        # ── Combine: 60% chatbot security + 40% ML ──────────
        final_risk = int(0.6 * chatbot_risk + 0.4 * ml_risk)

        # ── Store log ────────────────────────────────────────
        RequestLog.objects.create(
            user_id=user_id,
            ip=ip,
            device=device,
            endpoint=endpoint,
            risk_score=final_risk,
            attack_type=attack_type,
            decision=decision,
            user_input=user_input,
            latency_ms=latency_ms,
        )

        return Response({
            "status": "logged",
            "chatbot_risk": chatbot_risk,
            "ml_risk": ml_risk,
            "final_risk": final_risk,
        })


# ─── GET /api/sessions/ ──────────────────────────────────────────────
class SessionsView(APIView):
    """Returns last 100 request logs for the Security Dashboard."""

    def get(self, request):
        logs = RequestLog.objects.order_by("-timestamp")[:100]
        # Build user_id -> username map
        user_ids = set(log.user_id for log in logs if log.user_id)
        user_map = {str(u.user_id): u.username for u in ChatbotUser.objects.filter(user_id__in=user_ids)}
        data = [
            {
                "user": user_map.get(log.user_id, log.user_id[:8] if log.user_id else "—"),
                "session_id": str(log.id),
                "ip_address": log.ip or "—",
                "risk_score": log.risk_score,
                "status": "blocked" if (log.risk_score or 0) > 70 else "active",
                "device": log.device or "—",
                "endpoint": log.endpoint or "—",
                "attack_type": log.attack_type or "—",
                "decision": log.decision or "—",
                "created_at": log.timestamp.isoformat(),
            }
            for log in logs
        ]
        return Response(data)


# ─── GET /api/alerts/ ────────────────────────────────────────────────
class AlertsView(APIView):
    """Returns high-risk request logs as security alerts (risk > 40)."""

    def get(self, request):
        logs = RequestLog.objects.filter(risk_score__gt=40).order_by("-timestamp")[:50]
        user_ids = set(log.user_id for log in logs if log.user_id)
        user_map = {str(u.user_id): u.username for u in ChatbotUser.objects.filter(user_id__in=user_ids)}
        data = [
            {
                "user": user_map.get(log.user_id, log.user_id[:8] if log.user_id else "—"),
                "risk_score": log.risk_score,
                "reason": f"Attack: {log.attack_type}" if log.attack_type and log.attack_type != "—" else f"High risk on {log.endpoint or 'unknown'}",
                "attack_type": log.attack_type or "—",
                "decision": log.decision or "—",
                "user_input": (log.user_input or "")[:100],
                "ip": log.ip or "—",
                "device": log.device or "—",
                "timestamp": log.timestamp.isoformat(),
            }
            for log in logs
        ]
        return Response(data)


# ─── GET /api/users/ ─────────────────────────────────────────────────
class UsersListView(APIView):
    """Returns all registered chatbot users."""

    def get(self, request):
        users = ChatbotUser.objects.all().order_by('-created_at')
        data = [
            {
                "user_id": str(u.user_id),
                "username": u.username,
                "email": u.email,
                "last_login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
                "joined_at": u.created_at.strftime("%Y-%m-%d") if u.created_at else "",
            }
            for u in users
        ]
        return Response({"message": "OK", "data": data, "error": None})
