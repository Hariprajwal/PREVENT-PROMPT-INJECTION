from rest_framework.views import APIView
from rest_framework.response import Response
from collections import Counter

from core.models import RequestLog, ChatbotUser


# ─── GET /api/users/ (flat array format for Users.jsx) ───────────────
class UserListView(APIView):

    def get(self, request):
        users = ChatbotUser.objects.all().order_by('-created_at')
        data = [
            {
                "id": str(u.user_id),
                "name": u.username,
                "email": u.email,
                "last_login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
                "joined_at": u.created_at.strftime("%Y-%m-%d") if u.created_at else "",
            }
            for u in users
        ]
        return Response(data)


# ─── GET /api/user/summary/?user_id=<id> ─────────────────────────────
class UserSummaryView(APIView):

    def get(self, request):
        user_id = request.query_params.get("user_id")
        if not user_id:
            return Response({"error": "user_id is required"}, status=400)

        logs = list(RequestLog.objects.filter(user_id=user_id))

        if not logs:
            return Response({
                "user_id": user_id,
                "total_requests": 0,
                "avg_risk_score": 0,
                "requests_per_day": 0,
                "avg_packets_per_request": 0,
                "frequency_interval": "N/A",
            })

        total = len(logs)
        avg_risk = round(sum(l.risk_score or 0 for l in logs) / total, 1)

        # Group by day
        from django.db.models.functions import TruncDate
        from django.db.models import Count
        daily = (
            RequestLog.objects.filter(user_id=user_id)
            .annotate(day=TruncDate("timestamp"))
            .values("day")
            .annotate(cnt=Count("id"))
        )
        num_days = max(len(daily), 1)
        requests_per_day = round(total / num_days, 1)

        # Frequency between requests
        timestamps = sorted(l.timestamp for l in logs if l.timestamp)
        if len(timestamps) > 1:
            deltas = [
                (timestamps[i + 1] - timestamps[i]).total_seconds() / 60
                for i in range(len(timestamps) - 1)
            ]
            avg_interval = round(sum(deltas) / len(deltas), 1)
            frequency = f"Every {avg_interval} mins"
        else:
            frequency = "N/A"

        return Response({
            "user_id": user_id,
            "total_requests": total,
            "avg_risk_score": avg_risk,
            "requests_per_day": requests_per_day,
            "avg_packets_per_request": round(total / num_days, 1),
            "frequency_interval": frequency,
        })


# ─── GET /api/user/analytics/?user_id=<id> ───────────────────────────
class UserAnalyticsView(APIView):

    def get(self, request):
        user_id = request.query_params.get("user_id")
        if not user_id:
            return Response({"error": "user_id is required"}, status=400)

        logs = RequestLog.objects.filter(user_id=user_id)

        ip_counter = Counter(l.ip for l in logs if l.ip)
        endpoint_counter = Counter(l.endpoint for l in logs if l.endpoint)
        device_counter = Counter(l.device for l in logs if l.device)

        return Response({
            "user_id": user_id,
            "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(5)],
            "top_endpoints": [{"endpoint": ep, "count": c} for ep, c in endpoint_counter.most_common(5)],
            "top_devices": [{"device": d, "count": c} for d, c in device_counter.most_common(5)],
        })


# ─── GET /api/user/logs/?user_id=<id>&page=1&limit=10 ────────────────
class UserLogsView(APIView):

    def get(self, request):
        user_id = request.query_params.get("user_id")
        if not user_id:
            return Response({"error": "user_id is required"}, status=400)

        page = int(request.query_params.get("page", 1))
        limit = int(request.query_params.get("limit", 10))
        offset = (page - 1) * limit

        qs = RequestLog.objects.filter(user_id=user_id).order_by("-timestamp")
        total = qs.count()
        logs = qs[offset: offset + limit]

        return Response({
            "user_id": user_id,
            "page": page,
            "limit": limit,
            "count": total,
            "results": [
                {
                    "user_id": log.user_id,
                    "ip": log.ip,
                    "device": log.device,
                    "endpoint": log.endpoint,
                    "risk_score": log.risk_score,
                    "attack_type": log.attack_type or "—",
                    "decision": log.decision or "—",
                    "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M") if log.timestamp else None,
                }
                for log in logs
            ],
        })
