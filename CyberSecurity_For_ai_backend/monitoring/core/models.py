from django.db import models
import uuid


class ChatbotUser(models.Model):
    """Simplified user model — no auth, just identity for the chatbot."""
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username


class UserProfile(models.Model):
    """Stores behavioral baselines for risk scoring."""
    user = models.OneToOneField(ChatbotUser, on_delete=models.CASCADE)
    usual_ip_prefixes = models.JSONField(default=dict)
    usual_device = models.CharField(max_length=100, null=True, blank=True)
    usual_login_start = models.IntegerField(default=0)
    usual_login_end = models.IntegerField(default=23)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile: {self.user.username}"


class RequestLog(models.Model):
    """Logs every chatbot interaction for monitoring and risk analysis."""
    user_id = models.CharField(max_length=255)
    ip = models.GenericIPAddressField(null=True, blank=True)
    device = models.CharField(max_length=255, null=True, blank=True)
    endpoint = models.CharField(max_length=255, null=True, blank=True)
    risk_score = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    # Chatbot-specific fields
    attack_type = models.CharField(max_length=100, null=True, blank=True)
    decision = models.CharField(max_length=20, null=True, blank=True)
    user_input = models.TextField(null=True, blank=True)
    latency_ms = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp}] {self.user_id} — risk:{self.risk_score}"
