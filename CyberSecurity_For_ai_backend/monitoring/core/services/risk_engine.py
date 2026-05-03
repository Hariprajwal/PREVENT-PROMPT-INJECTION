from datetime import datetime

def calculate_risk(user_profile, context):
    score = 0
    reasons = []

    # IP check
    if user_profile.usual_ip_prefixes:
        ip_data = user_profile.usual_ip_prefixes or {}
        prefix = ".".join(context["ip"].split(".")[:2])

        count = ip_data.get(prefix, 0)

        if count == 0:
            score += 30
            reasons.append("new_ip")
        elif count < 5:
            score += 20
            reasons.append("rare_ip")
        elif count < 15:
            score += 10
            reasons.append("uncommon_ip")
        else:
            score += 0  # trusted

    # Device check
    if user_profile.usual_device and context["device"] != user_profile.usual_device:
        score += 20
        reasons.append("new_device")

    # Time anomaly
    hour = datetime.utcnow().hour
    if not (user_profile.usual_login_start <= hour <= user_profile.usual_login_end):
        score += 10
        reasons.append("unusual_time")

    return score, reasons
