def decide(score):
    if score < 30:
        return "ALLOW"
    elif score < 60:
        return "MONITOR"
    elif score < 80:
        return "CHALLENGE"
    else:
        return "BLOCK"
