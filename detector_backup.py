import re


def detect_scam(message):
    message = message.lower()

    score = 0
    reasons = []

    # 1. Urgent language
    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "limited time",
        "last chance"
    ]

    for word in urgent_words:
        if word in message:
            score += 15
            reasons.append("Urgent or pressure-based language detected")
            break

    # 2. Prize / reward scams
    prize_words = [
        "prize",
        "winner",
        "won",
        "lottery",
        "reward",
        "cashback",
        "gift"
    ]

    for word in prize_words:
        if word in message:
            score += 20
            reasons.append("Prize or reward related language detected")
            break

    # 3. Banking / financial information
    banking_words = [
        "bank",
        "account",
        "upi",
        "credit card",
        "debit card",
        "payment"
    ]

    for word in banking_words:
        if word in message:
            score += 20
            reasons.append("Financial or banking information mentioned")
            break

    # 4. Sensitive information
    sensitive_words = [
        "otp",
        "password",
        "pin",
        "cvv"
    ]

    for word in sensitive_words:
        if word in message:
            score += 25
            reasons.append("Sensitive information request detected")
            break

    # 5. Suspicious links
    url_pattern = r"https?://\S+|www\.\S+"

    if re.search(url_pattern, message):
        score += 20
        reasons.append("Suspicious link detected")

    # Keep score within 100
    score = min(score, 100)

    # Risk classification
    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "SUSPICIOUS"
    else:
        risk = "LOW RISK"

    return risk, score, reasons