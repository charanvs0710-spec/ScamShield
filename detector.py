import re


def detect_scam(message):
    message = message.lower()

    score = 0
    reasons = []
    category = "General Suspicious Message"

    # 1. Urgency / pressure
    urgent_words = [
        "urgent", "immediately", "act now",
        "within 24 hours", "last chance",
        "account will be blocked",
        "account will be suspended"
    ]

    if any(word in message for word in urgent_words):
        score += 15
        reasons.append("Urgent or pressure-based language detected")

    # 2. Prize / reward
    prize_words = [
        "prize", "winner", "won", "lottery",
        "reward", "cashback", "gift", "lucky draw"
    ]

    if any(word in message for word in prize_words):
        score += 20
        reasons.append("Prize or reward related language detected")
        category = "Prize / Reward Scam"

    # 3. Banking / financial
    banking_words = [
        "bank", "account", "upi", "credit card",
        "debit card", "payment", "transaction",
        "refund", "kyc"
    ]

    if any(word in message for word in banking_words):
        score += 20
        reasons.append("Financial or banking information mentioned")
        category = "Banking / Financial Scam"

    # 4. Sensitive information
    sensitive_words = [
        "otp", "password", "pin", "cvv",
        "passcode", "verification code"
    ]

    if any(word in message for word in sensitive_words):
        score += 25
        reasons.append("Sensitive information request detected")

    # 5. Suspicious URL
    url_pattern = r"https?://\S+|www\.\S+"

    if re.search(url_pattern, message):
        score += 20
        reasons.append("Suspicious link detected")

    # 6. Threat / fear
    threat_words = [
        "legal action", "police", "arrest",
        "penalty", "fine", "blocked",
        "suspended", "deactivated"
    ]

    if any(word in message for word in threat_words):
        score += 20
        reasons.append("Threat or fear-based language detected")

    # 7. Impersonation
    impersonation_words = [
        "customer care", "support team",
        "bank officer", "government",
        "income tax", "police department",
        "official"
    ]

    if any(word in message for word in impersonation_words):
        score += 15
        reasons.append("Possible organization impersonation detected")

    # Keep score within 100
    score = min(score, 100)

    # Risk classification
    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "SUSPICIOUS"
    else:
        risk = "LOW RISK"

    # Confidence
    confidence = min(score + 20, 95)

    # Attacker intent
    if any(word in message for word in [
        "otp", "pin", "cvv", "password", "passcode"
    ]):
        intent = "Steal sensitive credentials or account access"

    elif any(word in message for word in [
        "upi", "payment", "bank",
        "credit card", "debit card"
    ]):
        intent = "Obtain financial information or money"

    elif re.search(url_pattern, message):
        intent = "Trick the victim into visiting a potentially malicious website"

    elif any(word in message for word in [
        "prize", "lottery", "winner", "reward"
    ]):
        intent = "Trick the victim using a fake reward or prize"

    elif any(word in message for word in [
        "kyc", "verify account", "account blocked"
    ]):
        intent = "Steal personal information through fake verification"

    else:
        intent = "No clear attacker objective detected"

    return risk, score, reasons, category, confidence, intent