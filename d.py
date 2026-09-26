import os
import re
import joblib

from url import analyze_url


# ============================================================
# LOAD MACHINE LEARNING MODEL
# ============================================================

MODEL_PATH = os.path.join(
    "models",
    "scamshield_nlp.pkl"
)

try:
    model = joblib.load(MODEL_PATH)
    ML_AVAILABLE = True
    print("ScamShield NLP model loaded successfully.")

except Exception:
    model = None
    ML_AVAILABLE = False
    print("WARNING: NLP model not found.")
    print("Run: py train_model.py")


# ============================================================
# HIGH-VALUE SECURITY SIGNALS
# ============================================================

CREDENTIAL_TERMS = [
    "otp",
    "password",
    "pin",
    "cvv",
    "verification code",
    "security code"
]


FINANCIAL_TERMS = [
    "bank",
    "upi",
    "payment",
    "transaction",
    "credit card",
    "debit card",
    "refund",
    "cashback",
    "kyc",
    "account"
]


THREAT_TERMS = [
    "blocked",
    "suspended",
    "deactivated",
    "legal action",
    "arrest",
    "penalty",
    "fine"
]


URGENCY_TERMS = [
    "urgent",
    "immediately",
    "act now",
    "verify now",
    "within 24 hours",
    "last chance"
]


# ============================================================
# ORGANIZATION IDENTITY SIGNALS
# ============================================================

ORGANIZATION_TERMS = {

    "SBI": [
        "sbi",
        "state bank of india",
        "sbi bank"
    ],

    "HDFC Bank": [
        "hdfc",
        "hdfc bank"
    ],

    "ICICI Bank": [
        "icici",
        "icici bank"
    ],

    "Axis Bank": [
        "axis bank"
    ],

    "Paytm": [
        "paytm"
    ],

    "PhonePe": [
        "phonepe"
    ],

    "Google Pay": [
        "google pay",
        "gpay"
    ],

    "Income Tax Department": [
        "income tax department",
        "income tax"
    ],

    "Police": [
        "police department",
        "cyber police"
    ]
}


# ============================================================
# HELPER
# ============================================================

def contains_term(message, terms):

    for term in terms:

        if re.search(
            r"\b" + re.escape(term) + r"\b",
            message
        ):
            return True

    return False


# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_scam(message):

    original_message = message

    message = message.lower().strip()

    reasons = []


    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    ml_probability = 0.0
    ml_prediction = 0

    if ML_AVAILABLE:

        probabilities = model.predict_proba(
            [message]
        )[0]

        # Probability of class 1 = scam
        ml_probability = probabilities[1]

        ml_prediction = int(
            model.predict([message])[0]
        )


    # --------------------------------------------------------
    # SECURITY SIGNALS
    # --------------------------------------------------------

    credential = contains_term(
        message,
        CREDENTIAL_TERMS
    )

    financial = contains_term(
        message,
        FINANCIAL_TERMS
    )

    threat = contains_term(
        message,
        THREAT_TERMS
    )

    urgency = contains_term(
        message,
        URGENCY_TERMS
    )


    # --------------------------------------------------------
    # IDENTITY / IMPERSONATION DETECTION
    # --------------------------------------------------------

    claimed_identity = None

    for organization, terms in ORGANIZATION_TERMS.items():

        if contains_term(message, terms):

            claimed_identity = organization

            reasons.append(
                f"Message claims to represent {organization}"
            )

            break

    impersonation = claimed_identity is not None


    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_detected = False
    url_score = 0
    url_findings = []

    url_pattern = r"https?://\S+|www\.\S+"

    url_match = re.search(
        url_pattern,
        original_message,
        re.IGNORECASE
    )

    if url_match:

        url_detected = True

        detected_url = (
            url_match.group()
            .rstrip(".,!?)]}")
        )

        url_score, url_findings = analyze_url(
            detected_url
        )

        reasons.extend(url_findings)


    # --------------------------------------------------------
    # ML EVIDENCE
    # --------------------------------------------------------

    if ML_AVAILABLE:

        if ml_probability >= 0.80:

            reasons.append(
                f"NLP model strongly indicates scam "
                f"({ml_probability:.0%} probability)"
            )

        elif ml_probability >= 0.60:

            reasons.append(
                f"NLP model indicates suspicious language "
                f"({ml_probability:.0%} probability)"
            )

        elif ml_probability <= 0.20:

            reasons.append(
                f"NLP model indicates legitimate language "
                f"({(1 - ml_probability):.0%} probability)"
            )


    # --------------------------------------------------------
    # SECURITY EVIDENCE
    # --------------------------------------------------------

    if credential:

        reasons.append(
            "Sensitive credential information requested"
        )

    if financial:

        reasons.append(
            "Financial context detected"
        )

    if threat:

        reasons.append(
            "Threat or fear-based language detected"
        )

    if urgency:

        reasons.append(
            "Urgency or pressure detected"
        )


    # --------------------------------------------------------
    # HYBRID RISK CALCULATION
    # --------------------------------------------------------

    # ML = primary semantic signal
    # Rules = supporting evidence
    # URL = technical evidence

    if ML_AVAILABLE:

        ml_score = ml_probability * 60

    else:

        ml_score = 0


    rule_score = 0


    if impersonation:

        rule_score += 8


    if credential:

        rule_score += 10


    if financial:

        rule_score += 8


    if threat:

        rule_score += 8


    if urgency:

        rule_score += 6


    if url_detected:

        rule_score += min(url_score, 25)


    # --------------------------------------------------------
    # CORRELATION
    # --------------------------------------------------------

    if financial and credential:

        rule_score += 10

        reasons.append(
            "Financial context combined with credential request"
        )


    if threat and urgency:

        rule_score += 8

        reasons.append(
            "Threat combined with urgency"
        )


    if url_detected and credential:

        rule_score += 10

        reasons.append(
            "Suspicious link combined with credential request"
        )

        if impersonation and financial:

            rule_score += 8

            reasons.append(
                "Claimed organization combined with financial context"
            )


    if impersonation and credential:

        rule_score += 10

        reasons.append(
            "Claimed organization combined with credential request"
        )


    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    score = round(
        min(
            ml_score + rule_score,
            100
        )
    )


    # --------------------------------------------------------
    # TECHNICAL EVIDENCE
    # --------------------------------------------------------

    technical_evidence = any(

        phrase.lower() in " ".join(reasons).lower()

        for phrase in [

            "raw ip address detected",
            "non-standard port detected",
            "url uses http instead of https",
            "possible look-alike punycode domain detected",
            "link-shortening service",
            "embedded login information",
            "unusually large number of subdomains",
            "url contains '@' character"
        ]
    )


    # --------------------------------------------------------
    # STRONG EVIDENCE
    # --------------------------------------------------------

    strong_evidence = (

        financial

        and credential

        and url_detected

        and (
            technical_evidence
            or threat
        )
    )


    # Force 100 only when strong evidence exists

    if strong_evidence:

        score = 100


    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score == 100:

        risk = "CRITICAL"

    elif score >= 90:

        risk = "CRITICAL"

    elif score >= 60:

        risk = "HIGH RISK"

    elif score >= 30:

        risk = "SUSPICIOUS"

    else:

        risk = "LOW RISK"


    # --------------------------------------------------------
    # CATEGORY
    # --------------------------------------------------------

    if financial and credential:

        category = "Banking / Credential Scam"

    elif credential:

        category = "Credential / OTP Scam"

    elif url_detected and financial:

        category = "Financial Phishing"

    elif url_detected:

        category = "Suspicious Link Scam"

    elif financial:

        category = "Financial Scam"

    elif impersonation:

        category = "Organization Impersonation Scam"

    elif threat:

        category = "Threat-Based Scam"

    else:

        category = "Suspicious Message"


    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    evidence_count = sum([
        credential,
        financial,
        threat,
        urgency,
        url_detected,
        technical_evidence
    ])


    if ML_AVAILABLE:

        # Start from ML model's certainty
        confidence = round(
            max(
                ml_probability,
                1 - ml_probability
            ) * 100
        )

        # Give a small boost when independent
        # security evidence agrees with detection

        if evidence_count >= 3:

            confidence += 5

        elif evidence_count >= 2:

            confidence += 3

        confidence = min(
            confidence,
            97
        )

    else:

        confidence = min(
            50 + (evidence_count * 7),
            90
        )


    # Strong converging evidence gets very high confidence

    if strong_evidence:

        confidence = 99


    # --------------------------------------------------------
    # ATTACKER INTENT
    # --------------------------------------------------------

    if financial and credential:

        intent = (
            "Likely attempt to obtain credentials or "
            "verification information for financial access"
        )

    elif credential:

        intent = (
            "Likely attempt to obtain sensitive "
            "authentication information"
        )

    elif financial and url_detected:

        intent = (
            "Likely attempt to redirect the victim to "
            "a fraudulent financial destination"
        )

    elif url_detected:

        intent = (
            "Likely attempt to make the victim visit "
            "a potentially malicious website"
        )

    elif financial:

        intent = (
            "Likely attempt to obtain money or "
            "financial information"
        )

    elif threat:

        intent = (
            "Likely attempt to manipulate the victim "
            "through fear or consequences"
        )

    else:

        intent = (
            "No clear attacker objective identified"
        )


    # --------------------------------------------------------
    # REMOVE DUPLICATE REASONS
    # --------------------------------------------------------

    reasons = list(
        dict.fromkeys(reasons)
    )


    # --------------------------------------------------------
    # RETURN SAME FORMAT AS YOUR EXISTING APP
    # --------------------------------------------------------

    return (
        risk,
        score,
        reasons,
        category,
        confidence,
        intent
    )