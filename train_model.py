# train_model.py

import os
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)


# ============================================================
# TRAINING DATA
# 1 = SCAM
# 0 = LEGITIMATE
#
# This is only a starter dataset.
# For the final system, replace this with a much larger
# properly labelled dataset.
# ============================================================

messages = [

    # ---------------- SCAM ----------------

    "URGENT your bank account will be blocked verify your account immediately",
    "Congratulations you have won a lottery prize click the link to claim",
    "Your OTP is required to complete this transaction",
    "Your account has been suspended login immediately to restore access",
    "You have received a cashback reward claim it now",
    "Your KYC has expired verify your details immediately",
    "You are selected for an easy work from home job pay registration fee",
    "Instant loan approved pay processing fee to receive money",
    "Double your money with guaranteed investment returns",
    "Your parcel is waiting pay delivery charges using this link",
    "Verify your banking information to avoid account closure",
    "Click this link to confirm your payment",
    "Your credit card has been blocked update your information",
    "Government refund available submit your bank details",
    "You won a cash prize provide your account details",
    "Security alert login immediately to prevent account suspension",
    "Your UPI account requires verification send the OTP",
    "Earn money daily from home pay a small registration fee",
    "Guaranteed profit investment opportunity limited time",
    "Pay customs charges to release your package",

    # ---------------- LEGITIMATE ----------------

    "Your electricity bill is due on the 20th of this month",
    "Your bank statement is now available in the official application",
    "Your order has been shipped and will arrive tomorrow",
    "Your appointment is scheduled for Monday at 10 AM",
    "Your monthly subscription has been renewed successfully",
    "Your college examination timetable has been published",
    "Your payment was successfully completed",
    "Your package has been delivered",
    "Your account statement can be viewed in the mobile application",
    "The meeting has been scheduled for tomorrow",
    "Your flight booking has been confirmed",
    "Your password was changed successfully",
    "Your monthly bill is ready to view",
    "The requested document is available in your account",
    "Your application has been received successfully",
    "Your order is currently being processed",
    "Your appointment reminder is scheduled for tomorrow",
    "The transaction was completed successfully",
    "Your membership renewal was successful",
    "The university has published the examination results"
]


labels = [
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,

    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0
]


# ============================================================
# SPLIT DATA
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    messages,
    labels,
    test_size=0.25,
    random_state=42,
    stratify=labels
)


# ============================================================
# NLP + MACHINE LEARNING PIPELINE
# ============================================================

model = Pipeline([

    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            sublinear_tf=True,
            max_features=5000
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        )
    )
])


# ============================================================
# TRAIN
# ============================================================

print("\nTraining ScamShield NLP model...\n")

model.fit(X_train, y_train)


# ============================================================
# TEST
# ============================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions, zero_division=0)
recall = recall_score(y_test, predictions, zero_division=0)
f1 = f1_score(y_test, predictions, zero_division=0)


print("======================================")
print("       SCAMSHIELD MODEL RESULTS")
print("======================================")

print(f"Accuracy :  {accuracy:.2%}")
print(f"Precision:  {precision:.2%}")
print(f"Recall   :  {recall:.2%}")
print(f"F1 Score :  {f1:.2%}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Scam"],
        zero_division=0
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs("models", exist_ok=True)

joblib.dump(
    model,
    "models/scamshield_nlp.pkl"
)

print("\nModel saved successfully:")
print("models/scamshield_nlp.pkl")