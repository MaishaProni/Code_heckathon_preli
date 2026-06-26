"""
QueueStorm Investigator - Pure rule-based complaint investigation service
SUST CSE Carnival 2026 / Codex Community Hackathon
"""

import re
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, field_validator

app = FastAPI(title="QueueStorm Investigator")


# ─── Models ───────────────────────────────────────────────────────────────────

class Transaction(BaseModel):
    transaction_id: str
    timestamp: Optional[str] = None
    type: Optional[str] = None
    amount: Optional[float] = None
    counterparty: Optional[str] = None
    status: Optional[str] = None


class AnalyzeRequest(BaseModel):
    ticket_id: str
    complaint: str
    language: Optional[str] = None
    channel: Optional[str] = None
    user_type: Optional[str] = None
    campaign_context: Optional[str] = None
    transaction_history: Optional[List[Transaction]] = []
    metadata: Optional[dict] = None

    @field_validator("complaint")
    @classmethod
    def complaint_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("complaint must not be empty")
        return v.strip()


class AnalyzeResponse(BaseModel):
    ticket_id: str
    relevant_transaction_id: Optional[str]
    evidence_verdict: str         # consistent | inconsistent | insufficient_data
    case_type: str
    severity: str                 # low | medium | high | critical
    department: str
    agent_summary: str
    recommended_next_action: str
    customer_reply: str
    human_review_required: bool
    confidence: Optional[float] = None
    reason_codes: Optional[List[str]] = None


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    msg = first.get("msg", "Validation error")
    return JSONResponse(status_code=422, content={"error": "Invalid request", "detail": msg})


@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Contact support through official channels."},
    )


# ─── Keyword taxonomy ─────────────────────────────────────────────────────────
# Phishing is checked first; order matters when complaint matches multiple types.

_PHISHING_KW = [
    # English
    "someone called", "called me asking", "asked for my pin", "asked for my otp",
    "asked for my password", "share your pin", "share your otp", "share your password",
    "give me your pin", "give me your otp", "give me your password",
    "asking for pin", "asking for otp", "asking for password",
    "share pin", "share otp", "share password",
    "scam", "fraud call", "fraudster", "impersonating", "impersonator",
    "fake bkash", "fake agent", "suspicious call", "suspicious sms", "suspicious message",
    "phishing", "claiming to be from bkash", "pretending to be",
    # Banglish
    "pin dite boleche", "otp dite boleche", "pin chai", "otp chai",
    # Bangla
    "পিন চাইছে", "ওটিপি চাইছে", "পাসওয়ার্ড চাইছে",
    "ফোন করে পিন", "ফোন করে ওটিপি",
    "প্রতারণা", "প্রতারক", "সন্দেহজনক",
]

_WRONG_TRANSFER_KW = [
    # English
    "wrong number", "wrong person", "wrong recipient", "wrong account",
    "sent to wrong", "transferred to wrong", "wrong transfer", "wrong mobile",
    "mistakenly sent", "accidentally sent", "sent by mistake",
    "wrong bkash number", "wrong contact",
    # Banglish
    "bhul number", "bhul manush", "wrong e pathiyechi",
    # Bangla
    "ভুল নম্বরে", "ভুল নম্বর", "ভুল মানুষকে", "ভুল ব্যক্তিকে",
    "ভুলে পাঠিয়েছি", "ভুলে দিয়েছি",
]

_DUPLICATE_KW = [
    # English
    "charged twice", "double charge", "duplicate charge", "duplicate payment",
    "paid twice", "deducted twice", "two times", "charged two times",
    "double deduction", "double deducted", "same payment twice", "billed twice",
    # Banglish
    "dui baar", "duibar",
    # Bangla
    "দুইবার", "দুবার", "ডুপ্লিকেট", "দুইবার কাটা", "দুইবার চার্জ",
]

_PAYMENT_FAILED_KW = [
    # English – adjacent phrases
    "payment failed", "transaction failed", "payment unsuccessful", "failed transaction",
    "failed payment", "payment not successful", "transaction not successful",
    "balance deducted but", "money deducted but", "deducted from account",
    "balance gone", "money gone", "amount deducted",
    "cash out failed", "cash_out failed", "not received the money",
    "payment not completed", "taka failed", "failed but balance",
    "balance was deducted", "was deducted", "got deducted",
    "deducted but not", "deducted but did not", "deducted but payment",
    "but not received", "cut but not",
    # Banglish
    "payment fail", "transaction fail", "fail hoyeche", "kata giyeche",
    # Bangla
    "টাকা কাটা গেছে কিন্তু", "ব্যালেন্স কাটা", "পেমেন্ট ফেল", "ট্রানজেকশন ফেল",
    "কাটা গেছে কিন্তু", "টাকা কাটা",
]

_MERCHANT_SETTLEMENT_KW = [
    # English
    "settlement", "merchant settlement", "settlement not received",
    "settlement delayed", "pending settlement", "settlement pending", "settlement amount",
    # Banglish
    "settlement pai ni",
    # Bangla
    "সেটেলমেন্ট", "সেটেলমেন্ট পাইনি", "মার্চেন্ট পেমেন্ট পাইনি",
]

_AGENT_CASH_IN_KW = [
    # English
    "cash in", "cash-in", "cashin", "cash_in", "cash deposit",
    "deposited cash", "through agent", "agent cash", "agent deposit",
    "balance not updated", "balance not reflected", "not credited",
    # Banglish
    "cash diyechi", "agent theke", "cash in korechhi",
    # Bangla
    "ক্যাশ ইন", "এজেন্টের কাছে ক্যাশ", "ক্যাশ দিয়েছি", "এজেন্টের কাছে",
]

_REFUND_KW = [
    # English
    "refund", "money back", "want my money back", "return my money",
    "return the money", "give back", "give me back",
    "want refund", "need refund", "requesting refund", "please refund",
    # Banglish
    "refund dao", "return koro",
    # Bangla
    "রিফান্ড", "টাকা ফেরত", "ফেরত চাই", "টাকা ফিরিয়ে দিন",
]

# Priority-ordered: phishing first (safety), then more specific cases
_CASE_PATTERNS: List[tuple] = [
    ("phishing_or_social_engineering", _PHISHING_KW),
    ("wrong_transfer",                 _WRONG_TRANSFER_KW),
    ("duplicate_payment",              _DUPLICATE_KW),
    ("payment_failed",                 _PAYMENT_FAILED_KW),
    ("merchant_settlement_delay",      _MERCHANT_SETTLEMENT_KW),
    ("agent_cash_in_issue",            _AGENT_CASH_IN_KW),
    ("refund_request",                 _REFUND_KW),
]

# Co-occurrence patterns: all required_words must appear anywhere in complaint
# (case_type, [required_words...], boost_score)
_COOCCURRENCE_PATTERNS = [
    # Wrong transfer – "sent" + non-receipt signal
    ("wrong_transfer", ["sent", "didn't get"],      4),
    ("wrong_transfer", ["sent", "did not get"],     4),
    ("wrong_transfer", ["sent", "didn't receive"],  4),
    ("wrong_transfer", ["sent", "did not receive"], 4),
    ("wrong_transfer", ["sent", "not received"],    3),
    ("wrong_transfer", ["sent", "wrong"],           3),
    ("wrong_transfer", ["transfer", "wrong"],       3),
    ("wrong_transfer", ["sent", "mistake"],         2),
    ("wrong_transfer", ["transferred", "wrong"],    3),
    # Payment failed
    ("payment_failed", ["payment", "failed"],       3),
    ("payment_failed", ["balance", "deducted"],     3),
    ("payment_failed", ["money", "deducted"],       3),
    ("payment_failed", ["deducted", "not received"],3),
    ("payment_failed", ["failed", "balance"],       2),
    # Duplicate
    ("duplicate_payment", ["charged", "twice"],     3),
    ("duplicate_payment", ["paid", "twice"],        3),
    ("duplicate_payment", ["deducted", "twice"],    3),
    # Refund
    ("refund_request", ["want", "money back"],      3),
    ("refund_request", ["give", "back"],            2),
    # Agent
    ("agent_cash_in_issue", ["cash", "agent"],      3),
    ("agent_cash_in_issue", ["deposit", "not reflected"], 3),
    # Merchant
    ("merchant_settlement_delay", ["merchant", "settlement"], 3),
    ("merchant_settlement_delay", ["settlement", "not"],      2),
]

_DEPT_MAP = {
    "wrong_transfer":               "dispute_resolution",
    "payment_failed":               "payments_ops",
    "refund_request":               "customer_support",
    "duplicate_payment":            "payments_ops",
    "merchant_settlement_delay":    "merchant_operations",
    "agent_cash_in_issue":          "agent_operations",
    "phishing_or_social_engineering": "fraud_risk",
    "other":                        "customer_support",
}

_CASE_TX_TYPES = {
    "wrong_transfer":               ["transfer"],
    "payment_failed":               ["payment", "transfer", "cash_out"],
    "refund_request":               ["payment", "transfer", "refund"],
    "duplicate_payment":            ["payment", "transfer"],
    "merchant_settlement_delay":    ["settlement", "payment"],
    "agent_cash_in_issue":          ["cash_in"],
    "phishing_or_social_engineering": [],
    "other":                        [],
}


# ─── Safe text templates (safety rules enforced here) ─────────────────────────

_CUSTOMER_REPLY_EN = {
    "phishing_or_social_engineering": (
        "Thank you for alerting us to this suspicious activity. "
        "Please be aware that our official support will never ask for your PIN, OTP, password, "
        "or any security credential under any circumstance. "
        "Do not share this information with anyone claiming to represent us. "
        "Your report has been escalated to our security team for immediate review. "
        "Please contact us only through our official app or hotline."
    ),
    "wrong_transfer": (
        "Thank you for reaching out. We have recorded your concern regarding the unintended transfer. "
        "Our dispute resolution team will review the transaction details and take appropriate action "
        "through official procedures. We will keep you informed through official channels. "
        "Please do not share your PIN or OTP with anyone."
    ),
    "payment_failed": (
        "Thank you for contacting us. We have received your report regarding the payment issue. "
        "Our payments team will investigate the transaction status and verify any balance discrepancy. "
        "Any eligible amount will be returned through official channels. "
        "We will update you on the outcome. Please do not share your PIN or OTP with anyone."
    ),
    "duplicate_payment": (
        "Thank you for bringing this to our attention. We have noted your report of a possible duplicate charge. "
        "Our team will review your transaction history and investigate thoroughly. "
        "Any eligible amount will be returned through official channels. "
        "Please do not share your PIN or OTP with anyone."
    ),
    "merchant_settlement_delay": (
        "Thank you for contacting us regarding your settlement. We have noted your concern. "
        "Our merchant operations team will review the settlement status and investigate any delays. "
        "We will update you through official channels once the review is complete."
    ),
    "agent_cash_in_issue": (
        "Thank you for reaching out. We have recorded your concern about the cash-in transaction. "
        "Our team will verify the transaction with the relevant records. "
        "If a discrepancy is confirmed, it will be resolved through official procedures. "
        "Please do not share your PIN or OTP with anyone."
    ),
    "refund_request": (
        "Thank you for contacting us. We have received your request and it is under review. "
        "Our team will assess the details of your case. "
        "If your request is found eligible, any applicable amount will be processed through official channels. "
        "We appreciate your patience. Please do not share your PIN or OTP with anyone."
    ),
    "other": (
        "Thank you for contacting us. We have received your concern and assigned it to the appropriate team. "
        "Our support staff will review your case and respond through official channels. "
        "Please do not share any personal credentials or sensitive information with anyone."
    ),
}

_CUSTOMER_REPLY_BN = {
    "phishing_or_social_engineering": (
        "আপনি সতর্ক থাকায় আমরা কৃতজ্ঞ। আমাদের অফিসিয়াল সাপোর্ট কখনও আপনার পিন, ওটিপি বা পাসওয়ার্ড চাইবে না। "
        "কাউকে এই তথ্য শেয়ার করবেন না। আমাদের নিরাপত্তা দল বিষয়টি তদন্ত করছে। "
        "শুধুমাত্র অফিসিয়াল চ্যানেলে আমাদের সাথে যোগাযোগ করুন।"
    ),
    "wrong_transfer": (
        "আপনার লেনদেনের বিষয়ে আমরা অবগত হয়েছি। আমাদের ডিসপুট রেজোলিউশন দল বিষয়টি যাচাই করবে এবং "
        "অফিসিয়াল প্রক্রিয়ার মাধ্যমে প্রয়োজনীয় পদক্ষেপ নেবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    "payment_failed": (
        "আপনার অভিযোগটি আমরা গ্রহণ করেছি। আমাদের পেমেন্ট দল লেনদেনের স্ট্যাটাস যাচাই করবে। "
        "যোগ্য ক্ষেত্রে যেকোনো পরিমাণ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। "
        "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    "duplicate_payment": (
        "আপনার রিপোর্টটি আমরা গ্রহণ করেছি। আমাদের দল আপনার লেনদেনের ইতিহাস যাচাই করবে। "
        "ডুপ্লিকেট চার্জ নিশ্চিত হলে যোগ্য পরিমাণ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। "
        "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    "merchant_settlement_delay": (
        "আপনার সেটেলমেন্টের বিষয়ে আমরা অবগত হয়েছি। আমাদের মার্চেন্ট অপারেশন্স দল স্ট্যাটাস যাচাই করবে "
        "এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে।"
    ),
    "agent_cash_in_issue": (
        "আপনার ক্যাশ ইন লেনদেনের বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে "
        "এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    "refund_request": (
        "আপনার অনুরোধটি আমরা গ্রহণ করেছি এবং পর্যালোচনা করা হচ্ছে। যোগ্য ক্ষেত্রে যেকোনো পরিমাণ "
        "অফিসিয়াল চ্যানেলে প্রক্রিয়া করা হবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    "other": (
        "আপনার অভিযোগটি আমরা গ্রহণ করেছি এবং সংশ্লিষ্ট দলে পাঠানো হয়েছে। "
        "আমাদের সাপোর্ট স্টাফ অফিসিয়াল চ্যানেলে আপনার সাথে যোগাযোগ করবে। "
        "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
}

_RECOMMENDED_ACTIONS = {
    "phishing_or_social_engineering": (
        "Escalate immediately to the fraud_risk team. "
        "Advise customer not to share any credentials. "
        "Verify whether any unauthorized transaction occurred. "
        "Log the incident for security review and block suspicious access if detected."
    ),
    "wrong_transfer": (
        "Review the transaction details and verify the recipient against the claimed wrong number. "
        "Initiate the dispute resolution process. "
        "Do not promise recovery to the customer. "
        "Escalate to dispute_resolution team for further action."
    ),
    "payment_failed": (
        "Verify the transaction status in the payments system. "
        "Check whether the balance was actually deducted. "
        "Route to payments_ops for full investigation and reconciliation. "
        "Initiate automatic reversal flow within standard SLA if balance was deducted on a failed payment."
    ),
    "duplicate_payment": (
        "Verify the transaction history for duplicate entries matching the reported amount. "
        "Confirm with the biller/merchant whether only one payment was received. "
        "If duplicate is confirmed, route to payments_ops for reversal processing. "
        "Do not confirm any credit or reversal to the customer."
    ),
    "merchant_settlement_delay": (
        "Check settlement schedule and current batch status in the merchant portal. "
        "Route to merchant_operations team for follow-up with the settlement processing team. "
        "Communicate a revised ETA to the merchant if the batch is delayed."
    ),
    "agent_cash_in_issue": (
        "Verify the cash-in transaction against agent records and balance ledger. "
        "Route to agent_operations team. "
        "Request transaction receipt from the customer if available. "
        "Resolve within standard cash-in SLA."
    ),
    "refund_request": (
        "Review the referenced transaction and the nature of the complaint. "
        "Inform the customer that refund eligibility depends on the merchant's own policy if applicable. "
        "Route to dispute_resolution for contested cases. Do not confirm any refund."
    ),
    "other": (
        "Review the customer complaint and available transaction history. "
        "Ask for specific details if the complaint is vague (transaction ID, amount, time). "
        "Route to customer_support for further investigation and response."
    ),
}


# ─── Rule-based logic ─────────────────────────────────────────────────────────

def classify_case(complaint: str) -> tuple:
    """Returns (case_type, confidence, reason_codes)."""
    cl = complaint.lower()
    scores: dict = {}  # case_type -> (score, matched_kws)

    # Phase 1: exact substring keyword matching
    for case_type, keywords in _CASE_PATTERNS:
        matched = [kw for kw in keywords if kw in cl]
        if matched:
            scores[case_type] = (len(matched), matched)

    # Phase 2: co-occurrence boosting
    for case_type, required_words, boost in _COOCCURRENCE_PATTERNS:
        if all(w in cl for w in required_words):
            prev_score, prev_kws = scores.get(case_type, (0, []))
            label = "+".join(required_words)
            scores[case_type] = (prev_score + boost, prev_kws + [label])

    if not scores:
        return "other", 0.4, ["no_keyword_match"]

    # Phishing always wins (safety priority)
    if "phishing_or_social_engineering" in scores:
        best = "phishing_or_social_engineering"
    else:
        best = max(scores, key=lambda k: scores[k][0])

    total_score, matched_kws = scores[best]
    confidence = min(0.92, 0.50 + total_score * 0.08)
    reason_codes = [best] + [f"kw:{kw}" for kw in matched_kws[:2]]
    return best, confidence, reason_codes


def extract_amount(text: str) -> Optional[float]:
    """Extract BDT amount from complaint text (handles ASCII digits only)."""
    patterns = [
        r'(\d[\d,]*)\s*(?:taka|bdt|tk|৳|টাকা)',
        r'(?:taka|bdt|tk|৳|টাকা)\s*(\d[\d,]*)',
        r'\b(\d{4,})\b',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1).replace(",", ""))
            except ValueError:
                pass
    return None


def _amounts_close(a: float, b: float) -> bool:
    if a == 0 and b == 0:
        return True
    return abs(a - b) / max(abs(a), abs(b)) < 0.06


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _score_tx(tx: Transaction, cl: str, case_type: str, complaint_amount: Optional[float]) -> int:
    score = 0
    expected_types = _CASE_TX_TYPES.get(case_type, [])

    if tx.transaction_id and tx.transaction_id.lower() in cl:
        score += 6
    if tx.counterparty and str(tx.counterparty) in cl:
        score += 4
    if complaint_amount and tx.amount:
        if _amounts_close(complaint_amount, tx.amount):
            score += 4
        elif abs(complaint_amount - tx.amount) < 200:
            score += 2
    if expected_types and tx.type and tx.type in expected_types:
        score += 3
    # Status bonuses per case type
    if case_type == "payment_failed" and tx.status in ("failed", "pending"):
        score += 3
    elif case_type == "wrong_transfer" and tx.status == "completed" and tx.type == "transfer":
        score += 3
    elif case_type == "agent_cash_in_issue" and tx.type == "cash_in":
        score += 3
    elif case_type == "merchant_settlement_delay" and tx.type == "settlement":
        score += 3
    elif case_type == "refund_request" and tx.status == "completed":
        score += 2
    elif case_type == "duplicate_payment" and tx.status == "completed":
        score += 2

    return score


def find_best_tx(
    transactions: List[Transaction], complaint: str, case_type: str
) -> Optional[Transaction]:
    """Return best matching transaction, or None when ambiguous or no match."""
    if not transactions or case_type == "phishing_or_social_engineering":
        return None

    cl = complaint.lower()
    amt = extract_amount(complaint)
    scored = [(tx, _score_tx(tx, cl, case_type, amt)) for tx in transactions]
    scored = [(tx, s) for tx, s in scored if s > 1]   # minimum threshold

    if not scored:
        return None

    best_score = max(s for _, s in scored)
    top = [tx for tx, s in scored if s >= best_score - 1]

    if len(top) > 1:
        # For duplicate_payment: pick the LATER transaction (likely the duplicate)
        if case_type == "duplicate_payment":
            def _ts_key(t: Transaction):
                dt = _parse_ts(t.timestamp)
                return dt if dt else datetime.min
            return max(top, key=_ts_key)
        # Otherwise, ambiguous – return None
        if len(top) > 1 and all(
            _score_tx(t, cl, case_type, amt) == best_score for t in top
        ):
            return None

    return top[0]


def _has_established_recipient(
    tx: Transaction, transactions: List[Transaction]
) -> bool:
    """Return True if there are 2+ other completed transfers to the same counterparty."""
    if not tx or not tx.counterparty:
        return False
    others = [
        t for t in transactions
        if t.transaction_id != tx.transaction_id
        and t.counterparty == tx.counterparty
        and t.type == "transfer"
        and t.status == "completed"
    ]
    return len(others) >= 1   # 1+ prior means established pattern


def _has_duplicate_pair(transactions: List[Transaction], complaint_amount: Optional[float]) -> bool:
    """Return True if 2+ transactions share the same amount."""
    amounts: list = []
    for tx in transactions:
        if tx.amount is None:
            continue
        for prev in amounts:
            if _amounts_close(tx.amount, prev):
                return True
        amounts.append(tx.amount)
    if complaint_amount:
        matches = [t for t in transactions if t.amount and _amounts_close(t.amount, complaint_amount)]
        if len(matches) >= 2:
            return True
    return False


def determine_verdict(
    case_type: str,
    tx: Optional[Transaction],
    transactions: List[Transaction],
    complaint: str,
) -> str:
    if case_type == "phishing_or_social_engineering":
        return "insufficient_data"
    if tx is None:
        return "insufficient_data"

    if case_type == "payment_failed":
        if tx.status in ("failed", "pending"):
            return "consistent"
        if tx.status == "completed":
            return "inconsistent"
        return "insufficient_data"

    if case_type == "wrong_transfer":
        if tx.status == "reversed":
            return "inconsistent"
        if tx.status == "completed" and tx.type == "transfer":
            # Established recipient pattern → inconsistent claim
            if _has_established_recipient(tx, transactions):
                return "inconsistent"
            return "consistent"
        return "insufficient_data"

    if case_type == "duplicate_payment":
        amt = extract_amount(complaint)
        if _has_duplicate_pair(transactions, amt):
            return "consistent"
        return "insufficient_data"

    if case_type == "refund_request":
        if tx.status == "reversed":
            return "inconsistent"
        if tx.status == "completed":
            return "consistent"
        return "insufficient_data"

    if case_type == "merchant_settlement_delay":
        if tx.status in ("pending", "failed"):
            return "consistent"
        if tx.status == "completed":
            return "inconsistent"
        return "insufficient_data"

    if case_type == "agent_cash_in_issue":
        if tx.type == "cash_in" and tx.status in ("completed", "pending"):
            return "consistent"
        return "insufficient_data"

    if tx.status:
        return "consistent"
    return "insufficient_data"


def determine_severity(case_type: str, verdict: str, tx: Optional[Transaction], complaint_amount: Optional[float]) -> str:
    """
    Severity is driven primarily by case_type + verdict, not raw amount.
    Amount is a secondary signal for wrong_transfer only.
    """
    if case_type == "phishing_or_social_engineering":
        return "critical"

    # These case types are high when evidence is consistent
    if case_type in ("duplicate_payment", "payment_failed", "agent_cash_in_issue"):
        return "high" if verdict == "consistent" else "medium"

    # Merchant settlements: operational delays, always medium
    if case_type == "merchant_settlement_delay":
        return "medium"

    if case_type == "wrong_transfer":
        amount = (tx.amount if tx and tx.amount else None) or complaint_amount
        if verdict == "consistent" and amount and amount >= 5000:
            return "high"
        return "medium"

    if case_type == "refund_request":
        amount = (tx.amount if tx and tx.amount else None) or complaint_amount
        if amount and amount >= 1000:
            return "medium"
        return "low"

    return "low"   # other


def determine_department(case_type: str, severity: str, verdict: str) -> str:
    dept = _DEPT_MAP.get(case_type, "customer_support")
    if case_type == "refund_request":
        if severity in ("high", "critical") or verdict == "inconsistent":
            return "dispute_resolution"
        return "customer_support"
    return dept


def determine_human_review(case_type: str, severity: str, verdict: str, has_tx: bool) -> bool:
    """
    True for: phishing, confirmed wrong transfers, confirmed duplicates,
    confirmed agent cash-in issues, high-value refunds.
    False for: payment_failed (ops handles automatically), merchant_ops delays,
    vague/unmatched complaints.
    """
    if case_type == "phishing_or_social_engineering":
        return True
    if case_type == "wrong_transfer":
        return has_tx   # True only when a specific transaction is identified
    if case_type in ("duplicate_payment", "agent_cash_in_issue") and verdict == "consistent":
        return True
    if case_type == "refund_request" and severity in ("high", "critical"):
        return True
    return False


def build_agent_summary(
    case_type: str, tx: Optional[Transaction],
    complaint_amount: Optional[float], verdict: str,
) -> str:
    amount = (tx.amount if tx and tx.amount else complaint_amount) or 0
    amt_str = f"{amount:.0f}" if amount else "unknown"
    tx_ref = f" via {tx.transaction_id}" if tx else ""

    templates = {
        "phishing_or_social_engineering": (
            "Customer reports a suspicious interaction involving requests for credentials or "
            "personal security information. Immediate escalation to fraud_risk team required."
        ),
        "wrong_transfer": (
            f"Customer reports sending {amt_str} BDT to an unintended recipient{tx_ref}. "
            f"Evidence verdict: {verdict}."
        ),
        "payment_failed": (
            f"Customer reports a failed payment of {amt_str} BDT{tx_ref}. "
            f"Transaction status evidence: {verdict}."
        ),
        "duplicate_payment": (
            f"Customer reports a duplicate charge of {amt_str} BDT{tx_ref}. "
            f"Evidence verdict: {verdict}."
        ),
        "merchant_settlement_delay": (
            f"Merchant reports a delayed settlement of {amt_str} BDT{tx_ref}. "
            f"Evidence verdict: {verdict}."
        ),
        "agent_cash_in_issue": (
            f"Customer reports cash-in of {amt_str} BDT not reflected in balance{tx_ref}. "
            f"Evidence: {verdict}."
        ),
        "refund_request": (
            f"Customer requests a refund of {amt_str} BDT{tx_ref}. "
            f"Evidence verdict: {verdict}."
        ),
        "other": (
            f"Customer submitted a vague complaint. Evidence verdict: {verdict}. "
            "Insufficient detail to identify a specific transaction or issue."
        ),
    }
    return templates.get(case_type, templates["other"])


def get_customer_reply(case_type: str, language: Optional[str]) -> str:
    """Return safe customer reply in the appropriate language."""
    if language == "bn":
        return _CUSTOMER_REPLY_BN.get(case_type, _CUSTOMER_REPLY_BN["other"])
    return _CUSTOMER_REPLY_EN.get(case_type, _CUSTOMER_REPLY_EN["other"])


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze-ticket", response_model=AnalyzeResponse)
def analyze_ticket(req: AnalyzeRequest):
    complaint = req.complaint
    transactions: List[Transaction] = req.transaction_history or []

    # 1. Classify
    case_type, cls_confidence, reason_codes = classify_case(complaint)

    # 2. Match best transaction (or None if ambiguous / not applicable)
    tx = find_best_tx(transactions, complaint, case_type)
    complaint_amount = extract_amount(complaint)

    # 3. Evidence verdict
    verdict = determine_verdict(case_type, tx, transactions, complaint)

    # 4. Routing metadata
    severity   = determine_severity(case_type, verdict, tx, complaint_amount)
    department = determine_department(case_type, severity, verdict)
    human_rev  = determine_human_review(case_type, severity, verdict, tx is not None)

    # 5. Text fields (safety rules enforced via templates)
    agent_summary      = build_agent_summary(case_type, tx, complaint_amount, verdict)
    recommended_action = _RECOMMENDED_ACTIONS.get(case_type, _RECOMMENDED_ACTIONS["other"])
    customer_reply     = get_customer_reply(case_type, req.language)

    # 6. Confidence and reason codes
    tx_conf    = 0.85 if tx else 0.30
    confidence = round((cls_confidence + tx_conf) / 2, 2)
    if tx:
        reason_codes.append("transaction_match")

    return AnalyzeResponse(
        ticket_id=req.ticket_id,
        relevant_transaction_id=tx.transaction_id if tx else None,
        evidence_verdict=verdict,
        case_type=case_type,
        severity=severity,
        department=department,
        agent_summary=agent_summary,
        recommended_next_action=recommended_action,
        customer_reply=customer_reply,
        human_review_required=human_rev,
        confidence=confidence,
        reason_codes=reason_codes,
    )
