# QueueStorm Investigator

A rule-based complaint investigation API for mobile financial services (bKash-style). Built for the SUST CSE Carnival 2026 / Codex Community Hackathon.

## What it does

Takes a customer support ticket (complaint text + transaction history) and automatically:

- Classifies the complaint into a case type
- Matches the most relevant transaction from the customer's history
- Determines whether the evidence supports or contradicts the complaint
- Routes the case to the right department
- Assigns severity and flags whether a human agent needs to review
- Generates a safe, templated reply for the customer (English or Bangla)

All logic is pure rule-based — no LLM, no external calls.

## Case types detected

| Case Type | Description |
|---|---|
| `phishing_or_social_engineering` | Someone asked the customer for their PIN/OTP/password |
| `wrong_transfer` | Customer sent money to the wrong number |
| `payment_failed` | Payment deducted but not delivered |
| `duplicate_payment` | Charged twice for the same transaction |
| `merchant_settlement_delay` | Merchant's settlement not received |
| `agent_cash_in_issue` | Cash deposited through agent but balance not updated |
| `refund_request` | Customer wants money returned |
| `other` | Vague or unclassifiable complaint |

## How classification works

1. **Keyword matching** — scans the complaint (English, Banglish, Bangla) against curated keyword lists per case type
2. **Co-occurrence boosting** — scores complaints higher when multiple relevant words appear together (e.g. "balance" + "deducted")
3. **Phishing always wins** — if any phishing signal is detected, it overrides all other case types for safety
4. **Transaction scoring** — each transaction in history is scored against the complaint by transaction ID mention, amount match, counterparty match, type, and status

## API

### `GET /health`
Returns `{"status": "ok"}`.

### `POST /analyze-ticket`

**Request body:**
```json
{
  "ticket_id": "TKT-001",
  "complaint": "I was charged twice for the same payment of 500 taka",
  "language": "en",
  "channel": "app",
  "user_type": "customer",
  "transaction_history": [
    {
      "transaction_id": "TXN-123",
      "timestamp": "2026-06-25T10:00:00Z",
      "type": "payment",
      "amount": 500.0,
      "counterparty": "merchant_abc",
      "status": "completed"
    }
  ]
}
```

`language` accepts `"en"` (default) or `"bn"` for Bangla customer replies.

**Response:**
```json
{
  "ticket_id": "TKT-001",
  "relevant_transaction_id": "TXN-123",
  "evidence_verdict": "consistent",
  "case_type": "duplicate_payment",
  "severity": "high",
  "department": "payments_ops",
  "agent_summary": "Customer reports a duplicate charge of 500 BDT via TXN-123. Evidence verdict: consistent.",
  "recommended_next_action": "Verify the transaction history for duplicate entries...",
  "customer_reply": "Thank you for bringing this to our attention...",
  "human_review_required": true,
  "confidence": 0.74,
  "reason_codes": ["duplicate_payment", "kw:charged twice", "transaction_match"]
}
```

**Evidence verdicts:**
- `consistent` — transaction data supports the complaint
- `inconsistent` — transaction data contradicts the complaint
- `insufficient_data` — not enough information to verify

## Running locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs available at `http://localhost:8000/docs`.

## Deploying to Render

**Build command:**
```
pip install -r requirements.txt
```

**Start command:**
```
uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Requirements

- Python 3.10+
- FastAPI
- Uvicorn
- Pydantic v2
