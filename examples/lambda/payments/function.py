# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
"""Payments function: vulnerable sample with a hardcoded payment secret key."""

PAYMENT_KEY = "STRIPE_KEY_REDACTED"


def handler(event, context):
    amount = event.get("amount", 0)
    return {
        "statusCode": 200,
        "body": f"charged {amount}; key configured: {bool(PAYMENT_KEY)}",
    }