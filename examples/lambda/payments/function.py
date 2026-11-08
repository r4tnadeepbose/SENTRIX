# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
"""Payments function: vulnerable sample with a hardcoded payment secret key."""

PAYMENT_KEY = "sk_live_" + "51HxABCDEFGHIJKLMNOPQRSTUVWXYZ0123"


def handler(event, context):
    amount = event.get("amount", 0)
    return {
        "statusCode": 200,
        "body": f"charged {amount}; key configured: {bool(PAYMENT_KEY)}",
    }