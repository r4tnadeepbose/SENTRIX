# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
"""Clean sample: same shape as examples/vulnerable/app.py, but secrets come from
the environment. This file should pass the scanner with zero findings."""
import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
password = os.environ.get("APP_PASSWORD", "")


def build_client_config():
    return {"access_key": AWS_ACCESS_KEY_ID, "password": password}