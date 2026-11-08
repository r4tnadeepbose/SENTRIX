# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
"""Vulnerable sample: hardcoded cloud key id and password. The gate should flag this file."""

AWS_ACCESS_KEY_ID = "AKIA" + "QRSTUVWXYZ123456"
password = "SomeSecret123"


def build_client_config():
    return {"access_key": AWS_ACCESS_KEY_ID, "password": password}