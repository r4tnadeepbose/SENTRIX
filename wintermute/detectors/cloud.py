"""Cloud provider credential detectors (AWS, GCP, Azure)."""
from __future__ import annotations

import re

from wintermute.detectors.base import Detector, register

register(Detector(
    id="aws-access-key-id",
    title="AWS Access Key ID",
    severity="high",
    pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    secret_group=1,
    keywords=("AKIA", "ASIA"),
    family="cloud",
    remediation="rotate-aws",
))

register(Detector(
    id="aws-secret-access-key",
    title="AWS Secret Access Key",
    severity="critical",
    pattern=re.compile(
        r"(?:aws_secret_access_key|aws_secret|secret_access_key)"
        r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
        re.IGNORECASE,
    ),
    secret_group=1,
    keywords=("aws_secret", "secret_access_key"),
    family="cloud",
    remediation="rotate-aws",
))

register(Detector(
    id="gcp-api-key",
    title="Google Cloud API Key",
    severity="high",
    pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    secret_group=1,
    keywords=("AIza",),
    family="cloud",
    remediation="rotate-gcp",
))

register(Detector(
    id="gcp-service-account",
    title="GCP Service Account Private Key Material",
    severity="critical",
    pattern=re.compile(r'"private_key":\s*"(-----BEGIN PRIVATE KEY-----[^"]+)"'),
    secret_group=1,
    keywords=("private_key",),
    family="cloud",
    remediation="rotate-gcp",
))

register(Detector(
    id="azure-storage-connection",
    title="Azure Storage Connection String",
    severity="critical",
    pattern=re.compile(
        r"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,};[^\"'\s]+)"
    ),
    secret_group=1,
    keywords=("AccountKey=",),
    family="cloud",
    remediation="rotate-azure",
))

register(Detector(
    id="azure-client-secret",
    title="Azure AD Client Secret",
    severity="critical",
    pattern=re.compile(
        r"(?:client_secret|azure_secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9~_.\-]{30,})\b",
        re.IGNORECASE,
    ),
    secret_group=1,
    keywords=("client_secret", "azure_secret"),
    family="cloud",
))