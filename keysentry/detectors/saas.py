"""SaaS and developer-platform token detectors."""
from __future__ import annotations

import re

from keysentry.detectors.base import Detector, register

register(Detector(
    id="github-token",
    title="GitHub Personal / OAuth / App Token",
    severity="critical",
    pattern=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    secret_group=1,
    keywords=("ghp_", "github_pat_"),
    family="saas",
    remediation="rotate-github",
))

register(Detector(
    id="gitlab-token",
    title="GitLab Personal Access Token",
    severity="critical",
    pattern=re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
    secret_group=1,
    keywords=("glpat-",),
    family="saas",
    remediation="rotate-gitlab",
))

register(Detector(
    id="slack-token",
    title="Slack Bot / User / Legacy Token",
    severity="high",
    pattern=re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
    secret_group=1,
    keywords=("xox",),
    family="saas",
    remediation="rotate-slack",
))

register(Detector(
    id="slack-webhook",
    title="Slack Incoming Webhook URL",
    severity="medium",
    pattern=re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]+)"),
    secret_group=1,
    keywords=("hooks.slack.com",),
    family="saas",
    remediation="rotate-slack",
))

register(Detector(
    id="stripe-key",
    title="Stripe Secret / Restricted Key",
    severity="critical",
    pattern=re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"),
    secret_group=1,
    keywords=("sk_live_", "rk_live_", "sk_test_"),
    family="saas",
    remediation="rotate-stripe",
))

register(Detector(
    id="sendgrid-key",
    title="SendGrid API Key",
    severity="high",
    pattern=re.compile(r"\b(SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,})\b"),
    secret_group=1,
    keywords=("SG.",),
    family="saas",
))

register(Detector(
    id="twilio-key",
    title="Twilio API Key",
    severity="high",
    pattern=re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
    secret_group=1,
    keywords=("SK",),
    family="saas",
))

register(Detector(
    id="openai-key",
    title="OpenAI API Key",
    severity="critical",
    pattern=re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9\-_]{20,})\b"),
    secret_group=1,
    keywords=("sk-",),
    family="ai",
    remediation="rotate-openai",
))

register(Detector(
    id="anthropic-key",
    title="Anthropic API Key",
    severity="critical",
    pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{20,})\b"),
    secret_group=1,
    keywords=("sk-ant-",),
    family="ai",
))

register(Detector(
    id="npm-token",
    title="npm Access Token",
    severity="high",
    pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36,})\b"),
    secret_group=1,
    keywords=("npm_",),
    family="saas",
))

register(Detector(
    id="pypi-token",
    title="PyPI Upload Token",
    severity="high",
    pattern=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b"),
    secret_group=1,
    keywords=("pypi-",),
    family="saas",
))

register(Detector(
    id="mailchimp-key",
    title="Mailchimp API Key",
    severity="medium",
    pattern=re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
    secret_group=1,
    keywords=("-us",),
    family="saas",
))