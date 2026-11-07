"""Detector registry: one pattern set, reused by every layer."""
from keysentry.detectors import base, cloud, crypto, generic, saas  # noqa: F401
from keysentry.detectors.base import REGISTRY, Detector, all_detectors, register

__all__ = ["REGISTRY", "Detector", "all_detectors", "register"]