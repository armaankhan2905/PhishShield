"""Detection layer: pattern-based PII/PCI detection.

Usage:
    from src.detection import detect
"""
from .main import detect, detect_trace, DetectionResult, DETECTORS

__all__ = ["detect", "detect_trace", "DetectionResult", "DETECTORS"]
