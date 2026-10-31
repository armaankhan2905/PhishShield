"""Tests run rules-only by default, so results don't depend on whether models are trained locally.

Tests that need the models use the `models_on` fixture (tests/test_models.py).
"""
import pytest


@pytest.fixture(autouse=True)
def _models_off(monkeypatch, request):
    if "models_on" not in request.fixturenames:
        monkeypatch.setenv("PHISHSHIELD_MODELS", "0")


@pytest.fixture
def models_on(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_MODELS", "1")
