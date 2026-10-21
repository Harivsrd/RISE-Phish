"""Pytest configuration and shared fixtures for RISE-Phish test suite.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture(scope="session")
def test_client():
    """Provides a synchronous test client for FastAPI endpoints."""
    with TestClient(app) as client:
        yield client
