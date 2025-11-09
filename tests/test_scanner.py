# ============================================================
# Project: Network Scanner
# File: test_scanner.py
# Author: Moffat Gichure
# Date: 09-Nov-2025
# Description: Unit tests for the NetworkScanner class.
# ============================================================
import sys, os
# Ensure the project root is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src.scanner import NetworkScanner


@pytest.fixture
def scanner():
    return NetworkScanner(timeout=1.0, concurrency=5)


def test_icmp_localhost(scanner):
    if os.getenv("CI") or os.getenv("SKIP_NETWORK"):
        pytest.skip("Skipping network test in CI environment")
    res = scanner.icmp_scan("127.0.0.1")
    assert isinstance(res, dict)
    assert "127.0.0.1" in res


def test_tcp_structure(scanner):
    if os.getenv("CI") or os.getenv("SKIP_NETWORK"):
        pytest.skip("Skipping network test in CI environment")
    res = scanner.tcp_port_scan("127.0.0.1", [22, 80])
    assert isinstance(res, dict)
    assert "127.0.0.1" in res
