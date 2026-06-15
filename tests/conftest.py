from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_semgrep_scan():
    """Globally mock SemgrepScanner.scan to avoid invoking the real binary during tests."""
    with patch("phoenixsec.core.semgrep.SemgrepScanner.scan", return_value=[]):
        yield
