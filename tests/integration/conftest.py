"""Integration test package for WebBreaker."""

import pytest


def pytest_addoption(parser):
    """Add --run-integration flag to enable integration tests."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests against a vulnerable Flask app",
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is passed."""
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Integration tests require --run-integration flag. "
                   "Run: pytest tests/integration/ --run-integration"
        )
        for item in items:
            if "integration" in str(item.fspath):
                item.add_marker(skip_integration)