"""Utility functions and helpers."""

from datetime import datetime, timezone

# Create a UTC timezone object for compatibility
UTC = timezone.utc


def utc_now() -> datetime:
    """Get current UTC datetime.

    Returns:
        Current datetime in UTC timezone
    """
    return datetime.now(UTC)
