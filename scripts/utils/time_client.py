"""Authoritative Time Client - Ensures all time calculations use external time sources"""

import re
from datetime import datetime, timezone
from typing import Optional

import requests
import structlog

logger = structlog.get_logger()


class AuthoritativeTimeClient:
    """
    Client for fetching authoritative time from external sources.

    This ensures all time-based operations in the application use
    a consistent, authoritative time source rather than system time.

    Primary: NIST Time API
    Fallback: WorldTimeAPI
    """

    NIST_URL = "https://time.nist.gov/actualtime.cgi?lzbc=siqm9b"
    WORLDTIME_URL = "https://worldtimeapi.org/api/timezone/Etc/UTC"
    TIMEOUT = 5
    MAX_RETRIES = 3

    @classmethod
    def get_current_time(cls) -> datetime:
        """
        Get authoritative current time from external source.

        Priority order:
        1. NIST Time API (official US government source)
        2. WorldTimeAPI (reliable fallback)
        3. System time (last resort, with warning logged)

        Returns:
            datetime: Current time (UTC timezone)
        """
        # Try NIST first
        try:
            nist_time = cls._fetch_nist_time()
            if nist_time:
                logger.info(
                    "Fetched authoritative time from NIST",
                    time=nist_time.isoformat(),
                )
                return nist_time
        except Exception as e:
            logger.warning("NIST time fetch failed", error=str(e))

        # Fallback to WorldTimeAPI
        try:
            worldtime = cls._fetch_worldtime()
            if worldtime:
                logger.info(
                    "Fetched authoritative time from WorldTimeAPI",
                    time=worldtime.isoformat(),
                )
                return worldtime
        except Exception as e:
            logger.warning("WorldTimeAPI fetch failed", error=str(e))

        # Last resort: system time with warning
        logger.error(
            "⚠️  FALLBACK: Using system time - external time sources unavailable"
        )
        return datetime.now(timezone.utc)

    @classmethod
    def _fetch_nist_time(cls) -> Optional[datetime]:
        """Fetch time from NIST"""
        for attempt in range(cls.MAX_RETRIES):
            try:
                response = requests.get(cls.NIST_URL, timeout=cls.TIMEOUT)
                response.raise_for_status()

                # NIST returns: <timestamp time='1729354821123' delay='0'/>
                match = re.search(r"time='(\d+)'", response.text)
                if match:
                    timestamp_ms = int(match.group(1))
                    timestamp_s = timestamp_ms / 1000
                    return datetime.fromtimestamp(timestamp_s, tz=timezone.utc)

            except Exception:
                if attempt == cls.MAX_RETRIES - 1:
                    raise
                continue

        return None

    @classmethod
    def _fetch_worldtime(cls) -> Optional[datetime]:
        """Fetch time from WorldTimeAPI"""
        for attempt in range(cls.MAX_RETRIES):
            try:
                response = requests.get(cls.WORLDTIME_URL, timeout=cls.TIMEOUT)
                response.raise_for_status()

                data = response.json()
                # WorldTimeAPI returns ISO 8601 datetime string
                datetime_str = data["datetime"]
                return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))

            except Exception:
                if attempt == cls.MAX_RETRIES - 1:
                    raise
                continue

        return None

    @classmethod
    def get_current_date_string(cls, fmt: str = "%Y-%m-%d") -> str:
        """Get current date as formatted string"""
        return cls.get_current_time().strftime(fmt)

    @classmethod
    def get_current_year(cls) -> int:
        """Get current year from authoritative source"""
        return cls.get_current_time().year

    @classmethod
    def get_current_datetime_iso(cls) -> str:
        """Get current datetime in ISO 8601 format"""
        return cls.get_current_time().isoformat()


# Convenience functions for common operations
def get_authoritative_now() -> datetime:
    """Get current time from authoritative source"""
    return AuthoritativeTimeClient.get_current_time()


def get_current_year() -> int:
    """Get current year from authoritative source"""
    return AuthoritativeTimeClient.get_current_year()


def get_current_date() -> str:
    """Get current date (YYYY-MM-DD) from authoritative source"""
    return AuthoritativeTimeClient.get_current_date_string()


if __name__ == "__main__":
    # Test the client
    print("Testing Authoritative Time Client...")
    print("=" * 60)

    current_time = get_authoritative_now()
    print(f"Authoritative Time: {current_time.isoformat()}")
    print(f"Date: {get_current_date()}")
    print(f"Year: {get_current_year()}")
    print(f"Timezone: {current_time.tzinfo}")
    print("=" * 60)
    print("✓ Time client operational")
