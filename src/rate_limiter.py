#!/usr/bin/env python3
"""
Rate limiting module for API calls.

Enforces rate limits based on API provider requirements and configured API keys.
Supports real-time tracking from API headers with persistent state file fallback.
"""

import time
import sys
import json
import os
from typing import Dict, Tuple, Optional
from collections import deque
from datetime import datetime
from pathlib import Path


class RateLimitStateManager:
    """
    Manages persistent rate limit state across tool runs.
    Stores real-time rate limit data from API headers to disk.
    """
    
    STATE_FILE = ".rate_limit_state.json"
    
    def __init__(self):
        """Initialize state manager."""
        self.state_path = Path(self.STATE_FILE)
        self.state: Dict[str, Dict] = self._load_state()
    
    def _load_state(self) -> Dict[str, Dict]:
        """Load rate limit state from disk, discarding expired or stale entries."""
        if not self.state_path.exists():
            return {}
        try:
            with open(self.state_path, 'r') as f:
                raw = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
        
        now = time.time()
        clean = {}
        changed = False
        
        for api_name, entry in raw.items():
            reset_time = entry.get('reset_time')
            last_updated = entry.get('last_updated', 0)
            
            # Drop entries whose explicit reset window has passed
            if reset_time is not None and now > reset_time:
                changed = True
                continue
            
            # Drop entries with no reset_time that are older than the longest
            # possible rate-limit window (120 s is a safe upper bound for all APIs)
            if reset_time is None and (now - last_updated) > 120:
                changed = True
                continue
            
            clean[api_name] = entry
        
        if changed:
            # Persist the cleaned state immediately
            try:
                with open(self.state_path, 'w') as f:
                    json.dump(clean, f, indent=2)
            except IOError:
                pass
        
        return clean
    
    def _save_state(self) -> None:
        """Save rate limit state to disk."""
        try:
            with open(self.state_path, 'w') as f:
                json.dump(self.state, f, indent=2)
        except IOError:
            pass  # Silently ignore write errors
    
    def update(self, api_name: str, remaining: Optional[int], reset_time: Optional[int]) -> None:
        """Update state for an API with real-time data from headers.
        
        Args:
            api_name: API name ('nvd', 'epss', 'kev', etc.)
            remaining: Requests remaining from X-RateLimit-Remaining header
            reset_time: Reset time from X-RateLimit-Reset header
        """
        if remaining is not None or reset_time is not None:
            if api_name not in self.state:
                self.state[api_name] = {}
            
            if remaining is not None:
                self.state[api_name]['remaining'] = remaining
            if reset_time is not None:
                self.state[api_name]['reset_time'] = reset_time
            
            self.state[api_name]['last_updated'] = time.time()
            self._save_state()
    
    def get(self, api_name: str) -> Optional[Dict]:
        """Get stored state for an API.
        
        Returns:
            Dict with 'remaining' and 'reset_time' keys, or None
        """
        if api_name not in self.state:
            return None
        
        entry = self.state[api_name]
        now = time.time()
        
        # Expired if explicit reset_time has passed
        if 'reset_time' in entry and now > entry['reset_time']:
            del self.state[api_name]
            self._save_state()
            return None
        
        # Expired if no reset_time but last_updated is older than 120 s
        if 'reset_time' not in entry:
            last_updated = entry.get('last_updated', 0)
            if (now - last_updated) > 120:
                del self.state[api_name]
                self._save_state()
                return None
        
        return entry
    
    def clear(self, api_name: str = None) -> None:
        """Clear state for an API or all APIs.
        
        Args:
            api_name: Specific API to clear, or None for all
        """
        if api_name:
            if api_name in self.state:
                del self.state[api_name]
        else:
            self.state.clear()
        self._save_state()


class RateLimiter:
    """
    Rate limiter for API endpoints.
    
    Supports different rate limits based on whether API keys are configured.
    """
    
    # Rate limits: (requests_per_window, window_size_seconds, friendly_name)
    # GitHub search API limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
    #   Unauthenticated: 10 requests/minute (search endpoint is more restrictive than primary 60/hr)
    #   Authenticated:   30 requests/minute
    RATE_LIMITS = {
        "nvd_no_key":      (5,  60,   "5 requests/minute"),   # NVD without key
        "nvd_with_key":    (5,  1,    "5 requests/second"),   # NVD with key
        "epss":            (30, 60,   "30 requests/minute"),  # EPSS public API
        "kev":             (10, 60,   "10 requests/minute"),  # CISA KEV public API
        "vulncheck":       (60, 60,   "60 requests/minute"),  # VulnCheck community API
        "osv":             (60, 60,   "60 requests/minute"),  # OSV public API
        "github_no_token": (10, 60,   "10 requests/minute (unauthenticated search)"),
        "github_token":    (30, 60,   "30 requests/minute (authenticated search)"),
    }
    
    def __init__(self, api_name: str, has_api_key: bool = False, state_manager: Optional[RateLimitStateManager] = None):
        """
        Initialize rate limiter for an API.
        
        Args:
            api_name: Name of the API ('nvd', 'epss', 'kev')
            has_api_key: Whether API key is configured for this API
            state_manager: Optional state manager for persistent state
        """
        self.api_name = api_name
        self.has_api_key = has_api_key
        self.request_times: Dict[str, deque] = {}  # Keyed by endpoint
        self.remaining_requests: Optional[int] = None  # Real-time from API headers
        self.reset_time: Optional[int] = None  # Reset time from API headers
        self.state_manager = state_manager  # For persistent state fallback
        self.has_header_data = False  # Track if we got real data from headers
        self.was_rate_limited = False  # Track if this API hit rate limit during this run
        self._last_announced_reset_time = None  # Track reset_time of last announced rate limit
        
        # Select rate limit based on API name and key status
        if api_name == "nvd":
            limit_key = "nvd_with_key" if has_api_key else "nvd_no_key"
        elif api_name == "epss":
            limit_key = "epss"
        elif api_name == "kev":
            limit_key = "kev"
        elif api_name == "vulncheck":
            limit_key = "vulncheck"
        elif api_name == "osv":
            limit_key = "osv"
        elif api_name == "github":
            limit_key = "github_token" if has_api_key else "github_no_token"
        else:
            raise ValueError(f"Unknown API: {api_name}")
        
        self.rate_limit, self.window_size, self.friendly_limit = self.RATE_LIMITS[limit_key]
        self.limit_key = limit_key
        
        # Try to load from persistent state (fallback if no headers)
        if self.state_manager:
            stored = self.state_manager.get(api_name)
            if stored:
                self.remaining_requests = stored.get('remaining')
                self.reset_time = stored.get('reset_time')
                self.has_header_data = False  # Mark as fallback data
    
    def can_make_request(self, endpoint: str = "default") -> Tuple[bool, Optional[float]]:
        """
        Check if a request can be made to the endpoint.
        
        Args:
            endpoint: Endpoint identifier (for per-endpoint tracking)
            
        Returns:
            Tuple of (can_make_request, seconds_to_wait)
        """
        now = time.time()
        
        # First check: if we have persistent rate limit data (from headers or 429 error)
        if self.reset_time is not None:
            if now < self.reset_time:
                # Still in rate limit window
                wait_time = self.reset_time - now
                return False, max(0.1, wait_time)
            else:
                # Rate limit window has passed, reset the state
                self.remaining_requests = None
                self.reset_time = None
        
        # Check remaining requests if we're tracking from headers
        if self.remaining_requests is not None and self.remaining_requests <= 0:
            # No requests remaining from API headers
            if self.reset_time is not None and now < self.reset_time:
                wait_time = self.reset_time - now
                return False, max(0.1, wait_time)
        
        # Second check: local sliding window tracking
        if endpoint not in self.request_times:
            self.request_times[endpoint] = deque()
        
        request_queue = self.request_times[endpoint]
        
        # Remove requests outside the window
        while request_queue and request_queue[0] < now - self.window_size:
            request_queue.popleft()
        
        # Check if we can make a request
        if len(request_queue) < self.rate_limit:
            return True, None
        
        # Calculate wait time
        oldest_request = request_queue[0]
        wait_time = (oldest_request + self.window_size) - now
        return False, max(0.1, wait_time)
    
    def acquire(self, endpoint: str = "default", max_retries: int = 5) -> None:
        """
        Acquire permission to make a request (blocking if necessary).
        Displays a single in-place countdown line updated every second.
        Uses exponential backoff for secondary rate limit hits (retry-after).

        Args:
            endpoint: Endpoint identifier
            max_retries: Maximum number of times to retry after secondary rate limit
        """
        can_request, wait_time = self.can_make_request(endpoint)
        if can_request:
            if endpoint not in self.request_times:
                self.request_times[endpoint] = deque()
            self.request_times[endpoint].append(time.time())
            return

        # Only announce rate limit once per reset period (avoid spam)
        self.was_rate_limited = True
        if self.reset_time != self._last_announced_reset_time:
            self._last_announced_reset_time = self.reset_time
            key_status = "with API key" if self.has_api_key else "without API key"
            sys.stdout.write(
                f"\n⏸  Rate limit reached for {self.api_name.upper()} API "
                f"({key_status}) — {self.friendly_limit}\n"
            )
            sys.stdout.flush()

        retry_count = 0
        backoff_base = 1.0  # seconds; doubles each retry (exponential backoff)

        # Countdown loop — overwrite a single line with \r each tick
        while True:
            can_request, wait_time = self.can_make_request(endpoint)
            if can_request:
                break

            # Check if this looks like a secondary rate limit (reset_time very far out)
            # Secondary limits send retry-after; handle_rate_limit_error stores it in reset_time
            is_secondary = (
                self.reset_time is not None
                and (self.reset_time - time.time()) > self.window_size * 2
            )
            if is_secondary and retry_count >= max_retries:
                sys.stdout.write("\r" + " " * 72 + "\r")
                sys.stdout.flush()
                raise RuntimeError(
                    f"Secondary rate limit for {self.api_name.upper()} "
                    f"persisted after {max_retries} retries — giving up"
                )

            total_window = float(
                (self.reset_time - time.time()) if self.reset_time else self.window_size
            )
            remaining = float(wait_time or 1.0)
            mins, secs = divmod(int(remaining), 60)

            bar_width = 20
            elapsed_frac = max(0.0, min(1.0, 1.0 - remaining / max(total_window, 1)))
            filled = int(elapsed_frac * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)

            backoff_hint = f" (retry {retry_count}/{max_retries})" if retry_count > 0 else ""
            line = (
                f"   ⏳ [{bar}] {mins:02d}:{secs:02d} — "
                f"waiting for {self.api_name.upper()} rate limit reset{backoff_hint}"
            )
            sys.stdout.write(f"\r{line.ljust(78)}")
            sys.stdout.flush()

            sleep_for = min(remaining, 1.0)
            time.sleep(sleep_for)

            # After the window clears, check if we should apply exponential backoff
            can_request, new_wait = self.can_make_request(endpoint)
            if not can_request and new_wait and new_wait > 0 and remaining <= 1.0:
                # Still blocked after window — apply exponential backoff
                backoff_wait = backoff_base * (2 ** retry_count)
                retry_count += 1
                sys.stdout.write(
                    f"\r   ↩  Still limited — backing off {backoff_wait:.0f}s "
                    f"(attempt {retry_count}/{max_retries})".ljust(78)
                )
                sys.stdout.flush()
                time.sleep(backoff_wait)

        # Clear the countdown line
        sys.stdout.write("\r" + " " * 78 + "\r")
        sys.stdout.flush()

        if endpoint not in self.request_times:
            self.request_times[endpoint] = deque()
        self.request_times[endpoint].append(time.time())
    
    def update_from_headers(self, remaining: Optional[int], reset_time: Optional[int]) -> None:
        """
        Update real-time rate limit info from API response headers.
        Persists to disk for fallback on next run.
        
        Args:
            remaining: X-RateLimit-Remaining value from response
            reset_time: X-RateLimit-Reset value from response
        """
        if remaining is not None:
            self.remaining_requests = remaining
        if reset_time is not None:
            self.reset_time = reset_time
        
        # Mark that we have real header data
        if remaining is not None or reset_time is not None:
            self.has_header_data = True
        
        # Save to persistent state for fallback on next run
        if self.state_manager and (remaining is not None or reset_time is not None):
            self.state_manager.update(self.api_name, remaining, reset_time)
    
    def was_rate_limited_during_run(self) -> bool:
        """Check if this API was rate-limited at any point during this run.
        
        Returns:
            True if rate limit was hit, False otherwise
        """
        return self.was_rate_limited


class GlobalRateLimitManager:
    """
    Manages rate limiters for all APIs with persistent state support.
    """
    
    def __init__(self):
        """Initialize the manager."""
        self.limiters: Dict[str, RateLimiter] = {}
        self.state_manager = RateLimitStateManager()  # Persistent state across runs
    
    def get_limiter(self, api_name: str, has_api_key: bool = False) -> RateLimiter:
        """Get or create a rate limiter for an API."""
        key = f"{api_name}_{has_api_key}"
        if key not in self.limiters:
            self.limiters[key] = RateLimiter(api_name, has_api_key, self.state_manager)
        return self.limiters[key]
    
    def get_rate_limited_apis_during_run(self) -> list:
        """Get list of APIs that were rate-limited during this run.
        
        Returns:
            List of API names that hit rate limits
        """
        limited = []
        for limiter in self.limiters.values():
            if limiter.was_rate_limited_during_run():
                limited.append(limiter.api_name.upper())
        return limited


# Global manager instance
_manager = GlobalRateLimitManager()


def get_rate_limiter(api_name: str, has_api_key: bool = False) -> RateLimiter:
    """Get a rate limiter instance."""
    return _manager.get_limiter(api_name, has_api_key)


def get_apis_rate_limited_during_run() -> list:
    """Get list of APIs that were rate-limited during this run."""
    return _manager.get_rate_limited_apis_during_run()


def _get_header_case_insensitive(headers, *possible_keys):
    """Get header value case-insensitively from multiple possible keys.
    
    Args:
        headers: HTTP response headers
        *possible_keys: Possible header names to check
        
    Returns:
        Header value or None if not found
    """
    for key in possible_keys:
        if key in headers:
            return headers[key]
    
    # If not found with exact case, try case-insensitive search
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for key in possible_keys:
        lower_key = key.lower()
        if lower_key in headers_lower:
            return headers_lower[lower_key]
    
    return None


def update_rate_limit_from_response(api_name: str, response_headers) -> None:
    """Extract and store real-time rate limit info from API response headers.
    
    Args:
        api_name: Name of the API ('nvd', 'epss', 'kev', 'vulncheck', 'osv', 'github')
        response_headers: HTTP response headers (urllib.HTTPMessage or dict-like)
    """
    try:
        # Try to get rate limit headers (varies by API)
        remaining = None
        reset_time = None
        
        # API-specific header extraction
        if api_name.lower() == 'epss':
            # EPSS uses non-standard headers (case-insensitive lookup)
            limit_val = _get_header_case_insensitive(response_headers, 'X-Limit', 'x-limit')
            offset_val = _get_header_case_insensitive(response_headers, 'X-Offset', 'x-offset')
            
            if limit_val and offset_val:
                try:
                    limit = int(limit_val)
                    offset = int(offset_val)
                    remaining = limit - offset  # Calculate remaining based on pagination
                    reset_time = None  # EPSS doesn't provide reset time in headers
                except (ValueError, TypeError):
                    pass
        else:
            # Standard rate limit header names (GitHub, etc.)
            remaining_keys = ['X-RateLimit-Remaining', 'x-ratelimit-remaining']
            reset_keys = ['X-RateLimit-Reset', 'x-ratelimit-reset']
            
            # Extract headers (case-insensitive)
            remaining_val = _get_header_case_insensitive(response_headers, *remaining_keys)
            if remaining_val:
                remaining = int(remaining_val)
            
            reset_val = _get_header_case_insensitive(response_headers, *reset_keys)
            if reset_val:
                reset_time = int(reset_val)
        
        # Update the appropriate limiter if we found rate limit info
        if remaining is not None or reset_time is not None:
            limiter = get_rate_limiter(api_name)
            limiter.update_from_headers(remaining, reset_time)
    except (ValueError, KeyError, TypeError):
        # Silently ignore errors in parsing headers
        pass


def handle_rate_limit_error(api_name: str, status_code: int = 429, error_headers=None) -> None:
    """Handle rate limit errors (HTTP 429/403) and update state.

    Reads the exact reset time from the error response headers when available
    (x-ratelimit-reset, retry-after) so acquire() waits the correct duration
    instead of guessing now + window_size.

    Args:
        api_name: Name of the API that was rate limited
        status_code: HTTP status code (default 429)
        error_headers: Optional headers from the error response (urllib.HTTPMessage or dict)
    """
    if status_code in (429, 403):
        try:
            limiter = get_rate_limiter(api_name)
            now = time.time()
            reset_time = None

            if error_headers is not None:
                # Prefer x-ratelimit-reset (exact epoch second from GitHub)
                reset_val = _get_header_case_insensitive(
                    error_headers,
                    'x-ratelimit-reset', 'X-RateLimit-Reset'
                )
                if reset_val:
                    try:
                        reset_time = int(reset_val)
                    except (ValueError, TypeError):
                        pass

                # Fall back to retry-after (relative seconds, used by secondary limits)
                if reset_time is None:
                    retry_after = _get_header_case_insensitive(
                        error_headers, 'retry-after', 'Retry-After'
                    )
                    if retry_after:
                        try:
                            reset_time = int(now) + int(retry_after)
                        except (ValueError, TypeError):
                            pass

            # Last resort: now + window
            if reset_time is None:
                reset_time = int(now + limiter.window_size)

            limiter.update_from_headers(remaining=0, reset_time=reset_time)
            limiter.has_header_data = True
        except Exception:
            pass
