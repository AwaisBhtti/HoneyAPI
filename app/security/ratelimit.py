import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import HTTPException, Request

_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(key_prefix: str, max_requests: int = 30, window_s: int = 60) -> Callable[[Request], None]:
    """Sliding-window in-memory rate limiter dependency."""

    def _dependency(request: Request) -> None:
        client_ip = request.client.host if request.client else "127.0.0.1"
        bucket_key = f"{key_prefix}:{client_ip}"
        now = time.time()
        q = _BUCKETS[bucket_key]

        while q and q[0] <= now - window_s:
            q.popleft()

        if len(q) >= max_requests:
            raise HTTPException(
                status_code=429,
                detail={"error": {"code": "RATE_LIMITED", "message": "Rate limit exceeded; try again later"}},
            )
        q.append(now)

    return _dependency
