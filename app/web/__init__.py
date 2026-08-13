from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections import Counter
from pathlib import Path
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.forensics.case_copilot_v6 import install_base_patch

install_base_patch()

from app.enterprise.api import install_enterprise_routes
from app.soc.api import install_soc_routes
from app.web.autonomous import install_autonomous_routes
from app.web.dashboard import DashboardService, create_dashboard_app as _create_dashboard_app


class _RuntimeMetrics:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests = 0
        self.errors = 0
        self.rejected_large = 0
        self.latency_ms = 0.0
        self.by_status: Counter[str] = Counter()

    def observe(self, status: int, latency_ms: float) -> None:
        with self.lock:
            self.requests += 1
            self.latency_ms += latency_ms
            if status >= 500:
                self.errors += 1
            self.by_status[str(status)] += 1

    def prometheus(self) -> str:
        with self.lock:
            avg = self.latency_ms / self.requests if self.requests else 0.0
            lines = [
                "# TYPE sentinel_requests_total counter",
                f"sentinel_requests_total {self.requests}",
                "# TYPE sentinel_errors_total counter",
                f"sentinel_errors_total {self.errors}",
                "# TYPE sentinel_rejected_large_requests_total counter",
                f"sentinel_rejected_large_requests_total {self.rejected_large}",
                "# TYPE sentinel_average_latency_ms gauge",
                f"sentinel_average_latency_ms {avg:.3f}",
            ]
            for status, count in sorted(self.by_status.items()):
                lines.append(f'sentinel_responses_total{{status="{status}"}} {count}')
            return "\n".join(lines) + "\n"


_METRICS = _RuntimeMetrics()
_ACCESS_LOG = logging.getLogger("sentinel.access")
if not _ACCESS_LOG.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _ACCESS_LOG.addHandler(_handler)
    _ACCESS_LOG.setLevel(logging.INFO)
    _ACCESS_LOG.propagate = False


def create_dashboard_app(cases_root: str = "cases", sigma_rules: str = "rules/sigma"):
    app = _create_dashboard_app(cases_root=cases_root, sigma_rules=sigma_rules)
    install_autonomous_routes(app, cases_root=cases_root, sigma_rules=sigma_rules)
    install_enterprise_routes(app, cases_root=cases_root)
    install_soc_routes(app, cases_root=cases_root, sigma_rules=sigma_rules)

    max_request_bytes = int(os.getenv("SENTINEL_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
    case_root_path = Path(cases_root)

    @app.middleware("http")
    async def sentinel_runtime_guard(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        length = request.headers.get("content-length")
        if length:
            try:
                too_large = int(length) > max_request_bytes
            except ValueError:
                too_large = False
            if too_large:
                with _METRICS.lock:
                    _METRICS.rejected_large += 1
                return JSONResponse(
                    status_code=413,
                    content={"detail": "request body too large", "request_id": request_id},
                    headers={"X-Request-ID": request_id},
                )

        started = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - started) * 1000
        _METRICS.observe(response.status_code, latency_ms)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        _ACCESS_LOG.info(json.dumps({
            "event": "http_request",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "latency_ms": round(latency_ms, 3),
        }, sort_keys=True))
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "service": "sentinel-ai"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        case_root_path.mkdir(parents=True, exist_ok=True)
        readable = os.access(case_root_path, os.R_OK)
        writable = os.access(case_root_path, os.W_OK)
        ready = readable and writable
        payload = {
            "status": "ready" if ready else "not-ready",
            "service": "sentinel-ai",
            "checks": {"http": True, "cases_readable": readable, "cases_writable": writable},
        }
        if not ready:
            return JSONResponse(status_code=503, content=payload)
        return payload

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return PlainTextResponse(_METRICS.prometheus(), media_type="text/plain; version=0.0.4")

    return app


__all__ = ["DashboardService", "create_dashboard_app"]
