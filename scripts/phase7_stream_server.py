from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.operations.api import install_operations_routes


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel X Mission Telemetry", docs_url=None, redoc_url=None)
    origins = [
        item.strip()
        for item in os.getenv(
            "SENTINEL_UI_ORIGINS",
            "http://127.0.0.1:5173,http://localhost:5173",
        ).split(",")
        if item.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Accept", "X-Sentinel-Role"],
    )
    install_operations_routes(app, data_root=os.getenv("SENTINEL_DATA_ROOT", "data"))

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "service": "sentinel-mission-telemetry", "read_only": True}

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "scripts.phase7_stream_server:app",
        host="127.0.0.1",
        port=int(os.getenv("SENTINEL_OPERATIONS_PORT", "8766")),
        reload=False,
    )
