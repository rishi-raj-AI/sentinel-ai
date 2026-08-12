from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Sentinel AI local investigation dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument("--reload", action="store_true", help="Enable development auto-reload")
    args = parser.parse_args()
    uvicorn.run(
        "app.web.dashboard:create_dashboard_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
