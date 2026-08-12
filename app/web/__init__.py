from app.forensics.case_copilot_v2 import install_base_patch

install_base_patch()

from app.web.dashboard import DashboardService, create_dashboard_app

__all__ = ["DashboardService", "create_dashboard_app"]
