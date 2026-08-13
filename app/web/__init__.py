from app.forensics.case_copilot_v6 import install_base_patch

install_base_patch()

from app.enterprise.api import install_enterprise_routes
from app.web.autonomous import install_autonomous_routes
from app.web.dashboard import DashboardService, create_dashboard_app as _create_dashboard_app


def create_dashboard_app(cases_root: str = "cases", sigma_rules: str = "rules/sigma"):
    app = _create_dashboard_app(cases_root=cases_root, sigma_rules=sigma_rules)
    install_autonomous_routes(app, cases_root=cases_root, sigma_rules=sigma_rules)
    install_enterprise_routes(app, cases_root=cases_root)
    return app


__all__ = ["DashboardService", "create_dashboard_app"]
