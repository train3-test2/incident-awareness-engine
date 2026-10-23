"""Explicitly opt-in, local-only development experiments; never production services."""

from html import escape

from fastapi.responses import HTMLResponse

_DASHBOARD_TITLE = '<h1 class="page-title">운영 현황</h1>'


def labeled_dashboard(body: str, label: str) -> HTMLResponse:
    """Badge a wrapped Dashboard as non-operational, or withhold it.

    A missing title anchor must never serve an unlabeled lab page that looks operational.
    """
    if body.count(_DASHBOARD_TITLE) != 1:
        return HTMLResponse("Isolation label anchor missing; lab Dashboard withheld", 503)
    badge = f'<span class="operator-demo-badge" role="note">{escape(label)}</span>'
    return HTMLResponse(body.replace(_DASHBOARD_TITLE, _DASHBOARD_TITLE + badge))
