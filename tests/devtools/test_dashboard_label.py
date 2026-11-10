"""Wrapped lab Dashboards are labeled as non-operational, or withheld."""

from pathlib import Path

from incident_awareness.devtools import labeled_dashboard

TEMPLATE = Path("src/incident_awareness/dashboard/ui/dashboard.html").read_text(encoding="utf-8")


def test_production_template_has_exactly_one_escaped_label():
    response = labeled_dashboard(TEMPLATE, "TEST <격리> 운영 실측 아님")
    assert response.status_code == 200
    assert response.body.decode().count('role="note">TEST &lt;격리&gt; 운영 실측 아님</span>') == 1


def test_missing_title_anchor_withholds_the_page_instead_of_serving_it_unlabeled():
    response = labeled_dashboard(TEMPLATE.replace("운영 현황</h1>", "Renamed</h1>"), "TEST")
    assert response.status_code == 503
    assert "dashboard-view" not in response.body.decode()
