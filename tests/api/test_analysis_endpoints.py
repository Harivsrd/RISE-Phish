"""Integration test suite for Phase 17: Full FastAPI Endpoint Integration & Persistence.

Validates:
1. POST /api/v1/analyze: Live pipeline orchestration and technical report generation.
2. Caching behavior: Fast retrieval when force_fresh=False.
3. GET /api/v1/analysis/{id}: Deep technical forensics retrieval.
4. 404 handling on unknown analysis IDs.
5. GET /api/v1/history: Paginated history listing and verdict filtering.
6. GET /api/v1/stats: Dashboard metrics and brand targeting telemetry.
7. DELETE /api/v1/analysis/{id}: Historical record deletion.
8. Error handling on invalid URL inputs.
"""
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.app.models.schemas import CrawlerResult, ThreatVerdict


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Sets up an isolated temporary SQLite database for each test session."""
    test_db_file = str(tmp_path / "test_rise_phish.db")
    monkeypatch.setenv("SQLITE_DB_URL", f"sqlite:///{test_db_file}")
    
    # Reinitialize singleton database manager to use temp DB
    import backend.app.storage.database as db_mod
    db_mod._db_manager = db_mod.DatabaseManager(db_path=test_db_file)
    db_mod._db_manager.init_db()
    yield
    db_mod._db_manager = None


def test_analyze_endpoint_success(test_client: TestClient):
    """Verify POST /api/v1/analyze runs pipeline and returns full forensics."""
    # Mock crawler to avoid network dependence in unit tests
    mock_crawler_res = CrawlerResult(
        analysis_id="test-job-001",
        input_url="https://portal-session-sync.net/auth",
        final_url="https://portal-session-sync.net/auth",
        success=True,
        html="""<!DOCTYPE html>
<html>
<head><title>Microsoft Security Center</title></head>
<body>
  <h1>Sign In to 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭</h1>
  <form action="/login" method="POST">
    <input type="password" name="password" placeholder="Password" />
    <button type="submit">Sign In</button>
  </form>
</body>
</html>""",
        visible_text="Sign In to 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭\nPassword Sign In",
        title="Microsoft Security Center",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_crawler_res,
    ):
        payload = {
            "url": "https://portal-session-sync.net/auth",
            "force_fresh": True,
        }
        response = test_client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "analysis_id" in data
        assert data["url"] == "https://portal-session-sync.net/auth"
        assert data["status"] == "COMPLETED"
        assert data["verdict"] in ("PHISHING", "INVESTIGATE", "SAFE")
        assert "composite_threat_score" in data
        assert "representations" in data
        assert data["representations"]["r1_raw"]["text"] != ""
        assert "crce" in data
        assert "decision" in data
        assert "explanation" in data
        assert "user_advisory" in data["explanation"]
        assert "analyst_report" in data["explanation"]


def test_analyze_endpoint_cache_behavior(test_client: TestClient):
    """Verify caching: second call with force_fresh=False returns cached response."""
    mock_crawler_res = CrawlerResult(
        analysis_id="test-cache-001",
        input_url="https://example.com/cached-portal",
        final_url="https://example.com/cached-portal",
        success=True,
        html="<html><body><p>Welcome to official example portal.</p></body></html>",
        visible_text="Welcome to official example portal.",
        title="Official Portal",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_crawler_res,
    ) as mock_crawl:
        payload = {"url": "https://example.com/cached-portal", "force_fresh": False}
        
        # First call: executes crawl
        res1 = test_client.post("/api/v1/analyze", json=payload)
        assert res1.status_code == 200
        analysis_id_1 = res1.json()["analysis_id"]
        assert mock_crawl.call_count == 1

        # Second call: returns cached record without calling crawler again
        res2 = test_client.post("/api/v1/analyze", json=payload)
        assert res2.status_code == 200
        analysis_id_2 = res2.json()["analysis_id"]
        assert analysis_id_1 == analysis_id_2
        assert mock_crawl.call_count == 1  # Not called again!


def test_get_analysis_by_id(test_client: TestClient):
    """Verify GET /api/v1/analysis/{id} retrieves complete stored report."""
    mock_crawler_res = CrawlerResult(
        analysis_id="retrieve-test-001",
        input_url="https://apple-auth-check.xyz/login",
        final_url="https://apple-auth-check.xyz/login",
        success=True,
        html="<html><body><h1>Sign in to Apple ID</h1><input type='password'></body></html>",
        visible_text="Sign in to Apple ID",
        title="Apple ID Verification",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_crawler_res,
    ):
        post_res = test_client.post(
            "/api/v1/analyze",
            json={"url": "https://apple-auth-check.xyz/login", "force_fresh": True},
        )
        assert post_res.status_code == 200
        aid = post_res.json()["analysis_id"]

        # Fetch via GET
        get_res = test_client.get(f"/api/v1/analysis/{aid}")
        assert get_res.status_code == 200
        get_data = get_res.json()
        assert get_data["analysis_id"] == aid
        assert get_data["url"] == "https://apple-auth-check.xyz/login"
        assert get_data["decision"] is not None


def test_get_analysis_by_id_not_found(test_client: TestClient):
    """Verify GET /api/v1/analysis/{unknown_id} returns 404."""
    response = test_client.get("/api/v1/analysis/non-existent-uuid-12345")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_history_and_pagination(test_client: TestClient):
    """Verify GET /api/v1/history returns paginated scan records."""
    mock_res_template = CrawlerResult(
        analysis_id="hist-001",
        input_url="https://site1.com",
        final_url="https://site1.com",
        success=True,
        html="<html><body><p>Public site 1</p></body></html>",
        visible_text="Public site 1",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_res_template,
    ):
        # Insert 3 scans
        for i in range(3):
            test_client.post(
                "/api/v1/analyze",
                json={"url": f"https://example-history-{i}.com", "force_fresh": True},
            )

        # Retrieve history with limit=2
        res = test_client.get("/api/v1/history?limit=2&offset=0")
        assert res.status_code == 200
        hist = res.json()
        assert hist["total"] >= 3
        assert len(hist["items"]) == 2

        # Retrieve page 2
        res_page2 = test_client.get("/api/v1/history?limit=2&offset=2")
        assert res_page2.status_code == 200
        hist_page2 = res_page2.json()
        assert len(hist_page2["items"]) >= 1


def test_dashboard_stats_endpoint(test_client: TestClient):
    """Verify GET /api/v1/stats calculates aggregate scan telemetry."""
    mock_crawler_res = CrawlerResult(
        analysis_id="stats-test-001",
        input_url="https://stats-test.com",
        final_url="https://stats-test.com",
        success=True,
        html="<html><body><h1>Sign In</h1><input type='password'></body></html>",
        visible_text="Sign In",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_crawler_res,
    ):
        test_client.post(
            "/api/v1/analyze",
            json={"url": "https://stats-test.com", "force_fresh": True},
        )

        res = test_client.get("/api/v1/stats")
        assert res.status_code == 200
        stats = res.json()
        assert stats["total_scans"] >= 1
        assert "phishing_detected" in stats
        assert "safe_sites" in stats
        assert "average_threat_score" in stats


def test_delete_analysis_endpoint(test_client: TestClient):
    """Verify DELETE /api/v1/analysis/{id} removes record from storage."""
    mock_crawler_res = CrawlerResult(
        analysis_id="del-test-001",
        input_url="https://delete-me.com",
        final_url="https://delete-me.com",
        success=True,
        html="<html><body><p>Delete me</p></body></html>",
        visible_text="Delete me",
    )

    with patch(
        "backend.app.api.service.collect_page",
        new_callable=AsyncMock,
        return_value=mock_crawler_res,
    ):
        res = test_client.post(
            "/api/v1/analyze",
            json={"url": "https://delete-me.com", "force_fresh": True},
        )
        aid = res.json()["analysis_id"]

        # Delete it
        del_res = test_client.delete(f"/api/v1/analysis/{aid}")
        assert del_res.status_code == 200
        assert del_res.json()["status"] == "deleted"

        # Subsequent GET should return 404
        get_res = test_client.get(f"/api/v1/analysis/{aid}")
        assert get_res.status_code == 404


def test_invalid_url_handling(test_client: TestClient):
    """Verify crawler validation failure on invalid scheme or malformed URL."""
    payload = {"url": "ftp://malformed-scheme.com", "force_fresh": True}
    res = test_client.post("/api/v1/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAILED"
    assert data["error_message"] is not None
