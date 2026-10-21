"""End-to-End System Integration & Verification Test Suite (Phase 19).

Validates the full RISE-Phish operational pipeline in an integrated environment:
1. Real Playwright Headless Chromium crawler capturing live DOM & screenshot.
2. Feature extraction (HTML hierarchy, syntactic URL, Unicode analyzer).
3. Multi-representation compilation (R1 Raw, R2 Normalized, R3 Visual, R4 Semantic, R5 URL).
4. CRCE Pairwise Discrepancy Matrix & Visual-Normalization Convergence signature.
5. Lightweight SLM dual-task execution (Semantic Recovery & Threat Reasoning).
6. Non-linear Evidence Fusion with interactive boosts.
7. Calibrated operational Decision Engine & Threat Posture Policies.
8. Dual-Audience Explainability Engine (User Advisory & SOC Analyst Forensic Drawer).
9. SQLite WAL persistence, indexing, caching, and historical retrieval.
10. Multi-request concurrency and network failure resilience.
"""
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import socket
import threading
import time
from typing import Generator
import pytest

from backend.app.api.service import analyze_url_pipeline
from backend.app.crawler.browser import BrowserManager
from backend.app.decision.risk import ThreatVerdict, DefensiveAction
from backend.app.models.schemas import AnalysisDetailResponse
from backend.app.storage.database import get_db_manager


class MockWebHandler(BaseHTTPRequestHandler):
    """Local HTTP request handler simulating realistic benign and phishing web portals."""

    def do_GET(self) -> None:
        if self.path == "/login-math-spoof":
            content = """<!DOCTYPE html>
<html>
<head><title>Microsoft Security Center</title></head>
<body>
  <h1>Sign In to 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭 Account</h1>
  <p>Verify your account credentials to prevent suspension.</p>
  <form action="/auth" method="POST">
    <label>Email: <input type="text" name="email" value="user@domain.com" /></label>
    <label>Password: <input type="password" name="password" /></label>
    <button type="submit">Sign In</button>
  </form>
</body>
</html>"""
            self._send_html(content)

        elif self.path == "/login-homoglyph-cyrillic":
            # Cyrillic small letter byelorussian-ukrainian i (U+0456)
            content = """<!DOCTYPE html>
<html>
<head><title>Microsoft Account Login</title></head>
<body>
  <h1>Sign in to m\u0456crosoft online services</h1>
  <form action="/login" method="POST">
    <input type="password" name="pwd" placeholder="Enter password" />
    <button type="submit">Log In</button>
  </form>
</body>
</html>"""
            self._send_html(content)

        elif self.path == "/login-zero-width":
            # Zero-width spaces (U+200B) and Plane 14 tag characters (U+E0061)
            content = """<!DOCTYPE html>
<html>
<head><title>Secure Banking Login</title></head>
<body>
  <h1>Pay\u200bPal \U000E0061Security Verification</h1>
  <p>Identity confirmation is required immediately.</p>
  <form action="/verify" method="POST">
    <input type="password" name="pin" />
    <button type="submit">Confirm PIN</button>
  </form>
</body>
</html>"""
            self._send_html(content)

        elif self.path == "/benign-multilingual":
            # Legitimate French corporate page with natural accents and no credential forms
            content = """<!DOCTYPE html>
<html>
<head><title>Portail Entreprise Officiel</title></head>
<body>
  <h1>Bienvenue sur votre espace sécurisé</h1>
  <p>Consultez les informations générales, nos services et nos coordonnées de contact.</p>
  <footer>Mentions légales et politique de confidentialité conformes au RGPD.</footer>
</body>
</html>"""
            self._send_html(content)

        else:
            self.send_response(404)
            self.end_headers()

    def _send_html(self, content: str) -> None:
        payload = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        """Silence HTTP request access logs during tests."""
        pass


@pytest.fixture(scope="module")
def mock_web_server() -> Generator[str, None, None]:
    """Spins up a local HTTP test server on an ephemeral OS port."""
    server = HTTPServer(("127.0.0.1", 0), MockWebHandler)
    host, port = server.server_address
    base_url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path, monkeypatch):
    """Sets up an isolated temporary SQLite database for each test session."""
    test_db_file = str(tmp_path / "test_e2e_integration.db")
    monkeypatch.setenv("SQLITE_DB_URL", f"sqlite:///{test_db_file}")

    import backend.app.storage.database as db_mod
    db_mod._db_manager = db_mod.DatabaseManager(db_path=test_db_file)
    db_mod._db_manager.init_db()
    yield db_mod._db_manager
    db_mod._db_manager = None


@pytest.mark.asyncio
async def test_e2e_live_playwright_crawl_and_full_pipeline(mock_web_server: str):
    """Verify live Chromium crawl, full R1-R5 multi-representation pipeline, and DB persistence."""
    target_url = f"{mock_web_server}/login-math-spoof"

    # Execute full analysis pipeline
    response = await analyze_url_pipeline(url=target_url, force_fresh=True)

    # 1. Pipeline status and core identification
    assert response.status == "COMPLETED"
    assert response.url == target_url
    assert response.analysis_id is not None

    # 2. Crawler verification (Live Chromium rendered the DOM and captured fields)
    assert response.html_features is not None
    assert response.html_features.has_password_field is True
    assert "Microsoft Security Center" in response.html_features.title

    # 3. Multi-Representation Suite (R1-R5)
    reps = response.representations
    assert reps is not None
    assert "𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭" in reps.r1_raw.text
    # Mathematical bold normalized by NFKC to Latin Microsoft
    assert "Microsoft" in reps.r2_normalized.text
    assert reps.r4_semantic.form_intent_summary is not None
    assert reps.r5_url.hostname == "127.0.0.1"

    # 4. CRCE Discrepancy Matrix
    crce = response.crce
    assert crce is not None
    assert crce.raw_normalized_discrepancy > 0.0

    # 5. Evidence Fusion & Decision
    assert response.composite_threat_score >= 0.40
    assert response.verdict in (ThreatVerdict.PHISHING, ThreatVerdict.INVESTIGATE)
    assert response.recommended_action in (
        DefensiveAction.BLOCK_ACCESS,
        DefensiveAction.WARN_USER,
        DefensiveAction.ISOLATE_SANDBOX,
    )

    # 6. Dual-Audience Explainability
    exp = response.explanation
    assert exp is not None
    assert exp.user_advisory is not None
    assert len(exp.user_advisory.bullet_points) > 0
    assert exp.user_advisory.action_advice != ""
    assert exp.analyst_report is not None
    assert exp.analyst_report.composite_threat_score == response.composite_threat_score

    # 7. Database Verification
    db = get_db_manager()
    record = db.get_record(response.analysis_id)
    assert record is not None
    assert record["url"] == target_url
    assert record["verdict"] == response.verdict.value
    persisted_report = json.loads(record["report_json"])
    assert persisted_report["analysis_id"] == response.analysis_id


@pytest.mark.asyncio
async def test_e2e_visual_normalization_convergence_attack(mock_web_server: str):
    """Verify live crawl detection of Cyrillic homoglyph visual convergence attack."""
    target_url = f"{mock_web_server}/login-homoglyph-cyrillic"

    response = await analyze_url_pipeline(url=target_url, force_fresh=True)

    assert response.status == "COMPLETED"
    assert response.visual_normalization_convergence is True
    assert response.crce.visual_normalization_convergence is True

    # Rule CRIT-01 or elevated phishing policy triggered
    assert response.verdict == ThreatVerdict.PHISHING
    assert response.recommended_action == DefensiveAction.BLOCK_ACCESS
    assert response.composite_threat_score >= 0.70

    # User advisory reflects visual evasion
    advisory = response.explanation.user_advisory
    assert advisory.status_level == "DANGER"
    assert "phishing" in advisory.headline.lower() or "deceptive" in advisory.headline.lower() or "spoof" in advisory.headline.lower()


@pytest.mark.asyncio
async def test_e2e_zero_width_steganography_attack(mock_web_server: str):
    """Verify live detection of invisible zero-width and plane-14 characters."""
    target_url = f"{mock_web_server}/login-zero-width"

    response = await analyze_url_pipeline(url=target_url, force_fresh=True)

    assert response.status == "COMPLETED"
    assert response.unicode_analysis is not None
    assert response.unicode_analysis.zero_width_count > 0
    assert response.unicode_analysis.tag_character_count > 0
    assert response.unicode_analysis.unicode_anomaly_score >= 0.10

    # R1 contains hidden characters; R2 strips them
    r1_len = len(response.representations.r1_raw.text)
    r2_len = len(response.representations.r2_normalized.text)
    assert r1_len > r2_len


@pytest.mark.asyncio
async def test_e2e_benign_site_authentic_consistency(mock_web_server: str):
    """Verify that legitimate multi-lingual content with accents is classified SAFE."""
    target_url = f"{mock_web_server}/benign-multilingual"

    response = await analyze_url_pipeline(url=target_url, force_fresh=True)

    assert response.status == "COMPLETED"
    assert response.visual_normalization_convergence is False
    assert response.verdict == ThreatVerdict.SAFE
    assert response.recommended_action == DefensiveAction.ALLOW
    assert response.composite_threat_score < 0.40

    # User advisory shows SAFE status
    advisory = response.explanation.user_advisory
    assert advisory.status_level == "SAFE"
    assert "Safe" in advisory.headline or "Authentic" in advisory.headline


@pytest.mark.asyncio
async def test_e2e_caching_and_force_fresh_contract(mock_web_server: str):
    """Verify caching behavior: reuse of cached analysis vs force_fresh re-evaluation."""
    target_url = f"{mock_web_server}/benign-multilingual"

    # First run (computes and caches)
    run_1 = await analyze_url_pipeline(url=target_url, force_fresh=True)

    # Second run without force_fresh (should hit cache)
    run_2 = await analyze_url_pipeline(url=target_url, force_fresh=False)

    assert run_1.analysis_id == run_2.analysis_id
    assert run_1.composite_threat_score == run_2.composite_threat_score

    # Third run with force_fresh=True (bypasses cache and generates new record)
    run_3 = await analyze_url_pipeline(url=target_url, force_fresh=True)

    assert run_3.analysis_id != run_1.analysis_id
    assert run_3.url == target_url

    # Check both records exist in DB
    db = get_db_manager()
    rows, total = db.list_records(limit=10)
    assert total >= 2


@pytest.mark.asyncio
async def test_e2e_crawler_unreachable_network_resilience():
    """Verify system handles unreachable network targets gracefully with DEGRADED status."""
    # Port 59871 is unused
    dead_url = "http://127.0.0.1:59871/dead-service"

    response = await analyze_url_pipeline(url=dead_url, force_fresh=True)

    # Must not raise unhandled exception; returns DEGRADED status
    assert response.status == "DEGRADED"
    assert response.error_message is not None
    assert response.analysis_id is not None

    # Stored in DB
    db = get_db_manager()
    record = db.get_record(response.analysis_id)
    assert record is not None
    assert record["status"] == "DEGRADED"


@pytest.mark.asyncio
async def test_e2e_concurrent_pipeline_execution(mock_web_server: str):
    """Verify SQLite WAL handles concurrent multi-client requests without database locks."""
    urls = [
        f"{mock_web_server}/login-math-spoof",
        f"{mock_web_server}/login-homoglyph-cyrillic",
        f"{mock_web_server}/login-zero-width",
        f"{mock_web_server}/benign-multilingual",
    ]

    # Run all 4 requests concurrently
    tasks = [analyze_url_pipeline(url=u, force_fresh=True) for u in urls]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    assert len(results) == 4
    analysis_ids = {r.analysis_id for r in results}
    assert len(analysis_ids) == 4  # All distinct

    # Verify all records stored properly in DB
    db = get_db_manager()
    for r in results:
        rec = db.get_record(r.analysis_id)
        assert rec is not None
        assert rec["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_e2e_full_system_latency_profiling(mock_web_server: str):
    """Profile latency of end-to-end execution to ensure real-time responsiveness."""
    target_url = f"{mock_web_server}/login-math-spoof"

    start_time = time.perf_counter()
    response = await analyze_url_pipeline(url=target_url, force_fresh=True)
    total_elapsed_ms = (time.perf_counter() - start_time) * 1000

    assert response.status == "COMPLETED"
    # End-to-end execution with full browser crawl, multi-repr, SLM, and DB persistence
    # must complete comfortably within 6000ms on RTX 3050 / local host
    assert total_elapsed_ms < 6000, f"Pipeline took {total_elapsed_ms:.1f}ms, expected < 6000ms"
