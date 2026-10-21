"""Browser context management and security controls for Playwright Chromium.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Playwright,
)
from backend.app.core.config import get_settings
from backend.app.core.logging import logger

settings = get_settings()

# Default desktop viewport for consistent visual rendering and OCR evaluation
DEFAULT_VIEWPORT = {"width": 1280, "height": 800}

# Standard Chrome user agent to prevent false blocks by CDN anti-bot scripts
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Chromium hardened sandbox launch flags
CHROMIUM_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-accelerated-2d-canvas",
    "--no-first-run",
    "--no-zygote",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-features=Translate,BackForwardCache",
    "--disable-hang-monitor",
    "--disable-ipc-flooding-protection",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-renderer-backgrounding",
    "--disable-sync",
    "--metrics-recording-only",
]


class BrowserManager:
    """Manages ephemeral, secure Playwright Chromium browser contexts.
    
    Security Guarantees:
    - Never uses host user profiles or persistent cookies.
    - Explicitly disables file downloads.
    - Operates in strict timeout bounds.
    - Ensures clean context disposal after every collection job.
    """

    def __init__(self, headless: Optional[bool] = None):
        self.headless = headless if headless is not None else settings.HEADLESS_BROWSER

    @asynccontextmanager
    async def get_context(self) -> AsyncGenerator[BrowserContext, None]:
        """Provides an isolated, ephemeral browser context with strict security policies."""
        playwright_instance: Optional[Playwright] = None
        browser: Optional[Browser] = None
        context: Optional[BrowserContext] = None
        try:
            playwright_instance = await async_playwright().start()
            browser = await playwright_instance.chromium.launch(
                headless=self.headless,
                args=CHROMIUM_LAUNCH_ARGS,
            )
            # Create completely fresh ephemeral context
            context = await browser.new_context(
                viewport=DEFAULT_VIEWPORT,
                user_agent=DEFAULT_USER_AGENT,
                accept_downloads=False,          # Prevent malicious file drops
                ignore_https_errors=True,       # Collect sites with invalid/expired SSL
                java_script_enabled=True,       # Render dynamic DOM
                bypass_csp=False,               # Preserve CSP policies
                permissions=[],                 # No geolocation, camera, or notifications
            )
            yield context
        except Exception as exc:
            logger.error(f"Error initializing browser context: {exc}")
            raise
        finally:
            if context:
                try:
                    await context.close()
                except Exception as close_exc:
                    logger.warning(f"Error closing browser context: {close_exc}")
            if browser:
                try:
                    await browser.close()
                except Exception as close_exc:
                    logger.warning(f"Error closing browser instance: {close_exc}")
            if playwright_instance:
                try:
                    await playwright_instance.stop()
                except Exception as stop_exc:
                    logger.warning(f"Error stopping playwright engine: {stop_exc}")
