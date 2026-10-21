"""Webpage collection module using Playwright Chromium.

Extracts rendered HTML, screenshots, redirect chains, visible text, and
interactive DOM structures (forms, credentials inputs, buttons, links)
under strict sandbox controls.
"""
import os
import re
import time
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from playwright.async_api import Error as PlaywrightError, Page, Response, TimeoutError as PlaywrightTimeoutError

from backend.app.core.config import get_settings
from backend.app.core.logging import logger
from backend.app.crawler.browser import BrowserManager
from backend.app.models.schemas import (
    CrawlerResult,
    FormInput,
    FormSummary,
    RedirectHop,
)

settings = get_settings()

# Allowed protocols for analysis
ALLOWED_SCHEMES = {"http", "https", "data"}

# JavaScript helper for structured interactive element extraction
EXTRACTION_SCRIPT = """
() => {
    // 1. Extract Links
    const links = Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:'));

    // 2. Extract Buttons
    const buttons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]'))
        .map(b => (b.innerText || b.value || b.getAttribute('aria-label') || '').trim())
        .filter(text => text.length > 0);

    // 3. Extract All Input Elements
    const allInputs = Array.from(document.querySelectorAll('input, select, textarea')).map(el => {
        const type = (el.getAttribute('type') || (el.tagName.toLowerCase() === 'textarea' ? 'textarea' : 'text')).toLowerCase();
        return {
            input_type: type,
            name: el.getAttribute('name') || null,
            id: el.getAttribute('id') || null,
            placeholder: el.getAttribute('placeholder') || null,
            is_password: type === 'password'
        };
    });

    // 4. Extract Forms and their internal inputs
    const forms = Array.from(document.querySelectorAll('form')).map(f => {
        const formInputs = Array.from(f.querySelectorAll('input, select, textarea')).map(el => {
            const type = (el.getAttribute('type') || (el.tagName.toLowerCase() === 'textarea' ? 'textarea' : 'text')).toLowerCase();
            return {
                input_type: type,
                name: el.getAttribute('name') || null,
                id: el.getAttribute('id') || null,
                placeholder: el.getAttribute('placeholder') || null,
                is_password: type === 'password'
            };
        });
        const hasPassword = formInputs.some(inp => inp.is_password);
        return {
            action: f.getAttribute('action') || null,
            method: (f.getAttribute('method') || 'get').toLowerCase(),
            id: f.getAttribute('id') || null,
            name: f.getAttribute('name') || null,
            inputs: formInputs,
            has_password: hasPassword
        };
    });

    // 5. Extract Visible Text
    const visibleText = document.body ? document.body.innerText : '';

    return {
        links: Array.from(new Set(links)),
        buttons: Array.from(new Set(buttons)),
        all_inputs: allInputs,
        forms: forms,
        visible_text: visibleText
    };
}
"""


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validates that URL string has an acceptable scheme and format.
    
    Returns:
        (is_valid, error_reason)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    url_trimmed = url.strip()
    parsed = urlparse(url_trimmed)

    if not parsed.scheme:
        return False, f"Missing scheme in URL '{url}'. Expected http:// or https://"

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http, https, and data URLs are permitted."

    if parsed.scheme.lower() in {"http", "https"} and not parsed.netloc:
        return False, f"Malformed URL '{url}': hostname is missing."

    return True, None


async def collect_page(
    url: str,
    analysis_id: Optional[str] = None,
    timeout_ms: Optional[int] = None,
    capture_screenshot: bool = True,
    browser_manager: Optional[BrowserManager] = None,
) -> CrawlerResult:
    """Navigates to the specified URL using a controlled Playwright Chromium sandbox.

    Gathers browser-rendered HTML, screenshot, title, redirect hops, visible text,
    forms, inputs, and interactive button metadata. Gracefully handles timeouts,
    DNS failures, and network errors.
    """
    start_time = time.perf_counter()
    job_id = analysis_id or str(uuid.uuid4())
    effective_timeout = timeout_ms or settings.CRAWLER_TIMEOUT_MS

    # 1. URL Scheme & Syntax Validation
    is_valid, validation_err = validate_url(url)
    if not is_valid:
        elapsed = int((time.perf_counter() - start_time) * 1000)
        logger.warning(f"URL validation failed for '{url}': {validation_err}")
        return CrawlerResult(
            analysis_id=job_id,
            input_url=url,
            success=False,
            error_type="invalid_url",
            error_message=validation_err,
            elapsed_ms=elapsed,
        )

    # Prepare screenshot target directory
    screenshot_path: Optional[str] = None
    if capture_screenshot:
        os.makedirs(settings.SCREENSHOTS_DIR, exist_ok=True)
        screenshot_path = os.path.join(settings.SCREENSHOTS_DIR, f"{job_id}.png")

    manager = browser_manager or BrowserManager()
    redirect_chain: List[str] = []
    redirect_hops: List[RedirectHop] = []

    try:
        async with manager.get_context() as context:
            page = await context.new_page()

            # Set per-page timeouts
            page.set_default_navigation_timeout(effective_timeout)
            page.set_default_timeout(effective_timeout)

            # Listen for HTTP responses to log redirect chain and status
            async def handle_response(response: Response):
                # Track main document requests
                if response.request.resource_type == "document":
                    headers_dict = {k: v for k, v in response.headers.items()}
                    redirect_hops.append(
                        RedirectHop(
                            url=response.url,
                            status_code=response.status,
                            headers=headers_dict,
                        )
                    )
                    if response.url not in redirect_chain:
                        redirect_chain.append(response.url)

            page.on("response", handle_response)

            logger.info(f"Navigating to '{url}' [Job ID: {job_id}] with timeout {effective_timeout}ms")
            main_response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=effective_timeout,
            )

            # Brief settling window for dynamic JS hydration
            try:
                await page.wait_for_load_state("load", timeout=min(5000, effective_timeout))
            except PlaywrightTimeoutError:
                logger.debug(f"Page load state timed out on '{url}', proceeding with DOM content.")

            # Record final properties
            final_url = page.url
            if final_url not in redirect_chain:
                redirect_chain.append(final_url)

            status_code = main_response.status if main_response else (
                redirect_hops[-1].status_code if redirect_hops else 200
            )
            title = await page.title()
            html = await page.content()

            # Capture screenshot
            actual_screenshot_path: Optional[str] = None
            if capture_screenshot and screenshot_path:
                try:
                    await page.screenshot(
                        path=screenshot_path,
                        full_page=False,  # Viewport captures typical user perspective
                        timeout=min(10000, effective_timeout),
                    )
                    actual_screenshot_path = screenshot_path
                except Exception as sc_exc:
                    logger.warning(f"Screenshot capture failed for '{url}': {sc_exc}")

            # Extract structured DOM data
            dom_data = await page.evaluate(EXTRACTION_SCRIPT)

            # Parse inputs and forms into Pydantic models
            input_fields = [FormInput(**inp) for inp in dom_data.get("all_inputs", [])]
            password_fields = [inp for inp in input_fields if inp.is_password]
            forms = [
                FormSummary(
                    action=f.get("action"),
                    method=f.get("method", "get"),
                    id=f.get("id"),
                    name=f.get("name"),
                    inputs=[FormInput(**inp) for inp in f.get("inputs", [])],
                    has_password=f.get("has_password", False),
                )
                for f in dom_data.get("forms", [])
            ]

            elapsed = int((time.perf_counter() - start_time) * 1000)
            logger.info(
                f"Collection completed for '{url}' in {elapsed}ms. "
                f"Status: {status_code}, Title: '{title}', Password inputs: {len(password_fields)}"
            )

            return CrawlerResult(
                analysis_id=job_id,
                input_url=url,
                final_url=final_url,
                status_code=status_code,
                redirect_chain=redirect_chain,
                redirect_hops=redirect_hops,
                title=title,
                html=html,
                visible_text=dom_data.get("visible_text", ""),
                screenshot_path=actual_screenshot_path,
                links=dom_data.get("links", []),
                forms=forms,
                input_fields=input_fields,
                password_fields=password_fields,
                buttons=dom_data.get("buttons", []),
                success=True,
                elapsed_ms=elapsed,
            )

    except PlaywrightTimeoutError as timeout_exc:
        elapsed = int((time.perf_counter() - start_time) * 1000)
        logger.error(f"Crawler timeout ({effective_timeout}ms) for '{url}': {timeout_exc}")
        return CrawlerResult(
            analysis_id=job_id,
            input_url=url,
            success=False,
            error_type="timeout",
            error_message=f"Navigation or rendering timed out after {effective_timeout}ms.",
            elapsed_ms=elapsed,
        )

    except PlaywrightError as pw_exc:
        elapsed = int((time.perf_counter() - start_time) * 1000)
        error_msg = str(pw_exc)
        error_type = "connection_error"
        if "ERR_NAME_NOT_RESOLVED" in error_msg or "DNS" in error_msg:
            error_type = "dns_failure"
        elif "ERR_CONNECTION_REFUSED" in error_msg:
            error_type = "connection_refused"
        elif "ERR_CERT" in error_msg or "SSL" in error_msg:
            error_type = "ssl_error"

        logger.error(f"Playwright error ({error_type}) for '{url}': {error_msg}")
        return CrawlerResult(
            analysis_id=job_id,
            input_url=url,
            success=False,
            error_type=error_type,
            error_message=error_msg,
            elapsed_ms=elapsed,
        )

    except Exception as exc:
        elapsed = int((time.perf_counter() - start_time) * 1000)
        logger.exception(f"Unexpected crawler exception for '{url}': {exc}")
        return CrawlerResult(
            analysis_id=job_id,
            input_url=url,
            success=False,
            error_type="unexpected_error",
            error_message=str(exc),
            elapsed_ms=elapsed,
        )
