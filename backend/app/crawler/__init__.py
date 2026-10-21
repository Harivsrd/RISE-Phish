"""Playwright web crawler package for RISE-Phish.
"""
from backend.app.crawler.browser import BrowserManager
from backend.app.crawler.collector import collect_page, validate_url

__all__ = ["BrowserManager", "collect_page", "validate_url"]
