"""HTML processing and structured feature extraction module.

Parses browser-rendered or raw HTML using BeautifulSoup and lxml,
producing clean structural, lexical, credential, and metadata features
without flooding downstream SLMs with raw markup tags.
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment

from backend.app.core.logging import logger
from backend.app.models.schemas import (
    FormInput,
    FormSummary,
    HeadingItem,
    HTMLFeatures,
    ImageSummary,
)

# Tags whose content should be stripped when generating clean visible text
DISCARD_TAGS = {"script", "style", "noscript", "svg", "head", "meta", "link", "template"}


def clean_text(text: Optional[str]) -> str:
    """Collapses repeated whitespace and strips leading/trailing characters."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def build_slm_structured_text(
    title: Optional[str],
    headings: List[HeadingItem],
    forms: List[FormSummary],
    buttons: List[str],
    alt_texts: List[str],
    placeholders: List[str],
    visible_sample: str,
    meta_attributes: Dict[str, str],
) -> str:
    """Synthesizes a compact, structured text prompt for SLM consumption."""
    sections = []

    # Title section
    if title:
        sections.append(f"[TITLE]\n{title}")

    # Meta indicators
    meta_parts = []
    if "description" in meta_attributes:
        meta_parts.append(f"Description: {meta_attributes['description']}")
    if "og:title" in meta_attributes:
        meta_parts.append(f"OG Title: {meta_attributes['og:title']}")
    if meta_parts:
        sections.append("[METADATA]\n" + "\n".join(meta_parts))

    # Headings hierarchy
    if headings:
        heading_lines = [f"- (H{h.level}) {h.text}" for h in headings[:10]]
        sections.append("[HEADINGS]\n" + "\n".join(heading_lines))

    # Forms & Credential collection points
    if forms:
        form_lines = []
        for idx, f in enumerate(forms, 1):
            pwd_flag = " [CONTAINS PASSWORD INPUT]" if f.has_password else ""
            form_lines.append(f"Form {idx}: method={f.method.upper()}, action={f.action or 'none'}{pwd_flag}")
            for inp in f.inputs:
                marker = " [PASSWORD FIELD]" if inp.is_password else ""
                form_lines.append(
                    f"  * input type={inp.input_type}, name={inp.name or 'none'}, "
                    f"placeholder='{inp.placeholder or ''}'{marker}"
                )
        sections.append("[FORMS & INPUTS]\n" + "\n".join(form_lines))

    # Interactive elements
    if buttons:
        sections.append("[BUTTONS]\n" + ", ".join(buttons[:15]))

    if placeholders:
        sections.append("[INPUT PLACEHOLDERS]\n" + ", ".join(placeholders[:15]))

    if alt_texts:
        sections.append("[IMAGE ALTS]\n" + ", ".join(alt_texts[:10]))

    # Visible body sample (capped to prevent context flooding)
    clean_sample = visible_sample[:1500].strip()
    if clean_sample:
        sections.append(f"[VISIBLE CONTENT SAMPLE]\n{clean_sample}")

    return "\n\n".join(sections)


def extract_html_features(
    html_content: Optional[str],
    base_url: Optional[str] = None,
) -> HTMLFeatures:
    """Parses HTML markup into a strongly-typed HTMLFeatures model.

    Args:
        html_content: Raw or browser-rendered HTML string.
        base_url: Optional origin URL for resolving relative action/href targets.

    Returns:
        Structured HTMLFeatures instance.
    """
    if not html_content or not isinstance(html_content, str):
        logger.debug("Empty or non-string HTML content provided.")
        return HTMLFeatures()

    # Prefer lxml parser for performance and robustness; fallback to standard html.parser
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception as parse_exc:
        logger.warning(f"lxml parser failed: {parse_exc}. Falling back to html.parser.")
        soup = BeautifulSoup(html_content, "html.parser")

    # 1. Total tag count
    all_elements = soup.find_all(True)
    total_tags = len(all_elements)

    # 2. Extract Document Title
    title_tag = soup.find("title")
    title = clean_text(title_tag.string if title_tag else None)

    # 3. Extract Meta Attributes
    meta_attributes: Dict[str, str] = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        content = meta.get("content")
        if name and content:
            meta_attributes[str(name).lower()] = clean_text(str(content))

    # 4. Extract Headings (h1 to h6)
    headings: List[HeadingItem] = []
    for level in range(1, 7):
        for h_tag in soup.find_all(f"h{level}"):
            h_text = clean_text(h_tag.get_text())
            if h_text:
                headings.append(HeadingItem(level=level, text=h_text))

    # 5. Extract Paragraphs
    paragraphs: List[str] = []
    for p_tag in soup.find_all("p"):
        p_text = clean_text(p_tag.get_text())
        if p_text and len(p_text) > 3:
            paragraphs.append(p_text)

    # 6. Extract Images and Alt Texts
    images: List[ImageSummary] = []
    alt_texts: List[str] = []
    for img in soup.find_all("img"):
        src = img.get("src")
        alt = clean_text(img.get("alt"))
        title_attr = clean_text(img.get("title"))

        resolved_src = urljoin(base_url, src) if (base_url and src) else src
        images.append(ImageSummary(src=resolved_src, alt=alt or None, title=title_attr or None))
        if alt:
            alt_texts.append(alt)

    # 7. Extract Hyperlinks
    links: List[str] = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if href and not href.startswith("javascript:") and not href.startswith("#"):
            resolved_href = urljoin(base_url, href) if base_url else href
            links.append(resolved_href)
    unique_links = list(dict.fromkeys(links))

    # 8. Extract Buttons
    buttons: List[str] = []
    for btn in soup.find_all(["button", "input"]):
        tag_name = btn.name.lower()
        if tag_name == "button":
            b_text = clean_text(btn.get_text() or btn.get("value") or btn.get("aria-label"))
            if b_text:
                buttons.append(b_text)
        elif tag_name == "input" and btn.get("type", "").lower() in {"submit", "button", "reset"}:
            b_text = clean_text(btn.get("value") or btn.get("aria-label"))
            if b_text:
                buttons.append(b_text)
    for a_btn in soup.find_all("a", role="button"):
        b_text = clean_text(a_btn.get_text())
        if b_text:
            buttons.append(b_text)
    unique_buttons = list(dict.fromkeys(buttons))

    # 9. Extract Input Fields, Placeholders & Password Inputs across entire DOM
    all_inputs: List[FormInput] = []
    placeholders: List[str] = []
    for el in soup.find_all(["input", "textarea", "select"]):
        tag_name = el.name.lower()
        inp_type = (el.get("type") or ("textarea" if tag_name == "textarea" else "text")).lower()
        inp_name = el.get("name")
        inp_id = el.get("id")
        placeholder = clean_text(el.get("placeholder"))
        is_pwd = (inp_type == "password")

        if placeholder:
            placeholders.append(placeholder)

        all_inputs.append(
            FormInput(
                input_type=inp_type,
                name=inp_name,
                id=inp_id,
                placeholder=placeholder or None,
                is_password=is_pwd,
            )
        )

    unique_placeholders = list(dict.fromkeys(placeholders))
    password_inputs = [inp for inp in all_inputs if inp.is_password]
    has_password_field = len(password_inputs) > 0

    # 10. Extract Forms & Associated Elements
    forms: List[FormSummary] = []
    for form in soup.find_all("form"):
        form_action = form.get("action")
        resolved_action = urljoin(base_url, form_action) if (base_url and form_action) else form_action
        form_method = (form.get("method") or "get").lower()
        form_id = form.get("id")
        form_name = form.get("name")

        form_child_inputs: List[FormInput] = []
        for el in form.find_all(["input", "textarea", "select"]):
            tag_name = el.name.lower()
            inp_type = (el.get("type") or ("textarea" if tag_name == "textarea" else "text")).lower()
            inp_name = el.get("name")
            inp_id = el.get("id")
            placeholder = clean_text(el.get("placeholder"))
            is_pwd = (inp_type == "password")

            form_child_inputs.append(
                FormInput(
                    input_type=inp_type,
                    name=inp_name,
                    id=inp_id,
                    placeholder=placeholder or None,
                    is_password=is_pwd,
                )
            )

        form_has_pwd = any(inp.is_password for inp in form_child_inputs)
        forms.append(
            FormSummary(
                action=resolved_action,
                method=form_method,
                id=form_id,
                name=form_name,
                inputs=form_child_inputs,
                has_password=form_has_pwd,
            )
        )

    # 11. Script, iframe, and statistical features
    script_count = len(soup.find_all("script"))
    iframe_count = len(soup.find_all("iframe"))

    # 12. Sanitized Visible Text Extraction
    # Create clone to mutate without affecting original tree
    cloned_soup = BeautifulSoup(str(soup), "lxml" if "lxml" in soup.builder.features else "html.parser")
    for element in cloned_soup(DISCARD_TAGS):
        element.decompose()
    for comment in cloned_soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()

    raw_visible = cloned_soup.body.get_text(separator=" ") if cloned_soup.body else cloned_soup.get_text(separator=" ")
    visible_text = clean_text(raw_visible)

    # 13. Build Structured SLM Text Representation
    slm_text = build_slm_structured_text(
        title=title,
        headings=headings,
        forms=forms,
        buttons=unique_buttons,
        alt_texts=list(dict.fromkeys(alt_texts)),
        placeholders=unique_placeholders,
        visible_sample=visible_text,
        meta_attributes=meta_attributes,
    )

    return HTMLFeatures(
        title=title or None,
        headings=headings,
        paragraphs=paragraphs,
        visible_text=visible_text,
        links=unique_links,
        forms=forms,
        buttons=unique_buttons,
        input_fields=all_inputs,
        password_inputs=password_inputs,
        images=images,
        alt_texts=list(dict.fromkeys(alt_texts)),
        placeholders=unique_placeholders,
        meta_attributes=meta_attributes,
        total_tags=total_tags,
        script_count=script_count,
        iframe_count=iframe_count,
        has_password_field=has_password_field,
        structured_slm_text=slm_text,
    )
