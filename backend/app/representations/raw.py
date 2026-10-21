"""R1: Raw representation generator.

Preserves exact raw text and code points extracted from the rendered webpage
without any normalization, entity decoding, or filtering.
"""
from backend.app.models.schemas import RawRepresentation


def build_raw_representation(
    raw_text: str,
    source_type: str = "dom_text_nodes",
) -> RawRepresentation:
    """Builds an immutable R1 RawRepresentation preserving exact code points.

    Args:
        raw_text: Exact string content from DOM text nodes or visible elements.
        source_type: Descriptor of origin source.

    Returns:
        Structured RawRepresentation instance.
    """
    safe_text = raw_text or ""
    return RawRepresentation(
        text=safe_text,
        character_count=len(safe_text),
        source_type=source_type,
    )
