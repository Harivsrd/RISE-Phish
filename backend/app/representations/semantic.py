"""R4: Semantic representation generator.

Synthesizes structural intent, headings hierarchy, form goals, and action tokens
to represent core semantic claims made to the webpage visitor.
"""
from typing import List, Optional

from backend.app.models.schemas import HTMLFeatures, SemanticRepresentation


def build_semantic_representation(
    html_features: Optional[HTMLFeatures],
) -> SemanticRepresentation:
    """Builds R4 SemanticRepresentation from structured HTML features.

    Args:
        html_features: Processed HTMLFeatures model from Phase 2.

    Returns:
        Structured SemanticRepresentation instance.
    """
    if not html_features:
        return SemanticRepresentation()

    # Flatten headings text
    headings_text = " | ".join(h.text for h in html_features.headings)

    # Summarize form intents
    form_intents = []
    for idx, f in enumerate(html_features.forms, 1):
        pwd_note = " [Credential/Password Form]" if f.has_password else ""
        input_names = [inp.name or inp.input_type for inp in f.inputs]
        form_intents.append(
            f"Form {idx} ({f.method.upper()} -> {f.action or 'self'}): {', '.join(input_names)}{pwd_note}"
        )
    form_intent_summary = "\n".join(form_intents)

    # Action tokens (buttons, submission verbs)
    action_tokens = list(dict.fromkeys(html_features.buttons))

    return SemanticRepresentation(
        title=html_features.title,
        headings_text=headings_text,
        form_intent_summary=form_intent_summary,
        action_tokens=action_tokens,
        structured_content=html_features.structured_slm_text,
    )
