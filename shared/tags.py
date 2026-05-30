"""Helpers for normalized MiniEDR tags."""

from collections.abc import Iterable

COMPANY_TAG_PREFIX = "company:"


def normalize_company(value: object) -> str:
    """Return a compact company value suitable for a normalized tag."""
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def build_company_tag(company: object) -> str:
    company_value = normalize_company(company)
    return f"{COMPANY_TAG_PREFIX}{company_value}" if company_value else ""


def extract_company_from_tags(tags: Iterable[object] | None) -> str:
    if not tags:
        return ""

    for tag in tags:
        if not isinstance(tag, str):
            continue
        normalized = tag.strip()
        if normalized.lower().startswith(COMPANY_TAG_PREFIX):
            return normalize_company(normalized[len(COMPANY_TAG_PREFIX) :])
    return ""


def merge_company_tag(tags: Iterable[object] | None, company: object) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        normalized = " ".join(tag.strip().split())
        if normalized and normalized not in seen:
            merged.append(normalized)
            seen.add(normalized)

    company_tag = build_company_tag(company)
    if company_tag and company_tag not in seen:
        merged.append(company_tag)

    return merged
