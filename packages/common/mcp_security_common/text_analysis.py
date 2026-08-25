"""Text analysis, regex extraction, homoglyph detection, and similarity calculation."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple


def detect_regex_patterns(text: str, patterns: List[str]) -> List[Tuple[str, str]]:
    """
    Evaluates a list of regex patterns against text.
    Returns list of tuples (matched_pattern, matched_text).
    """
    if not text:
        return []
    matches: List[Tuple[str, str]] = []
    for pattern in patterns:
        try:
            m = re.search(pattern, text)
            if m:
                matches.append((pattern, m.group(0)))
        except re.error:
            continue
    return matches



def extract_urls(text: str) -> List[str]:
    """Extracts all HTTP/HTTPS URLs from text."""
    if not text:
        return []
    url_pattern = r'https?://[^\s"\'<>]+'
    return re.findall(url_pattern, text)


def extract_schema_descriptions(schema: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Recursively extracts all 'description' fields from a JSON Schema tree.
    Returns list of tuples (json_path, description_text).
    """
    results: List[Tuple[str, str]] = []

    def _walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if "description" in node and isinstance(node["description"], str):
            results.append((path or "root", node["description"]))
        if "properties" in node and isinstance(node["properties"], dict):
            for prop_name, prop_val in node["properties"].items():
                _walk(prop_val, f"{path}.properties.{prop_name}" if path else f"properties.{prop_name}")
        if "items" in node and isinstance(node["items"], dict):
            _walk(node["items"], f"{path}.items" if path else "items")
        if "$defs" in node and isinstance(node["$defs"], dict):
            for def_name, def_val in node["$defs"].items():
                _walk(def_val, f"{path}.$defs.{def_name}" if path else f"$defs.{def_name}")

    _walk(schema, "")
    return results


# Common homoglyph character substitutions table for fast detection
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',  # Cyrillic
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    'I': 'l', 'l': 'I', '1': 'l', '0': 'o', 'O': '0',  # Visual confusion in ASCII/Latin
}


def normalize_homoglyphs(text: str) -> str:
    """Normalizes Unicode characters to standard NFKD form and maps known confusable glyphs to base ASCII."""
    # First apply NFKD normalization
    decomposed = unicodedata.normalize('NFKD', text)
    # Strip non-spacing marks (accents, diacritics)
    base_ascii = "".join(c for c in decomposed if not unicodedata.combining(c))
    # Apply direct glyph substitution
    result = []
    for char in base_ascii:
        result.append(HOMOGLYPH_MAP.get(char, char))
    return "".join(result)


def is_homoglyph_collision(candidate: str, target: str) -> bool:
    """
    Checks if candidate is non-identical to target in raw form but normalizes to the same base string.
    """
    if candidate == target:
        return False
    norm_cand = normalize_homoglyphs(candidate).lower()
    norm_target = normalize_homoglyphs(target).lower()
    return norm_cand == norm_target


def detect_tool_name_homoglyph(
    tool_name: str,
    standard_names: Optional[List[str]] = None,
) -> Optional[Tuple[str, str]]:
    """
    Detects if tool_name is a homoglyph variation of any standard tool name.
    Returns (standard_name, reason) if a collision is detected, else None.
    """
    default_standards = [
        "send_email",
        "execute_sql",
        "run_command",
        "read_file",
        "write_file",
        "fetch_url",
        "bash",
        "terminal",
        "deploy_app",
        "upload_file",
        "delete_file",
    ]
    standards = standard_names or default_standards

    # Check against standard names
    for std in standards:
        if is_homoglyph_collision(tool_name, std):
            return (std, f"Tool name '{tool_name}' is a Unicode homoglyph mimicking standard tool '{std}'")

    # Check for non-ASCII characters in name
    if any(ord(c) > 127 for c in tool_name):
        return ("ascii_check", f"Tool name '{tool_name}' contains non-ASCII Unicode characters")

    return None


def compute_text_similarity(text1: str, text2: str) -> float:
    """
    Computes text similarity (0.0 to 1.0) using word n-gram Jaccard index
    with deterministic fallback if scikit-learn is unavailable.
    """
    if not text1 or not text2:
        return 0.0
    if text1.strip() == text2.strip():
        return 1.0

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english')
        matrix = vectorizer.fit_transform([text1, text2])
        score = float(cosine_similarity(matrix[0:1], matrix[1:2])[0][0])
        return max(0.0, min(1.0, score))
    except Exception:
        # Fallback Jaccard token overlap
        words1 = set(re.findall(r'\w+', text1.lower()))
        words2 = set(re.findall(r'\w+', text2.lower()))
        if not words1 or not words2:
            return 0.0
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return float(intersection / union) if union > 0 else 0.0
