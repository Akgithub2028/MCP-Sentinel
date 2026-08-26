"""Deep edge case tests for common text analysis, rules parser, and reporting."""

import pytest

from mcp_security_common.rules_engine import RuleDefinition, load_rules
from mcp_security_common.text_analysis import (
    compute_text_similarity,
    detect_regex_patterns,
    detect_tool_name_homoglyph,
    extract_schema_descriptions,
    is_homoglyph_collision,
    normalize_homoglyphs,
)


def test_text_analysis_deep_branches():
    # 1. normalize_homoglyphs with mixed and non-homoglyph chars
    assert normalize_homoglyphs("clean_string") == "clean_string"
    assert normalize_homoglyphs("send_em\u0430il") == "send_email"
    assert normalize_homoglyphs("") == ""

    # 2. is_homoglyph_collision
    assert is_homoglyph_collision("send_em\u0430il", "send_email") is True
    assert is_homoglyph_collision("read_file", "send_email") is False
    assert is_homoglyph_collision("different_length", "diff") is False

    # 3. detect_tool_name_homoglyph with non-ASCII char
    res = detect_tool_name_homoglyph("execute_sql\u200b")
    assert res is not None

    # 4. compute_text_similarity fallback without sklearn or empty
    assert compute_text_similarity("word1 word2", "word1 word2") == 1.0
    assert compute_text_similarity("only1", "only2") == 0.0

    # Test Jaccard fallback exception branch
    from unittest.mock import patch

    with patch("sklearn.feature_extraction.text.TfidfVectorizer", side_effect=ImportError("mocked missing sklearn")):
        sim_fallback = compute_text_similarity("apple banana cherry", "apple banana date")
        assert 0.4 < sim_fallback < 0.6
        assert compute_text_similarity("!!!", "???") == 0.0

    # Test invalid regex handling
    assert detect_regex_patterns("test text", ["[unclosed"]) == []

    # 5. extract_schema_descriptions on empty / non-dict schema
    assert extract_schema_descriptions({}) == []
    assert extract_schema_descriptions(None) == []  # type: ignore


def test_rules_engine_invalid_yaml(tmp_path):
    bad_rule_file = tmp_path / "bad_rule.yml"
    bad_rule_file.write_text("invalid: yaml: content: [unclosed", encoding="utf-8")
    rules = load_rules(tmp_path)
    assert len(rules) == 0

    non_dict_rule = tmp_path / "non_dict.yml"
    non_dict_rule.write_text("plain string\n", encoding="utf-8")
    with pytest.raises(Exception):
        RuleDefinition.from_file(non_dict_rule)
