"""Coverage boost tests for Guardrail anomaly detector and pin store."""

import json
from unittest.mock import MagicMock

from mcp_guardrail.anomaly import Tier2MLAnomalyDetector
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_security_common.mcp_types import MCPTool


def test_pin_store_all_methods(tmp_path):
    pin_file = tmp_path / "custom_pins.json"
    store = SchemaPinStore(pin_file)
    store.server_name = "test_custom_server"

    tool = MCPTool(name="t1", description="desc1", inputSchema={"type": "object"})
    h = store.record_pin(tool)
    store.save()

    # Test load from existing dict in file
    reloaded = SchemaPinStore(pin_file)
    assert reloaded.server_name == "test_custom_server"
    assert reloaded.pins["t1"] == h

    # Test load from dictionary pins in file
    dict_pin_file = tmp_path / "dict_pins.json"
    dict_pin_file.write_text(
        json.dumps({"server_name": "srv", "pins": {"tool1": {"hash": "abc12345"}}}), encoding="utf-8"
    )
    dict_store = SchemaPinStore(dict_pin_file)
    assert dict_store.pins["tool1"] == "abc12345"

    # Test verify_tool
    is_valid, exp, act = reloaded.verify_tool(tool)
    assert is_valid is True
    assert exp == h

    # Mutated server tool
    mutated_tool = MCPTool(name="t1", description="mutated_desc", inputSchema={"type": "object"})
    is_valid_mut, exp_mut, act_mut = reloaded.verify_tool(mutated_tool)
    assert is_valid_mut is False
    assert exp_mut == h
    assert act_mut != exp_mut

    # Unpinned tool
    unpinned_tool = MCPTool(name="unpinned", description="desc", inputSchema={})
    is_valid_unpinned, exp_un, _ = reloaded.verify_tool(unpinned_tool)
    assert is_valid_unpinned is False
    assert exp_un is None


def test_anomaly_detector_all_onnx_and_feature_branches():
    detector = Tier2MLAnomalyDetector()

    # 1. extract_features with default arguments and varied inputs
    vec1 = detector.extract_features("normal_tool", {"a": 1, "b": 2}, description_length=100)
    assert len(vec1) == 8
    assert vec1[2] == 2.0  # arg_count

    vec2 = detector.extract_features("tool_with_url", {"url": "https://evil.com/data"}, description_length=50)
    assert len(vec2) == 8
    assert vec2[6] == 1.0  # has_url

    vec3 = detector.extract_features("tool_with_cred", {"token": "my_secret_key"}, description_length=50)
    assert len(vec3) == 8
    assert vec3[7] == 1.0  # has_cred

    # 2. ONNX prediction execution path
    if detector.is_onnx:
        is_anom, score = detector.predict_anomaly("normal_tool", {"a": 1})
        assert isinstance(is_anom, bool)
        assert isinstance(score, float)

        # Mock single output onnx response
        mock_ort = MagicMock()
        mock_ort.get_inputs.return_value = [MagicMock(name="float_input")]
        mock_ort.run.return_value = [[-0.5]]
        detector_single = Tier2MLAnomalyDetector()
        detector_single.model = mock_ort
        detector_single.is_onnx = True
        detector_single.is_active = True
        is_a, sc = detector_single.predict_anomaly("tool", {})
        assert is_a is True

    # 3. Predict anomaly when disabled
    detector.is_active = False
    assert detector.predict_anomaly("tool", {}) == (False, 0.0)
