"""Tests for MCP authentication and OAuth2 token management."""

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import yaml

from mcp_scanner.auth import AuthProvider, MCPAuthConfig
from mcp_scanner.connection import HttpMCPConnection


def test_auth_config_default():
    cfg = MCPAuthConfig()
    assert cfg.auth_type == "none"
    provider = AuthProvider(cfg)


@pytest.mark.asyncio
async def test_auth_bearer_token_direct():
    cfg = MCPAuthConfig(auth_type="bearer", bearer_token="secret_token_abc")
    provider = AuthProvider(cfg)
    headers = await provider.get_auth_headers()
    assert headers == {"Authorization": "Bearer secret_token_abc"}


@pytest.mark.asyncio
async def test_auth_bearer_token_from_env(monkeypatch):
    monkeypatch.setenv("CUSTOM_TOKEN_VAR", "env_secret_999")
    cfg = MCPAuthConfig(auth_type="bearer", bearer_token_env_var="CUSTOM_TOKEN_VAR")
    provider = AuthProvider(cfg)
    headers = await provider.get_auth_headers()
    assert headers == {"Authorization": "Bearer env_secret_999"}


@pytest.mark.asyncio
async def test_auth_custom_header(monkeypatch):
    monkeypatch.setenv("MY_API_KEY", "key_12345")
    cfg = MCPAuthConfig(auth_type="header", header_name="X-API-KEY", header_value_env_var="MY_API_KEY")
    provider = AuthProvider(cfg)
    headers = await provider.get_auth_headers()
    assert headers == {"X-API-KEY": "key_12345"}


def test_auth_config_from_yaml_file():
    with TemporaryDirectory() as tmpdir:
        cfg_file = Path(tmpdir) / "auth.yaml"
        data = {
            "auth_type": "bearer",
            "bearer_token": "token_from_yaml",
        }
        cfg_file.write_text(yaml.dump(data), encoding="utf-8")

        cfg = MCPAuthConfig.from_file(cfg_file)
        assert cfg.auth_type == "bearer"
        assert cfg.bearer_token == "token_from_yaml"


def test_auth_config_from_json_file():
    with TemporaryDirectory() as tmpdir:
        cfg_file = Path(tmpdir) / "auth.json"
        data = {
            "auth_type": "bearer",
            "bearer_token": "token_from_json",
        }
        cfg_file.write_text(json.dumps(data), encoding="utf-8")

        cfg = MCPAuthConfig.from_file(cfg_file)
        assert cfg.auth_type == "bearer"
        assert cfg.bearer_token == "token_from_json"


def test_auth_config_from_env_discovery(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "auto_token_555")
    cfg = MCPAuthConfig.from_env()
    assert cfg.auth_type == "bearer"
    assert cfg.bearer_token == "auto_token_555"


@pytest.mark.asyncio
async def test_oauth2_token_grant_and_caching(monkeypatch):
    monkeypatch.setenv("OAUTH_SECRET_VAR", "mock_oauth_secret")
    cfg = MCPAuthConfig(
        auth_type="oauth2_client_credentials",
        oauth2_token_url="https://auth.example.com/oauth/token",
        oauth2_client_id="test_client",
        oauth2_client_secret_env_var="OAUTH_SECRET_VAR",
        oauth2_scopes=["mcp:read"],
    )
    provider = AuthProvider(cfg)

    # Mock the HTTP token exchange using httpx.Response
    mock_resp = httpx.Response(200, json={"access_token": "mocked_jwt_token_xyz", "expires_in": 3600})

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        headers = await provider.get_auth_headers()
        assert headers == {"Authorization": "Bearer mocked_jwt_token_xyz"}

        # Second call should use cached token without additional network request
        headers2 = await provider.get_auth_headers()
        assert headers2 == {"Authorization": "Bearer mocked_jwt_token_xyz"}
        assert mock_post.call_count == 1


@pytest.mark.asyncio
async def test_http_connection_uses_auth_provider():
    cfg = MCPAuthConfig(auth_type="bearer", bearer_token="conn_test_token")
    conn = HttpMCPConnection("http://localhost:9999", auth_config=cfg)

    mock_resp = httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        await conn.connect()
        try:
            await conn.send_request("test_method", {})
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]
            assert "headers" in call_kwargs
            assert call_kwargs["headers"] == {"Authorization": "Bearer conn_test_token"}
        finally:
            await conn.close()
