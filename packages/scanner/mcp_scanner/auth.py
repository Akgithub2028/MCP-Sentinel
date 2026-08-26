"""Authentication and OAuth 2.0 token management for MCP server connections."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)


@dataclass
class MCPAuthConfig:
    """Authentication configuration for MCP connections."""

    auth_type: str = "none"  # "none" | "bearer" | "oauth2_client_credentials" | "header"

    # Bearer token settings
    bearer_token: str | None = None
    bearer_token_env_var: str | None = None  # e.g., "MCP_AUTH_TOKEN"

    # OAuth2 Client Credentials settings
    oauth2_token_url: str | None = None
    oauth2_client_id: str | None = None
    oauth2_client_secret: str | None = None
    oauth2_client_secret_env_var: str | None = None
    oauth2_scopes: list[str] = field(default_factory=list)

    # Custom Header settings
    header_name: str | None = None
    header_value: str | None = None
    header_value_env_var: str | None = None

    @classmethod
    def from_file(cls, path: Path | str) -> MCPAuthConfig:
        """Loads auth config from a YAML or JSON file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Auth config file not found: {file_path}")

        content = file_path.read_text(encoding="utf-8")
        if file_path.suffix.lower() == ".json":
            raw_data = json.loads(content)
        else:
            raw_data = yaml.safe_load(content)

        return cls.from_dict(raw_data or {})

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPAuthConfig:
        return cls(
            auth_type=data.get("auth_type", "none").lower(),
            bearer_token=data.get("bearer_token"),
            bearer_token_env_var=data.get("bearer_token_env_var"),
            oauth2_token_url=data.get("oauth2_token_url"),
            oauth2_client_id=data.get("oauth2_client_id"),
            oauth2_client_secret=data.get("oauth2_client_secret"),
            oauth2_client_secret_env_var=data.get("oauth2_client_secret_env_var"),
            oauth2_scopes=list(data.get("oauth2_scopes", [])),
            header_name=data.get("header_name"),
            header_value=data.get("header_value"),
            header_value_env_var=data.get("header_value_env_var"),
        )

    @classmethod
    def from_env(cls) -> MCPAuthConfig:
        """Auto-discovers auth configuration from standard environment variables."""
        if "MCP_AUTH_TOKEN" in os.environ:
            return cls(auth_type="bearer", bearer_token=os.environ["MCP_AUTH_TOKEN"])
        elif "MCP_OAUTH_TOKEN_URL" in os.environ and "MCP_OAUTH_CLIENT_ID" in os.environ:
            return cls(
                auth_type="oauth2_client_credentials",
                oauth2_token_url=os.environ["MCP_OAUTH_TOKEN_URL"],
                oauth2_client_id=os.environ["MCP_OAUTH_CLIENT_ID"],
                oauth2_client_secret_env_var="MCP_OAUTH_CLIENT_SECRET",
            )
        return cls(auth_type="none")


class AuthProvider:
    """Resolves authentication configuration to HTTP headers, handling token grants and caching."""

    def __init__(self, config: MCPAuthConfig | None = None):
        self.config = config or MCPAuthConfig(auth_type="none")
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0

    async def get_auth_headers(self) -> dict[str, str]:
        """Resolves active auth configuration to HTTP headers."""
        auth_type = self.config.auth_type.lower()

        if auth_type == "bearer":
            token = self._resolve_bearer_token()
            if token:
                return {"Authorization": f"Bearer {token}"}
            return {}

        elif auth_type == "oauth2_client_credentials":
            token = await self._get_or_fetch_oauth2_token()
            if token:
                return {"Authorization": f"Bearer {token}"}
            return {}

        elif auth_type == "header":
            header_name = self.config.header_name
            header_val = self._resolve_header_value()
            if header_name and header_val:
                return {header_name: header_val}
            return {}

        return {}

    def _resolve_bearer_token(self) -> str | None:
        if self.config.bearer_token:
            return self.config.bearer_token
        if self.config.bearer_token_env_var and self.config.bearer_token_env_var in os.environ:
            return os.environ[self.config.bearer_token_env_var]
        return None

    def _resolve_header_value(self) -> str | None:
        if self.config.header_value:
            return self.config.header_value
        if self.config.header_value_env_var and self.config.header_value_env_var in os.environ:
            return os.environ[self.config.header_value_env_var]
        return None

    def _resolve_client_secret(self) -> str | None:
        if self.config.oauth2_client_secret:
            return self.config.oauth2_client_secret
        if self.config.oauth2_client_secret_env_var and self.config.oauth2_client_secret_env_var in os.environ:
            return os.environ[self.config.oauth2_client_secret_env_var]
        return None

    async def _get_or_fetch_oauth2_token(self) -> str | None:
        now = time.time()
        # Return cached token if valid with at least 30s buffer
        if self._cached_token and now < (self._token_expires_at - 30.0):
            return self._cached_token

        if not self.config.oauth2_token_url or not self.config.oauth2_client_id:
            logger.warning("OAuth2 configuration missing token_url or client_id")
            return None

        client_secret = self._resolve_client_secret()
        if not client_secret:
            logger.warning("OAuth2 client secret not found in config or environment")
            return None

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.config.oauth2_client_id,
            "client_secret": client_secret,
        }
        if self.config.oauth2_scopes:
            payload["scope"] = " ".join(self.config.oauth2_scopes)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.config.oauth2_token_url, data=payload)
                if resp.status_code != 200:
                    logger.error("OAuth2 token grant failed with status %d: %s", resp.status_code, resp.text)
                    return None

                data = resp.json()
                access_token = data.get("access_token")
                expires_in = float(data.get("expires_in", 3600))

                self._cached_token = access_token
                self._token_expires_at = now + expires_in
                return access_token
        except Exception as e:
            logger.error("OAuth2 token request exception: %s", e)
            return None
