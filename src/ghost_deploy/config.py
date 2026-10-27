import re
import secrets
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SSH_KEY = re.compile(
    r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|"
    r"ecdsa-sha2-nistp521) [A-Za-z0-9+/=]+(?: .*)?$"
)
_USER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_PASSWORD = re.compile(r"^[A-Za-z0-9]{16,128}$")
_IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[A-Za-z0-9._-]+$"
)
_TUNNELS = {"none", "cloudflare", "tailscale", "wireguard", "custom"}
_CF_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,2000}")
_TS_KEY = re.compile(r"tskey-[A-Za-z0-9_-]{10,400}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENDPOINT = re.compile(
    r"(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|\d{1,3}(?:\.\d{1,3}){3}):([1-9]\d{0,4})$"
)


class DeployConfig(BaseSettings):
    """Values that change between deployments. Secrets stay out of the compose file."""

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )

    domain: str
    acme_email: str
    ssh_public_key: str
    mysql_password: str = ""
    mysql_root_password: str = ""
    admin_user: str = "ghostadmin"
    ghost_image: str = "ghost:5-alpine"
    mysql_image: str = "mysql:8.4"
    caddy_image: str = "caddy:2-alpine"
    tunnel: str = "none"
    cloudflare_tunnel_token: str = ""
    cloudflare_ssh_hostname: str = ""
    tailscale_auth_key: str = ""
    tailscale_hostname: str = ""
    wireguard_endpoint: str = ""

    @field_validator("domain")
    @classmethod
    def check_domain(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if not _DOMAIN.fullmatch(value):
            raise ValueError("domain must be a hostname such as blog.example.com")
        return value

    @field_validator("acme_email")
    @classmethod
    def check_email(cls, value: str) -> str:
        value = value.strip()
        if not _EMAIL.fullmatch(value):
            raise ValueError("acme_email must be an email address")
        return value

    @field_validator("ssh_public_key")
    @classmethod
    def check_ssh_key(cls, value: str) -> str:
        value = value.strip()
        if not _SSH_KEY.fullmatch(value):
            raise ValueError("ssh_public_key must be a single OpenSSH public key line")
        return value

    @field_validator("admin_user")
    @classmethod
    def check_user(cls, value: str) -> str:
        if not _USER.fullmatch(value):
            raise ValueError("admin_user must be a short lowercase Linux username")
        return value

    @field_validator("mysql_password", "mysql_root_password")
    @classmethod
    def check_password(cls, value: str) -> str:
        if not value:
            return secrets.token_hex(24)
        if not _PASSWORD.fullmatch(value):
            raise ValueError("database passwords must be 16-128 letters and digits")
        return value

    @field_validator("ghost_image", "mysql_image", "caddy_image")
    @classmethod
    def check_image(cls, value: str) -> str:
        if not _IMAGE.fullmatch(value):
            raise ValueError("image must look like name:tag")
        return value

    @field_validator("tunnel")
    @classmethod
    def check_tunnel(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in _TUNNELS:
            raise ValueError("tunnel must be none, cloudflare, tailscale, wireguard, or custom")
        return value

    @field_validator("cloudflare_tunnel_token")
    @classmethod
    def check_cloudflare_token(cls, value: str) -> str:
        value = "".join(value.split())
        if value and not _CF_TOKEN.fullmatch(value):
            raise ValueError("CLOUDFLARE_TUNNEL_TOKEN must be the token from Cloudflare")
        return value

    @field_validator("tailscale_auth_key")
    @classmethod
    def check_tailscale_key(cls, value: str) -> str:
        value = value.strip()
        if value and not _TS_KEY.fullmatch(value):
            raise ValueError("TAILSCALE_AUTH_KEY must be a tskey-auth key")
        return value

    @field_validator("cloudflare_ssh_hostname")
    @classmethod
    def check_cloudflare_hostname(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if value and not _DOMAIN.fullmatch(value):
            raise ValueError("CLOUDFLARE_SSH_HOSTNAME must be a hostname")
        return value

    @field_validator("tailscale_hostname")
    @classmethod
    def check_tailscale_hostname(cls, value: str) -> str:
        value = value.strip().lower()
        if value and not _LABEL.fullmatch(value):
            raise ValueError("TAILSCALE_HOSTNAME must be a single DNS label")
        return value

    @field_validator("wireguard_endpoint")
    @classmethod
    def check_wireguard_endpoint(cls, value: str) -> str:
        value = value.strip().lower()
        if not value:
            return ""
        match = _ENDPOINT.fullmatch(value)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("WIREGUARD_ENDPOINT must look like blog.example.com:51820")
        return value

    @model_validator(mode="after")
    def require_tunnel_credentials(self) -> "DeployConfig":
        if self.tunnel == "cloudflare" and not self.cloudflare_tunnel_token:
            raise ValueError("CLOUDFLARE_TUNNEL_TOKEN is required when TUNNEL=cloudflare")
        if self.tunnel == "tailscale" and not self.tailscale_auth_key:
            raise ValueError("TAILSCALE_AUTH_KEY is required when TUNNEL=tailscale")
        return self


def load_config(env_file: Path | None) -> DeployConfig:
    if env_file is None:
        return DeployConfig()
    if not env_file.is_file():
        raise FileNotFoundError(env_file)
    return DeployConfig(_env_file=env_file)
