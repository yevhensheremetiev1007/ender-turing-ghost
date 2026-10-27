import re
import secrets
from pathlib import Path

from pydantic import field_validator
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


def load_config(env_file: Path | None) -> DeployConfig:
    if env_file is None:
        return DeployConfig()
    if not env_file.is_file():
        raise FileNotFoundError(env_file)
    return DeployConfig(_env_file=env_file)
