"""Build the files a fresh Ubuntu host needs to boot Ghost."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ghost_deploy.config import DeployConfig

HETZNER_USER_DATA_LIMIT = 32 * 1024
GHOST_ROOT = "/opt/ghost"

DEFAULT_TUNNEL_SCRIPT = """#!/bin/bash
set -euo pipefail
# SSH is already bound to 127.0.0.1:22.
# Replace this script with a tunnel client to reach that port.
exit 0
"""

_DANGEROUS_TUNNEL = (
    re.compile(r"ufw\s+allow\b.*\b(?:22|openssh)\b", re.IGNORECASE),
    re.compile(r"iptables\b.*\b22\b.*\bACCEPT\b", re.IGNORECASE),
    re.compile(r"ListenAddress\s+(?:0\.0\.0\.0|::)"),
    re.compile(r"PasswordAuthentication\s+yes", re.IGNORECASE),
    re.compile(r"PermitRootLogin\s+(?:yes|without-password|prohibit-password)", re.IGNORECASE),
)

_ALLOWED_CADDY_PORTS = {"80:80", "443:443", "443:443/udp"}


class BundleError(ValueError):
    """The rendered bundle would expose SSH or the database."""


@dataclass(frozen=True)
class Bundle:
    files: dict[str, str]

    @property
    def user_data(self) -> str:
        return self.files["cloud-init.yaml"]


def render_bundle(config: DeployConfig, tunnel_script: str | None = None) -> Bundle:
    script = DEFAULT_TUNNEL_SCRIPT if tunnel_script is None else tunnel_script
    _reject_dangerous_tunnel(script)
    files = {
        "docker-compose.yml": _compose(config),
        "Caddyfile": _caddyfile(config),
        "ghost.env": _env_file(config),
        "sshd-lockdown.conf": _sshd(config),
        "tunnel-setup.sh": _ensure_trailing_newline(script.strip() + "\n"),
        "bootstrap.sh": _bootstrap(config),
    }
    files["cloud-init.yaml"] = _cloud_init(config, files)
    bundle = Bundle(files)
    check_bundle(bundle, config)
    return bundle


def write_bundle(bundle: Bundle, output: Path) -> None:
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in bundle.files.items():
        if "/" in name or name.startswith("."):
            raise BundleError(f"refusing to write {name}")
        path = output / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)


def check_bundle(bundle: Bundle, config: DeployConfig) -> None:
    compose_text = bundle.files["docker-compose.yml"]
    if config.mysql_password in compose_text or config.mysql_root_password in compose_text:
        raise BundleError("database password is baked into the compose file")
    _check_compose(compose_text, config)
    _check_caddy(bundle.files["Caddyfile"], config)
    _check_env(bundle.files["ghost.env"], config)
    _check_sshd(bundle.files["sshd-lockdown.conf"], config.admin_user)
    _check_bootstrap(bundle.files["bootstrap.sh"])
    _check_cloud_init(bundle.user_data, bundle, config)


def _compose(config: DeployConfig) -> str:
    document = {
        "name": "ghost",
        "services": {
            "ghost": {
                "image": config.ghost_image,
                "restart": "unless-stopped",
                "depends_on": {"db": {"condition": "service_healthy"}},
                "environment": {
                    "database__client": "mysql",
                    "database__connection__host": "db",
                    "database__connection__user": "ghost",
                    "database__connection__password": "${MYSQL_PASSWORD}",
                    "database__connection__database": "ghost",
                    "database__connection__port": "3306",
                    "url": f"https://{config.domain}",
                },
                "volumes": ["ghost_content:/var/lib/ghost/content"],
            },
            "db": {
                "image": config.mysql_image,
                "restart": "unless-stopped",
                "environment": {
                    "MYSQL_DATABASE": "ghost",
                    "MYSQL_USER": "ghost",
                    "MYSQL_PASSWORD": "${MYSQL_PASSWORD}",
                    "MYSQL_ROOT_PASSWORD": "${MYSQL_ROOT_PASSWORD}",
                },
                "volumes": ["ghost_db:/var/lib/mysql"],
                "healthcheck": {
                    "test": ["CMD", "mysqladmin", "ping", "-h", "localhost"],
                    "interval": "5s",
                    "timeout": "5s",
                    "retries": 30,
                    "start_period": "20s",
                },
            },
            "caddy": {
                "image": config.caddy_image,
                "restart": "unless-stopped",
                "depends_on": ["ghost"],
                "ports": ["80:80", "443:443", "443:443/udp"],
                "volumes": [
                    f"{GHOST_ROOT}/Caddyfile:/etc/caddy/Caddyfile:ro",
                    "caddy_data:/data",
                    "caddy_config:/config",
                ],
            },
        },
        "volumes": {
            "ghost_content": None,
            "ghost_db": None,
            "caddy_data": None,
            "caddy_config": None,
        },
    }
    return _dump(document)


def _caddyfile(config: DeployConfig) -> str:
    return (
        "{\n"
        f"\temail {config.acme_email}\n"
        "}\n\n"
        f"{config.domain} {{\n"
        "\treverse_proxy ghost:2368\n"
        "}\n"
    )


def _env_file(config: DeployConfig) -> str:
    return (
        f"MYSQL_PASSWORD={config.mysql_password}\n"
        f"MYSQL_ROOT_PASSWORD={config.mysql_root_password}\n"
        f"DOMAIN={config.domain}\n"
    )


def _sshd(config: DeployConfig) -> str:
    return (
        "ListenAddress 127.0.0.1\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        f"AllowUsers {config.admin_user}\n"
    )


def _bootstrap(config: DeployConfig) -> str:
    return f"""#!/bin/bash
set -euo pipefail
umask 077
exec >>/var/log/ghost-bootstrap.log 2>&1
echo "bootstrap start $(date -Is)"
chmod 0600 {GHOST_ROOT}/ghost.env
chmod 0700 {GHOST_ROOT}/tunnel-setup.sh
usermod -aG docker {config.admin_user}
systemctl enable --now docker
for _ in 1 2 3 4 5 6 7 8 9 10; do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
systemctl reload ssh || systemctl restart ssh
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
docker compose --env-file {GHOST_ROOT}/ghost.env -f {GHOST_ROOT}/docker-compose.yml up -d
bash {GHOST_ROOT}/tunnel-setup.sh
echo "bootstrap done $(date -Is)"
"""


def _cloud_init(config: DeployConfig, files: dict[str, str]) -> str:
    write_files = [
        _write_file(f"{GHOST_ROOT}/docker-compose.yml", files["docker-compose.yml"], "0644"),
        _write_file(f"{GHOST_ROOT}/Caddyfile", files["Caddyfile"], "0644"),
        _write_file(f"{GHOST_ROOT}/ghost.env", files["ghost.env"], "0600"),
        _write_file(f"{GHOST_ROOT}/bootstrap.sh", files["bootstrap.sh"], "0700"),
        _write_file(f"{GHOST_ROOT}/tunnel-setup.sh", files["tunnel-setup.sh"], "0700"),
        _write_file(
            "/etc/ssh/sshd_config.d/99-ghost-lockdown.conf",
            files["sshd-lockdown.conf"],
            "0644",
        ),
    ]
    document = {
        "ssh_pwauth": False,
        "package_update": True,
        "packages": [
            "ca-certificates",
            "curl",
            "docker.io",
            "docker-compose-v2",
            "openssh-server",
            "ufw",
        ],
        "users": [
            {
                "name": config.admin_user,
                "shell": "/bin/bash",
                "lock_passwd": True,
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "ssh_authorized_keys": [config.ssh_public_key],
            }
        ],
        "write_files": write_files,
        "runcmd": [f"bash {GHOST_ROOT}/bootstrap.sh"],
    }
    text = "#cloud-config\n" + _dump(document)
    if len(text.encode()) > HETZNER_USER_DATA_LIMIT:
        raise BundleError("cloud-init exceeds the Hetzner user_data limit of 32 KiB")
    return text


def _write_file(path: str, content: str, permissions: str) -> dict[str, str]:
    return {
        "path": path,
        "permissions": permissions,
        "content": content,
    }


def _check_compose(text: str, config: DeployConfig) -> None:
    data = yaml.safe_load(text)
    services = data["services"]
    for name in ("ghost", "db", "caddy"):
        if name not in services:
            raise BundleError(f"compose is missing the {name} service")
    for name in ("ghost", "db"):
        if services[name].get("ports"):
            raise BundleError(f"{name} publishes host ports")
    ports = {str(item) for item in services["caddy"].get("ports", [])}
    if ports != _ALLOWED_CADDY_PORTS:
        raise BundleError(f"caddy ports must be {_ALLOWED_CADDY_PORTS}, got {ports}")
    url = services["ghost"]["environment"]["url"]
    if url != f"https://{config.domain}":
        raise BundleError("ghost url does not match the configured domain")


def _check_caddy(text: str, config: DeployConfig) -> None:
    if config.domain not in text or "reverse_proxy ghost:2368" not in text:
        raise BundleError("Caddyfile does not proxy the domain to Ghost")
    if config.acme_email not in text:
        raise BundleError("Caddyfile is missing the ACME email")


def _check_env(text: str, config: DeployConfig) -> None:
    values = dict(
        line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#")
    )
    if values.get("MYSQL_PASSWORD") != config.mysql_password:
        raise BundleError("ghost.env is missing the database password")
    if values.get("MYSQL_ROOT_PASSWORD") != config.mysql_root_password:
        raise BundleError("ghost.env is missing the database root password")


def _check_sshd(text: str, admin_user: str) -> None:
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    required = {
        "ListenAddress 127.0.0.1",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin no",
        "PubkeyAuthentication yes",
        f"AllowUsers {admin_user}",
    }
    missing = required.difference(lines)
    if missing:
        raise BundleError(f"sshd drop-in is missing {', '.join(sorted(missing))}")
    for line in lines:
        if line.startswith("ListenAddress ") and line != "ListenAddress 127.0.0.1":
            raise BundleError(f"sshd listens outside localhost: {line}")
        if line.startswith("PasswordAuthentication ") and not line.endswith(" no"):
            raise BundleError(line)
        if line.startswith("PermitRootLogin ") and line != "PermitRootLogin no":
            raise BundleError(line)


def _check_bootstrap(text: str) -> None:
    required = (
        "ufw default deny incoming",
        "ufw allow 80/tcp",
        "ufw allow 443/tcp",
        "ufw --force enable",
        f"bash {GHOST_ROOT}/tunnel-setup.sh",
    )
    for line in required:
        if line not in text:
            raise BundleError(f"bootstrap is missing {line}")
    _reject_dangerous_tunnel(text)


def _check_cloud_init(text: str, bundle: Bundle, config: DeployConfig) -> None:
    if not text.startswith("#cloud-config\n"):
        raise BundleError("user data must start with #cloud-config")
    data = yaml.safe_load(text.split("\n", 1)[1])
    if data.get("ssh_pwauth") is not False:
        raise BundleError("cloud-init allows SSH passwords")
    packages = set(data.get("packages", []))
    for package in ("docker.io", "docker-compose-v2", "ufw", "openssh-server"):
        if package not in packages:
            raise BundleError(f"cloud-init does not install {package}")
    users = data.get("users") or []
    if len(users) != 1 or users[0].get("name") != config.admin_user:
        raise BundleError("cloud-init creates an unexpected user")
    if users[0].get("lock_passwd") is not True:
        raise BundleError("admin account keeps a password")
    if users[0].get("ssh_authorized_keys") != [config.ssh_public_key]:
        raise BundleError("admin authorized keys do not match the configured key")
    written = {item["path"]: item for item in data.get("write_files", [])}
    expected = {
        f"{GHOST_ROOT}/docker-compose.yml": ("docker-compose.yml", "0644"),
        f"{GHOST_ROOT}/Caddyfile": ("Caddyfile", "0644"),
        f"{GHOST_ROOT}/ghost.env": ("ghost.env", "0600"),
        f"{GHOST_ROOT}/bootstrap.sh": ("bootstrap.sh", "0700"),
        f"{GHOST_ROOT}/tunnel-setup.sh": ("tunnel-setup.sh", "0700"),
        "/etc/ssh/sshd_config.d/99-ghost-lockdown.conf": ("sshd-lockdown.conf", "0644"),
    }
    for path, (name, mode) in expected.items():
        item = written.get(path)
        if item is None:
            raise BundleError(f"cloud-init does not write {path}")
        if str(item.get("permissions")) != mode:
            raise BundleError(f"{path} permissions are {item.get('permissions')}, expected {mode}")
        if item.get("content") != bundle.files[name]:
            raise BundleError(f"cloud-init changed the contents of {name}")
    if data.get("runcmd") != [f"bash {GHOST_ROOT}/bootstrap.sh"]:
        raise BundleError("cloud-init does not run the bootstrap script")


def _reject_dangerous_tunnel(script: str) -> None:
    if "\x00" in script:
        raise BundleError("tunnel script contains a NUL byte")
    for pattern in _DANGEROUS_TUNNEL:
        if pattern.search(script):
            raise BundleError(
                "tunnel script would open public SSH or weaken sshd; "
                "forward to 127.0.0.1:22 instead"
            )


def _ensure_trailing_newline(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


class _Dumper(yaml.SafeDumper):
    pass


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.nodes.ScalarNode:
    style = None
    if "\n" in data:
        style = "|"
    elif re.fullmatch(r"0\d+", data):
        style = "'"
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


def _represent_none(dumper: yaml.SafeDumper, _data: None) -> yaml.nodes.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:null", "")


_Dumper.add_representer(str, _represent_str)
_Dumper.add_representer(type(None), _represent_none)


def _dump(document: dict) -> str:
    return yaml.dump(document, Dumper=_Dumper, sort_keys=False, allow_unicode=True)
