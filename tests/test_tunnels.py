import base64

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import ValidationError

from ghost_deploy.cli import main
from ghost_deploy.config import DeployConfig
from ghost_deploy.render import BundleError, render_bundle

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostDeployTestKeyOnlyForUnitTests operator@laptop"


def config(**overrides: str) -> DeployConfig:
    values: dict[str, str] = {
        "domain": "blog.example.com",
        "acme_email": "admin@example.com",
        "ssh_public_key": KEY,
        "mysql_password": "a" * 24,
        "mysql_root_password": "b" * 24,
    }
    values.update(overrides)
    return DeployConfig(**values)

TOKEN = "A" * 40
AUTH_KEY = "tskey-auth-abcdefghijklmnopqrst"


def _public(private_b64: str) -> str:
    raw = base64.b64decode(private_b64)
    key = X25519PrivateKey.from_private_bytes(raw)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public).decode("ascii")


def _value(text: str, key: str) -> str:
    prefix = f"{key} = "
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise AssertionError(key)


def test_cloudflare_keeps_the_token_out_of_the_connect_hint():
    bundle = render_bundle(config(tunnel="cloudflare", cloudflare_tunnel_token=TOKEN))
    script = bundle.files["tunnel-setup.sh"]
    assert "cloudflared service install" in script
    assert TOKEN in script
    assert TOKEN in bundle.user_data
    assert TOKEN not in bundle.files["connect.txt"]
    assert "ssh.blog.example.com" in bundle.files["connect.txt"]
    assert bundle.files["tunnel-ports.txt"] == "# no extra public ports\n"
    assert "ufw allow 22" not in script


def test_tailscale_prints_an_ssh_command_without_the_auth_key():
    bundle = render_bundle(config(tunnel="tailscale", tailscale_auth_key=AUTH_KEY))
    assert f"--auth-key={AUTH_KEY} " in bundle.files["tunnel-setup.sh"]
    assert "tailscale ssh ghostadmin@blog-example-com" in bundle.files["connect.txt"]
    assert AUTH_KEY not in bundle.files["connect.txt"]
    assert AUTH_KEY in bundle.user_data


def test_wireguard_splits_keys_and_limits_ssh_to_wg0():
    bundle = render_bundle(config(tunnel="wireguard", wireguard_endpoint="203.0.113.10:51821"))
    script = bundle.files["tunnel-setup.sh"]
    client = bundle.files["wireguard-client.conf"]
    server_private = _value(script, "PrivateKey")
    client_private = _value(client, "PrivateKey")
    assert _public(server_private) == _value(client, "PublicKey")
    assert _public(client_private) == _value(script, "PublicKey")
    assert client_private not in bundle.user_data
    assert server_private not in client
    assert "ListenAddress 10.66.0.1" in script
    assert "ufw allow in on wg0 to any port 22 proto tcp" in script
    assert "ufw allow 51821/udp" in script
    assert bundle.files["tunnel-ports.txt"] == "51821/udp\n"
    assert "ssh ghostadmin@10.66.0.1" in bundle.files["connect.txt"]
    data = yaml.safe_load(bundle.user_data.split("\n", 1)[1])
    written = {item["path"] for item in data["write_files"]}
    assert "/opt/ghost/wireguard-client.conf" not in written
    lockdown = next(
        item["content"]
        for item in data["write_files"]
        if item["path"] == "/etc/ssh/sshd_config.d/99-ghost-lockdown.conf"
    )
    assert "ListenAddress 127.0.0.1" in lockdown
    assert "10.66.0.1" not in lockdown


def test_rejects_public_ssh_and_accepts_wg0_only():
    with pytest.raises(BundleError):
        render_bundle(config(), tunnel_script="#!/bin/bash\nufw allow in on eth0 to any port 22 proto tcp\n")
    bundle = render_bundle(
        config(),
        tunnel_script="#!/bin/bash\nufw allow in on wg0 to any port 22 proto tcp\n",
    )
    assert "wg0" in bundle.files["tunnel-setup.sh"]


def test_refuses_a_built_in_tunnel_plus_a_custom_script():
    with pytest.raises(BundleError):
        render_bundle(
            config(tunnel="cloudflare", cloudflare_tunnel_token=TOKEN),
            tunnel_script="#!/bin/bash\necho hi\n",
        )


def test_requires_credentials_for_the_selected_tunnel():
    with pytest.raises(ValidationError):
        config(tunnel="cloudflare")
    with pytest.raises(ValidationError):
        config(tunnel="tailscale")
    with pytest.raises(BundleError):
        render_bundle(config(tunnel="custom"))


def test_render_command_uses_the_tunnel_from_the_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "DOMAIN=blog.example.com\n"
        "ACME_EMAIL=admin@example.com\n"
        f"SSH_PUBLIC_KEY={KEY}\n"
        "TUNNEL=tailscale\n"
        f"TAILSCALE_AUTH_KEY={AUTH_KEY}\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    code = main(["render", "--env-file", str(env), "--output", str(output)])
    assert code == 0
    connect = (output / "connect.txt").read_text(encoding="utf-8")
    assert "tailscale ssh ghostadmin@blog-example-com" in connect
    assert AUTH_KEY not in connect
    assert (output / "connect.txt").stat().st_mode & 0o777 == 0o600
