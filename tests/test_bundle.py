import yaml
import pytest
from pydantic import ValidationError

from ghost_deploy.cli import main
from ghost_deploy.config import DeployConfig
from ghost_deploy.render import BundleError, render_bundle

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostDeployTestKeyOnlyForUnitTests operator@laptop"


def config(**overrides: str) -> DeployConfig:
    values = {
        "domain": "blog.example.com",
        "acme_email": "admin@example.com",
        "ssh_public_key": KEY,
        "mysql_password": "a" * 24,
        "mysql_root_password": "b" * 24,
    }
    values.update(overrides)
    return DeployConfig(**values)


def test_bundle_keeps_ssh_on_localhost_and_publishes_only_caddy():
    bundle = render_bundle(config())
    compose = yaml.safe_load(bundle.files["docker-compose.yml"])
    assert "ports" not in compose["services"]["ghost"]
    assert "ports" not in compose["services"]["db"]
    assert set(compose["services"]["caddy"]["ports"]) == {"80:80", "443:443", "443:443/udp"}
    sshd = bundle.files["sshd-lockdown.conf"]
    assert "ListenAddress 127.0.0.1" in sshd
    assert "PasswordAuthentication no" in sshd
    assert "PermitRootLogin no" in sshd
    assert "AllowUsers ghostadmin" in sshd
    assert "a" * 24 not in bundle.files["docker-compose.yml"]
    assert "MYSQL_PASSWORD=" + "a" * 24 in bundle.files["ghost.env"]


def test_cloud_init_embeds_the_same_files_and_disables_ssh_passwords():
    bundle = render_bundle(config())
    text = bundle.user_data
    assert text.startswith("#cloud-config\n")
    assert len(text.encode()) < 32 * 1024
    data = yaml.safe_load(text.split("\n", 1)[1])
    assert data["ssh_pwauth"] is False
    assert data["runcmd"] == ["bash /opt/ghost/bootstrap.sh"]
    env = next(item for item in data["write_files"] if item["path"] == "/opt/ghost/ghost.env")
    assert env["permissions"] == "0600"
    assert env["content"] == bundle.files["ghost.env"]
    bootstrap = bundle.files["bootstrap.sh"]
    assert "ufw allow 22" not in bootstrap
    assert "ufw allow 80/tcp" in bootstrap
    assert "ufw allow 443/tcp" in bootstrap


def test_custom_tunnel_script_is_installed_verbatim():
    script = "#!/bin/bash\nset -euo pipefail\necho tunnel-up\n"
    bundle = render_bundle(config(), tunnel_script=script)
    assert bundle.files["tunnel-setup.sh"] == script
    data = yaml.safe_load(bundle.user_data.split("\n", 1)[1])
    written = next(item for item in data["write_files"] if item["path"].endswith("tunnel-setup.sh"))
    assert written["content"] == script
    assert written["permissions"] == "0700"


def test_tunnel_script_cannot_open_public_ssh():
    with pytest.raises(BundleError):
        render_bundle(config(), tunnel_script="#!/bin/bash\nufw allow 22/tcp\n")


def test_rejects_a_bad_domain_and_a_short_password():
    with pytest.raises(ValidationError):
        config(domain="not a domain")
    with pytest.raises(ValidationError):
        config(mysql_password="short")


def test_generates_database_passwords_when_empty():
    generated = config(mysql_password="", mysql_root_password="")
    assert len(generated.mysql_password) == 48
    assert generated.mysql_password.isalnum()
    bundle = render_bundle(generated)
    assert generated.mysql_password in bundle.files["ghost.env"]
    assert generated.mysql_password not in bundle.files["docker-compose.yml"]


def test_render_command_writes_a_private_bundle(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "DOMAIN=blog.example.com\n"
        "ACME_EMAIL=admin@example.com\n"
        f"SSH_PUBLIC_KEY={KEY}\n"
        f"MYSQL_PASSWORD={'c' * 24}\n"
        f"MYSQL_ROOT_PASSWORD={'d' * 24}\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    code = main(["render", "--env-file", str(env), "--output", str(output)])
    assert code == 0
    cloud_init = output / "cloud-init.yaml"
    assert cloud_init.read_text(encoding="utf-8").startswith("#cloud-config\n")
    assert cloud_init.stat().st_mode & 0o777 == 0o600
    assert (output / "ghost.env").stat().st_mode & 0o777 == 0o600


def test_render_command_explains_a_missing_env_file(tmp_path):
    code = main(["render", "--env-file", str(tmp_path / "missing.env"), "--output", str(tmp_path / "out")])
    assert code == 2
