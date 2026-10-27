import json
import urllib.parse

import pytest
from pydantic import ValidationError

from ghost_deploy.cli import main
from ghost_deploy.config import DeployConfig
from ghost_deploy.hetzner import Hetzner, HetznerError, deploy_host, destroy_host, opens_ssh, port_covers_22, verify_host

TOKEN = "hcloud-test-token-value"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostDeployTestKeyOnlyForUnitTests operator@laptop"


def config(**overrides: str) -> DeployConfig:
    values: dict[str, str] = {
        "domain": "blog.example.com",
        "acme_email": "admin@example.com",
        "ssh_public_key": KEY,
        "mysql_password": "a" * 24,
        "mysql_root_password": "b" * 24,
        "hetzner_api_token": TOKEN,
    }
    values.update(overrides)
    return DeployConfig(**values)


class FakeCloud:
    def __init__(self) -> None:
        self.servers: dict[int, dict] = {}
        self.firewalls: dict[int, dict] = {}
        self.calls: list[tuple[str, str, dict, bytes | None]] = []
        self._seq = 1

    def send(self, method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
        self.calls.append((method, url, headers, body))
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path.removeprefix("/v1")
        query = urllib.parse.parse_qs(parsed.query)
        payload = json.loads(body) if body else None
        status, data = self._route(method, path, query, payload)
        return status, b"" if data is None else json.dumps(data).encode()

    def client(self) -> Hetzner:
        return Hetzner(TOKEN, transport=self)

    def posted(self, path: str) -> list[dict]:
        found = []
        for method, url, _headers, body in self.calls:
            if method == "POST" and urllib.parse.urlsplit(url).path == path and body:
                found.append(json.loads(body))
        return found

    def _route(self, method: str, path: str, query: dict, payload: dict | None) -> tuple[int, dict | None]:
        if method == "GET" and path == "/servers":
            return self._named("/servers", "servers", query)
        if method == "GET" and path == "/firewalls":
            return self._named("/firewalls", "firewalls", query)
        if method == "POST" and path == "/firewalls":
            assert payload is not None
            firewall = {
                "id": self._next(),
                "name": payload["name"],
                "rules": payload["rules"],
                "applied_to": [],
            }
            self.firewalls[firewall["id"]] = firewall
            return 200, {"firewall": firewall}
        if method == "POST" and path == "/servers":
            assert payload is not None
            firewall_id = payload["firewalls"][0]["firewall"]
            server = {
                "id": self._next(),
                "name": payload["name"],
                "status": "running",
                "public_net": {"ipv4": {"ip": "203.0.113.10"}},
            }
            self.servers[server["id"]] = server
            self.firewalls[firewall_id]["applied_to"].append(
                {"type": "server", "server": {"id": server["id"]}}
            )
            return 200, {"server": server}
        if method == "GET" and path.startswith("/servers/"):
            server = self.servers.get(int(path.rsplit("/", 1)[1]))
            if server is None:
                return 404, {"error": {"message": "not found"}}
            return 200, {"server": server}
        if method == "DELETE" and path.startswith("/servers/"):
            server_id = int(path.rsplit("/", 1)[1])
            self.servers.pop(server_id)
            for firewall in self.firewalls.values():
                firewall["applied_to"] = [
                    item for item in firewall["applied_to"] if item["server"]["id"] != server_id
                ]
            return 200, {"action": {"command": "delete_server"}}
        if method == "DELETE" and path.startswith("/firewalls/"):
            firewall_id = int(path.rsplit("/", 1)[1])
            firewall = self.firewalls[firewall_id]
            if firewall["applied_to"]:
                return 409, {"error": {"message": "firewall in use"}}
            self.firewalls.pop(firewall_id)
            return 204, None
        raise AssertionError(f"unexpected {method} {path}")

    def _named(self, path: str, key: str, query: dict) -> tuple[int, dict]:
        name = query["name"][0]
        source = self.servers if path == "/servers" else self.firewalls
        items = [item for item in source.values() if item["name"] == name]
        return 200, {key: items, "meta": {"pagination": {"next_page": None}}}

    def _next(self) -> int:
        value = self._seq
        self._seq += 1
        return value


def _noop_sleep(_seconds: float) -> None:
    return None


def _ports_open(_ip: str, port: int) -> bool:
    return port != 22


def test_port_range_that_includes_ssh_is_rejected():
    assert port_covers_22("22")
    assert port_covers_22("20-25")
    assert not port_covers_22("80")
    assert not port_covers_22("443")


def test_deploy_attaches_a_firewall_without_ssh_before_the_server_exists(tmp_path):
    cloud = FakeCloud()
    host = deploy_host(config(), tmp_path, None, cloud.client(), sleep=_noop_sleep, attempts=3)
    posts = [(method, urllib.parse.urlsplit(url).path) for method, url, _headers, _body in cloud.calls if method == "POST"]
    assert posts == [("POST", "/v1/firewalls"), ("POST", "/v1/servers")]
    server = cloud.posted("/v1/servers")[0]
    firewall = cloud.posted("/v1/firewalls")[0]
    assert "ssh_keys" not in server
    assert server["firewalls"] == [{"firewall": host.firewall_id}]
    assert server["user_data"].startswith("#cloud-config\n")
    assert TOKEN not in server["user_data"]
    assert server["image"] == "ubuntu-24.04"
    assert server["location"] == "fsn1"
    assert not opens_ssh(firewall["rules"])
    assert {rule.get("port") for rule in firewall["rules"]} >= {"80", "443"}
    assert host.ipv4 == "203.0.113.10"
    assert host.created is True
    assert (tmp_path / "cloud-init.yaml").is_file()


def test_wireguard_opens_udp_and_still_omits_ssh(tmp_path):
    cloud = FakeCloud()
    deploy_host(config(tunnel="wireguard"), tmp_path, None, cloud.client(), sleep=_noop_sleep, attempts=3)
    rules = cloud.posted("/v1/firewalls")[0]["rules"]
    assert any(rule["protocol"] == "udp" and rule["port"] == "51820" for rule in rules)
    assert not opens_ssh(rules)


def test_deploy_again_does_not_create_a_second_server(tmp_path):
    cloud = FakeCloud()
    client = cloud.client()
    first = deploy_host(config(), tmp_path, None, client, sleep=_noop_sleep, attempts=3)
    second = deploy_host(config(), tmp_path, None, client, sleep=_noop_sleep, attempts=3)
    assert first.server_id == second.server_id
    assert second.created is False
    assert len(cloud.posted("/v1/servers")) == 1


def test_existing_firewall_that_exposes_ssh_blocks_deploy(tmp_path):
    cloud = FakeCloud()
    cloud.firewalls[1] = {
        "id": 1,
        "name": "ghost-blog-example-com",
        "rules": [{"direction": "in", "protocol": "tcp", "port": "22", "source_ips": ["0.0.0.0/0", "::/0"]}],
        "applied_to": [],
    }
    cloud._seq = 2
    with pytest.raises(HetznerError, match="exposes SSH"):
        deploy_host(config(), tmp_path, None, cloud.client(), sleep=_noop_sleep, attempts=3)
    assert cloud.servers == {}


def test_verify_accepts_a_closed_ssh_port_and_open_web_ports(tmp_path):
    cloud = FakeCloud()
    client = cloud.client()
    deploy_host(config(tunnel="wireguard"), tmp_path, None, client, sleep=_noop_sleep, attempts=3)
    host = verify_host(config(), client, probe=_ports_open, extra=[("udp", "51820")])
    assert host.ipv4 == "203.0.113.10"
    with pytest.raises(HetznerError, match="22 accepts"):
        verify_host(config(), client, probe=lambda _ip, _port: True)


def test_destroy_removes_the_server_before_the_firewall(tmp_path):
    cloud = FakeCloud()
    client = cloud.client()
    deploy_host(config(), tmp_path, None, client, sleep=_noop_sleep, attempts=3)
    result = destroy_host(config(), client, sleep=_noop_sleep, attempts=3)
    assert result.deleted_server is True
    assert result.deleted_firewall is True
    assert cloud.servers == {}
    assert cloud.firewalls == {}
    deletes = [urllib.parse.urlsplit(url).path for method, url, _headers, _body in cloud.calls if method == "DELETE"]
    assert deletes == ["/v1/servers/2", "/v1/firewalls/1"]
    again = destroy_host(config(), client, sleep=_noop_sleep, attempts=3)
    assert again.deleted_server is False
    assert again.deleted_firewall is False


def test_deploy_command_prints_the_address(tmp_path, capsys, monkeypatch):
    for name in (
        "DOMAIN",
        "ACME_EMAIL",
        "SSH_PUBLIC_KEY",
        "HETZNER_API_TOKEN",
        "HETZNER_SERVER_TYPE",
        "HETZNER_IMAGE",
        "HETZNER_LOCATION",
        "HETZNER_NAME",
        "TUNNEL",
        "MYSQL_PASSWORD",
        "MYSQL_ROOT_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text(
        "DOMAIN=blog.example.com\n"
        "ACME_EMAIL=admin@example.com\n"
        f"SSH_PUBLIC_KEY={KEY}\n"
        f"MYSQL_PASSWORD={'c' * 24}\n"
        f"MYSQL_ROOT_PASSWORD={'d' * 24}\n"
        f"HETZNER_API_TOKEN={TOKEN}\n",
        encoding="utf-8",
    )
    code = main(
        ["deploy", "--env-file", str(env), "--output", str(tmp_path / "out")],
        transport=FakeCloud(),
    )
    assert code == 0
    output = capsys.readouterr().out
    assert "ipv4 203.0.113.10" in output
    assert "https://blog.example.com" in output
    assert TOKEN not in output


def test_rejects_a_token_that_breaks_the_header():
    with pytest.raises(ValidationError):
        config(hetzner_api_token="token with spaces")
