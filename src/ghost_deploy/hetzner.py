"""Create a Hetzner server that is born behind a firewall with no SSH rule."""

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ghost_deploy.config import DeployConfig, _HCLOUD_NAME
from ghost_deploy.render import HETZNER_USER_DATA_LIMIT, Bundle, render_bundle, write_bundle

API_ROOT = "https://api.hetzner.cloud/v1"
_WORLD = ["0.0.0.0/0", "::/0"]


class HetznerError(RuntimeError):
    """The Cloud API call or the firewall policy cannot proceed."""


class Transport(Protocol):
    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]: ...


class UrllibTransport:
    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            raise HetznerError(f"Hetzner API is unreachable: {exc.reason}") from exc


class Hetzner:
    def __init__(
        self,
        token: str,
        transport: Transport | None = None,
        base_url: str = API_ROOT,
    ) -> None:
        self._token = token
        self._transport = transport or UrllibTransport()
        self._base_url = base_url.rstrip("/")

    def find_server(self, name: str) -> dict | None:
        return _only(self._list("servers", name), name, "server")

    def find_firewall(self, name: str) -> dict | None:
        return _only(self._list("firewalls", name), name, "firewall")

    def create_firewall(self, name: str, rules: list[dict]) -> dict:
        data = self.request("POST", "/firewalls", {"name": name, "rules": rules})
        return data["firewall"]

    def create_server(self, name: str, config: DeployConfig, user_data: str, firewall_id: int) -> dict:
        # ssh_keys is omitted on purpose. The firewall id is attached in this
        # same call, so the server has no public SSH window during first boot.
        data = self.request(
            "POST",
            "/servers",
            {
                "name": name,
                "server_type": config.hetzner_server_type,
                "image": config.hetzner_image,
                "location": config.hetzner_location,
                "firewalls": [{"firewall": firewall_id}],
                "user_data": user_data,
                "start_after_create": True,
                "public_net": {"enable_ipv4": True, "enable_ipv6": True},
                "labels": {"role": "ghost"},
            },
        )
        return data["server"]

    def get_server(self, server_id: int) -> dict | None:
        data = self.request("GET", f"/servers/{server_id}", allow_missing=True)
        if data is None:
            return None
        return data["server"]

    def delete_server(self, server_id: int) -> None:
        self.request("DELETE", f"/servers/{server_id}")

    def delete_firewall(self, firewall_id: int) -> None:
        self.request("DELETE", f"/firewalls/{firewall_id}")

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        allow_missing: bool = False,
    ) -> dict | None:
        body = None if payload is None else json.dumps(payload).encode()
        status, raw = self._transport.send(method, self._base_url + path, self._headers(), body)
        if status == 404 and allow_missing:
            return None
        data = json.loads(raw) if raw else {}
        if status >= 400:
            message = (data.get("error") or {}).get("message") or raw.decode(errors="replace")
            raise HetznerError(f"Hetzner API {status}: {message}")
        return data

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ghost-deploy",
        }

    def _list(self, collection: str, name: str) -> list[dict]:
        quoted = urllib.parse.quote(name)
        page = 1
        found: list[dict] = []
        for _ in range(20):
            data = self.request("GET", f"/{collection}?name={quoted}&page={page}")
            assert data is not None
            found.extend(item for item in data.get(collection, []) if item.get("name") == name)
            next_page = (data.get("meta") or {}).get("pagination", {}).get("next_page")
            if not next_page:
                break
            page = int(next_page)
        return found


def resource_name(config: DeployConfig) -> str:
    name = config.hetzner_name or "ghost-" + config.domain.replace(".", "-")
    if len(name) > 63:
        name = name[:63].rstrip("-")
    if _HCLOUD_NAME.fullmatch(name) is None:
        raise HetznerError(f"{name} is not a valid Hetzner resource name")
    return name


def firewall_rules(bundle: Bundle) -> list[dict]:
    specs = [("tcp", "80", "http"), ("tcp", "443", "https"), ("udp", "443", "http3"), ("icmp", None, "ping")]
    seen = {(protocol, port) for protocol, port, _description in specs}
    for protocol, port in extra_ports(bundle.files.get("tunnel-ports.txt", "")):
        if (protocol, port) not in seen:
            specs.append((protocol, port, f"{protocol}-{port}"))
            seen.add((protocol, port))
    rules = [_rule(protocol, port, description) for protocol, port, description in specs]
    if opens_ssh(rules):
        raise HetznerError("refusing to create a firewall that exposes SSH")
    return rules


def extra_ports(text: str) -> list[tuple[str, str]]:
    found = []
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        port, separator, protocol = entry.partition("/")
        if separator != "/" or protocol not in {"tcp", "udp"} or not port.isdigit():
            raise HetznerError(f"tunnel port {entry} must look like 51820/udp")
        if port_covers_22(port):
            raise HetznerError("a tunnel must not request public port 22")
        if not 1 <= int(port) <= 65535:
            raise HetznerError(f"tunnel port {entry} is outside 1-65535")
        found.append((protocol, port))
    return found


def opens_ssh(rules: list[dict]) -> bool:
    for rule in rules:
        if rule.get("direction", "in") != "in":
            continue
        if rule.get("protocol") not in {"tcp", "udp"}:
            continue
        if port_covers_22(str(rule.get("port") or "")):
            return True
    return False


def port_covers_22(port: str) -> bool:
    if port in {"22", "any"}:
        return True
    if "-" in port:
        start, end = port.split("-", 1)
        if start.isdigit() and end.isdigit():
            return int(start) <= 22 <= int(end)
    return False


def deploy_host(
    config: DeployConfig,
    output: Path,
    tunnel_script: str | None,
    client: Hetzner,
    sleep=time.sleep,
    attempts: int = 90,
) -> "Host":
    _require_token(config)
    name = resource_name(config)
    existing = client.find_server(name)
    if existing is not None:
        firewall = _firewall_for(client, name, int(existing["id"]))
        return Host(name, int(existing["id"]), int(firewall["id"]), _ipv4(existing), created=False)
    bundle = render_bundle(config, tunnel_script=tunnel_script)
    _reject_token_leak(config, bundle)
    write_bundle(bundle, output)
    firewall = _fresh_firewall(client, name, firewall_rules(bundle))
    created = client.create_server(name, config, bundle.user_data, int(firewall["id"]))
    running = _wait_running(client, int(created["id"]), sleep, attempts)
    return Host(name, int(running["id"]), int(firewall["id"]), _ipv4(running), created=True)


def destroy_host(config: DeployConfig, client: Hetzner, sleep=time.sleep, attempts: int = 90) -> "DestroyResult":
    _require_token(config)
    name = resource_name(config)
    server = client.find_server(name)
    deleted_server = server is not None
    if server is not None:
        client.delete_server(int(server["id"]))
        _wait_gone(client, int(server["id"]), sleep, attempts)
    firewall = client.find_firewall(name)
    deleted_firewall = firewall is not None
    if firewall is not None:
        client.delete_firewall(int(firewall["id"]))
    return DestroyResult(name, deleted_server, deleted_firewall)


def verify_host(
    config: DeployConfig,
    client: Hetzner,
    probe=None,
    extra: list[tuple[str, str]] | None = None,
) -> "Host":
    _require_token(config)
    name = resource_name(config)
    server = client.find_server(name)
    if server is None:
        raise HetznerError(f"{name} does not exist")
    firewall = _firewall_for(client, name, int(server["id"]))
    rules = firewall.get("rules") or []
    if opens_ssh(rules):
        raise HetznerError(f"{name} firewall exposes SSH")
    required = [("tcp", "80"), ("tcp", "443"), *(extra or [])]
    missing = [f"{port}/{protocol}" for protocol, port in required if not _has_port(rules, protocol, port)]
    if missing:
        raise HetznerError(f"{name} firewall is missing {', '.join(missing)}")
    address = _ipv4(server)
    check = probe or tcp_open
    if check(address, 22):
        raise HetznerError(f"{address}:22 accepts connections")
    closed = [port for port in (80, 443) if not check(address, port)]
    if closed:
        joined = " and ".join(str(port) for port in closed)
        raise HetznerError(f"{address}:{joined} is not accepting connections yet")
    return Host(name, int(server["id"]), int(firewall["id"]), address, created=False)


@dataclass(frozen=True)
class Host:
    name: str
    server_id: int
    firewall_id: int
    ipv4: str
    created: bool


@dataclass(frozen=True)
class DestroyResult:
    name: str
    deleted_server: bool
    deleted_firewall: bool


def tcp_open(ip: str, port: int, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _fresh_firewall(client: Hetzner, name: str, rules: list[dict]) -> dict:
    current = client.find_firewall(name)
    if current is not None:
        if current.get("applied_to"):
            raise HetznerError(f"firewall {name} is already applied to another resource")
        if opens_ssh(current.get("rules") or []):
            raise HetznerError(f"firewall {name} exposes SSH; delete it before deploying")
        client.delete_firewall(int(current["id"]))
    return client.create_firewall(name, rules)


def _firewall_for(client: Hetzner, name: str, server_id: int) -> dict:
    firewall = client.find_firewall(name)
    if firewall is None or server_id not in _applied_server_ids(firewall):
        raise HetznerError(f"{name} is missing its firewall")
    if opens_ssh(firewall.get("rules") or []):
        raise HetznerError(f"{name} firewall exposes SSH")
    return firewall


def _applied_server_ids(firewall: dict) -> set[int]:
    found = set()
    for item in firewall.get("applied_to") or []:
        server = item.get("server")
        if isinstance(server, dict) and "id" in server:
            found.add(int(server["id"]))
        elif isinstance(server, int):
            found.add(server)
    return found


def _wait_running(client: Hetzner, server_id: int, sleep, attempts: int) -> dict:
    last = "missing"
    for attempt in range(attempts):
        server = client.get_server(server_id)
        if server is None:
            raise HetznerError("server disappeared before it started")
        last = str(server.get("status"))
        if last == "running":
            return server
        if last in {"error", "deleting"}:
            raise HetznerError(f"server entered status {last}")
        if attempt < attempts - 1:
            sleep(2)
    raise HetznerError(f"server stayed in status {last}")


def _wait_gone(client: Hetzner, server_id: int, sleep, attempts: int) -> None:
    for attempt in range(attempts):
        if client.get_server(server_id) is None:
            return
        if attempt < attempts - 1:
            sleep(2)
    raise HetznerError("server is still deleting")


def _has_port(rules: list[dict], protocol: str, port: str) -> bool:
    return any(
        rule.get("direction", "in") == "in" and rule.get("protocol") == protocol and str(rule.get("port")) == port
        for rule in rules
    )


def _rule(protocol: str, port: str | None, description: str) -> dict:
    rule = {
        "direction": "in",
        "protocol": protocol,
        "source_ips": list(_WORLD),
        "description": description,
    }
    if port is not None:
        rule["port"] = port
    return rule


def _require_token(config: DeployConfig) -> None:
    if not config.hetzner_api_token:
        raise HetznerError("HETZNER_API_TOKEN is required")


def _reject_token_leak(config: DeployConfig, bundle: Bundle) -> None:
    if len(bundle.user_data.encode()) > HETZNER_USER_DATA_LIMIT:
        raise HetznerError("cloud-init exceeds the Hetzner user_data limit of 32 KiB")
    if config.hetzner_api_token in bundle.user_data:
        raise HetznerError("refusing to place the Hetzner token in user data")


def _ipv4(server: dict) -> str:
    address = ((server.get("public_net") or {}).get("ipv4") or {}).get("ip")
    if not address:
        raise HetznerError("server has no public IPv4 address")
    return str(address)


def _only(matches: list[dict], name: str, kind: str) -> dict | None:
    if len(matches) > 1:
        raise HetznerError(f"more than one {kind} is named {name}")
    return matches[0] if matches else None
