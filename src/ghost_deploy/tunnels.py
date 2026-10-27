"""Tunnel adapters. Each one reaches sshd on 127.0.0.1:22 without a public SSH port."""

import base64
import re
import shlex
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ghost_deploy.config import DeployConfig
from ghost_deploy.render import DEFAULT_TUNNEL_SCRIPT, BundleError

WG_ADDRESS = "10.66.0.1"
WG_CLIENT_ADDRESS = "10.66.0.2"
WG_PORT = 51820


@dataclass(frozen=True)
class TunnelPlan:
    script: str
    connect_hint: str
    local_files: dict[str, str]


def build_tunnel(config: DeployConfig, tunnel_script: str | None) -> TunnelPlan:
    provider = config.tunnel
    if tunnel_script is not None and provider not in {"none", "custom"}:
        raise BundleError("use either a built-in tunnel or --tunnel-script")
    if tunnel_script is not None:
        provider = "custom"
    if provider == "none":
        return TunnelPlan(
            script=DEFAULT_TUNNEL_SCRIPT,
            connect_hint=(
                f"SSH listens on 127.0.0.1:22 for {config.admin_user}.\n"
                "Set TUNNEL to cloudflare, tailscale, or wireguard, or pass --tunnel-script.\n"
            ),
            local_files={"tunnel-ports.txt": "# no extra public ports\n"},
        )
    if provider == "custom":
        if tunnel_script is None:
            raise BundleError("a custom tunnel needs --tunnel-script")
        return TunnelPlan(
            script=tunnel_script,
            connect_hint=(
                f"The custom script is installed as /opt/ghost/tunnel-setup.sh.\n"
                f"Connect through that tunnel as {config.admin_user}. SSH is on 127.0.0.1:22.\n"
            ),
            local_files={"tunnel-ports.txt": "# no extra public ports\n"},
        )
    if provider == "cloudflare":
        return _cloudflare(config)
    if provider == "tailscale":
        return _tailscale(config)
    if provider == "wireguard":
        return _wireguard(config)
    raise BundleError(f"unknown tunnel {provider}")


def _cloudflare(config: DeployConfig) -> TunnelPlan:
    hostname = config.cloudflare_ssh_hostname or f"ssh.{config.domain}"
    token = shlex.quote(config.cloudflare_tunnel_token)
    script = f"""#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update
apt-get install -y cloudflared
cloudflared service install {token}
systemctl enable --now cloudflared
"""
    hint = (
        f"In Cloudflare, publish a TCP hostname {hostname} aimed at localhost:22.\n"
        "Then, from a machine with cloudflared:\n\n"
        f"ssh -o ProxyCommand='cloudflared access ssh --hostname {hostname}' "
        f"{config.admin_user}@{hostname}\n"
    )
    return TunnelPlan(script, hint, {"tunnel-ports.txt": "# no extra public ports\n"})


def _tailscale(config: DeployConfig) -> TunnelPlan:
    hostname = config.tailscale_hostname or config.domain.replace(".", "-")
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", hostname) is None:
        raise BundleError("TAILSCALE_HOSTNAME must be a single DNS label")
    key = shlex.quote(config.tailscale_auth_key)
    script = f"""#!/bin/bash
set -euo pipefail
umask 077
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --auth-key={key} --ssh --hostname={shlex.quote(hostname)} --accept-dns=false
"""
    hint = (
        "Tailscale SSH answers on the tailnet. The tailnet ACL must allow "
        f"login as {config.admin_user}.\n\n"
        f"tailscale ssh {config.admin_user}@{hostname}\n"
    )
    return TunnelPlan(script, hint, {"tunnel-ports.txt": "# no extra public ports\n"})


def _wireguard(config: DeployConfig) -> TunnelPlan:
    endpoint = config.wireguard_endpoint or f"{config.domain}:{WG_PORT}"
    _host, port_text = endpoint.rsplit(":", 1)
    port = int(port_text)
    server_private, server_public = _wireguard_keypair()
    client_private, client_public = _wireguard_keypair()
    script = f"""#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y wireguard
install -d -m 0700 /etc/wireguard
cat > /etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = {WG_ADDRESS}/24
ListenPort = {port}
PrivateKey = {server_private}
[Peer]
PublicKey = {client_public}
AllowedIPs = {WG_CLIENT_ADDRESS}/32
EOF
chmod 0600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
ufw allow {port}/udp
ufw allow in on wg0 to any port 22 proto tcp
cat > /etc/ssh/sshd_config.d/50-wireguard.conf <<'EOF'
ListenAddress {WG_ADDRESS}
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
  systemctl reload ssh && break
  sleep 1
done
"""
    client = f"""[Interface]
Address = {WG_CLIENT_ADDRESS}/24
PrivateKey = {client_private}

[Peer]
PublicKey = {server_public}
Endpoint = {endpoint}
AllowedIPs = {WG_ADDRESS}/32
PersistentKeepalive = 25
"""
    hint = (
        "Import wireguard-client.conf into WireGuard, then:\n\n"
        f"ssh {config.admin_user}@{WG_ADDRESS}\n\n"
        f"Allow UDP {port} to the server in the Hetzner firewall. "
        "The host firewall already allows that port and SSH on wg0.\n"
    )
    return TunnelPlan(
        script,
        hint,
        {
            "wireguard-client.conf": client,
            "tunnel-ports.txt": f"{port}/udp\n",
        },
    )


def _wireguard_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode("ascii")
