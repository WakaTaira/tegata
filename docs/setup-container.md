# Container setup

This is the ContainerBoundary: the daemon runs on the Linux host, while the
agent runs in a rootful Docker container. A dedicated Docker bridge provides the
boundary. The host daemon listens on the bridge gateway, and `tegata-bridge`
forwards the container's authenticated RPC calls and CDP tunnel.

Rootless Docker and Podman are not supported. A container using `--network host`
has the same boundary as a host-side agent and is outside this setup.

## Host daemon

Configure a user-defined bridge with a fixed Linux bridge name. The fixed name is
the key used by the firewall rule:

```sh
docker network create --subnet 172.30.0.0/24 \
  --opt com.docker.network.bridge.name=tegata0 tegata
```

Add a TCP listener alongside the existing UNIX listener in the daemon's TOML
configuration:

```toml
[[listen]]
kind = "unix"
path = "/run/tegata/tegatad.sock"
allowed_uids = [1000]
operator_uids = [1000]

[[listen]]
kind = "tcp"
bind = "172.30.0.1"
port = 21575
```

`bind` is required, and `0.0.0.0` and `::` are refused. The TCP token is sent in
plaintext without TLS, so bind only to the gateway IP of the private Docker
bridge. Do not bind the listener to any other host interface.

On NixOS, the equivalent module options are:

```nix
services.tegata.listen.tcp = {
  bind = "172.30.0.1";
  port = 21575;
};
services.tegata.operatorUids = [ 1000 ];
```

The default for `services.tegata.listen.tcp` is `null`, so no TCP port exists
unless it is configured. `operatorUids` defaults to `[]`; root and these uids can
call peer administration RPCs from the UNIX socket.

Allow inbound traffic on the bridge and this port only. On NixOS:

```nix
networking.firewall.interfaces.tegata0.allowedTCPPorts = [ 21575 ];
```

On another Linux host, an equivalent iptables rule is:

```sh
sudo iptables -I INPUT -i tegata0 -p tcp --dport 21575 -j ACCEPT
```

Do not open port `21575` on other interfaces.

## Issue a named token

Issue the token on the host through the daemon's UNIX socket:

```sh
sudo tegatad peer issue --label agent --socket /run/tegata/tegatad.sock
```

The plaintext token is displayed once. Store it in a host file readable only by
the operator, for example:

```sh
sudo install -m 0600 /dev/null /etc/tegata/agent-token
sudo sh -c 'umask 077; printf "%s\n" "TOKEN_FROM_peer_issue" > /etc/tegata/agent-token'
```

Replace the placeholder with the token from `peer issue`. Do not put the token in
an environment variable. To manage the named token, use the daemon's peer
administration commands:

```sh
sudo tegatad peer revoke <peer_id> --socket /run/tegata/tegatad.sock
sudo tegatad peer list --socket /run/tegata/tegatad.sock
```

The bridge refuses a token file that is not mode 0600.

## Container bridge

The project does not distribute a container image. Build `tegata-bridge` from a
checkout, or copy the result of the Nix `packages.tegata-bridge` package:

```sh
cargo build --release -p tegata-bridge
```

Inside the agent container, start the bridge with the named token:

```sh
tegata-bridge \
  --socket /run/tegata-bridge/bridge.sock \
  --token-file /run/secrets/tegata-token \
  --daemon-addr 172.30.0.1:21575
```

If `--daemon-addr` is omitted, the bridge uses the default route's gateway on
port `21575`. Its UNIX socket accepts connections only from processes with the
same uid. Configure the MCP server to use that socket:

```sh
TEGATA_SOCKET=/run/tegata-bridge/bridge.sock TEGATA_BRIDGE=1 \
  tegata-mcp
```

Use the `tegata-mcp` Nix package, or run `node packages/tegata-mcp/dist/index.js`
when using a checkout.

The MCP `status`, `login`, and `logout` operations are the same as for a host
agent. `login` returns an endpoint such as
`ws://127.0.0.1:<port>/...`; that `127.0.0.1` is inside the container and
identifies the bridge's CDP tunnel.

## Compose example

The image containing the bridge and MCP server is supplied by the operator. The
network is created separately as the external `tegata` network above, and the
token file must already be mode 0600:

```yaml
services:
  tegata-agent:
    image: your-agent-image
    networks:
      - tegata
    secrets:
      - tegata-token

networks:
  tegata:
    external: true

secrets:
  tegata-token:
    file: /etc/tegata/agent-token
```

The container command or entrypoint starts `tegata-bridge` and the MCP server
with the paths shown above. The agent container receives no Docker socket,
`--privileged` flag, or host directory mount.

## Verification

The container acceptance tests live under `tests/acceptance/container/` and the
CI `container` job exercises the same boundary. Run them with `npm run
test:container`; set `TEGATA_DOCKER="sudo docker"` to use Docker through sudo.
The suite skips when Docker is unavailable.
