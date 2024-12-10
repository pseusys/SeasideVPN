# Viridian Algae

> Current version: **"0.0.2"**

Small CLI-based client application, written in `Python`.
It can be run on linux (in for- and background), it's highly customizable.
Created mainly for development and testing purposes.

> Target platform: _linux_ only

## Dependencies

1. `python3` (interpreter) version >= 3.10
  Installation guide can be found [here](https://www.python.org/downloads/).
2. `protobuf` (compiler) version >= 24.4
  Installation guide example can be found [here](https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os).
3. `poetry` (build system) version >= 1.0.0
  Installation guide can be found [here](https://python-poetry.org/docs/#installation).

## Implementation details

### Initialization

Upon initialization, the algae `tunnel` finds out the local **default** network interface, i.e. the interface the packets will be forwarded through if no local destination is found.
After that it creates a `TUN` device, sets current user and group as its owner.

Right before the connection, the algae `coordinator` opens gRPC channel to caerulean `whirlpool` and requests token from it.
Then it connects to caerulean `whirlpool`.

Just after the connection, the algae `tunnel` uses `iptables-legacy` firewall to configure traffic.
The following rules are prepended to the existing chains (in order):

1. `iptables -t mangle -A OUTPUT --src: [LOCAL_DEFAULT_NETWORK_INTERFACE_IP] -o [LOCAL_DEFAULT_NETWORK_INTERFACE] --dst [CAERULEAN_INTERNAL_IP] -j ACCEPT`
2. `iptables -t mangle -A OUTPUT -o [LOCAL_DEFAULT_NETWORK_INTERFACE] ! --dst [LOCAL_DEFAULT_NETWORK] -j MARK --set-mark 65`
3. `iptables -t mangle -A OUTPUT -o [LOCAL_DEFAULT_NETWORK_INTERFACE] ! --dst [LOCAL_DEFAULT_NETWORK] -j ACCEPT`
4. `... all iptables rules that existed before ...`

... and same rule set for `FORWARD` chain.

After that it sets tunnel device `MTU`, IP address (the IP address is `192.168.0.65`) and changes state to `UP`.
It also cleares routing table #65, sets default route to caerulean internal IP there and sets routing lookup for packets marked with number `65` in table #65.

Finally, the algae `viridian` launches two asyncio coroutines: one for reading packets from tunnel, encrypting them and sending in UDP packets to the specified caerulean `whirlpool` port, and another for reading packets from caerulean `whirlpool`, decrypting them and writing to the tunnel device.

While connection is active, the algae `coordinator` sends healthcheck gRPC messages to caerulean `whirlpool` with random timeouts.
If a non-fatal exception happens, `coordinator` tries to stop algae `viridian` and re-initialize connection, starting from token request, but skipping `tunnel` initialization (since it wasn't stopped).

### Termination

Upon connection interruption (fatal exception or manual), `coordinator` tries sending to caerulean whirlpool exception message.
Then it closes gRPC channel.

Right after that, the algae `tunnel` removes all the `iptables` rules it added (just pops them from the beginning of the tables).
After that it flushes routing table #65, resets routing lookup for packets marked with number `65` and sets tunnel device state to `DOWN`.

> NB! The same cleanup sequence happens if an error before connection is established.

Finally, the algae `tunnel` deletes the tunnel device.

## Configuration and running

> Required packages: `iptables`, `iproute2`.

All required python dependencies can be installed with this command:

```bash
poetry install --without devel
```

Algae can be executed with following command:

```bash
sudo poetry run execute [PAYLOAD_VALUE]
```

Superuser rights required for tunnel interface creation.

The following CLI arguments are supported:

- `-a --address [ADDRESS]`: Caerulean server address, to connect to (default: `127.0.0.1`).
- `-c --ctrl-port`: Control port - the port that will be used for control communication with caerulean (default: `8587`).
- `-l --link`: Connection certificate in link form (will overwrite other parameters specified).
- `-h --help`: Print short command notice and exit.
- `-v --version`: Print current algae version and exit.

It also sensitive to the following environmental variable:

- `SEASIDE_TUNNEL_NAME`: Name of the tunnel interface (default: `seatun`).
- `SEASIDE_TUNNEL_ADDRESS`: IP address of the tunnel (default: `192.168.0.65`).
- `SEASIDE_TUNNEL_NETMASK`: Netmask of the tunnel network (default: `255.255.255.0`).
- `SEASIDE_TUNNEL_SVA`: A special constant used for packet marking and routing table setting (default: `65`).
- `SEASIDE_USER_NAME`: User name that will be used during connection (default: `default_algae_user`).
- `SEASIDE_MIN_HC_TIME`: Minimal time between two healthcheck control messages, in seconds (default: `1`).
- `SEASIDE_MAX_HC_TIME`: Maximal time between two healthcheck control messages, in seconds (default: `5`).
- `SEASIDE_CONNECTION_TIMEOUT`: Timeout for gRPC control connection, in seconds (default: `3.0`).
- `SEASIDE_LOG_LEVEL`: Output verbosity logging level, can be "error", "warning", "info", "debug" (default: `DEBUG`).
- `SEASIDE_ROOT_CERTIFICATE_AUTHORITY`: Custom certificate authority file path for whirlpool server.

## Caerulean installation script

TODO!!

## Other commands

Lint all python files:

```bash
sudo poetry run lint
```

Test (all types of tests):

```bash
sudo poetry run test-all
```

Build standalone executable (OS-specific):

```bash
sudo poetry run build
```

Bundle installation script:

```bash
sudo poetry run bundle
```

Clean build artifacts:

```bash
sudo poetry run clean
poetry env remove --all
```

There are other commands available, run this to get the full list:

```bash
sudo poetry run help
```

## Test sets

Four test sets are included:

1. `unit`: Unit tests for `algae` viridian.
2. `integration`: Integration tests for communication between `algae` viridian and `whirlpool` caerulean.
3. `local`: Smoke test for UDP server access in a chaotic network.
4. `remote`: Smoke test for real-world website access.
5. `domain`: Smoke test for DNS website resolving.
6. `smoke`: All of the `local`, `remote` and `domain` test sets.
7. `all`: All the tests specified.