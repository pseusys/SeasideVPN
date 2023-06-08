# Viridian Algae

> Target platform: _linux_ only

Small CLI-based client application, written in Python3.
It can be run on linux (in for- and background), it's highly customizable.
Created mainly for development and testing purposes.

## Configuration

> Required packages: `ip`, `python3`, `poetry` (from pip)

Poetry can (and should) be installed globally with something like this command:

```bash
pip3 install poetry
```

All required dependencies can be installed with this command:

```bash
poetry install --all-extras
```

Algae can be executed with following command:

```bash
sudo poetry run execute
```

superuser rights required for tunnel interface creation.

It can be run with following arguments:

- `-t <tunnel_name>` - name of the tunnel device that will be used for packet forwarding (default: "seatun").
- `-e <encrypt>` - execution mode: whether algae is run in VPN (True) or Proxy (False) mode (default: True).
- `-m <connection_mtu>` - tunnel MTU (default: 1500).
- `-b <connection buffer>` - connection buffer size, in bytes (default: 2000).
- `-a <address>` - caerulean server address, to connect to (default: 127.0.0.1).
- `-p <sea_port>` - seaside port: the port that will be used for exchanging data packets with caerulean (default: 8542).
- `-c <control_port>` - control port: the port that will be used for control communication with caerulean (default: 8543).

It also sensitive to the following environmental variable:

- `LOG_LEVEL` - the output verbosity level, can be "error", "warning", "info", "debug" (default: "DEBUG").

## Other commands

Lint (but not reformat) python files:

```bash
sudo poetry run lint
```

Lint (and reformat) python files:

```bash
sudo poetry run format
```

Test (both unit and integration):

```bash
sudo poetry run test
```

Build standalone executable (OS-specific):

```bash
sudo poetry run build
```

Clean build artifacts:

```bash
sudo poetry run clean
poetry env remove --all
```
