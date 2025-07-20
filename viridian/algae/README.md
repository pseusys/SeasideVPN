# Viridian Algae

> Current version: **"0.0.3"**

A set of tools and utilities, written in `Python`.
It includes multiple tests and tools, including sample [client app](#sample-client), caerulean [installer](#caerulean-installer), admin [fixtures](#admin-fixtures), [protocol implementations](#protocol-descriptions) and more.
Created mainly for development and testing purposes.

> Target platform: _linux_ only

## Dependencies

1. `python3` (interpreter) version >= 3.10
  Installation guide can be found [here](https://www.python.org/downloads/).
2. `poetry` (build system) version >= 2.0
  Installation guide can be found [here](https://python-poetry.org/docs/#installation).
3. System packages: `iptables`, `iproute2`.

## Configuration and running

All required python dependencies can be installed with this command:

```bash
poetry install --all-extras
```

## Sample client

> Requires `client` extra.

Sample client app is built using traditional Linux VPN architecture.
The architecture is described in more detail in [`reef` README](../reef/README.md#general-idea).
Here, the `algae` client is also optionally capable of authenticating user before connection (using a gRPC call).
The client is mainly implemented for integration testing and is not meant for production.

Detailed description of arguments required for starting the client can be received with this command:

```bash
sudo poetry poe client --help
```

> The most CLI options and settings are also similar to the ones of `reef`.

## Caerulean installer

> Requires `bundle` extra for compilation and `setup` extra for running (will be installed automatically).

Caerulean installation script consists of several python files in `setup` directory.
It can deploy different caerulean server apps on Linux machines with different architectures.
The script itself has no external dependencies, does not require installation or building and can be used as a deployment entrypoint.
It also is not demanding in terms of interpreter version: some reasonably-old `python3` (like `3.8`, available on most of the systems) should be just enough.
The script can be used as-is or compressed for uploading to a remote server using the following command:

```bash
sudo poetry poe bundle [INSTALLATION_SCRIPT_NAME]
```

The script is flexible and accepts multiple different parameters, that will not be described here.
Detailed parameter description can be received by running this command:

```bash
poetry run python3 -m setup --help
```

For each individual caerulean, the options closely resemble the environment variables they depend on.
The option description for each individual caerulean in the following list: (`whirlpool`) can be received by running this command:

```bash
poetry run python3 -m setup CAERULEAN_NAME --help
```

In order to achieve reproducible caerulean deployments, `conf.env` and `certificates` files can be uploaded before deployment.
Combined with relevant script arguments, they will prevent script from regenerating system settings.

Examples of this script usage can be found in [whirlpool make](../../caerulean/whirlpool/Makefile) and [Beget deployment script](../../.github/scripts//deploy_whirlpool_beget.mjs).

## Admin fixtures

Admin fixtures provide CLI to caerulean gRPC.
They can be used for manual user adding, parameter setting, configuration, etc.
More information about fixtures is available from running this command:

```bash
poetry run python3 -m fixture --help
```

### Whirlpool: Supply Viridian

This fixture adds a viridian to whirlpool, generating a valid token with requested parameters.
It can be used for adding viridians with administrator privileges to a whirlpool node.
Detailed description of this fixture can be retrieved using this command:

```bash
poetry run python3 -m fixture supply-viridian --help
```

## Protocol Descriptions

> Requires `protocol` extra.
> Might also require `python` executable temporary patching, but that is described separately in [the notebook](./typhoon/typhoon.ipynb).

Contains some documentation files, jupyter notebooks and support scripts for more detailed and formal description of the protocols utilized by Seaside VPN.
In the notebooks, some real-world diagrams and packet capture statistics are shown, protocol behavior under pressure is presented.
The [documentation README file](./typhoon/README.md) describes the TYPHOON protocol, presents its state diagrams, common values, random parameters and limitations.
There is no detailed documentation for PORT protocol though, since it is in the end just a stripped version of TYPHOON, with delivery guarantees and healthcheck messages removed (they are provided by TCP).

## Other commands

> Requires `codestyle` dependency for linting and `test` for testing.
> Tests also rely on `devel` extra, but they run in Docker containers, so it will be automatically installed inside.

Lint all python files:

```bash
sudo poetry poe lint
```

Test (all types of tests):

```bash
sudo poetry poe test-all
```

Build standalone executable (OS-specific):

```bash
sudo poetry poe build [EXECUTABLE_NAME]
```

Clean build artifacts:

```bash
sudo poetry poe clean
poetry env remove --all
```

There are other commands available, run this to get the full list:

```bash
sudo poetry poe help
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
