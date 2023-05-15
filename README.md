# SeasideVPN

A simple PPTP UDP VPN

> Inspired by [this](https://github.com/habibiefaried/vpn-protocol-udp-pptp) project and tutorial.

My first program in `Go`, written with assistance of multiple tutorials and ChatGPT.

## Conventions

Each program here has a special numeric identifier, that is the ASCII code of the first letter of its' name (capitalized).
So far the numeric identification table looks like this:

| Program Name | Numeric Identifier |
| --- | --- |
| Caerulean Whirlpool | 87 |
| Viridian Algae | 65 |
| Seaside VPN | 83 |

## Caerulean

Caerulean is server side of SeaSide VPN, it consists of several parts:

### Surface

TODO!

### Whirlpool

Whirlpool program is written in Go language.
It manages encrypting, decrypting, assembling and transferring requests and responses.

Whirlpool accepts client packages at UDP port 1723, no more than 32000 bytes in size, encrypted.
TODO: encryption negotiation is yet to be implemented!

> WARNING! Any UDP packets arriving to port 1723 will be treated as user packets, i.e. user should never send packets to port 1723 of any server via Seaside VPN!

Test whirlpool server (with algae client):

```bash
make test-caerulean-whirlpool
```

#### Run whirlpool server

> Required packages: `iptables`, `ip`

Run whirlpool server:

```bash
make -C caerulean/whirlpool run
```

Lint and format golang files:

```bash
make -C caerulean/whirlpool lint
```

Restore `iptables` configuration after run:

```bash
make -C caerulean/whirlpool clean
```

Clean build artifacts:

```bash
make -C caerulean/whirlpool clean
```

#### Time diagram

```mermaid
sequenceDiagram
    actor Client
    box Caerulean
    participant Input as Caerulean UDP port 1723
    participant Tunnel
    participant Output as Caerulean Output
    end
    participant Server

    Note right of Client: Encrypt request, pack in UDP
    Client ->> Input: Encrypted & packed client request
    
    Note right of Input: Decrypt and unpack request
    Input ->> Tunnel: Decrypted client request binary

    Note right of Tunnel: Construct original packet
    Tunnel ->> Output: Decrypted client request

    Note right of Output: Masquerade and send packet
    Output ->> Server: Client request

    Note right of Output: Receive and unmasquerade packet
    Server ->> Output: Server response
    
    Note right of Tunnel: Send packet to tunnel
    Output ->> Tunnel: Routed server response

    Note right of Input: Encrypt request, pack in UDP
    Tunnel ->> Input: Encrypted server response

    Note right of Client: Decrypt and unpack request
    Input ->> Client: Encrypted & packed server response (UDP)
```

## Viridian

Viridian is client side of SeaSide VPN, there are several client options:

### Algae

Small CLI-based client application, written in Python3.
It can be run on linux (in for- and background), highly customizable.
Created mainly for development and testing purposes.

#### Run algae client

> Required packages: `ip`

Run algae client:

```bash
make -C viridian/algae run
```

Clean build artifacts:

```bash
make -C viridian/algae clean
```

## Test

```bash
make test-all
```

## TODOs

1. Add run options to all run configurations, Makefiles
