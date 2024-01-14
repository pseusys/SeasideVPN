# SeasideVPN

A simple PPTP UDP and VPN system

> Inspired by [this](https://github.com/habibiefaried/vpn-protocol-udp-pptp) project and tutorial.

My first program in `Go`, written with assistance of multiple tutorials and ChatGPT.

## General info

Seaside is a VPN and distributed system, focused on making final user traffic not easily detectable so that the whole system access blocking becomes not cost-effective.

For user traffic encryption `XChaCha20-Poly1305` encryption is used.
For protocol obfuscation special [`wavy messages`](#wavy-messages) protocol is used.

Target users of the system are **groups** of people (companies, communities, etc.), residing in different countries and wishing to create their own VPN network.
System deployment and integration is (planned) to be easy even for not very familiar with networking people, so that each system instance will consist of several connected individually managed nodes.

> **NB!** As no global infrastructure (i.e. public servers, domen names, etc.) is planned, user privacy and safety solely depends on the each system instance _node operators_.
> System can only exist and be active until the people that use it **trust each other**! 🤝

### System structure

Below, you can see the (planned) system structure.
Following naming is used:

- [`Surface`](#surface) is the main node of the system instance.
  It keeps track of actual gateway worker nodes, collects statistics, performs load-balancing and user distribution.
  It also manages user authentication and payments, distributes incomes among VPN node owners.
  Basically, the owner of the `surface` node owns (and is responsible) for the whole system instance.
- [`Whirlpool`](#whirlpool) is a worker node.
  It allows user traffic forwarding, encryption, etc.
  Several `whirlpool` nodes in different locations and of different performance can be included into a single system instance.
  In order to make the sytem truly P2P, all system instance users are encouraged to manage their own `whirlpool` node and though contribute to the system.
- [`Viridian`](#viridian-client) is a user application (desctop, mobile, browser, etc.).
  One `viridian` can be connected to one seaside system instance at a time, but is allowed to choose between different `whirlpool`s in it.

```mermaid
graph LR
  S[Surface] -.- W1([Whirlpool 1])
  S[Surface] -.- W2([Whirlpool 2])
  S[Surface] -.- W3([Whirlpool 3])

  W1([Whirlpool 1]) --> I{Internet}
  W2([Whirlpool 2]) --> I{Internet}
  W3([Whirlpool 3]) --> I{Internet}

  V1{{Viridian 1}} -.- S[Surface]
  V1{{Viridian 1}} --> W1([Whirlpool 1])

  V2{{Viridian 2}} -.- S[Surface]
  V2{{Viridian 2}} --> W1([Whirlpool 1])

  V3{{Viridian 3}} -.- S[Surface]
  V3{{Viridian 3}} --> W1([Whirlpool 1])

  V4{{Viridian 4}} -.- S[Surface]
  V4{{Viridian 4}} --> W2([Whirlpool 2])

  V5{{Viridian 5}} -.- S[Surface]
  V5{{Viridian 5}} --> W2([Whirlpool 2])

  V6{{Viridian 6}} ---> W3([Whirlpool 3])
```

On this diagram, an example SeaSide system is shown.
Three `viridian`s are connected to internet via `whirlpool` №1 and two other `viridian`s via `whirlpool` №2.
All of them are also connected to `surface` node.
The last `viridian` №6 is connected only to `whirlpool` №3 and not to `surface` node, that is only possible if `viridian` №6 is the administrator of `whirlpool` №3.

### Conventions

Each program here has a special numeric identifier, that is the ASCII code of the first letter of its' name (capitalized).  
The numeric identification table can be found below:

| Program Name | Numeric Identifier |
| --- | --- |
| Caerulean Whirlpool | 87 |
| Viridian Algae | 65 |
| Seaside VPN | 83 |

There are some important notes and conditions that must be fulfilled in order for system to work as expected:

- Viridian packets must not exceed 65495 bytes (that is max UDP packet size minus overflow for encryption).

## Data, connections and protocols

The key difference of SeaSide VPN from other VPN systems is it's undetectability.
Indeed, according to several articles ([this](https://ieeexplore.ieee.org/document/8275301), [this](https://www.ir.com/guides/deep-packet-inspection) or [this](https://www.sciencedirect.com/science/article/abs/pii/S0167404813000837)), packet analysis is done according to several techniques:

- Packet header analysis.
- Packet content analysis.
- Packet exchange time analysis.

SeaSide VPN offers several ways to handle all these cases:

1. All VPN and control packets are encrypted and don't have any unencrypted header.
2. Control packet lengths are randomized with random length tail.
3. Control packets (healthcheck) sending time is random.

Following ways are yet to be implemented:

1. VPN packets sending via several "gateway" servers with different IPs, simulating `BitTorrent` protocol.
2. All ports and endpoint names are randomized.

The typical packet structure corresponds to special "wavy protocol" (described [right below](#wavy-messages)).
The only way to decrypt a packet is guessing `XChaCha20-Poly1305` key (32 bytes).
The only way to prove two messages use "wavy protocol" and belong to one user is either becoming a client of the same system as the user or intercepting 2 packets and guessing packet signature multiplier (8 bytes).

### Wavy messages

All the raw IP packets sent and received by the system (except for initial data exchange packets) have the following structure:

| Addition | Signature | Payload | Tail |
| --- | --- | --- | --- |
| 8 bytes | 8 bytes | (random) | (random) |

Packets can be `signed` and `unsigned`, `tailed` and `untailed`.
In order to encrypt the message, two 8-byte integers are required: `multiplier` and `zero_user_id`.
One important number is `max_prime` prime number, that is equal to $2^{64} - 59$.
For every packet, `addition` is a random number.

User ID is a 2-byte integer.
If packet is signed, `signature` can be calculated:

```math
((multiplier \cdot ((user\_id + zero\_user\_id) \bmod max\_prime)) + addition) \bmod max\_prime
```

For calculation of user ID having `signature` and `addition`, the following value is required: `unmultiplier`, that is modular multiplicative inverse of `multiplier`.
User ID can be calculated:

```math
(((unmultiplier \cdot (signature - addition)) \bmod max\_prime) - zero\_user\_id + max\_prime) \bmod max\_prime
```

Tail is expected only for control messages (because they usually have equal length that can be detected).
A special function has to be defined for tail length calculation: `bit_count`, that maps 64-bit integers to numbers of `1` in their binary representation.
Tail length can be calculated:

```math
bit\_count(zero\_user\_id \oplus addition) \bmod 64
```

> NB! For `XChaCha20-Poly1305` cipher, `addition` and `signature` bytes are included into nonce.

### Viridian to whirlpool connection

TODO: diagram.

> **NB!** Although the protocol is stateful, the current stateis not really important:
> viridian can re-connect to caerulean _any_ time it wants!

## Caerulean (server)

Caerulean is server side of Seaside VPN, it consists of several parts:

### Surface

🚧 Under construction! 🚧

### Whirlpool

See detailed documentation [here](./caerulean/whirlpool/README.md).

## Viridian (client)

Viridian is client side of Seaside VPN, there are several client options:

### Algae

See detailed documentation [here](./viridian/algae/README.md).

## General launching commands

Commands for all projects testing and linting are defined in root `Makefile`.
These are:

- ```bash
  make test
  ```

  for testing all system components.

- ```bash
  make lint
  ```

  for linting all system components.

## Future development

### Roadmap

- `caerulean/surface` - distributed node manager
- `viridian/...` - google chrome (and other browser) extension
- `viridian/...` - windows and linux GUI client ([wintun](https://git.zx2c4.com/wintun/about/) + [qt](https://www.qt.io/))
- `viridian/...` - android / ios clients

### TODOs

1. Add unit tests to both `caerulean/whirlpool` and `viridian/algae` (do not run them in Docker).
2. Write documentation for both `caerulean/whirlpool` and `viridian/algae`.
3. Remove all `(planned)` marks from READMEs.
4. Add shell build, generation, etc. script for easy `caerulean/whirlpool` deployment (with and without container).
5. Add clean make rule to clean docker images + networks.
6. Check control connections to whirlpool, maybe `http` package.
7. Move cli args to env vars
8. All errors to JoinError
9. Add image build target to whirlpool make.
10. Use http.Error in network.go.
11. Set GET and POST checks in GO.
12. Check other tools (nftables) / libs for server
13. Move some configs tp env
14. Check other tools (nftables) / libs for server
15. Whirlpool: -m limit tcp packet number (user number \* tcp method number \* tcp connection packets)
16. Move default params extraction to controller
17. Add "stress" profile with pumba on internal router for enhanced testing, use tcp echo server (can be found on dockerhub) (4 containrrs, no ext router).
18. Add "load" profile for direct access (3 containers) and multiple clients and performance analysis for whirlpool.
19. Replace array-buffers with REAL buffers in Go
20. Warning if packet is too large
21. GO: one type for many args
22. Parse tunnel properties in config contrutor
23. Check tunnel address (not in users list): IP and Gateway
24. Port numbers exchange (users to server, server to users)
25. Write script for downloading/running/configuring server
26. Control healthcheck times by cosine function, increase max delay to smth like 360 seconds, add random response delay
27. Addresses for VPN connection: black and white list (limit addresses to use VPN with) <- add traffic analysis tool to client
28. Advice on traffic distribution (proxy nodes), all routes and ports masking.
29. On caerulean side: switch to 10.x.x.x tunnel IP, 1st X will be the number of PROXY the acket has been received from
30. Protocol disguise: QOTD or any raw socket or data stream
31. Add RTP protocol disguise option (to obfuscation, sent by client)
32. In case of admin connection: require admin configuration file (with proxies, ports, etc.)
33. For connection: alias mapping (for all nodes) dict in YAML
34. Network center: for connection not only link, but also a special key is required. Without the key connection by IP only is impossible. Key is distributed alongside with network center IP and port and IS NEVER SHOWN TO PROVIDER AS PLAINTEXT. Connection request includes this key + proposed session key.
35. Create general functions for decryption+unmarshalling and encryption+marshalling for network.go ONLY
36. TEST LOCAL and GLOBAL python and go
37. Rewrite pythoon with async/await.

All user requests to control port encrypted with public key, all answers with session key.
Both requests and responses to sea port encrypted with session key.

Upon initialization make a file dump with all values generated -> volume
Logrus write to file?
Default vilumes in docker compose, default log level below info

Connection can be done via network surface or directly to a node (http://[NODE_IP]/auth)

### Considerations

1. Use a library for `iptables` management in `caerulean/whirlpool` - if some other types of operations (not adding) are required; same about `ip route` and regex in `whirlpool/console.go`.
   If so, consider also environment restoration in the end of main in `main.go`.

### Current goals

- Add healthcheck to all containers. Health chech special env var [here](https://ma.ttias.be/show-the-environment-variables-of-a-running-process-in-linux/) is a guide on how to do that.
- Add `try ... except ...` blocks for missing imports in `viridian/algae/script.py`
- Use monkeypatching to replace random bytes function with one returning zeros and random int with one returning const for easier message obfuscation testing.
- Pass `gravity` as an input parameter.
- Add "connection certificate" description to README.md.

### Dependencies

- `protoc` (can be installed via package manager, e.g. `apt install protobuf-compiler` for Ubuntu)
