# Caerulean Whirlpool

> Target platform: _linux_ only

Whirlpool program is written in Go language.  
It manages encrypting, decrypting, assembling and transferring requests and responses.

Whirlpool accepts client packages at UDP port 8542, no more than 2000 bytes in size, encrypted.  

Whirlpool sends messages to UDP port 8542, in packets of size 2000, encrypted.

> WARNING! Any UDP packets arriving to port 8542 will be treated as user packets, i.e. user should never send packets to port 8542 of any server via Seaside VPN!

## Configuration

> Required packages: `iptables`, `ip`

The executable file can be produced with this command:

```bash
make -C caerulean/whirlpool build [EXECUTABLE_NAME=<executable_file_name>]
```

the executable file can be found under `caerulean/whirlpool/build` root.
The executable requires superuser rights to be launched for tunnel interface creation.

It can be run with following arguments:

- `-a <internal_address>` - **internal** IP address: the IP address that will be used to listen to user events (required!).
- `-e <external_address>` - **external** IP address: the IP address that will be used to forward user packets to, most commonly, interntet (default: same as _<internal_address>_).
- `-p <sea_port>` - seaside port: the port that will be used for exchanging data packets with user (default: 8542).
- `-c <control_port>` - control port: the port that will be used for control communication with user (default: 8543).
- `-t <user_time_to_live>` - time after that inactive user record will be deleted from server, in minutes (default: 300).
- `-u <max_user_limit>` - maximum amout of users that can be simultaneously connected to the node (default: 16).

It also sensitive to the following environmental variable:

- `LOG_LEVEL` - the output verbosity level, can be "panic", "fatal", "error", "warning", "info", "debug", "trace" (default: "WARNING").

## Run whirlpool

- Run whirlpool (with default params):

  ```bash
  make -C caerulean/whirlpool run 
  ```

  localhost address will be used for both input and output.

- Lint and format golang files:

  ```bash
  make -C caerulean/whirlpool lint
  ```

- Restore `iptables` configuration after run:

  ```bash
  make -C caerulean/whirlpool restore
  ```

- Clean build artifacts:

  ```bash
  make -C caerulean/whirlpool clean
  ```

## Time diagram

```mermaid
sequenceDiagram
    actor Client
    box Caerulean
    participant Input as Caerulean UDP port 8542
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
