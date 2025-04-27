from asyncio import sleep
from contextlib import asynccontextmanager
from ctypes import CDLL, Structure, byref, c_int, c_uint32, get_errno
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address
from json import dumps, loads
from os import environ, strerror
from pathlib import Path
from subprocess import CalledProcessError, Popen, PIPE, run
from sys import executable
from threading import Event
from time import time
from typing import AsyncIterator, Callable, List, Optional, Tuple

from ipywidgets import Password, Button, Output
from IPython.display import display
from matplotlib import pyplot as plt
from matplotlib.patches import Patch
from scapy.all import AsyncSniffer, PacketList, Packet
from scapy.layers.inet import UDP, IP

from sources.utils.crypto import Asymmetric, Symmetric
from sources.protocol.utils import ProtocolFlag
from sources.protocol import SeasideClient


# Constants

LIBC = CDLL(None, use_errno=True)

ASYMMETRIC = Asymmetric()
LISTENER_KEY = ASYMMETRIC._private_key + ASYMMETRIC._public_key
CLIENT_KEY = ASYMMETRIC._public_key
USER_TOKEN = b"Random user token!"

PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
CAP_NET_ADMIN = 12
CAP_VERSION = 0x19980330
CAPABILITY_U32S = 2


# Enums and classes:

class CapHeader(Structure):
    _fields_ = [("version", c_uint32), ("pid", c_int)]

class CapData(Structure):
    _fields_ = [("effective", c_uint32), ("permitted", c_uint32), ("inheritable", c_uint32)]


@dataclass
class ColorInfo:
    color: str
    description: str


class ColorGroup(Enum):
    UNKNOWN_CLIENT = ColorInfo("#BDBDBD", "Unknown packet (apparently from client)")
    UNKNOWN_ANY = ColorInfo("#757575", "Unknown packet (sender unknown)")
    UNKNOWN_SERVER = ColorInfo("#424242", "Unknown packet (apparently from server)")
    TERMINATION_CLIENT = ColorInfo("#FF8A80", "Termination packet (from client)")
    TERMINATION_SERVER = ColorInfo("#C62828", "Termination packet (from server)")
    DATA_CLIENT = ColorInfo("#A5D6A7", "Data packet (from client)")
    DATA_SERVER = ColorInfo("#1B5E20", "Data packet (from server)")
    SHADOWRIDE_CLIENT = ColorInfo("#CE93D8", "Shadowride packet (from client)")
    SHADOWRIDE_SERVER = ColorInfo("#4A148C", "Shadowride packet (from server)")
    HANDSHAKE_CLIENT = ColorInfo("#FFCC80", "Handshake packet (from client)")
    HANDSHAKE_SERVER = ColorInfo("#E65100", "Handshake packet (from server)")
    INITIAL_CLIENT = ColorInfo("#81D4FA", "Initial packet (from client)")
    INITIAL_SERVER = ColorInfo("#01579B", "Initial packet (from server)")


@dataclass
class SnifferWrapper:
    sniffer: AsyncSniffer
    server_address: IPv4Address
    client_address: IPv4Address


@dataclass
class VisualConf:
    pass


@dataclass
class PlotConf(VisualConf):
    expand_time: bool = True
    spread_mult: float = 3.0


@dataclass
class GraphConf(VisualConf):
    pass


class SequenceConfig:
    @classmethod
    def base_delay(cls) -> float:
        return float(environ["TYPHOON_MAX_NEXT_IN"]) + float(environ["TYPHOON_MAX_TIMEOUT"])

    def __init__(self, message: str = "Sequence message!", messages: int = 8, print_every: int = 1, start_from: int = 1, quiet: bool = False, client_sequence: Optional[Callable[[float], float]] = None, server_sequence: Optional[Callable[[int], float]] = None) -> None:
        self._messages_limit = messages
        self._client_messages_received = 0
        self._server_messages_received = 0
        self._sequence_message = message
        self._print_every = print_every
        self._start_from = start_from
        self._quiet = quiet
        self._client_sequence = self._generate_sequence() if client_sequence is None else client_sequence
        self._server_sequence = self._generate_sequence(0) if server_sequence is None else server_sequence

    def _generate_sequence(self, base_delay: Optional[float] = None, modifier: float = 0.01) -> Callable[[float], float]:
        base_delay = self.base_delay() if base_delay is None else base_delay
        def sequence(delay: float) -> float:
            return base_delay * (1 + delay * modifier)
        return sequence

    def _print(self, will_print: bool, message: str) -> None:
        if not self._quiet and will_print:
            print(message)

    def _encode_message(self, iteration: int) -> bytes:
        return dumps({"num": iteration, "data": self._sequence_message}).encode()

    def _decode_message(self, message: bytes) -> int:
        return loads(message.decode())["num"]

    async def seq_client_callback(self, message: bytes) -> None:
        self._client_messages_received += 1
        will_print = self._client_messages_received % self._print_every == 0
        self._print(will_print, f"Message returned: {self._decode_message(message) + 1} ({self._client_messages_received})")
    
    async def seq_server_callback(self, _: int, message: bytes) -> bytes:
        self._server_messages_received += 1
        will_print = self._server_messages_received % self._print_every == 0
        self._print(will_print, f"Message received: {self._decode_message(message) + 1} ({self._server_messages_received})")
        await sleep(self._server_sequence(self._server_messages_received))
        return message
    
    async def process(self, client: SeasideClient) -> None:
        messages_sent = 0
        delay = self._start_from
        while messages_sent < self._messages_limit:
            delay = self._client_sequence(delay)
            await client.write(self._encode_message(messages_sent))
            will_print = messages_sent % self._print_every == 0
            self._print(will_print, f"Message sent: {messages_sent + 1}/{self._messages_limit}, next in {delay}")
            await sleep(delay)
            messages_sent += 1


# Private functions:

def _get_packet_data(packet: Packet) -> bytes:
    return bytes(packet[UDP].payload)


def _decode_packet(packet: bytes, sender: str, client: str, server: str) -> Tuple[int, ColorInfo]:
    flags = packet[0]
    if flags == ProtocolFlag.INIT:
        if sender == client:
            color = ColorGroup.INITIAL_CLIENT.value
        elif sender == server:
            color = ColorGroup.INITIAL_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    elif flags == ProtocolFlag.HDSK:
        if sender == client:
            color = ColorGroup.HANDSHAKE_CLIENT.value
        elif sender == server:
            color = ColorGroup.HANDSHAKE_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    elif flags == ProtocolFlag.HDSK | ProtocolFlag.DATA:
        if sender == client:
            color = ColorGroup.SHADOWRIDE_CLIENT.value
        elif sender == server:
            color = ColorGroup.SHADOWRIDE_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    elif flags == ProtocolFlag.DATA:
        if sender == client:
            color = ColorGroup.DATA_CLIENT.value
        elif sender == server:
            color = ColorGroup.DATA_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    elif flags == ProtocolFlag.TERM:
        if sender == client:
            color = ColorGroup.TERMINATION_CLIENT.value
        elif sender == server:
            color = ColorGroup.TERMINATION_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    else:
        if sender == client:
            color = ColorGroup.UNKNOWN_CLIENT.value
        elif sender == server:
            color = ColorGroup.UNKNOWN_SERVER.value
        else:
            color = ColorGroup.UNKNOWN_ANY.value
    return len(packet), color


def _get_packet_times(packets: PacketList, start_time: float) -> List[int]:
    return [int((start_time - p.time) * 1000) for p in packets]


def _parse_packets(packets: PacketList, client: str, server: str) -> List[Tuple[int, ColorInfo]]:
    packet_lengths = list()

    while True:
        try:
            key, data = ASYMMETRIC.decrypt(_get_packet_data(packets[0]))
            packet_lengths += [_decode_packet(data, packets[0][IP].src, client, server)]
            symmetric = Symmetric(key)
            break
        except ValueError:
            packet_lengths += [(len(packets[0]) - ASYMMETRIC.ciphertext_overhead, ColorGroup.UNKNOWN_CLIENT.value)]

    for packet in packets[1:]:
        try:
            data = symmetric.decrypt(_get_packet_data(packet))
            packet_lengths += [_decode_packet(data, packet[IP].src, client, server)]
        except ValueError:
            packet_lengths += [(len(packet) - symmetric.ciphertext_overhead, ColorGroup.UNKNOWN_ANY.value)]
    return packet_lengths


def _bin_pack_packets(length_color_pairs: List[Tuple[int, ColorInfo]], timestamps: List[int], spread_mult: float) -> Tuple[List[int], List[str]]:
    previous_timestamp = min(timestamps)
    communication_time = previous_timestamp - max(timestamps)
    empty_packets = len(length_color_pairs) * spread_mult

    lengths, colors = list(), list()
    for offset, (length, color) in zip(timestamps, length_color_pairs):
        difference = offset - previous_timestamp
        for i in range(int(empty_packets * (difference / communication_time))):
            lengths.append(0)
            colors.append("none")
        lengths.append(length)
        colors.append(color.color)
        previous_timestamp = offset

    return lengths, colors


def _run_command(command: str, check: bool = True) -> None:
    try:
        run(command, shell=True, text=True, check=check, capture_output=True)
    except CalledProcessError as e:
        print(f"Command '{e.cmd}' exited with error code {e.returncode}:\n\nSTDOUT:\n{e.stdout}\n\nSTDERR:\n{e.stderr}")
        raise e


def _teardown_network(client_interface: str, server_interface: str, full: bool = True) -> None:
    for iface in [client_interface, server_interface]:
        if full:
            _run_command(f"ip addr flush dev {iface}")
            _run_command(f"ip link set {iface} down")
    _run_command(f"ip link del {client_interface}", check=full)


def _setup_network(client_interface: str, server_interface: str, client_ip: str, server_ip: str, cidr: int = 32) -> None:
    _teardown_network(client_interface, server_interface, False)
    _run_command(f"ip link add {client_interface} type veth peer name {server_interface}")
    for iface, addr in [(client_interface, client_ip), (server_interface, server_ip)]:
        _run_command(f"ip link set {iface} up")
        _run_command(f"ip addr add {addr}/{cidr} dev {iface}")


def _teardown_traffic_control(interface: str, full: bool = True) -> None:
    if full:
        _run_command(f"tc filter del dev {interface} parent 1:0")
    _run_command(f"tc qdisc del dev {interface} root handle 1: prio", check=full)


def _setup_traffic_control(tc_config: str, interface: str, client_ip: str, server_ip: str) -> None:
    _run_command(f"tc qdisc add dev {interface} root handle 1: prio")
    _run_command(f"tc qdisc add dev {interface} parent 1:3 handle 30: netem {tc_config}")
    for src, dst in [(client_ip, server_ip), (server_ip, client_ip)]:
        _run_command(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip protocol 17 0xff match ip src {src}/32 match ip dst {dst}/32 flowid 1:3")


# Public functions:

def configure_ambient_permissions() -> None:
    idx = CAP_NET_ADMIN // 32
    bit = 1 << (CAP_NET_ADMIN % 32)
    header = CapHeader(version=CAP_VERSION, pid=0)
    data = (CapData * CAPABILITY_U32S)()

    if LIBC.capget(byref(header), data) != 0:
        raise OSError("Error receiving current process capabilities!", strerror(get_errno()))
    if not (data[idx].permitted & bit):
        raise PermissionError(f"Capability CAP_NET_ADMIN not in permitted set")

    data[idx].inheritable |= bit
    if LIBC.capset(byref(header), data) != 0:
        raise OSError("Error adding CAP_NET_ADMIN to inheritable set!", strerror(get_errno()))

    result = LIBC.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0)
    if result != 0:
        raise OSError("Error raising CAP_NET_ADMIN to ambient set!", strerror(get_errno()))

    print(f"Capabilities set successfully!")


def toggle_network_permissions(grant: bool) -> None:
    operator = "+" if grant else "-"
    action = "granting" if grant else "removing"
    python_command = f"sudo -S setcap cap_net_admin,cap_net_raw{operator}epi {Path(executable).resolve()}"

    hidden_text_input = Password(description="Enter Secret:")
    submit_button = Button(description="Submit")
    cancel_button = Button(description="Cancel")
    output = Output()

    def show_result(message: str) -> None:
        hidden_text_input.close()
        submit_button.close()
        cancel_button.close()
        print(message)

    def grant_permissions(executable: str, command: str) -> None:
        process = Popen(command, shell=True, text=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        password = hidden_text_input.value
        process.stdin.write(f"{password}\n")
        process.stdin.flush()
        stdout, stderr = process.communicate()
        exit_code = process.returncode
        if exit_code != 0:
            show_result(f"Permission {action} error to '{executable}'! You might want to rerun this cell.\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
        elif grant:
            show_result(f"Permissions granted to '{executable}'! Restart kernel for them to take effect!")
        else:
            show_result(f"Permissions removed from '{executable}'!")

    @output.capture()
    def communicate(_) -> None:
        grant_permissions("python", python_command)

    @output.capture()
    def cancel(_) -> None:
        show_result(f"Permission {action} cancelled. Some of the cells might not work!")

    submit_button.on_click(communicate)
    cancel_button.on_click(cancel)
    display(hidden_text_input, submit_button, cancel_button, output)


def show_packet_graph(packets: PacketList, client: str, server: str, start_time: Optional[float] = None, config: PlotConf = PlotConf()) -> None:
    start_time = time() if start_time is None else start_time
    packets = list({bytes(p): p for p in packets}.values())

    timestamps = _get_packet_times(packets, start_time)
    length_color_pairs = _parse_packets(packets, client, server)
    legend_elements = [Patch(facecolor=group.value.color, label=group.value.description) for group in ColorGroup]
    if config.expand_time:
        lengths, colors = _bin_pack_packets(length_color_pairs, timestamps, config.spread_mult)
    else:
        lengths, colors = zip(*[(l, c.color) for l, c in length_color_pairs])

    plt.figure(figsize=(12, 6))
    plt.bar(range(len(lengths)), lengths, color=colors)
    if config.expand_time:
        x_ticks_indexes = [t * (config.spread_mult + 1) for t in range(len(timestamps))]
        plt.xticks(ticks=x_ticks_indexes, labels=[f"-{t}ms" for t in timestamps], rotation=30)
    plt.xlabel("Packet Time" if config.expand_time else "Packet Number")
    plt.ylabel("Payload Size (bytes)")
    plt.title("Packet Payload Sizes Over Time")
    plt.legend(handles=legend_elements, bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.show()


def show_sequence_graph(packets: PacketList, client: str, server: str, start_time: Optional[float] = None, config: GraphConf = GraphConf()) -> None:
    start_time = time() if start_time is None else start_time
    packets = list({bytes(p): p for p in packets}.values())
    timestamps = _get_packet_times(packets, start_time)
    elements = [f"{c.description}, {l} bytes" for l, c in _parse_packets(packets, client, server)]

    y_step = 0.5
    positions = {"Client": 1, "Server": 5}
    y_start = y_step * (len(elements) + 1)

    _, ax = plt.subplots(figsize=(10, 5))
    ax.set_xlim(0, 6)
    ax.set_ylim(0, y_start)
    ax.axis("off")

    for name, x in positions.items():
        ax.text(x, y_start + 0.2, name, ha="center", fontsize=12)
        ax.plot([x, x], [0, y_start], linestyle="dashed", color="gray")

    for i, (msg, temp) in enumerate(zip(elements, timestamps)):
        y = y_start - (i + 1) * y_step
        x_start, x_end = (1, 5) if "from client" in msg else (5, 1)
        dx = x_end - x_start
        ax.arrow(x_start, y, dx, 0, head_width=0.1, head_length=0.15, length_includes_head=True, fc="black", ec="black")
        ax.text((x_start + x_end) / 2, y + 0.05, msg, ha="center", fontsize=10)
        ax.text((x_start + x_end) / 2, y - 0.15, f"-{temp}ms", ha="center", fontsize=10)

    plt.tight_layout()
    plt.show()


# Context managers:

@asynccontextmanager
async def sniff(visual_conf: Optional[VisualConf] = None, tc_config: Optional[str] = None, template_interface: str = "vethest", template_address: str = "192.168.111", effective_interface: str = "lo") -> AsyncIterator[SnifferWrapper]:
    server_interface, client_interface = f"{template_interface}0", f"{template_interface}1"
    server_address, client_address = f"{template_address}.1", f"{template_address}.2"

    try:
        _teardown_traffic_control(effective_interface, False)
        _setup_network(client_interface, server_interface, client_address, server_address)
        if tc_config is not None:
            _setup_traffic_control(tc_config, effective_interface, client_address, server_address)

        started = Event()
        filter = f"udp and ((src host {server_address} and dst host {client_address}) or (src host {client_address} and dst host {server_address}))"
        sniffer = AsyncSniffer(iface=effective_interface, filter=filter, store=True, started_callback=lambda: started.set())
        wrapper = SnifferWrapper(sniffer=sniffer, server_address=IPv4Address(server_address), client_address=IPv4Address(client_address))

        try:
            sniffer.start()
            started.wait()
            yield wrapper
        finally:
            await sleep(0.1)
            packets = sniffer.stop(True)
            if isinstance(visual_conf, PlotConf):
                show_packet_graph(sniffer.results, client_address, server_address, config=visual_conf)
            elif isinstance(visual_conf, GraphConf):
                show_sequence_graph(sniffer.results, client_address, server_address, config=visual_conf)
            else:
                print(f"Sniffer captured {len(packets)} TYPHOON packets!")

    finally:
        if tc_config is not None:
            _teardown_traffic_control(effective_interface)
        _teardown_network(client_interface, server_interface)
