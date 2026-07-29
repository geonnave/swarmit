"""Module containing the swarmit controller class."""

import dataclasses
import os
import threading
import time
from binascii import hexlify
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from dotbot_utils.protocol import Packet, Payload
from dotbot_utils.serial_interface import get_default_port
from rich import print
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from tqdm import tqdm

from swarmit.testbed.adapter import (
    DEVICE_CHUNK_RATE_HZ,
    OTA_DOWNLINK_UTILIZATION,
    GatewayAdapterBase,
    LinkGeometry,
    MarilibCloudAdapter,
    MarilibEdgeAdapter,
    derive_block_settings,
)
from swarmit.testbed.logger import LOGGER
from swarmit.testbed.ota import BLOCK_SIZE_DEFAULT, BlockTransfer
from swarmit.testbed.protocol import (
    BROADCAST_ADDRESS,
    LH2_FLAG_FROM_FLASH,
    LH2_FLAG_VALID,
    OTA_PROTOCOL_VERSION_BLOCK,
    OTA_PROTOCOL_VERSION_LEGACY,
    BootReason,
    DeviceType,
    FaultType,
    ImageResult,
    ImageState,
    PayloadCalibrationData,
    PayloadLH2Capture,
    PayloadMessage,
    PayloadOTAStart,
    PayloadRequestMessage,
    PayloadReset,
    PayloadStart,
    PayloadStop,
    PayloadType,
    StatusType,
    decode_cfsr,
    decode_reset_reason,
    decode_sfsr,
    decode_string_field,
)

CHUNK_SIZE = 128
COMMAND_TIMEOUT = 2
COMMAND_MAX_ATTEMPTS = 5
COMMAND_ATTEMPT_DELAY = 0.7
INACTIVE_TIMEOUT = 3  # s
STATUS_TIMEOUT = 2
MONITOR_TIMEOUT = 60  # s
OTA_MAX_RETRIES_DEFAULT = 10
OTA_ACK_TIMEOUT_DEFAULT = 0.7
# Shortest gap between two device-info broadcasts. One broadcast serves every
# stale bot at once - each answers in its own uplink cell - so this is a
# refresh rate for the whole fleet, not per device.
DEVICE_INFO_REFRESH_INTERVAL = 2.0  # s
# How many broadcasts a bot may ignore before it is written off as firmware
# that does not implement the message.
DEVICE_INFO_MAX_ATTEMPTS = 3
# How long `info` waits for replies when it asks explicitly.
DEVICE_INFO_TIMEOUT = 1.5  # s
SERIAL_PORT_DEFAULT = get_default_port()
VOLTAGE_MAX = 3000  # mV
VOLTAGE_FULL = 2900  # mV
VOLTAGE_WARNING = 1500  # mV


def _test_drop_chunks() -> set[int]:
    """Chunk indices to silently never transmit (fault injection).

    Set SWARMIT_OTA_TEST_DROP=200,201 to prove the finalize SHA256 rejects an
    incomplete image. This is a test seam, not configuration, which is why it
    lives in the environment and not in the settings file.
    """
    raw = os.environ.get("SWARMIT_OTA_TEST_DROP", "")
    return {int(x) for x in raw.split(",") if x.strip().lstrip("-").isdigit()}


class StaleBootloaderError(Exception):
    """Raised when a target bot's bootloader predates the block OTA protocol.

    Such a bot only speaks the retired per-chunk protocol, so it cannot be
    flashed over the air. Re-provision it over J-Link with
    ``dotbot device flash-swarmit-sandbox``.
    """

    def __init__(self, devices):
        self.devices = list(devices)
        super().__init__(
            f"{len(self.devices)} device(s) run a bootloader older than the "
            f"block OTA protocol: {', '.join(self.devices)}. Re-provision "
            "them with 'dotbot device flash-swarmit-sandbox'."
        )


@dataclass
class DeviceInfo:
    """What a bot reports it is running, decoded for display.

    Fetched once and cached; refreshed only when the status frame's
    generation counter stops matching `info_gen`.
    """

    info_version: int = 0
    info_gen: int = 0
    boot_count: int = 0
    uptime_s: int = 0
    boot_reason: int = 0
    bl_version: str = ""
    net_version: str = ""
    image_state: int = 0
    image_result: int = 0
    image_size: int = 0
    image_digest: str = ""  # hex, first 8 bytes of the image SHA256
    image_name: str = ""
    image_version: str = ""
    lh2_homography_count: int = 0
    lh2_flags: int = 0

    @classmethod
    def from_payload(cls, payload) -> "DeviceInfo":
        return cls(
            info_version=payload.info_version,
            info_gen=payload.info_gen,
            boot_count=payload.boot_count,
            uptime_s=payload.uptime_s,
            boot_reason=payload.boot_reason,
            bl_version=decode_string_field(payload.bl_version),
            net_version=decode_string_field(payload.net_version),
            image_state=payload.image_state,
            image_result=payload.image_result,
            image_size=payload.image_size,
            image_digest=bytes(payload.image_digest).hex(),
            image_name=decode_string_field(payload.image_name),
            image_version=decode_string_field(payload.image_version),
            lh2_homography_count=payload.lh2_homography_count,
            lh2_flags=payload.lh2_flags,
        )

    @property
    def image_label(self) -> str:
        """How to name this image in a table.

        The digest is the identity; the name is decoration that a bot flashed
        by an older controller simply does not have. Falling back to the
        digest keeps the column meaningful either way.
        """
        return self.image_name or self.image_digest[:16] or "-"

    @property
    def boot_reason_name(self) -> str:
        try:
            return BootReason(self.boot_reason).name
        except ValueError:
            return f"reason{self.boot_reason}"

    @property
    def image_state_name(self) -> str:
        try:
            return ImageState(self.image_state).name
        except ValueError:
            return f"state{self.image_state}"

    @property
    def image_result_name(self) -> str:
        try:
            return ImageResult(self.image_result).name
        except ValueError:
            return f"result{self.image_result}"

    @property
    def lh2_summary(self) -> str:
        if not self.lh2_homography_count:
            return "uncalibrated"
        noun = (
            "homography"
            if self.lh2_homography_count == 1
            else "homographies"
        )
        flags = []
        if self.lh2_flags & LH2_FLAG_VALID:
            flags.append("valid")
        if self.lh2_flags & LH2_FLAG_FROM_FLASH:
            flags.append("from flash")
        suffix = f" ({', '.join(flags)})" if flags else ""
        return f"{self.lh2_homography_count} {noun}{suffix}"


@dataclass
class NodeStatus:
    """Class that holds node status."""

    device: DeviceType = DeviceType.Unknown
    status: StatusType = StatusType.Bootloader
    battery: int = 0
    pos_x: int = 0
    pos_y: int = 0
    reset_reason: int = 0
    fault: int = 0
    from_ns: int = 0
    cfsr: int = 0
    sfsr: int = 0
    pc: int = 0
    lr: int = 0
    raw: str = ""  # hex of the full status packet as received
    last_updated_at: float = 0
    # Generation counter as of the most recent status frame. When it differs
    # from `info.info_gen` the cached block is stale and gets refetched.
    info_gen: int = 0
    info: DeviceInfo | None = None


@dataclass
class DataChunk:
    """Class that holds data chunks."""

    index: int
    size: int
    sha: bytes
    data: bytes


@dataclass
class StartOtaData:
    """Class that holds start ota data."""

    chunks: int = 0
    fw_hash: bytes = b""
    addrs: list[str] = dataclasses.field(default_factory=lambda: [])
    retries: int = 0


@dataclass
class Chunk:
    """Class that holds chunk status."""

    index: str = "0"
    size: str = "0B"
    acked: int = 0
    retries: int = 0

    def __repr__(self):
        return f"{dataclasses.asdict(self)}"


@dataclass
class TransferDataStatus:
    """Class that holds transfer data status for a single device."""

    chunks: list[Chunk] = dataclasses.field(default_factory=lambda: [])
    success: bool = False


@dataclass
class ResetLocation:
    """Class that holds reset location."""

    pos_x: int = 0
    pos_y: int = 0

    def __repr__(self):
        return f"(x={self.pos_x}, y={self.pos_y})"


def addr_to_hex(addr: int) -> str:
    """Convert an address to its hexadecimal representation."""
    return hexlify(addr.to_bytes(8, "big")).decode().upper()


def battery_level_color(level: int):
    if level > VOLTAGE_FULL:
        return "cyan"
    if level > VOLTAGE_WARNING:
        return "green"
    return "red"


# RESETREAS bit masks with a swarmit-specific meaning (see the bootloader's
# two watchdogs: WDT0 is the crash deadman the running app must pet, WDT1 is
# started by the stop command's DPPI path and nothing else).
_RR_WDT0 = 1 << 1  # crash / hang: app stopped petting the deadman
_RR_WDT1 = 1 << 25  # stop command (only thing that starts WDT1)
_RR_LOCKUP = 1 << 4
_RR_SREQ = 1 << 3  # soft reset: start_application or calibration-commit reboot
_RR_PIN = 1 << 0


def _fault_name(device_data) -> str:
    try:
        return FaultType(device_data.fault).name
    except ValueError:
        return f"fault{device_data.fault}"


def format_reset_cause(device_data) -> str:
    """Friendly one-line label for a node's last reset cause.

    Maps the raw RESETREAS + latched fault onto swarmit semantics. The raw
    values stay available in the inspect view for low-level debugging.
    """
    rr = device_data.reset_reason
    # Crash wins over everything: a stop racing a crash can set both bits.
    if device_data.fault or (rr & _RR_WDT0):
        # Surface the raw reset reason too (watchdog0 for the crash deadman,
        # lockup if the fault handler itself wedged) - it disambiguates the
        # crash path at a glance.
        reset_name = decode_reset_reason(rr)
        if device_data.fault:
            return (
                f"crashed ({reset_name} {_fault_name(device_data)} "
                f"pc=0x{device_data.pc:08x})"
            )
        return f"crashed ({reset_name})"
    if rr & _RR_WDT1:
        return "stopped"
    if rr & _RR_LOCKUP:
        return "lockup"
    if rr == 0 or (rr & _RR_PIN):
        return "power-on"
    if rr & _RR_SREQ:
        return "soft-reset"
    return decode_reset_reason(rr)


def reset_cause_color(device_data) -> str:
    if device_data.fault or (
        device_data.reset_reason & (_RR_WDT0 | _RR_LOCKUP)
    ):
        return "red"
    return "cyan"


def format_uptime(seconds: int) -> str:
    """Uptime as the operator reads it, not as a raw second count."""
    hours, rem = divmod(int(seconds), 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def image_mismatches(status_data) -> tuple[str, list[tuple[str, DeviceInfo]]]:
    """The fleet's majority image digest, and every device that differs.

    Comparison is on the digest, never the name: the name is display-only and
    two bots can carry the same label with different bytes. Devices that have
    not reported device info yet are not counted either way - unknown is not
    the same as different.
    """
    known = {
        addr: data.info
        for addr, data in status_data.items()
        if data.info is not None and data.info.image_digest
    }
    if len(known) < 2:
        return "", []
    counts: dict[str, int] = {}
    for info in known.values():
        counts[info.image_digest] = counts.get(info.image_digest, 0) + 1
    majority = max(counts, key=lambda digest: (counts[digest], digest))
    if counts[majority] == len(known):
        return majority, []
    odd = sorted(
        (
            (addr, info)
            for addr, info in known.items()
            if info.image_digest != majority
        ),
        key=lambda item: item[0],
    )
    return majority, odd


def generate_status(status_data, devices=[], status_message="found"):
    data = {
        addr: device_data
        for addr, device_data in status_data.items()
        if (devices and addr in devices) or (not devices)
    }
    if not data:
        return Group(Text(f"\nNo device {status_message}\n"))

    header = Text(
        f"\n{len(data)} device{'s' if len(data) > 1 else ''} {status_message}\n"
    )

    table = Table()
    table.add_column("Device Addr", style="magenta", no_wrap=True)
    table.add_column(
        "Type",
        style="cyan",
        justify="center",
    )
    table.add_column(
        "Battery",
        style="cyan",
        justify="center",
    )
    table.add_column(
        "Position",
        style="cyan",
        justify="center",
    )
    table.add_column(
        "Status",
        style="green",
        justify="center",
        width=max([len(m) for m in StatusType.__members__]),
    )
    table.add_column(
        "Image",
        style="cyan",
        justify="center",
    )
    table.add_column(
        "Last reset",
        style="cyan",
        justify="center",
    )
    majority, odd_ones = image_mismatches(data)
    odd_addrs = {addr for addr, _ in odd_ones}
    for device_addr, device_data in sorted(data.items()):
        info = device_data.info
        # "-" means the bot has not answered yet, which is what an older
        # bootloader looks like. It is deliberately not the same as a blank
        # name on a bot that did answer - that falls back to the digest.
        image = info.image_label if info else "-"
        if device_addr in odd_addrs:
            image = f"[yellow]{image}"

        table.add_row(
            f"{device_addr}",
            f"{device_data.device.name}",
            f"[{battery_level_color(device_data.battery)}]{device_data.battery / 1000:.2f}V ({int(device_data.battery / 3000 * 100)}%)",
            f"({device_data.pos_x}, {device_data.pos_y})",
            f"{'[bold cyan]' if device_data.status == StatusType.Running else '[bold green]'}{device_data.status.name}",
            image,
            f"[{reset_cause_color(device_data)}]{format_reset_cause(device_data)}",
        )
    if not odd_ones:
        return Group(header, table)

    # The point of putting a digest on the wire: the odd bot out surfaces
    # without an operator reading a hundred rows.
    plural = "s" if len(odd_ones) > 1 else ""
    lines = [
        Text(""),
        Text(
            f"! {len(odd_ones)} of {len(data)} device{plural} "
            f"differ{'' if len(odd_ones) > 1 else 's'} from the fleet majority:",
            style="yellow",
        ),
    ]
    for addr, info in odd_ones:
        label = f" ({info.image_name})" if info.image_name else ""
        lines.append(
            Text(
                f"    {addr}  image {info.image_digest[:16]}{label}, "
                f"majority is {majority[:16]}",
                style="yellow",
            )
        )
    return Group(header, table, *lines)


def generate_info(status_data, devices=[]):
    """Full per-device detail: every status field plus the raw crash report.

    The status table shows a friendly one-line reset cause; this dumps
    everything the bot reports - decoded and raw - for post-mortem of a
    specific robot.
    """
    data = {
        addr: device_data
        for addr, device_data in status_data.items()
        if (devices and addr in devices) or (not devices)
    }
    if not data:
        return Group(Text("\nNo matching device\n"))

    panels = [Text("")]
    for device_addr, d in sorted(data.items()):
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("field", style="bold cyan", no_wrap=True)
        table.add_column("value")

        table.add_row("Type", d.device.name)
        table.add_row("Status", d.status.name)
        table.add_row(
            "Battery",
            f"[{battery_level_color(d.battery)}]{d.battery / 1000:.2f}V "
            f"({int(d.battery / 3000 * 100)}%)",
        )
        table.add_row("Position", f"({d.pos_x}, {d.pos_y})")
        if d.last_updated_at:
            age = max(0.0, time.time() - d.last_updated_at)
            table.add_row("Last update", f"{age:.1f}s ago")

        if d.info is not None:
            info = d.info
            table.add_row("", "")
            table.add_row("Image", info.image_label)
            if info.image_version:
                table.add_row("  version", info.image_version)
            if info.image_digest:
                table.add_row("  digest", info.image_digest)
            if info.image_size:
                chunks = -(-info.image_size // CHUNK_SIZE)
                table.add_row(
                    "  size", f"{info.image_size} B ({chunks} chunks)"
                )
            table.add_row(
                "  state",
                f"{info.image_state_name} / {info.image_result_name}",
            )

            table.add_row("", "")
            table.add_row("Sandbox fw", f"bootloader  {info.bl_version}")
            table.add_row("", f"netcore     {info.net_version}")
            table.add_row("LH2 calibration", info.lh2_summary)
            table.add_row(
                "Uptime",
                f"{format_uptime(info.uptime_s)}   "
                f"(boot #{info.boot_count}, {info.boot_reason_name})",
            )

        table.add_row("", "")
        table.add_row(
            "Last reset",
            f"[{reset_cause_color(d)}]{format_reset_cause(d)}",
        )
        table.add_row(
            "  reset_reason",
            f"0x{d.reset_reason:08x} ({decode_reset_reason(d.reset_reason)})",
        )
        table.add_row(
            "  fault",
            f"{_fault_name(d)}"
            + (" (non-secure)" if d.fault and d.from_ns else "")
            + (" (secure)" if d.fault and not d.from_ns else ""),
        )
        if d.fault:
            cfsr_bits = decode_cfsr(d.cfsr)
            sfsr_bits = decode_sfsr(d.sfsr)
            table.add_row(
                "  cfsr",
                f"0x{d.cfsr:08x}" + (f" ({cfsr_bits})" if cfsr_bits else ""),
            )
            table.add_row(
                "  sfsr",
                f"0x{d.sfsr:08x}" + (f" ({sfsr_bits})" if sfsr_bits else ""),
            )
            elf = "app image" if d.from_ns else "bootloader image"
            table.add_row("  pc", f"0x{d.pc:08x}  (resolve against {elf})")
            table.add_row("  lr", f"0x{d.lr:08x}")

        if d.raw:
            spaced = " ".join(
                d.raw[i : i + 2] for i in range(0, len(d.raw), 2)
            )
            table.add_row("", "")
            table.add_row("Raw status pkt", spaced)
        panels.append(
            Panel(
                table,
                title=f"[bold magenta]{device_addr}[/]",
                title_align="left",
                border_style="cyan",
                padding=(0, 1),
                expand=False,
            )
        )
        panels.append(Text(""))
    return Group(*panels)


def print_transfer_status(
    status: dict[str, TransferDataStatus], start_data: int
) -> None:
    """Print the transfer status."""
    print()
    print("[bold]Transfer status:[/]")
    transfer_status_table = Table()
    transfer_status_table.add_column(
        "Device Addr", style="magenta", no_wrap=True
    )
    transfer_status_table.add_column(
        "Chunks acked", style="green", justify="center"
    )

    with Live(transfer_status_table, refresh_per_second=4) as live:
        live.update(transfer_status_table)
        for device_addr, status in sorted(status.items()):
            chunks_col_color = "[green]" if status.success else "[bold red]"
            transfer_status_table.add_row(
                f"{device_addr}",
                f"{chunks_col_color}{len([chunk for chunk in status.chunks if bool(chunk.acked)])}/{start_data.chunks}",
            )


def wait_for_done(timeout):
    """Wait for the condition to be met."""
    while timeout > 0:
        timeout -= 0.01
        time.sleep(0.01)
    return False


@dataclass
class ControllerSettings:
    """Class that holds controller settings."""

    serial_port: str = SERIAL_PORT_DEFAULT
    serial_baudrate: int = 1000000
    mqtt_host: str = "localhost"
    mqtt_port: int = 1883
    mqtt_use_tls: bool = False
    mqtt_username: str | None = None
    mqtt_password: str | None = None
    network_id: int = 1
    adapter: str = "serial"  # or "mqtt", "marilib-edge", "marilib-cloud"
    devices: list[str] = dataclasses.field(default_factory=lambda: [])
    map_size: str = "2500x2500"
    # in mm; 0 = infer from map_size as min(w, h) / 5
    calibration_distance: int = 0
    # OTA_START retry budget (the block transfer does its own repair rounds).
    ota_max_retries: int = OTA_MAX_RETRIES_DEFAULT
    ota_timeout: float = OTA_ACK_TIMEOUT_DEFAULT
    # Share of the gateway's downlink the OTA transfer may drive, and the
    # per-bot chunk-write ceiling. Together they set the chunk inject rate.
    ota_utilization: float = OTA_DOWNLINK_UTILIZATION
    ota_device_chunk_rate: float = DEVICE_CHUNK_RATE_HZ
    # Report-collection window in seconds; 0 derives it from the link geometry.
    # Too short and a report arriving after the broker round trip reads as
    # missing, costing a spurious repair round.
    ota_report_timeout: float = 0
    adapter_wait_timeout: float = 3
    verbose: bool = False


class Controller:
    """Class used to control a swarm testbed."""

    def __init__(self, settings: ControllerSettings):
        self.logger = LOGGER.bind(__context=__name__)
        self.settings = settings
        self._interface: GatewayAdapterBase = None
        self.status_data: dict[str, NodeStatus] = {}
        self.chunks: list[DataChunk] = []
        self.start_ota_data: StartOtaData = StartOtaData()
        self.transfer_data: dict[str, TransferDataStatus] = {}
        # OTA protocol version reported per bot in its OTA_START_ACK (1 = legacy
        # per-chunk, 2 = block/bitmap). Drives the transfer-path choice.
        self._ota_versions: dict[str, int] = {}
        # Active block transfer, so RX-thread report/finalize frames can be fed
        # into it. None outside a block-OTA transfer.
        self._block_transfer: BlockTransfer | None = None
        # Device-info cache, keyed by address. `_info_attempts` bounds how
        # often a bot that never answers is asked again: firmware predating
        # this message reports generation 0 forever, and without a cap that
        # would put a broadcast on the downlink every refresh interval for the
        # life of the session. The counter resets whenever a bot's generation
        # actually moves, so a re-flashed bot is probed afresh.
        self._device_info: dict[str, DeviceInfo] = {}
        self._info_attempts: dict[str, int] = {}
        self._info_gen_seen: dict[str, int] = {}
        self._info_last_broadcast: float = 0.0
        self._known_devices: dict[str, StatusType] = {}
        self._log_event_listeners: list = []
        self._log_listeners_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        if self.settings.adapter == "cloud":
            self._interface = MarilibCloudAdapter(
                self.settings.mqtt_host,
                self.settings.mqtt_port,
                self.settings.mqtt_use_tls,
                self.settings.network_id,
                verbose=self.settings.verbose,
                busy_wait_timeout=self.settings.adapter_wait_timeout,
                username=self.settings.mqtt_username,
                password=self.settings.mqtt_password,
            )
        else:
            self._interface = MarilibEdgeAdapter(
                self.settings.serial_port,
                self.settings.serial_baudrate,
                verbose=self.settings.verbose,
                busy_wait_timeout=self.settings.adapter_wait_timeout,
            )
        self._interface.init(self.on_frame_received)
        self._cleanup_thread.start()

    @property
    def known_devices(self) -> dict[str, StatusType]:
        """Return the known devices."""
        if not self._known_devices:
            wait_for_done(COMMAND_TIMEOUT)
            self._known_devices = self.status_data
        return self._known_devices

    @property
    def running_devices(self) -> list[str]:
        """Return the running devices."""
        return [
            addr
            for addr, node in self.known_devices.items()
            if (
                (
                    node.status == StatusType.Running
                    or node.status == StatusType.Programming
                )
                and (
                    not self.settings.devices or addr in self.settings.devices
                )
            )
        ]

    @property
    def resetting_devices(self) -> list[str]:
        """Return the resetting devices."""
        return [
            device_addr
            for device_addr, node in self.known_devices.items()
            if (
                node.status == StatusType.Resetting
                and (
                    not self.settings.devices
                    or device_addr in self.settings.devices
                )
            )
        ]

    @property
    def ready_devices(self) -> list[str]:
        """Return the ready devices."""
        return [
            device_addr
            for device_addr, node in self.known_devices.items()
            if (
                node.status == StatusType.Bootloader
                and (
                    not self.settings.devices
                    or device_addr in self.settings.devices
                )
            )
        ]

    @property
    def interface(self) -> GatewayAdapterBase:
        """Return the interface."""
        return self._interface

    def _cleanup_loop(self):
        while not self._stop_event.is_set():
            self.cleanup_inactive(INACTIVE_TIMEOUT)
            self._refresh_stale_device_info()
            time.sleep(1)

    def cleanup_inactive(self, timeout):
        now = time.time()
        inactive = [
            addr
            for addr, status in self.status_data.items()
            if now - status.last_updated_at > timeout
        ]
        for addr in inactive:
            del self.status_data[addr]
            self._device_info.pop(addr, None)
            self._info_attempts.pop(addr, None)
            self._info_gen_seen.pop(addr, None)

    def stale_device_info(self) -> list[str]:
        """Devices whose cached device info no longer matches their status.

        A bot is stale when it has never answered, or when the generation
        counter in its status frame has moved past the one its last reply
        carried. Bots that have ignored the request often enough to look like
        older firmware are excluded.
        """
        stale = []
        for addr, status in list(self.status_data.items()):
            cached = self._device_info.get(addr)
            if cached is not None and cached.info_gen == status.info_gen:
                continue
            if (
                self._info_attempts.get(addr, 0)
                >= DEVICE_INFO_MAX_ATTEMPTS
            ):
                continue
            stale.append(addr)
        return stale

    def _refresh_stale_device_info(self):
        """Ask the fleet for device info, but only when something changed.

        This is the whole point of the generation counter: in steady state
        nothing is stale and not a single packet goes out. A flash campaign or
        a reboot moves the counter and costs exactly one broadcast, which every
        stale bot answers in its own uplink cell.
        """
        stale = self.stale_device_info()
        if not stale:
            return
        now = time.time()
        if now - self._info_last_broadcast < DEVICE_INFO_REFRESH_INTERVAL:
            return
        self._info_last_broadcast = now
        for addr in stale:
            self._info_attempts[addr] = self._info_attempts.get(addr, 0) + 1
        try:
            self.request_device_info()
        except Exception:
            # The refresh runs on the cleanup thread; a transport hiccup here
            # must not take that thread down with it.
            self.logger.debug("device info refresh failed", exc_info=True)

    def request_device_info(self, devices=None):
        """Ask devices to emit their device-info block once.

        Broadcast by default: bots reply in their own uplink cells, so one
        request reaches the whole fleet for the cost of a single downlink
        packet.
        """
        payload = PayloadRequestMessage(
            msg_id=PayloadType.SWARMIT_DEVICE_INFO_RESP
        )
        if not devices:
            self.send_payload(BROADCAST_ADDRESS, payload)
            return
        for addr in devices:
            self.send_payload(int(addr, 16), payload)

    def fetch_device_info(
        self, devices=None, timeout=DEVICE_INFO_TIMEOUT
    ) -> dict[str, DeviceInfo]:
        """Request device info and wait for the replies to land.

        Used by the `info` command, which asks explicitly rather than waiting
        for the background refresh. Returns whatever arrived; a device that
        never answers is simply absent.
        """
        wanted = set(devices) if devices else set(self.status_data)
        # An explicit ask re-probes even a bot the background refresh has
        # written off, so a operator running `info` after re-flashing gets an
        # answer rather than the previous verdict.
        for addr in wanted:
            self._info_attempts.pop(addr, None)
        self.request_device_info(devices)
        deadline = time.time() + timeout
        while time.time() < deadline:
            # Waiting on "cached at all" would return immediately with the
            # entry from before the change; wait for the generation counters
            # to line up instead.
            if not wanted & set(self.stale_device_info()):
                break
            time.sleep(0.01)
        return {
            addr: info
            for addr, info in self._device_info.items()
            if addr in wanted
        }

    def terminate(self):
        """Terminate the controller."""
        self._stop_event.set()
        self._cleanup_thread.join()
        self.interface.close()

    def add_log_event_listener(self, callback) -> None:
        """Register `callback(event_dict)` for each SWARMIT_EVENT_LOG payload.

        The callback is invoked from the marilib RX thread, so it must
        not block. Listeners typically push the event into an
        asyncio.Queue (webserver) or queue.Queue (in-process client).
        """
        with self._log_listeners_lock:
            self._log_event_listeners.append(callback)

    def remove_log_event_listener(self, callback) -> None:
        with self._log_listeners_lock:
            try:
                self._log_event_listeners.remove(callback)
            except ValueError:
                pass

    def send_payload(self, destination: int, payload: Payload):
        """Send a frame to the devices."""
        self.interface.send_payload(destination, payload)

    def on_frame_received(self, header, packet: Packet):
        """Handle the received frame."""
        device_addr = f"{header.source:08X}"
        if packet.payload_type == PayloadType.SWARMIT_STATUS:
            now = time.time()
            status = NodeStatus(
                device=DeviceType(packet.payload.device),
                status=StatusType(packet.payload.status),
                battery=packet.payload.battery,
                pos_x=packet.payload.pos_x,
                pos_y=packet.payload.pos_y,
                reset_reason=packet.payload.reset_reason,
                fault=packet.payload.fault,
                from_ns=packet.payload.from_ns,
                cfsr=packet.payload.cfsr,
                sfsr=packet.payload.sfsr,
                pc=packet.payload.pc,
                lr=packet.payload.lr,
                raw=packet.to_bytes().hex(),
                last_updated_at=now,
                info_gen=packet.payload.info_gen,
                # Carried over rather than refetched: the block only changes
                # when the generation counter says it did.
                info=self._device_info.get(device_addr),
            )
            if self._info_gen_seen.get(device_addr) != status.info_gen:
                self._info_gen_seen[device_addr] = status.info_gen
                # Something changed on this bot, so it is worth asking again
                # even if it previously ignored us.
                self._info_attempts.pop(device_addr, None)
            self.status_data.update({device_addr: status})
        elif packet.payload_type == PayloadType.SWARMIT_DEVICE_INFO_RESP:
            info = DeviceInfo.from_payload(packet.payload)
            self._device_info[device_addr] = info
            self._info_attempts.pop(device_addr, None)
            if device_addr in self.status_data:
                self.status_data[device_addr].info = info
        elif packet.payload_type == PayloadType.SWARMIT_OTA_START_ACK:
            # A bootloader speaking the block protocol appends its version; a
            # legacy one sends the empty ack, which parses as version 1.
            self._ota_versions[device_addr] = getattr(
                packet.payload, "version", OTA_PROTOCOL_VERSION_LEGACY
            )
            if device_addr not in self.start_ota_data.addrs:
                self.start_ota_data.addrs.append(device_addr)
        elif packet.payload_type == PayloadType.SWARMIT_OTA_BLOCK_REPORT_RESP:
            if self._block_transfer is not None:
                self._block_transfer.on_report(
                    device_addr,
                    packet.payload.block_index,
                    packet.payload.received_mask,
                )
        elif packet.payload_type == PayloadType.SWARMIT_OTA_FINALIZE_RESP:
            if self._block_transfer is not None:
                self._block_transfer.on_finalize_resp(
                    device_addr, bool(packet.payload.ok)
                )
        elif packet.payload_type == PayloadType.SWARMIT_OTA_CHUNK_ACK:
            # Retired with the per-chunk path. Only a bootloader older than
            # this controller supports still sends these; parse and drop.
            self.logger.debug(
                "ignoring retired per-chunk ack",
                device_addr=device_addr,
                chunk_index=packet.payload.index,
            )
        elif packet.payload_type == PayloadType.SWARMIT_EVENT_LOG:
            if (
                self.settings.devices
                and device_addr not in self.settings.devices
            ):
                return
            logger = self.logger.bind(
                device_addr=device_addr,
                notification=PayloadType(packet.payload_type).name,
                timestamp=packet.payload.timestamp,
                data_size=packet.payload.count,
                data=packet.payload.data,
            )
            logger.info("LOG event")
            # Fan out to registered listeners (used by /events SSE in
            # daemon mode and LocalSwarmitClient.watch_log_events). Hex
            # the payload so it survives JSON round-tripping.
            event = {
                "addr": device_addr,
                "timestamp": packet.payload.timestamp,
                "data_size": packet.payload.count,
                "data_hex": bytes(packet.payload.data).hex(),
            }
            with self._log_listeners_lock:
                listeners = list(self._log_event_listeners)
            for cb in listeners:
                try:
                    cb(event)
                except Exception:
                    # never let a misbehaving listener kill the RX thread
                    pass

    def _live_status(self, timeout, devices=[], message="found", watch=False):
        """Request the live status of the testbed."""
        with Live(
            generate_status(self.status_data, devices, status_message=message),
            refresh_per_second=4,
        ) as live:
            while watch is True or timeout > 0:
                live.update(
                    generate_status(
                        self.status_data, devices, status_message=message
                    )
                )
                timeout -= 0.01
                time.sleep(0.01)

    def status(self, timeout=STATUS_TIMEOUT, watch=False):
        """Request the status of the testbed."""
        self._live_status(timeout, devices=self.settings.devices, watch=watch)

    def _send_start(self, device_addr: str):
        payload = PayloadStart()
        self.send_payload(int(device_addr, 16), payload)

    def start(self, devices=None, timeout=COMMAND_TIMEOUT):
        """Start the application."""
        if devices is None:
            devices = self.settings.devices or []
        ready_devices = self.ready_devices
        devices_to_start = (
            ready_devices
            if not devices
            else [d for d in devices if d in ready_devices]
        )
        attempts = 0
        while attempts < COMMAND_MAX_ATTEMPTS and not all(
            addr in self.status_data
            and self.status_data[addr].status == StatusType.Running
            for addr in devices_to_start
        ):
            if not devices:
                self._send_start(addr_to_hex(BROADCAST_ADDRESS))
            else:
                for device_addr in devices_to_start:
                    self._send_start(device_addr)
            attempts += 1
            time.sleep(COMMAND_ATTEMPT_DELAY)
        self._live_status(
            timeout, devices=devices_to_start, message="to start"
        )

    def stop(self, devices=None, timeout=COMMAND_TIMEOUT):
        """Stop the application."""
        if devices is None:
            devices = self.settings.devices or []
        stoppable_devices = self.running_devices + self.resetting_devices
        devices_to_stop = (
            stoppable_devices
            if not devices
            else [d for d in devices if d in stoppable_devices]
        )

        attempts = 0
        while attempts < COMMAND_MAX_ATTEMPTS and not all(
            self.status_data[addr].status
            in [StatusType.Stopping, StatusType.Bootloader]
            for addr in devices_to_stop
        ):
            if not devices:
                self.send_payload(BROADCAST_ADDRESS, PayloadStop())
            else:
                for device_addr in devices_to_stop:
                    self.send_payload(int(device_addr, 16), PayloadStop())
            attempts += 1
            time.sleep(COMMAND_ATTEMPT_DELAY)
        self._live_status(timeout, devices=devices_to_stop, message="to stop")

    def _send_reset(self, device_addr: int, location: ResetLocation):
        payload = PayloadReset(
            pos_x=location.pos_x,
            pos_y=location.pos_y,
        )
        self.send_payload(device_addr, payload)

    def reset(self, locations: dict[str, ResetLocation]):
        """Reset the application."""
        ready_devices = self.ready_devices
        for device_addr in self.settings.devices:
            if device_addr not in ready_devices:
                continue
            print(
                f"Resetting device {device_addr} with location {locations[device_addr]}"
            )
            self._send_reset(int(device_addr, 16), locations[device_addr])

    def monitor(
        self, timeout: float = MONITOR_TIMEOUT, run_forever: bool = True
    ):
        """Monitor the testbed."""
        self.logger.info("Monitoring testbed")
        while timeout > 0 or run_forever:
            time.sleep(0.01)
            timeout -= 0.01

    def _send_message(self, device_addr: int, message: str):
        payload = PayloadMessage(
            count=len(message),
            message=message.encode(),
        )
        self.send_payload(device_addr, payload)

    def send_message(self, message):
        """Send a message to the devices."""
        running_devices = self.running_devices
        if not self.settings.devices:
            self._send_message(BROADCAST_ADDRESS, message)
        else:
            for addr in self.settings.devices:
                if addr not in running_devices:
                    continue
                self._send_message(int(addr, 16), message)

    def send_lh2_calibration(self, calibration_file: bytes):
        matrix_size = 3 * 3 * 4  # 3x3, each element is 4 bytes (int32_t)
        if not calibration_file:
            raise ValueError("Calibration file is empty")

        # Supported format: 1-byte count + N * 36 bytes
        if (
            len(calibration_file) < 1
            or (len(calibration_file) - 1) % matrix_size != 0
        ):
            raise ValueError(
                f"Invalid calibration file size: expected 1+N*{matrix_size} bytes (count byte + matrices)"
            )

        homography_count = calibration_file[0]
        matrices_bytes = calibration_file[1:]
        expected_count = len(matrices_bytes) // matrix_size
        if homography_count != expected_count:
            raise ValueError(
                "Invalid calibration file: count byte does not match matrix payload length"
            )
        if homography_count == 0:
            raise ValueError(
                "Invalid calibration file: homography count cannot be zero"
            )

        if homography_count > 16:
            raise ValueError(
                "Invalid calibration file: homography count exceeds LH2 limit (16)"
            )

        ready_devices = self.ready_devices
        if not ready_devices:
            print(
                f"Sending {homography_count} calibration matrix/matrices to {BROADCAST_ADDRESS}..."
            )
        else:
            print(
                f"Sending {homography_count} calibration matrix/matrices to {len(ready_devices)} devices: {str(ready_devices)}..."
            )

        for homography_index in range(homography_count):
            print(f"Sending calibration matrix {homography_index}...")
            start = homography_index * matrix_size
            end = start + matrix_size
            payload = PayloadCalibrationData(
                homography_count=homography_count,
                homography_index=homography_index,
                homography=matrices_bytes[start:end],
            )
            if self.settings.verbose:
                print(payload)
                print(Packet.from_payload(payload).to_bytes())
            for _ in range(COMMAND_MAX_ATTEMPTS):
                # simple strategy to bypass non-reliable link layer, just send the payload multiple times
                if not ready_devices:
                    self.send_payload(BROADCAST_ADDRESS, payload)
                else:
                    for device_addr in ready_devices:
                        self.send_payload(int(device_addr, 16), payload)
                time.sleep(
                    0.3
                )  # give the device some time to process the payload

    def request_lh2_capture(self, device_addr: str):
        """Trigger a single raw LH2 capture on one device.

        The bot replies (only while READY) with a SWARMIT_EVENT_LOG whose
        payload starts with LH2_CALIB_TAG. Delivery is best-effort: callers
        await that log event and re-issue on timeout rather than relying on
        this single send.
        """
        self.send_payload(int(device_addr, 16), PayloadLH2Capture())

    def _send_start_ota(
        self,
        device_addr: str,
        devices_to_flash: set[str],
        firmware: bytes,
        image_name: str = "",
        image_version: str = "",
    ):
        def is_start_ota_acknowledged():
            if int(device_addr, 16) == BROADCAST_ADDRESS:
                return sorted(self.start_ota_data.addrs) == sorted(
                    devices_to_flash
                )
            else:
                return device_addr in self.start_ota_data.addrs

        payload = PayloadOTAStart(
            fw_length=len(firmware),
            fw_chunk_count=len(self.chunks),
            image_name=image_name,
            image_version=image_version,
        )
        send_time = time.time()
        send = True
        while (
            not is_start_ota_acknowledged()
            and self.start_ota_data.retries <= self.settings.ota_max_retries
        ):
            if send is True:
                self.send_payload(int(device_addr, 16), payload)
                send_time = time.time()
                self.start_ota_data.retries += 1
            time.sleep(0.001)
            send = time.time() - send_time > self.settings.ota_timeout

    def start_ota(
        self,
        firmware,
        devices=None,
        image_name: str = "",
        image_version: str = "",
    ) -> dict:
        """Start the OTA process.

        `image_name` and `image_version` are display-only labels the device
        stores alongside the image and reports back. They are never the basis
        of a decision - the digest is the identity - so leaving them empty
        costs only readability.
        """
        if devices is None:
            devices = self.settings.devices or []
        # Pad the image to a 4-byte boundary: the device writes flash a 32-bit
        # word at a time, so a final chunk whose length is not a multiple of 4
        # would drop its tail bytes and fail the whole-image FINALIZE check.
        # 0xFF is the erased-flash value, so the padding is a no-op on device.
        firmware = bytes(firmware)
        if len(firmware) % 4:
            firmware = firmware + b"\xff" * (4 - len(firmware) % 4)
        self.start_ota_data = StartOtaData()
        self._ota_versions = {}
        self.chunks = []
        digest = hashes.Hash(hashes.SHA256())
        chunks_count = int(len(firmware) / CHUNK_SIZE) + int(
            len(firmware) % CHUNK_SIZE != 0
        )
        for chunk_idx in range(chunks_count):
            if chunk_idx == chunks_count - 1:
                chunk_size = (
                    len(firmware) % CHUNK_SIZE
                    if len(firmware) % CHUNK_SIZE
                    else CHUNK_SIZE
                )
            else:
                chunk_size = CHUNK_SIZE
            data = firmware[
                chunk_idx * CHUNK_SIZE : chunk_idx * CHUNK_SIZE + chunk_size
            ]
            digest.update(data)
            chunk_sha = hashes.Hash(hashes.SHA256())
            chunk_sha.update(data)
            self.chunks.append(
                DataChunk(
                    index=chunk_idx,
                    size=chunk_size,
                    sha=chunk_sha.finalize()[
                        :8
                    ],  # the first 8 bytes should be enough
                    data=data,
                )
            )
        self.start_ota_data.fw_hash = digest.finalize()
        self.start_ota_data.chunks = len(self.chunks)
        devices_to_flash = self.ready_devices
        if not devices:
            print("Broadcast start ota notification...")
            self._send_start_ota(
                addr_to_hex(BROADCAST_ADDRESS),
                devices_to_flash,
                firmware,
                image_name,
                image_version,
            )
        else:
            for addr in devices:
                print(f"Sending start ota notification to {addr}...")
                self._send_start_ota(
                    addr, devices, firmware, image_name, image_version
                )
                time.sleep(0.2)
        return {
            "ota": self.start_ota_data,
            "acked": sorted(self.start_ota_data.addrs),
            "missed": sorted(
                set(devices).difference(set(self.start_ota_data.addrs))
            ),
        }

    @property
    def ota_block_size(self) -> int:
        """Chunks per block used by the OTA transfer."""
        return BLOCK_SIZE_DEFAULT

    def stale_bootloaders(self, devices) -> list[str]:
        """Devices whose OTA_START_ACK did not announce the block protocol.

        Their bootloader predates the block/bitmap path and only understands
        the retired per-chunk protocol. They cannot be flashed over the air by
        this controller; they need a re-provision over J-Link.
        """
        return sorted(
            addr
            for addr in devices
            if self._ota_versions.get(addr, OTA_PROTOCOL_VERSION_LEGACY)
            < OTA_PROTOCOL_VERSION_BLOCK
        )

    def transfer(
        self,
        firmware,
        devices,
        show_progress: bool = True,
    ) -> dict[str, TransferDataStatus]:
        """Transfer the firmware to the devices with the block/bitmap protocol.

        `show_progress` controls the built-in tqdm bar. Clients that render
        their own progress (e.g. the daemon's /flash/stream or
        LocalSwarmitClient.flash) pass False to avoid duplicate output.

        Raises ``StaleBootloaderError`` if any target bot still runs a
        pre-block bootloader, before a single chunk goes on the wire.
        """
        stale = self.stale_bootloaders(devices)
        if stale:
            self.logger.error(
                "ota aborted: stale bootloaders",
                devices=stale,
                required_version=OTA_PROTOCOL_VERSION_BLOCK,
            )
            raise StaleBootloaderError(stale)
        data_size = len(firmware)
        use_progress_bar = show_progress and not self.settings.verbose
        progress = None
        if use_progress_bar:
            progress = tqdm(
                range(0, data_size),
                unit="B",
                unit_scale=False,
                colour="green",
                ncols=100,
            )
            progress.set_description(
                f"Loading firmware ({int(data_size / 1024)}kB, block OTA)"
            )

        self.transfer_data = {}
        for _addr in devices:
            self.transfer_data[_addr] = TransferDataStatus()
            self.transfer_data[_addr].chunks = [
                Chunk(index=f"{i:03d}", size=f"{self.chunks[i].size:03d}B")
                for i in range(len(self.chunks))
            ]

        def on_progress(addr: str, chunk_index: int) -> None:
            td = self.transfer_data.get(addr)
            if td is None or chunk_index >= len(td.chunks):
                return
            chunk = td.chunks[chunk_index]
            if not chunk.acked:
                chunk.acked = 1
                if progress is not None:
                    progress.update(self.chunks[chunk_index].size)

        broadcast = not self.settings.devices
        drop_chunks = _test_drop_chunks()
        if drop_chunks:
            self.logger.warning(
                "ota test: dropping chunks", chunks=sorted(drop_chunks)
            )
        # Pacing comes from the link the gateway reports; the adapter owns that
        # derivation because it owns everything radio-shaped.
        geometry = self.interface.link_geometry()
        if geometry is None:
            self.logger.warning(
                "ota pacing: gateway has not reported a schedule, "
                "using the fallback",
                schedule=LinkGeometry.fallback().schedule_name,
            )
        settings = derive_block_settings(
            geometry,
            len(devices),
            self.settings.ota_utilization,
            self.settings.ota_device_chunk_rate,
        )
        if self.settings.ota_report_timeout:
            settings.report_timeout = self.settings.ota_report_timeout
        transfer = BlockTransfer(
            chunks=self.chunks,
            devices=list(devices),
            send_payload=self.send_payload,
            image_sha=self.start_ota_data.fw_hash,
            settings=settings,
            broadcast=broadcast,
            on_progress=on_progress,
            logger=self.logger,
            drop_chunks=drop_chunks,
        )
        self.logger.info(
            "ota transfer start",
            image_bytes=data_size,
            total_chunks=len(self.chunks),
            schedule=(geometry or LinkGeometry.fallback()).schedule_name,
            block_size=settings.block_size,
            inter_chunk_ms=round(settings.inter_chunk_delay * 1000, 1),
            report_timeout_ms=round(settings.report_timeout * 1000, 1),
            devices=len(devices),
        )
        self._block_transfer = transfer
        start_ts = time.time()
        try:
            results = transfer.run()
        finally:
            self._block_transfer = None
        elapsed = time.time() - start_ts
        if progress is not None:
            progress.close()

        for addr, result in results.items():
            td = self.transfer_data.get(addr)
            if td is not None:
                td.success = result.success
        delivered = sum(r.confirmed_chunks for r in results.values())
        waste = transfer.chunk_sends / delivered if delivered else 0
        rate = delivered / elapsed if elapsed else 0
        failed = {a: r for a, r in results.items() if not r.success}
        self.logger.info(
            "ota transfer complete",
            elapsed_s=round(elapsed, 2),
            chunk_sends=transfer.chunk_sends,
            delivered=delivered,
            waste_ratio=round(waste, 2),
            chunk_per_s=round(rate, 2),
            ok=not failed,
            failed_devices=len(failed),
        )
        # Genuine failures (finalize SHA did not match, or no finalize response)
        # are surfaced at WARNING so they reach the console too, with the missing
        # chunk list for diagnosis.
        for addr, result in failed.items():
            missing = transfer.missing_chunks(addr)
            self.logger.warning(
                "ota device failed",
                addr=addr,
                confirmed=result.confirmed_chunks,
                total=result.total_chunks,
                finalized=result.finalized,
                straggler=result.straggler,
                missing_count=len(missing),
                missing_chunks=missing[:64],
            )
        # Image is good (finalize passed) but the delivery bitmap under-counted -
        # a sign the report path churned under load. Not a failure, but worth a
        # breadcrumb for tuning.
        for addr, result in results.items():
            if (
                result.success
                and result.confirmed_chunks < result.total_chunks
            ):
                self.logger.info(
                    "ota bitmap under-tracked",
                    addr=addr,
                    confirmed=result.confirmed_chunks,
                    total=result.total_chunks,
                )
        return self.transfer_data
