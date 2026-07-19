"""Swarmit protocol definition."""

import dataclasses
from dataclasses import dataclass
from enum import Enum, IntEnum

from dotbot_utils.protocol import (
    Payload,
    PayloadFieldMetadata,
    register_parser,
)
from marilib.mari_protocol import DefaultPayloadType as MariDefaultPayloadType
from marilib.mari_protocol import MetricsProbePayload


class StatusType(Enum):
    """Types of device status."""

    Bootloader = 0
    Running = 1
    Stopping = 2
    Resetting = 3
    Programming = 4


class DeviceType(Enum):
    """Types of devices."""

    Unknown = 0
    DotBotV3 = 1
    DotBotV2 = 2
    nRF5340DK = 3
    nRF52840DK = 4


class PayloadType(IntEnum):
    """Types of DotBot payload types."""

    # Requests
    SWARMIT_STATUS = 0x80
    SWARMIT_START = 0x81
    SWARMIT_STOP = 0x82
    SWARMIT_RESET = 0x83
    SWARMIT_OTA_START = 0x84
    SWARMIT_OTA_CHUNK = 0x85
    SWARMIT_OTA_START_ACK = 0x86
    SWARMIT_OTA_CHUNK_ACK = 0x87
    SWARMIT_EVENT_GPIO = 0x88
    SWARMIT_EVENT_LOG = 0x89
    # Block-OTA (fast OTA) additions. Host -> device: report request and
    # finalize; device -> host: report response and finalize response.
    SWARMIT_OTA_BLOCK_REPORT_REQ = 0x8A
    SWARMIT_OTA_BLOCK_REPORT_RESP = 0x8B
    SWARMIT_OTA_FINALIZE = 0x8C
    SWARMIT_OTA_FINALIZE_RESP = 0x8D

    # Custom messages
    SWARMIT_MESSAGE = 0xA0

    # SwarmIT calibration data
    SWARMIT_LH2_CALIBRATION = 0xA1
    # Host -> node: trigger a raw LH2 capture (READY mode only)
    SWARMIT_LH2_CAPTURE = 0xA2

    # Marilib metrics probe
    METRICS_PROBE = MariDefaultPayloadType.METRICS_PROBE


# OTA protocol version reported by a bootloader in its OTA_START_ACK. Version 1
# is the legacy per-chunk stop-and-wait path (no version byte on the wire, so it
# parses as 1); version 2 is the block/bitmap-NACK path. The controller uses the
# block path only with the subset of bots that report version >= 2.
OTA_PROTOCOL_VERSION_LEGACY = 1
OTA_PROTOCOL_VERSION_BLOCK = 2


# First byte of a raw LH2 capture sample carried inside a SWARMIT_EVENT_LOG
# payload. Mirrors SWRMT_LH2_CALIB_TAG in the swarmit bootloader firmware; lets
# the host tell a calibration sample apart from a regular text log line. Each
# sample that follows is [lh_index:1][count1:4 LE][count2:4 LE].
LH2_CALIB_TAG = 0xCA


class FaultType(Enum):
    """Fault latched by the bootloader before the reset."""

    NoFault = 0
    HardFault = 1
    SecureFault = 2


# nRF5340 application core RESETREAS flags (bit position -> short label).
RESET_REASON_FLAGS = {
    1 << 0: "pin",
    1 << 1: "watchdog0",
    1 << 2: "ctrl-ap",
    1 << 3: "soft-reset",
    1 << 4: "lockup",
    1 << 5: "off-wakeup",
    1 << 6: "lpcomp",
    1 << 7: "debug-if",
    1 << 24: "nfc",
    1 << 25: "watchdog1",
    1 << 26: "vbus",
}


def decode_reset_reason(reset_reason: int) -> str:
    """Decode a RESETREAS register value into a short readable string."""
    if reset_reason == 0:
        return "power-on"
    labels = [
        label
        for mask, label in RESET_REASON_FLAGS.items()
        if reset_reason & mask
    ]
    unknown = reset_reason & ~sum(RESET_REASON_FLAGS)
    if unknown:
        labels.append(f"0x{unknown:08x}")
    return "+".join(labels)


# ARMv8-M Configurable Fault Status Register (CFSR) bits: MMFSR (0-7),
# BFSR (8-15), UFSR (16-31). Used by the inspect command to spell out the
# raw fault status the bootloader latched.
CFSR_FLAGS = {
    1 << 0: "IACCVIOL",
    1 << 1: "DACCVIOL",
    1 << 3: "MUNSTKERR",
    1 << 4: "MSTKERR",
    1 << 5: "MLSPERR",
    1 << 8: "IBUSERR",
    1 << 9: "PRECISERR",
    1 << 10: "IMPRECISERR",
    1 << 11: "UNSTKERR",
    1 << 12: "STKERR",
    1 << 13: "LSPERR",
    1 << 16: "UNDEFINSTR",
    1 << 17: "INVSTATE",
    1 << 18: "INVPC",
    1 << 19: "NOCP",
    1 << 20: "STKOF",
    1 << 24: "UNALIGNED",
    1 << 25: "DIVBYZERO",
}

# ARMv8-M Secure Fault Status Register (SFSR) bits.
SFSR_FLAGS = {
    1 << 0: "INVEP",
    1 << 1: "INVIS",
    1 << 2: "INVER",
    1 << 3: "AUVIOL",
    1 << 4: "INVTRAN",
    1 << 5: "LSPERR",
    1 << 6: "SFARVALID",
    1 << 7: "LSERR",
}


def _decode_flags(value: int, flags: dict[int, str]) -> str:
    if value == 0:
        return ""
    return "+".join(label for mask, label in flags.items() if value & mask)


def decode_cfsr(cfsr: int) -> str:
    """Decode a CFSR value into its set fault-status flag names."""
    return _decode_flags(cfsr, CFSR_FLAGS)


def decode_sfsr(sfsr: int) -> str:
    """Decode an SFSR value into its set secure-fault flag names."""
    return _decode_flags(sfsr, SFSR_FLAGS)


# Size of the status payload sent by firmware without crash-report support.
STATUS_LEGACY_SIZE = 12
# Size of the crash report appended to status payloads (mirrors
# ipc_crash_report_t in the swarmit firmware).
CRASH_REPORT_SIZE = 22


# Requests
@dataclass
class PayloadStatus(Payload):
    """Dataclass that holds an application status notification packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="device", disp="dev."),
            PayloadFieldMetadata(name="status", disp="st."),
            PayloadFieldMetadata(name="battery", disp="bat.", length=2),
            PayloadFieldMetadata(
                name="pos_x", disp="pos x", length=4, signed=True
            ),
            PayloadFieldMetadata(
                name="pos_y", disp="pos y", length=4, signed=True
            ),
            PayloadFieldMetadata(name="reset_reason", disp="rst", length=4),
            PayloadFieldMetadata(name="fault", disp="fault"),
            PayloadFieldMetadata(name="from_ns", disp="ns"),
            PayloadFieldMetadata(name="cfsr", disp="cfsr", length=4),
            PayloadFieldMetadata(name="sfsr", disp="sfsr", length=4),
            PayloadFieldMetadata(name="pc", disp="pc", length=4),
            PayloadFieldMetadata(name="lr", disp="lr", length=4),
        ]
    )

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

    def from_bytes(self, bytes_):
        # Firmware without crash-report support sends the legacy short
        # payload; parse it with a zeroed crash report so mixed fleets keep
        # reporting status during the bootloader rollout.
        if len(bytes_) == STATUS_LEGACY_SIZE:
            bytes_ = bytes(bytes_) + bytes(CRASH_REPORT_SIZE)
        return super().from_bytes(bytes_)


@dataclass
class PayloadEmpty(Payload):
    """Dataclass that holds an application request packet (start/stop/status)."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: []
    )


@dataclass
class PayloadStart(PayloadEmpty):
    """Dataclass that holds an application start request packet."""


@dataclass
class PayloadLH2Capture(PayloadEmpty):
    """Dataclass that holds a raw LH2 capture trigger (no body)."""


@dataclass
class PayloadStop(PayloadEmpty):
    """Dataclass that holds an application stop request packet."""


@dataclass
class PayloadReset(Payload):
    """Dataclass that holds an application reset request packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="pos_x", length=4),
            PayloadFieldMetadata(name="pos_y", length=4),
        ]
    )

    pos_x: int = 0
    pos_y: int = 0


@dataclass
class PayloadOTAStart(Payload):
    """Dataclass that holds an OTA start packet.

    `version` is appended at the end so a legacy bootloader that parses only
    the first 8 bytes (image size + chunk count) tolerates the extra byte.
    """

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="fw_length", disp="len.", length=4),
            PayloadFieldMetadata(
                name="fw_chunk_counts", disp="chunks", length=4
            ),
            PayloadFieldMetadata(name="version", disp="ver.", length=1),
        ]
    )

    fw_length: int = 0
    fw_chunk_count: int = 0
    version: int = OTA_PROTOCOL_VERSION_BLOCK


@dataclass
class PayloadOTAChunk(Payload):
    """Dataclass that holds an OTA chunk packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="index", disp="idx", length=4),
            PayloadFieldMetadata(name="count", disp="size"),
            PayloadFieldMetadata(name="sha", type_=bytes, length=8),
            PayloadFieldMetadata(name="chunk", type_=bytes, length=0),
        ]
    )

    index: int = 0
    count: int = 0
    sha: bytes = dataclasses.field(default_factory=lambda: bytearray)
    chunk: bytes = dataclasses.field(default_factory=lambda: bytearray)


@dataclass
class PayloadCalibrationData(Payload):
    """Dataclass that holds a calibration data packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(
                name="homography_count", disp="count", length=4
            ),
            PayloadFieldMetadata(
                name="homography_index", disp="idx", length=4
            ),
            PayloadFieldMetadata(
                name="homography", type_=bytes, length=3 * 3 * 4
            ),
        ]
    )

    homography_count: int = (
        0  # number of homography matrices used for localization
    )
    homography_index: int = 0  # index of the homography matrix to be sent
    homography: bytes = dataclasses.field(
        default_factory=lambda: bytearray
    )  # 9x4 bytes of the homography matrix


@dataclass
class PayloadOTAStartAck(Payload):
    """Dataclass that holds an application OTA start ACK notification packet.

    A block-OTA bootloader appends its `version` byte; a legacy bootloader
    sends the empty ack, which parses as version 1.
    """

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="version", disp="ver.", length=1),
        ]
    )

    version: int = OTA_PROTOCOL_VERSION_LEGACY

    def from_bytes(self, bytes_):
        # Legacy bootloaders send an empty ack (no version byte); treat that
        # as version 1 so mixed fleets negotiate correctly.
        if len(bytes_) == 0:
            self.version = OTA_PROTOCOL_VERSION_LEGACY
            return self
        return super().from_bytes(bytes_)


@dataclass
class PayloadOTAChunkAck(Payload):
    """Dataclass that holds an application OTA chunk ACK notification packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="index", disp="idx", length=4),
        ]
    )

    index: int = 0


@dataclass
class PayloadOTABlockReportReq(Payload):
    """Host -> device: request a bot's received-chunk bitmap for one block."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="block_index", disp="blk", length=4),
            PayloadFieldMetadata(name="block_size", disp="w"),
        ]
    )

    block_index: int = 0
    block_size: int = 0


@dataclass
class PayloadOTABlockReportResp(Payload):
    """Device -> host: bitmap of received+verified chunks for its block.

    `block_index` is the block the bot currently holds; a bot that has not yet
    written any chunk of the requested block reports an earlier block, which the
    controller reads as "needs the whole requested block".
    """

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="block_index", disp="blk", length=4),
            PayloadFieldMetadata(name="received_mask", disp="mask", length=4),
            PayloadFieldMetadata(name="status", disp="st."),
        ]
    )

    block_index: int = 0
    received_mask: int = 0
    status: int = 0


@dataclass
class PayloadOTAFinalize(Payload):
    """Host -> device: verify the whole written image against this SHA256."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="sha", type_=bytes, length=32),
        ]
    )

    sha: bytes = dataclasses.field(default_factory=lambda: bytearray)


@dataclass
class PayloadOTAFinalizeResp(Payload):
    """Device -> host: 1 if the image SHA256 matched, 0 otherwise."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="ok", disp="ok"),
        ]
    )

    ok: int = 0


@dataclass
class PayloadEvent(Payload):
    """Dataclass that holds an event notification packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="timestamp", disp="ts", length=4),
            PayloadFieldMetadata(name="count", disp="len."),
            PayloadFieldMetadata(
                name="data", disp="data", type_=bytes, length=0
            ),
        ]
    )

    timestamp: int = 0
    count: int = 0
    data: bytes = dataclasses.field(default_factory=lambda: bytearray)


@dataclass
class PayloadMessage(Payload):
    """Dataclass that holds a message packet."""

    metadata: list[PayloadFieldMetadata] = dataclasses.field(
        default_factory=lambda: [
            PayloadFieldMetadata(name="count", disp="len."),
            PayloadFieldMetadata(
                name="message", disp="msg", type_=bytes, length=0
            ),
        ]
    )

    count: int = 0
    message: bytes = dataclasses.field(default_factory=lambda: bytearray)


# Register all swarmit specific parsers at module level
register_parser(PayloadType.SWARMIT_STATUS, PayloadStatus)
register_parser(PayloadType.SWARMIT_START, PayloadStart)
register_parser(PayloadType.SWARMIT_STOP, PayloadStop)
register_parser(PayloadType.SWARMIT_RESET, PayloadReset)
register_parser(PayloadType.SWARMIT_OTA_START, PayloadOTAStart)
register_parser(PayloadType.SWARMIT_OTA_CHUNK, PayloadOTAChunk)
register_parser(PayloadType.SWARMIT_OTA_START_ACK, PayloadOTAStartAck)
register_parser(PayloadType.SWARMIT_OTA_CHUNK_ACK, PayloadOTAChunkAck)
register_parser(
    PayloadType.SWARMIT_OTA_BLOCK_REPORT_REQ, PayloadOTABlockReportReq
)
register_parser(
    PayloadType.SWARMIT_OTA_BLOCK_REPORT_RESP, PayloadOTABlockReportResp
)
register_parser(PayloadType.SWARMIT_OTA_FINALIZE, PayloadOTAFinalize)
register_parser(
    PayloadType.SWARMIT_OTA_FINALIZE_RESP, PayloadOTAFinalizeResp
)
register_parser(PayloadType.SWARMIT_EVENT_LOG, PayloadEvent)
register_parser(PayloadType.SWARMIT_MESSAGE, PayloadMessage)
register_parser(PayloadType.SWARMIT_LH2_CALIBRATION, PayloadCalibrationData)
register_parser(PayloadType.SWARMIT_LH2_CAPTURE, PayloadLH2Capture)
register_parser(PayloadType.METRICS_PROBE, MetricsProbePayload)
