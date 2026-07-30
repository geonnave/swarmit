import pytest

from swarmit.testbed.protocol import (
    CRASH_REPORT_SIZE,
    IMAGE_DIGEST_LEN,
    INFO_GEN_SIZE,
    INFO_STRING_LEN,
    STATUS_LEGACY_SIZE,
    PayloadDeviceInfo,
    PayloadOTAStart,
    PayloadRequestMessage,
    PayloadStatus,
    PayloadType,
    boot_reason,
    decode_cfsr,
    decode_reset_reason,
    decode_sfsr,
    decode_string_field,
    encode_string_field,
)


def test_payload_status_round_trip():
    payload = PayloadStatus(
        device=1,
        status=2,
        battery=2800,
        pos_x=100,
        pos_y=200,
        reset_reason=0x2,  # watchdog0
        fault=2,  # secure fault
        from_ns=1,
        cfsr=0x100,
        sfsr=0x8,
        pc=0x0001_2345,
        lr=0x0001_2340,
        info_gen=7,
    )
    raw = payload.to_bytes()
    assert len(raw) == STATUS_LEGACY_SIZE + CRASH_REPORT_SIZE + INFO_GEN_SIZE

    parsed = PayloadStatus().from_bytes(bytes(raw))
    assert parsed.info_gen == 7
    assert parsed.device == 1
    assert parsed.status == 2
    assert parsed.battery == 2800
    assert parsed.pos_x == 100
    assert parsed.pos_y == 200
    assert parsed.reset_reason == 0x2
    assert parsed.fault == 2
    assert parsed.from_ns == 1
    assert parsed.cfsr == 0x100
    assert parsed.sfsr == 0x8
    assert parsed.pc == 0x0001_2345
    assert parsed.lr == 0x0001_2340


def test_payload_status_legacy_frame():
    # Status payload from firmware without crash-report support: 12 bytes,
    # crash report fields parse as zero.
    legacy = PayloadStatus(
        device=1, status=1, battery=2900, pos_x=42, pos_y=43
    ).to_bytes()[:STATUS_LEGACY_SIZE]

    parsed = PayloadStatus().from_bytes(bytes(legacy))
    assert parsed.device == 1
    assert parsed.status == 1
    assert parsed.battery == 2900
    assert parsed.pos_x == 42
    assert parsed.pos_y == 43
    assert parsed.reset_reason == 0
    assert parsed.fault == 0
    assert parsed.from_ns == 0
    assert parsed.pc == 0


def test_payload_status_truncated_frame_raises():
    with pytest.raises(ValueError):
        PayloadStatus().from_bytes(bytes(5))


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "power-on"),
        (1 << 0, "pin"),
        (1 << 1, "watchdog0"),
        (1 << 3, "soft-reset"),
        (1 << 4, "lockup"),
        ((1 << 1) | (1 << 3), "watchdog0+soft-reset"),
        (1 << 25, "watchdog1"),
        (1 << 30, "0x40000000"),
    ],
)
def test_decode_reset_reason(value, expected):
    assert decode_reset_reason(value) == expected


def test_decode_cfsr():
    assert decode_cfsr(0) == ""
    assert decode_cfsr(1 << 1) == "DACCVIOL"
    assert decode_cfsr(1 << 25) == "DIVBYZERO"
    assert decode_cfsr(1 << 20) == "STKOF"


def test_decode_sfsr():
    assert decode_sfsr(0) == ""
    # NS write into a secure region -> attribution unit violation
    assert decode_sfsr(1 << 3) == "AUVIOL"
    assert decode_sfsr(1 << 0) == "INVEP"


def test_payload_status_pre_generation_frame():
    # Firmware with a crash report but no generation counter: the frame is one
    # byte short and must still parse, reporting generation 0.
    frame = PayloadStatus(device=1, status=1, battery=2900).to_bytes()[
        : STATUS_LEGACY_SIZE + CRASH_REPORT_SIZE
    ]
    parsed = PayloadStatus().from_bytes(bytes(frame))
    assert parsed.battery == 2900
    assert parsed.info_gen == 0


def test_device_info_matches_firmware_wire_size():
    # 154 bytes is the contract the firmware asserts on its own struct. If
    # this changes, swrmt_device_info_pkt_t must change with it.
    assert PayloadDeviceInfo().size == 154


def test_payload_device_info_round_trip():
    payload = PayloadDeviceInfo(
        info_version=1,
        info_gen=42,
        boot_count=37,
        uptime_s=4324,
        bl_version=encode_string_field("0.9.0-3-g29e2704"),
        net_version=encode_string_field("0.9.0-3-g29e2704"),
        image_state=0,
        image_result=1,
        image_size=59360,
        image_digest=bytes.fromhex("3f9a2c81d4e5b607"),
        image_name=encode_string_field("lakers-sandbox.bin"),
        image_version=encode_string_field("0.9.0-12-g1a2b3c4"),
        lh2_homography_count=4,
        lh2_flags=0b11,
    )
    parsed = PayloadDeviceInfo().from_bytes(bytes(payload.to_bytes()))

    assert parsed.info_gen == 42
    assert parsed.boot_count == 37
    assert parsed.uptime_s == 4324
    assert parsed.image_size == 59360
    assert bytes(parsed.image_digest).hex() == "3f9a2c81d4e5b607"
    assert decode_string_field(parsed.image_name) == "lakers-sandbox.bin"
    assert decode_string_field(parsed.image_version) == "0.9.0-12-g1a2b3c4"
    assert decode_string_field(parsed.bl_version) == "0.9.0-3-g29e2704"
    assert parsed.lh2_homography_count == 4
    assert parsed.lh2_flags == 0b11


def test_payload_device_info_short_payload_does_not_raise():
    # A bot running older firmware, or a truncated frame, parses as zeros
    # rather than taking down the RX thread.
    parsed = PayloadDeviceInfo().from_bytes(b"\x01\x05")
    assert parsed.info_version == 1
    assert parsed.info_gen == 5
    assert parsed.image_size == 0
    assert decode_string_field(parsed.image_name) == ""


def test_string_fields_are_nul_padded_and_truncated():
    # Exactly 32 bytes on the wire, always NUL-terminated, so a name at or
    # past the cap cannot run into the field that follows it.
    assert len(encode_string_field("short")) == INFO_STRING_LEN
    assert encode_string_field("short")[5:] == bytes(INFO_STRING_LEN - 5)

    long_name = "x" * 100
    encoded = encode_string_field(long_name)
    assert len(encoded) == INFO_STRING_LEN
    assert encoded[-1] == 0
    assert decode_string_field(encoded) == "x" * (INFO_STRING_LEN - 1)

    # 31 characters is the longest that survives intact.
    edge = "y" * (INFO_STRING_LEN - 1)
    assert decode_string_field(encode_string_field(edge)) == edge


def test_payload_ota_start_carries_image_labels():
    payload = PayloadOTAStart(
        fw_length=1024,
        fw_chunk_count=8,
        image_name="move-and-blink.bin",
        image_version="2.0",
    )
    raw = payload.to_bytes()
    # 9 bytes of the original message plus the two 32-byte labels.
    assert len(raw) == 9 + 2 * INFO_STRING_LEN

    parsed = PayloadOTAStart().from_bytes(bytes(raw))
    assert parsed.fw_length == 1024
    assert parsed.version == 2
    assert decode_string_field(parsed.image_name) == "move-and-blink.bin"
    assert decode_string_field(parsed.image_version) == "2.0"


def test_payload_ota_start_defaults_to_empty_labels():
    # A flash with no labels still produces a well-formed packet; the device
    # reads empty strings and the host falls back to the digest.
    raw = PayloadOTAStart(fw_length=8, fw_chunk_count=1).to_bytes()
    assert len(raw) == 9 + 2 * INFO_STRING_LEN
    parsed = PayloadOTAStart().from_bytes(bytes(raw))
    assert decode_string_field(parsed.image_name) == ""


def test_payload_request_message_defaults_to_device_info():
    payload = PayloadRequestMessage()
    raw = payload.to_bytes()
    assert len(raw) == 2
    assert raw[0] == PayloadType.SWARMIT_DEVICE_INFO_RESP
    assert raw[1] == 0

    parsed = PayloadRequestMessage().from_bytes(bytes(raw))
    assert parsed.msg_id == PayloadType.SWARMIT_DEVICE_INFO_RESP


def test_image_digest_length_matches_firmware():
    assert IMAGE_DIGEST_LEN == 8


@pytest.mark.parametrize(
    "reset_reason,fault,expected",
    [
        (0, 0, "PowerOnReboot"),
        (1 << 0, 0, "PowerOnReboot"),
        (1 << 1, 0, "HardwareWatchdogReset"),  # WDT0: the crash deadman
        (1 << 25, 0, "SoftwareReset"),  # WDT1: only the stop command
        (1 << 3, 0, "SoftwareReset"),
        # A cabled flash sets ctrl-ap + SREQ + LOCKUP at once. Testing LOCKUP
        # first reported a freshly programmed device as watchdog-reset, which
        # is what the bench caught.
        (0x1C, 0, "SoftwareReset"),
        # A bare lockup: Matter has no value for it, and claiming a watchdog
        # fired when none did is worse than admitting the enum cannot say.
        (1 << 4, 0, "Unspecified"),
        # A latched fault wins over everything.
        (1 << 3, 1, "HardwareWatchdogReset"),
    ],
)
def test_boot_reason_mapping(reset_reason, fault, expected):
    assert boot_reason(reset_reason, fault).name == expected


def test_boot_reason_is_derived_not_transmitted():
    # The device does not send it: everything the mapping needs already rides
    # the status frame, so a fix is a host change rather than a reflash.
    assert not hasattr(PayloadDeviceInfo(), "boot_reason")
