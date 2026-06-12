import pytest

from swarmit.testbed.protocol import (
    CRASH_REPORT_SIZE,
    STATUS_LEGACY_SIZE,
    PayloadStatus,
    decode_reset_reason,
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
        cfsr=0x100,
        sfsr=0x8,
        pc=0x0001_2345,
        lr=0x0001_2340,
    )
    raw = payload.to_bytes()
    assert len(raw) == STATUS_LEGACY_SIZE + CRASH_REPORT_SIZE

    parsed = PayloadStatus().from_bytes(bytes(raw))
    assert parsed.device == 1
    assert parsed.status == 2
    assert parsed.battery == 2800
    assert parsed.pos_x == 100
    assert parsed.pos_y == 200
    assert parsed.reset_reason == 0x2
    assert parsed.fault == 2
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
