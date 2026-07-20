from unittest.mock import patch

import pytest
from dotbot_utils.protocol import Packet
from marilib.mari_protocol import Frame as MariFrame
from marilib.mari_protocol import Header as MariHeader
from marilib.mari_protocol import NextProto
from marilib.model import SCHEDULES, EdgeEvent, GatewayInfo, MariGateway

from swarmit.testbed.adapter import (
    OTA_DOWNLINK_UTILIZATION,
    LinkGeometry,
    MarilibCloudAdapter,
    MarilibEdgeAdapter,
    derive_block_settings,
)
from swarmit.testbed.protocol import PayloadStatus

# Mari schedule ids, as announced by a gateway (marilib.model.SCHEDULES).
SCHEDULE_HUGE = 1
SCHEDULE_BIG = 3
SCHEDULE_MEDIUM = 4
SCHEDULE_TINY = 6


@patch("swarmit.testbed.adapter.MarilibSerialAdapter")
@patch("swarmit.testbed.adapter.MarilibEdge.send_frame")
def test_marilib_edge_adapter(send_frame_mock, _, capsys):
    adapter = MarilibEdgeAdapter(
        port="p", baudrate=1, verbose=True, busy_wait_timeout=0.1
    )
    packets = []

    def on_frame_received(_, f):
        packets.append(f)

    payload = PayloadStatus(device=1, status=2)
    packet = Packet().from_payload(payload)
    mari_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.SWARMIT_TESTBED),
        payload=packet.to_bytes(),
    )

    # should ignore if not initialized
    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)
    assert not packets

    adapter.init(on_frame_received)
    out, _ = capsys.readouterr()
    assert "Mari nodes available" in out

    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)

    assert packets == [packet]

    # a frame for another namespace is dropped by the strict next_proto gate
    other_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.DOTBOT_APP),
        payload=packet.to_bytes(),
    )
    adapter.on_event(EdgeEvent.NODE_DATA, other_frame)
    assert packets == [packet]

    adapter.on_event(EdgeEvent.NODE_JOINED, None)
    out, _ = capsys.readouterr()
    assert "Node joined" in out

    adapter.on_event(EdgeEvent.NODE_LEFT, None)
    out, _ = capsys.readouterr()
    assert "Node left" in out

    # invalid frame
    mari_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.SWARMIT_TESTBED),
        payload=b"`\x01invalid",
    )
    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)
    out, _ = capsys.readouterr()
    assert "Error parsing packet" in out

    adapter.send_payload(mari_frame.header.destination, payload)
    send_frame_mock.assert_called_once_with(
        dst=mari_frame.header.destination,
        payload=packet.to_bytes(),
        next_proto=NextProto.SWARMIT_TESTBED,
    )
    adapter.close()


@patch("swarmit.testbed.adapter.MarilibSerialAdapter")
def test_marilib_edge_adapter_init_failed(serial_adapter_mock, capsys):
    serial_adapter_mock.side_effect = Exception("init failed")
    with patch("sys.exit") as exit_mock:
        MarilibEdgeAdapter(
            port="p", baudrate=1, verbose=True, busy_wait_timeout=0.1
        )

    exit_mock.assert_called_with(1)
    out, _ = capsys.readouterr()
    assert "Error initializing MarilibEdge" in out


@patch("swarmit.testbed.adapter.MarilibMQTTAdapter")
@patch("swarmit.testbed.adapter.MarilibCloud.send_frame")
def test_marilib_cloud_adapter(send_frame_mock, _, capsys):
    adapter = MarilibCloudAdapter(
        host="h",
        port=1,
        use_tls=False,
        network_id=2,
        verbose=True,
        busy_wait_timeout=0.1,
    )

    packets = []

    def on_frame_received(_, f):
        packets.append(f)

    payload = PayloadStatus(device=1, status=2)
    packet = Packet().from_payload(payload)
    mari_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.SWARMIT_TESTBED),
        payload=packet.to_bytes(),
    )

    # should ignore if not initialized
    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)
    assert not packets

    adapter.init(on_frame_received)
    out, _ = capsys.readouterr()
    assert "Mari nodes available" in out

    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)

    assert packets == [packet]

    # a frame for another namespace is dropped by the strict next_proto gate
    other_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.DOTBOT_APP),
        payload=packet.to_bytes(),
    )
    adapter.on_event(EdgeEvent.NODE_DATA, other_frame)
    assert packets == [packet]

    adapter.on_event(EdgeEvent.NODE_JOINED, None)
    out, _ = capsys.readouterr()
    assert "Node joined" in out

    adapter.on_event(EdgeEvent.NODE_LEFT, None)
    out, _ = capsys.readouterr()
    assert "Node left" in out

    # invalid frame
    mari_frame = MariFrame(
        header=MariHeader(next_proto=NextProto.SWARMIT_TESTBED),
        payload=b"`\x01invalid",
    )
    adapter.on_event(EdgeEvent.NODE_DATA, mari_frame)
    out, _ = capsys.readouterr()
    assert "Error parsing packet" in out

    adapter.send_payload(mari_frame.header.destination, payload)
    send_frame_mock.assert_called_once_with(
        dst=mari_frame.header.destination,
        payload=packet.to_bytes(),
        next_proto=NextProto.SWARMIT_TESTBED,
    )
    adapter.close()


def test_link_geometry_from_schedule_id():
    geometry = LinkGeometry.from_schedule_id(SCHEDULE_MEDIUM)
    schedule = SCHEDULES[SCHEDULE_MEDIUM]
    assert geometry.schedule_name == "medium"
    assert geometry.slotframe_s == pytest.approx(
        schedule["sf_duration"] / 1000.0
    )
    # One downlink frame per D-cell per slotframe.
    assert geometry.downlink_pps == pytest.approx(
        schedule["d_down"] / geometry.slotframe_s
    )
    assert geometry.reported is True
    # An id the gateway has not reported yet (0 is the GatewayInfo default).
    assert LinkGeometry.from_schedule_id(0) is None


def test_link_geometry_fallback_is_flagged():
    fallback = LinkGeometry.fallback()
    assert fallback.schedule_name == "medium"
    assert fallback.reported is False


def test_derive_block_settings_paces_to_the_downlink():
    geometry = LinkGeometry.from_schedule_id(SCHEDULE_MEDIUM)
    settings = derive_block_settings(geometry, n_bots=1)
    assert settings.inter_chunk_delay == pytest.approx(
        1.0 / (geometry.downlink_pps * OTA_DOWNLINK_UTILIZATION), rel=0.02
    )
    assert settings.block_size == 32
    # The report window grows with the fleet...
    assert (
        derive_block_settings(geometry, n_bots=100).report_timeout
        > settings.report_timeout
    )
    # ...and a denser schedule (shorter slotframe) shortens it.
    tiny = LinkGeometry.from_schedule_id(SCHEDULE_TINY)
    assert (
        derive_block_settings(tiny, n_bots=1).report_timeout
        < settings.report_timeout
    )


def test_derive_block_settings_clamps_to_the_device():
    geometry = LinkGeometry.from_schedule_id(SCHEDULE_HUGE)
    # A device slower than the radio binds the inject rate instead.
    settings = derive_block_settings(
        geometry, n_bots=1, utilization=1.0, device_chunk_rate=5.0
    )
    assert settings.inter_chunk_delay == pytest.approx(1.0 / 5.0, rel=0.01)


def test_derive_block_settings_without_a_reported_schedule():
    # No geometry: pace with the fallback rather than refusing to flash.
    assert (
        derive_block_settings(None, n_bots=1).inter_chunk_delay
        == derive_block_settings(
            LinkGeometry.fallback(), n_bots=1
        ).inter_chunk_delay
    )


@patch("swarmit.testbed.adapter.MarilibSerialAdapter")
def test_edge_adapter_reports_link_geometry(_):
    adapter = MarilibEdgeAdapter(port="p", baudrate=1, busy_wait_timeout=0.1)
    # Nothing reported yet.
    assert adapter.link_geometry() is None
    adapter.mari.gateway.info.schedule_id = SCHEDULE_HUGE
    assert adapter.link_geometry().schedule_name == "huge"


@patch("swarmit.testbed.adapter.MarilibMQTTAdapter")
def test_cloud_adapter_reports_link_geometry(_):
    adapter = MarilibCloudAdapter(
        host="h", port=1, use_tls=False, network_id=2, busy_wait_timeout=0.1
    )
    assert adapter.link_geometry() is None
    adapter.mari.gateways = {
        0: MariGateway(info=GatewayInfo(address=0, schedule_id=SCHEDULE_BIG))
    }
    assert adapter.link_geometry().schedule_name == "big"


@patch("swarmit.testbed.adapter.MarilibMQTTAdapter")
def test_marilib_cloud_adapter_init_failed(mqtt_adapter_mock, capsys):
    mqtt_adapter_mock.side_effect = Exception("init failed")
    with patch("sys.exit") as exit_mock:
        MarilibCloudAdapter(
            host="h",
            port=1,
            use_tls=False,
            network_id=2,
            verbose=True,
            busy_wait_timeout=0.1,
        )

    exit_mock.assert_called_with(1)
    out, _ = capsys.readouterr()
    assert "Error initializing MarilibCloud" in out
