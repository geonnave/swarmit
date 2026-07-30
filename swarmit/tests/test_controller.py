import logging
import time
from unittest.mock import PropertyMock, patch

import pytest
from marilib.model import GatewayInfo, MariGateway

from swarmit.testbed.controller import (
    DEVICE_INFO_MAX_ATTEMPTS,
    Chunk,
    Controller,
    ControllerSettings,
    ResetLocation,
    StaleBootloaderError,
)
from swarmit.testbed.logger import setup_logging
from swarmit.testbed.ota import BlockOTASettings
from swarmit.testbed.protocol import OTA_PROTOCOL_VERSION_LEGACY, StatusType
from swarmit.tests.utils import (
    ChunkLossStrategy,
    MarilibMQTTAdapterMock,
    MarilibSerialAdapterMock,
    SwarmitNode,
)


def _fast_ota_settings(*args, **kwargs) -> BlockOTASettings:
    """Pacing stand-in for tests: no inter-chunk delay, short report window.

    The real derivation paces sends at the radio's downlink rate, which would
    stretch these transfers to tens of seconds. The mocked transport delivers
    instantly, so here pacing only costs wall clock.
    """
    return BlockOTASettings(inter_chunk_delay=0.0, report_timeout=0.02)


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.INACTIVE_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_basic():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    assert sorted(controller.known_devices.keys()) == [
        f"{node.address:08X}" for node in nodes
    ]
    assert sorted(controller.ready_devices) == [
        f"{node.address:08X}" for node in nodes
    ]
    assert sorted(controller.running_devices) == []
    assert sorted(controller.resetting_devices) == []

    nodes[0].status = StatusType.Running
    time.sleep(0.5)
    assert sorted(controller.ready_devices) == [f"{nodes[1].address:08X}"]
    assert sorted(controller.running_devices) == [f"{nodes[0].address:08X}"]
    assert sorted(controller.resetting_devices) == []

    nodes[1].status = StatusType.Resetting
    time.sleep(0.5)
    assert sorted(controller.ready_devices) == []
    assert sorted(controller.resetting_devices) == [f"{nodes[1].address:08X}"]
    assert sorted(controller.running_devices) == [f"{nodes[0].address:08X}"]

    nodes[0].enabled = False
    time.sleep(1.5)

    assert list(controller.known_devices.keys()) == [f"{nodes[1].address:08X}"]

    controller.terminate()


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.COMMAND_ATTEMPT_DELAY", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_start_broadcast():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    controller.start(timeout=0.1)
    time.sleep(0.3)
    assert all([node.status == StatusType.Running for node in nodes]) is True


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.COMMAND_ATTEMPT_DELAY", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_start_unicast():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    node3 = SwarmitNode(
        address=0x03, status=StatusType.Running, adapter=test_adapter
    )
    nodes.append(node3)

    for node in nodes:
        test_adapter.add_node(node)

    assert sorted(controller.known_devices.keys()) == [
        f"{node.address:08X}" for node in nodes
    ]

    controller.status_data = {}
    controller.start(devices=["00000001", "00000003"], timeout=0.1)
    time.sleep(0.3)
    assert nodes[0].status == StatusType.Running
    assert nodes[1].status == StatusType.Bootloader
    assert nodes[2].status == StatusType.Running


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.COMMAND_ATTEMPT_DELAY", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibMQTTAdapter",
    MarilibMQTTAdapterMock,
)
def test_controller_start_broadcast_cloud_adapter():
    controller = Controller(
        ControllerSettings(
            adapter="cloud", network_id=42, adapter_wait_timeout=0.1
        )
    )
    controller.interface.mari.gateways = {
        0: MariGateway(info=GatewayInfo(address=0, network_id=42))
    }
    test_adapter = controller.interface.mari.mqtt_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    controller.start(timeout=0.1)
    time.sleep(0.3)
    assert all([node.status == StatusType.Running for node in nodes]) is True


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.COMMAND_ATTEMPT_DELAY", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_stop_broadcast():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(
            address=addr, status=StatusType.Running, adapter=test_adapter
        )
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    controller.stop(timeout=0.1)
    time.sleep(0.3)
    assert (
        all([node.status == StatusType.Bootloader for node in nodes]) is True
    )


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.COMMAND_ATTEMPT_DELAY", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_stop_unicast():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(
            address=addr, status=StatusType.Running, adapter=test_adapter
        )
        for addr in [0x01, 0x02]
    ]
    node3 = SwarmitNode(address=0x03, adapter=test_adapter)
    nodes.append(node3)

    for node in nodes:
        test_adapter.add_node(node)

    assert sorted(controller.known_devices.keys()) == [
        f"{node.address:08X}" for node in nodes
    ]

    controller.stop(devices=["00000001", "00000003"], timeout=0.1)
    time.sleep(0.3)
    assert nodes[0].status == StatusType.Bootloader
    assert nodes[1].status == StatusType.Running
    assert nodes[2].status == StatusType.Bootloader


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_status(capsys):
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    controller.status(timeout=0.1)
    out, _ = capsys.readouterr()
    assert "No device found" in out

    node1 = SwarmitNode(address=0x01, adapter=test_adapter, battery=2950)
    node2 = SwarmitNode(address=0x02, adapter=test_adapter, battery=2100)
    node3 = SwarmitNode(address=0x03, adapter=test_adapter, battery=1500)
    nodes = [node1, node2, node3]
    for node in nodes:
        test_adapter.add_node(node)

    controller.status(timeout=0.1)
    out, _ = capsys.readouterr()
    assert "3 devices found" in out
    assert f"{node1.address:08X}" in out
    assert f"{node2.address:08X}" in out
    assert f"{node3.address:08X}" in out
    assert f"{2950/1000:.2f}V" in out
    assert f"{2100/1000:.2f}V" in out
    assert f"{1500/1000:.2f}V" in out


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibMQTTAdapter",
    MarilibMQTTAdapterMock,
)
def test_controller_status_adapter_cloud(capsys):
    controller = Controller(
        ControllerSettings(
            adapter="cloud", network_id=42, adapter_wait_timeout=0.1
        )
    )
    controller.interface.mari.gateways = {
        0: MariGateway(info=GatewayInfo(address=0, network_id=42))
    }
    test_adapter = controller.interface.mari.mqtt_interface
    controller.status(timeout=0.1)
    out, _ = capsys.readouterr()
    assert "No device found" in out

    node1 = SwarmitNode(address=0x01, adapter=test_adapter)
    node2 = SwarmitNode(address=0x02, adapter=test_adapter, battery=2100)
    node3 = SwarmitNode(address=0x03, adapter=test_adapter, battery=1500)
    nodes = [node1, node2, node3]
    for node in nodes:
        test_adapter.add_node(node)

    controller.status(timeout=0.1)
    time.sleep(0.3)
    out, _ = capsys.readouterr()
    assert "3 devices found" in out
    assert f"{node1.address:08X}" in out
    assert f"{node2.address:08X}" in out
    assert f"{node3.address:08X}" in out
    assert f"{2500/1000:.2f}V" in out
    assert f"{2100/1000:.2f}V" in out
    assert f"{1500/1000:.2f}V" in out


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_reset():
    controller = Controller(
        ControllerSettings(
            devices=["00000001", "00000002"], adapter_wait_timeout=0.1
        )
    )
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)
    locations = {
        "00000001": ResetLocation(pos_x=1000000, pos_y=2000),
        "00000002": ResetLocation(pos_x=2000000, pos_y=1000),
    }
    controller.reset(locations=locations)
    time.sleep(0.3)
    for node in nodes:
        assert node.status == StatusType.Resetting
    controller.stop(timeout=0.1)
    time.sleep(0.3)
    assert (
        all([node.status == StatusType.Bootloader for node in nodes]) is True
    )


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_reset_not_ready():
    controller = Controller(
        ControllerSettings(
            devices=["00000001", "00000002"], adapter_wait_timeout=0.1
        )
    )
    test_adapter = controller.interface.mari.serial_interface
    node1 = SwarmitNode(address=0x01, adapter=test_adapter)
    node2 = SwarmitNode(
        address=0x02, status=StatusType.Running, adapter=test_adapter
    )
    nodes = [node1, node2]

    for node in nodes:
        test_adapter.add_node(node)
    locations = {
        "00000001": ResetLocation(pos_x=1000000, pos_y=2000),
        "00000002": ResetLocation(pos_x=2000000, pos_y=1000),
    }
    controller.reset(locations=locations)
    time.sleep(0.3)
    assert node1.status == StatusType.Resetting
    assert node2.status == StatusType.Running

    controller.stop(timeout=0.1)
    time.sleep(0.3)
    assert node1.status == StatusType.Bootloader
    assert node2.status == StatusType.Bootloader


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_monitor(caplog):
    caplog.set_level(logging.INFO)
    setup_logging()
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))

    controller.monitor(run_forever=False, timeout=0.1)
    assert "Monitoring testbed" in caplog.text

    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)
        node.start_log_event_task()

    controller.monitor(run_forever=False, timeout=0.1)
    assert "Monitoring testbed" in caplog.text
    for node in nodes:
        assert f"Node {node.address:08X} log event" in caplog.text
    controller.terminate()


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_monitor_single_device(caplog):
    caplog.set_level(logging.INFO)
    setup_logging()
    controller = Controller(
        ControllerSettings(devices=["00000001"], adapter_wait_timeout=0.1)
    )

    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)
        node.start_log_event_task()

    controller.monitor(run_forever=False, timeout=0.1)
    assert "Monitoring testbed" in caplog.text
    assert "Node 00000001 log event" in caplog.text
    assert "Node 00000002 log event" not in caplog.text
    controller.terminate()


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_send_message_unicast(capsys):
    controller = Controller(
        ControllerSettings(
            devices=["00000001", "00000003"], adapter_wait_timeout=0.1
        )
    )
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(
            address=addr, status=StatusType.Running, adapter=test_adapter
        )
        for addr in [0x01, 0x02]
    ]
    node3 = SwarmitNode(address=0x03, adapter=test_adapter)
    nodes.append(node3)
    for node in nodes:
        test_adapter.add_node(node)

    controller.send_message("Hello robot!")
    out, _ = capsys.readouterr()
    assert "Node 00000001 received message: Hello robot!" in out
    assert "Node 00000003 received message: Hello robot!" not in out


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_send_message_broadcast(capsys):
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(
            address=addr, status=StatusType.Running, adapter=test_adapter
        )
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    controller.send_message("Hello robot!")
    out, _ = capsys.readouterr()
    for node in ["00000001", "00000002"]:
        assert f"Node {node} received message: Hello robot!" in out


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
@patch("swarmit.testbed.controller.COMMAND_MAX_ATTEMPTS", 1)
def test_controller_send_lh2_calibration_from_file_bytes():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    matrix_0 = bytes(range(36))
    matrix_1 = bytes(range(36, 72))
    calibration_file = bytes([2]) + matrix_0 + matrix_1

    with patch.object(
        type(controller),
        "ready_devices",
        new_callable=PropertyMock,
        return_value=["00000001"],
    ):
        with patch.object(controller, "send_payload") as send_payload_mock:
            controller.send_lh2_calibration(calibration_file)

    assert send_payload_mock.call_count == 2
    first_call = send_payload_mock.call_args_list[0].args
    second_call = send_payload_mock.call_args_list[1].args

    # ready_devices is set so the controller sends unicast to each device,
    # not broadcast. "00000001" → 0x1.
    assert first_call[0] == 0x1
    assert first_call[1].homography_count == 2
    assert first_call[1].homography_index == 0
    assert first_call[1].homography == matrix_0

    assert second_call[0] == 0x1
    assert second_call[1].homography_count == 2
    assert second_call[1].homography_index == 1
    assert second_call[1].homography == matrix_1
    controller.terminate()


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
@patch("swarmit.testbed.controller.COMMAND_MAX_ATTEMPTS", 1)
def test_controller_send_lh2_calibration_from_legacy_out_format():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    matrix = bytes(range(36))
    calibration_file = bytes([1]) + matrix

    with patch.object(
        type(controller),
        "ready_devices",
        new_callable=PropertyMock,
        return_value=["00000001"],
    ):
        with patch.object(controller, "send_payload") as send_payload_mock:
            controller.send_lh2_calibration(calibration_file)

    assert send_payload_mock.call_count == 1
    call = send_payload_mock.call_args_list[0].args
    # ready_devices is set → unicast to "00000001" → 0x1.
    assert call[0] == 0x1
    assert call[1].homography_count == 1
    assert call[1].homography_index == 0
    assert call[1].homography == matrix
    controller.terminate()


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
@patch("swarmit.testbed.controller.COMMAND_MAX_ATTEMPTS", 1)
def test_controller_send_lh2_calibration_invalid_size():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    with patch.object(
        type(controller),
        "ready_devices",
        new_callable=PropertyMock,
        return_value=["00000001"],
    ):
        with pytest.raises(ValueError, match="expected 1\\+N\\*36 bytes"):
            controller.send_lh2_calibration(b"\x00" * 35)
    controller.terminate()


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
@patch("swarmit.testbed.controller.COMMAND_MAX_ATTEMPTS", 1)
def test_controller_send_lh2_calibration_legacy_count_mismatch():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    calibration_file = bytes([2]) + bytes(range(36))
    with patch.object(
        type(controller),
        "ready_devices",
        new_callable=PropertyMock,
        return_value=["00000001"],
    ):
        with pytest.raises(ValueError, match="count byte does not match"):
            controller.send_lh2_calibration(calibration_file)
    controller.terminate()


@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
@patch("swarmit.testbed.controller.COMMAND_MAX_ATTEMPTS", 1)
def test_controller_send_lh2_calibration_raw_format_rejected():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    raw_matrix_only = bytes(range(36))
    with patch.object(
        type(controller),
        "ready_devices",
        new_callable=PropertyMock,
        return_value=["00000001"],
    ):
        with pytest.raises(ValueError, match="expected 1\\+N\\*36 bytes"):
            controller.send_lh2_calibration(raw_matrix_only)
    controller.terminate()


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_broadcast():
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    firmware = b"\x00" * 2**16

    ota_data = controller.start_ota(firmware)
    assert ota_data["acked"] == [f"{node.address:08X}" for node in nodes]
    assert ota_data["missed"] == []

    for node in nodes:
        assert node.status == StatusType.Programming

    result = controller.transfer(firmware, ota_data["acked"])
    time.sleep(0.3)
    assert all([transfer.success for transfer in result.values()]) is True


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_broadcast_verbose():
    controller = Controller(
        ControllerSettings(adapter_wait_timeout=0.1, verbose=True)
    )
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    firmware = b"\x00" * 2**16

    ota_data = controller.start_ota(firmware)
    assert ota_data["acked"] == [f"{node.address:08X}" for node in nodes]
    assert ota_data["missed"] == []

    for node in nodes:
        assert node.status == StatusType.Programming

    result = controller.transfer(firmware, ota_data["acked"])
    time.sleep(0.3)
    assert all([transfer.success for transfer in result.values()]) is True


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_unicast():
    controller = Controller(
        ControllerSettings(devices=["00000001"], adapter_wait_timeout=0.1)
    )
    test_adapter = controller.interface.mari.serial_interface
    nodes = [
        SwarmitNode(address=addr, adapter=test_adapter)
        for addr in [0x01, 0x02]
    ]
    for node in nodes:
        test_adapter.add_node(node)

    firmware = b"\x00" * 2**16 + b"\x01" * 1234

    ota_data = controller.start_ota(firmware)
    assert ota_data["acked"] == ["00000001"]
    assert ota_data["missed"] == []

    assert nodes[0].status == StatusType.Programming
    assert nodes[1].status == StatusType.Bootloader

    result = controller.transfer(firmware, ota_data["acked"])
    time.sleep(0.3)
    assert all([transfer.success for transfer in result.values()]) is True
    # The untargeted bot was never written to.
    assert nodes[1].received_chunks == set()


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_repairs_lost_chunks():
    """A chunk lost on the downlink is repaired from the block report."""
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    # node1 misses chunk 5 twice, then accepts the repair broadcast.
    node1 = SwarmitNode(
        address=0x01,
        loss_strategy=ChunkLossStrategy(drop_index=5, drop_count=2),
        adapter=test_adapter,
    )
    # node2 never receives chunk 5, so its image stays incomplete.
    node2 = SwarmitNode(
        address=0x02,
        loss_strategy=ChunkLossStrategy(drop_index=5, drop_count=10_000),
        adapter=test_adapter,
    )
    nodes = [node1, node2]
    for node in nodes:
        test_adapter.add_node(node)

    firmware = b"\x00" * 2**16

    ota_data = controller.start_ota(firmware)
    assert ota_data["acked"] == [f"{node.address:08X}" for node in nodes]

    result = controller.transfer(firmware, ota_data["acked"])
    assert result["00000001"].success is True
    assert result["00000002"].success is False
    # The repair actually delivered the chunk rather than giving up on it.
    assert 5 in node1.received_chunks
    assert 5 not in node2.received_chunks


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_finalize_mismatch_fails():
    """A complete delivery whose image SHA does not match is not a success."""
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    node = SwarmitNode(
        address=0x01, ota_should_fail=True, adapter=test_adapter
    )
    test_adapter.add_node(node)

    firmware = b"\x00" * 2**16

    ota_data = controller.start_ota(firmware)
    result = controller.transfer(firmware, ota_data["acked"])
    # Every chunk arrived, but the device rejected the whole-image hash.
    assert len(node.received_chunks) == node.total_chunks
    assert result["00000001"].success is False


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.OTA_ACK_TIMEOUT_DEFAULT", 0.1)
@patch("swarmit.testbed.controller.derive_block_settings", _fast_ota_settings)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_controller_ota_refuses_stale_bootloader():
    """A bot that never announces the block protocol aborts the flash."""
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    node = SwarmitNode(
        address=0x01,
        ota_protocol_version=OTA_PROTOCOL_VERSION_LEGACY,
        adapter=test_adapter,
    )
    test_adapter.add_node(node)

    firmware = b"\x00" * 2**16

    ota_data = controller.start_ota(firmware)
    assert ota_data["acked"] == ["00000001"]
    assert controller.stale_bootloaders(ota_data["acked"]) == ["00000001"]

    with pytest.raises(StaleBootloaderError) as exc:
        controller.transfer(firmware, ota_data["acked"])
    assert "00000001" in str(exc.value)
    assert "flash-swarmit-sandbox" in str(exc.value)
    # Aborted before any chunk went on the wire.
    assert node.received_chunks == set()


def test_controller_chunk_repr():
    chunk = Chunk(index=42, size=128, acked=True, retries=2)
    assert (
        repr(chunk)
        == "{'index': 42, 'size': 128, 'acked': True, 'retries': 2}"
    )


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.INACTIVE_TIMEOUT", 5)
@patch("swarmit.testbed.controller.DEVICE_INFO_REFRESH_INTERVAL", 0.05)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_device_info_fetched_once_per_change():
    """The generation counter is what bounds device-info traffic.

    A bot is read once when first seen and then never again until its
    generation moves, no matter how many status frames arrive in between.
    """
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    node = SwarmitNode(
        address=0x01,
        adapter=test_adapter,
        info_gen=3,
        image_name="lakers-sandbox.bin",
        image_version="0.9.0",
    )
    test_adapter.add_node(node)
    addr = f"{node.address:08X}"

    deadline = time.time() + 3
    while time.time() < deadline and controller.status_data.get(addr) is None:
        time.sleep(0.01)
    assert controller.status_data[addr] is not None

    # First read lands on its own, with no explicit request from the caller.
    deadline = time.time() + 3
    while time.time() < deadline and not controller.status_data[addr].info:
        time.sleep(0.01)
    info = controller.status_data[addr].info
    assert info is not None
    assert info.info_gen == 3
    assert info.image_name == "lakers-sandbox.bin"
    assert info.image_version == "0.9.0"
    assert info.image_label == "lakers-sandbox.bin"

    # Many more status frames go by; none of them costs a device-info round.
    asked_once = node.device_info_requests
    assert asked_once >= 1
    time.sleep(0.8)
    assert node.device_info_requests == asked_once
    assert controller.stale_device_info() == []

    # The bot reboots: the counter moves and exactly one more read follows.
    node.info_gen = 4
    node.boot_count = 4
    deadline = time.time() + 3
    while (
        time.time() < deadline
        and controller.status_data[addr].info.info_gen != 4
    ):
        time.sleep(0.01)
    assert controller.status_data[addr].info.info_gen == 4
    assert controller.status_data[addr].info.boot_count == 4
    assert node.device_info_requests == asked_once + 1

    node.stop()
    controller.terminate()


@patch("swarmit.testbed.controller.COMMAND_TIMEOUT", 0.1)
@patch("swarmit.testbed.controller.INACTIVE_TIMEOUT", 5)
@patch("swarmit.testbed.controller.DEVICE_INFO_REFRESH_INTERVAL", 0.02)
@patch(
    "swarmit.testbed.adapter.MarilibSerialAdapter", MarilibSerialAdapterMock
)
def test_device_info_gives_up_on_silent_firmware():
    """Firmware predating the message must not be asked forever.

    It reports generation 0 and never replies, so without a cap the
    controller would put a broadcast on the downlink every refresh interval
    for the life of the session.
    """
    controller = Controller(ControllerSettings(adapter_wait_timeout=0.1))
    test_adapter = controller.interface.mari.serial_interface
    node = SwarmitNode(
        address=0x02,
        adapter=test_adapter,
        info_gen=0,
        answers_device_info=False,
    )
    test_adapter.add_node(node)
    addr = f"{node.address:08X}"

    deadline = time.time() + 3
    while time.time() < deadline and controller.status_data.get(addr) is None:
        time.sleep(0.01)

    # Drive the sweep directly rather than waiting on the cleanup thread's
    # 1 Hz tick: what is under test is the attempt cap, not the scheduling.
    assert controller.stale_device_info() == [addr]
    for _ in range(DEVICE_INFO_MAX_ATTEMPTS):
        controller._info_last_broadcast = 0.0
        controller._refresh_stale_device_info()

    assert controller.stale_device_info() == []
    assert controller.status_data[addr].info is None
    assert node.device_info_requests == 0

    # A change on the bot re-opens the question, so a re-flashed device is
    # not written off forever by a verdict reached before it was reflashed.
    node.info_gen = 9
    deadline = time.time() + 3
    while (
        time.time() < deadline and controller.status_data[addr].info_gen != 9
    ):
        time.sleep(0.01)
    assert controller.stale_device_info() == [addr]

    node.stop()
    controller.terminate()
